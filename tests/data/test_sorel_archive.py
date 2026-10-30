"""Cloud publication tests use synthetic PEs and a local object-store double."""

from dataclasses import asdict, replace
import json
from pathlib import Path
import shutil
import sqlite3

import pytest
import yaml

from malweave.cli import main
from malweave.data import sorel, sorel_s3
from malweave.data import sorel_archive as archive
from tests.data.test_sorel import _job, _scanners
from tests.data.test_sorel_runner import _curl_fixture


@pytest.fixture
def cloud(tmp_path, monkeypatch):
    objects = tmp_path / "objects"
    uploads = []

    def location(uri):
        return objects / uri.removeprefix("s3://")

    def upload(source, uri, *, recursive=False):
        uploads.append(uri)
        target = location(uri)
        if recursive:
            shutil.copytree(source, target, dirs_exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def download(uri, target, *, missing_ok=False):
        source = location(uri)
        if missing_ok and not source.exists():
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        return True

    monkeypatch.setattr(archive, "_upload", upload)
    monkeypatch.setattr(archive, "_download", download)

    def aws(*args, **kwargs):
        assert args[:2] == ("s3", "rm")
        target = location(args[2])
        if "--recursive" in args:
            shutil.rmtree(target, ignore_errors=True)
        else:
            target.unlink(missing_ok=True)
        return True

    monkeypatch.setattr(archive, "_aws", aws)
    monkeypatch.setattr(archive.shutil, "which", lambda name: "/usr/bin/" + name)
    return location, uploads


def test_ten_sources_publish_evict_restore_resume_and_rebuild_evidence(
    tmp_path, monkeypatch, cloud
):
    location, uploads = cloud
    job, config, _ = _job(tmp_path, count=10)
    _scanners(monkeypatch)
    calls = _curl_fixture(monkeypatch)
    prefix = "s3://private/sorel/part-01"
    summary = sorel.run_sorel(job, config, limit=4, s3_prefix=prefix)
    assert summary["completed"] == 4
    assert len(calls) == 4
    assert not list(job.glob("tool-reports/**/*.json"))
    assert not list(job.glob("downloads/**/*.json"))
    assert not list(job.glob("exe/**/*"))
    assert not list(job.glob("downloads/**/*"))
    assert list(location(prefix + "/exe").rglob("*.exe"))
    assert list(location(prefix + "/evidence").glob("*.tar.gz"))
    assert uploads.index(prefix + "/checkpoint-latest.json") > 0
    moved = tmp_path / "moved"
    assert archive.restore(moved, prefix)
    assert sorel.verify_sorel(moved)["verified_sources"] == 4
    # Relocation retains the frozen contract and downloads only the remaining sources.
    final = sorel.run_sorel(moved, config)
    assert final["completed"] == 10 and final["pending"] == 0
    assert len(calls) == len(set(calls)) == 10
    assert sorel.verify_sorel(moved)["verified_sources"] == 10
    sorel.export_sorel(moved)
    assert (moved / "die-detections.csv").is_file()
    assert (moved / "downloads.csv").read_text().count("\n") == 11
    with pytest.raises(sorel.SorelError, match="config"):
        sorel.run_sorel(moved, replace(config, workers=1))


def test_upload_failure_keeps_local_evidence_and_retries_without_rescanning(
    tmp_path, monkeypatch, cloud
):
    _, _ = cloud
    job, config, _ = _job(tmp_path, count=2)
    _scanners(monkeypatch)
    calls = _curl_fixture(monkeypatch)
    upload = archive._upload

    def fail_evidence(source, destination, **kwargs):
        if "/evidence/" in destination:
            raise sorel.SorelError("synthetic upload failure")
        upload(source, destination, **kwargs)

    monkeypatch.setattr(archive, "_upload", fail_evidence)
    prefix = "s3://private/failure/part-01"
    with pytest.raises(sorel.SorelError, match="synthetic upload"):
        sorel.run_sorel(job, config, s3_prefix=prefix)
    assert len(calls) == 2
    assert list(job.glob("exe/**/*.exe"))
    assert list(job.glob("tool-reports/**/*.json"))
    with sqlite3.connect(job / "state.sqlite") as db:
        assert db.execute("SELECT SUM(archived) FROM sources").fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM archives").fetchone() == (0,)
    monkeypatch.setattr(archive, "_upload", upload)
    assert sorel.run_sorel(job, config)["pending"] == 0
    assert len(calls) == 2
    assert sorel.verify_sorel(job)["verified_sources"] == 2


def test_failed_checkpoint_pointer_preserves_previous_generation_and_checksums(
    tmp_path, monkeypatch, cloud
):
    location, _ = cloud
    job, config, _ = _job(tmp_path, count=2)
    _scanners(monkeypatch)
    _curl_fixture(monkeypatch)
    prefix = "s3://private/checkpoint/part-01"
    sorel.run_sorel(job, config, limit=1, s3_prefix=prefix)
    pointer_path = location(prefix + "/checkpoint-latest.json")
    original = pointer_path.read_bytes()
    upload = archive._upload

    def fail_pointer(source, destination, **kwargs):
        if destination.endswith("/checkpoint-latest.json"):
            raise sorel.SorelError("pointer failure")
        upload(source, destination, **kwargs)

    monkeypatch.setattr(archive, "_upload", fail_pointer)
    with pytest.raises(sorel.SorelError, match="pointer failure"):
        sorel.run_sorel(job, config)
    assert pointer_path.read_bytes() == original
    moved = tmp_path / "previous"
    assert archive.restore(moved, prefix)
    with sqlite3.connect(moved / "state.sqlite") as db:
        assert db.execute("SELECT SUM(done) FROM sources").fetchone() == (1,)
    pointer = json.loads(original)
    location(pointer["location"] + "/state.sqlite").write_bytes(b"corrupted")
    damaged = tmp_path / "damaged"
    with pytest.raises(sorel.SorelError, match="checksum"):
        archive.restore(damaged, prefix)
    assert not (damaged / "state.sqlite").exists()
    assert not (damaged / "selection.json").exists()


def test_remote_destination_identity_cannot_change(tmp_path, monkeypatch, cloud):
    job, config, _ = _job(tmp_path, count=1)
    _scanners(monkeypatch)
    _curl_fixture(monkeypatch)
    sorel.run_sorel(job, config, s3_prefix="s3://private/one")
    with pytest.raises(sorel.SorelError, match="destination changed"):
        sorel.run_sorel(job, config, s3_prefix="s3://private/two")
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(sorel.SorelError, match="already exists"):
        archive.SorelArchive(other, "s3://private/one", config)


def test_part_cli_appends_destination_and_restores_before_selecting(tmp_path, monkeypatch, cloud):
    location, _ = cloud
    _, base, metadata = _job(tmp_path, count=15)
    config = tmp_path / "full.yaml"
    config.write_text(yaml.safe_dump(asdict(replace(base, samples=0, partition_count=5))))
    job = tmp_path / "part-2"
    _scanners(monkeypatch)
    calls = _curl_fixture(monkeypatch)
    monkeypatch.setenv("MALWEAVE_SOREL_S3_PREFIX", "s3://private/collection")
    args = [
        "data",
        "sorel-run",
        "--part",
        "2",
        "--config",
        str(config),
        "--job-dir",
        str(job),
        "--metadata",
        str(metadata),
        "--limit",
        "1",
    ]
    assert main(args) == 0
    assert location("s3://private/collection/part-02/checkpoint-latest.json").exists()
    shutil.rmtree(job)
    metadata.unlink()  # Restore must work even without source metadata on the new machine.
    assert main(args) == 0
    assert len(calls) == len(set(calls)) == 2
    with sqlite3.connect(job / "state.sqlite") as db:
        assert db.execute("SELECT SUM(done),COUNT(*) FROM sources").fetchone() == (2, 3)


def test_interrupted_local_restore_can_retry_without_manual_deletion(tmp_path, monkeypatch, cloud):
    job, config, _ = _job(tmp_path, count=1)
    _scanners(monkeypatch)
    _curl_fixture(monkeypatch)
    prefix = "s3://private/restore/part-01"
    sorel.run_sorel(job, config, s3_prefix=prefix)
    moved = tmp_path / "moved"
    move = shutil.move

    def fail_selection(source, target):
        if Path(source).name == "selection.json":
            raise OSError("simulated interrupted restore")
        return move(source, target)

    monkeypatch.setattr(archive.shutil, "move", fail_selection)
    with pytest.raises(OSError, match="interrupted restore"):
        archive.restore(moved, prefix)
    assert (moved / "state.sqlite").exists()
    assert not (moved / "selection.json").exists()
    monkeypatch.setattr(archive.shutil, "move", move)
    assert archive.restore(moved, prefix)
    assert sorel.verify_sorel(moved)["verified_sources"] == 1


def _preflight_queries(monkeypatch):
    def query(*args):
        if args[:2] == ("sts", "get-caller-identity"):
            return {"Account": "synthetic", "Arn": "arn:aws:iam::synthetic:user/worker"}
        if args[:2] == ("s3api", "get-bucket-location"):
            return {"LocationConstraint": "ap-southeast-1"}
        if args[:2] == ("s3api", "list-objects-v2"):
            return {"KeyCount": 0}
        pytest.fail(f"Unexpected query: {args}")

    monkeypatch.setattr(sorel_s3, "_query", query)


def test_preflight_cli_defaults_read_only_and_checks_configured_collection(
    tmp_path, monkeypatch, cloud, capsys
):
    _, uploads = cloud
    _preflight_queries(monkeypatch)
    monkeypatch.setenv("MALWEAVE_SOREL_S3_PREFIX", "s3://private/sorel")
    assert main(["data", "sorel-s3-check"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["prefix"] == "s3://private/sorel"
    assert result["region"] == "ap-southeast-1"
    assert result["checks"]["put_get_checksum_delete"] == "not_tested"
    assert uploads == []


def test_preflight_text_round_trip_checks_checksum_and_removes_probe(monkeypatch, cloud):
    location, uploads = cloud
    _preflight_queries(monkeypatch)
    result = sorel_s3.check_sorel_s3("s3://private/sorel", write_test=True)
    assert result["checks"]["put_get_checksum_delete"] == "passed"
    assert len(uploads) == 1 and "/checks/" in uploads[0]
    assert not location(uploads[0]).exists()


def test_preflight_corrupted_round_trip_fails_and_cleans_probe(monkeypatch, cloud):
    location, uploads = cloud
    _preflight_queries(monkeypatch)

    def corrupt(uri, target, **kwargs):
        target.write_bytes(b"corrupted synthetic transfer")
        return True

    monkeypatch.setattr(archive, "_download", corrupt)
    with pytest.raises(sorel.SorelError, match="checksum mismatch"):
        sorel_s3.check_sorel_s3("s3://private/sorel", write_test=True)
    assert len(uploads) == 1 and not location(uploads[0]).exists()
