"""Synthetic S3 acquisition, durable evidence and restart/failure accounting."""

from dataclasses import replace
import gzip
from hashlib import sha256
import json
import shutil
import sqlite3
import sys

import pytest

from malweave.data import rands_die
from malweave.data.storage_io import DataError
from tests.data.test_rands import _fixture


@pytest.fixture
def setup_job(tmp_path, monkeypatch):
    root, config, _ = _fixture(tmp_path)
    die = tmp_path / "diec"
    die.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('Synthetic DiE fixture')\n"
        "else:\n"
        "    print(json.dumps({'detects': [{'filetype': 'PE', 'values': "
        "[{'type': 'packer', 'name': 'Synthetic'}]}]}))\n"
    )
    die.chmod(0o700)
    samples = sorted((root / "dataset").glob("??/*"))
    inventory = [
        {
            "Key": f"representations/raw/{path.parent.name}/{path.name}",
            "Size": path.stat().st_size,
            "ETag": '"synthetic-etag"',
        }
        for path in samples
    ]
    monkeypatch.setattr(rands_die, "_inventory", lambda prefix: iter(inventory))
    downloads = []

    def download(uri, destination, etag=None):
        downloads.append(uri)
        if uri.endswith(".csv"):
            shutil.copyfile(root / uri.rsplit("/", 1)[-1], destination)
        else:
            assert etag == '"synthetic-etag"'
            parts = uri.split("/")
            shutil.copyfile(root / "dataset" / parts[-2] / parts[-1], destination)

    monkeypatch.setattr(rands_die, "_download", download)
    job = tmp_path / "job"

    def run(**kwargs):
        return rands_die.run_rands_die(
            job,
            config,
            "s3://synthetic-test/metadata",
            die_command=str(die),
            retry_seconds=0,
            **kwargs,
        )

    return run, job, downloads, config, die, inventory


def test_separate_metadata_and_raw_prefixes(setup_job):
    run, job, downloads, _, _, _ = setup_job
    raw_prefix = "s3://synthetic-test/representations/raw"
    assert run(limit=1)["completed"] == 1
    assert downloads[0] == "s3://synthetic-test/metadata/Benign.csv"
    assert downloads[-1].startswith(raw_prefix + "/")
    assert json.loads((job / "tools.json").read_text())["raw_prefix"] == raw_prefix
    with pytest.raises(DataError, match="same bucket"):
        run(raw_prefix="s3://other/representations/raw")


def test_resume_retains_complete_reports_and_skips_recorded_sources(setup_job):
    run, job, downloads, _, _, _ = setup_job
    first = run(workers=10, limit=1)
    assert first["completed"] == 1
    assert first["pending"] == 1
    assert not list((job / "work").iterdir())
    second = run(workers=10)
    assert second["completed"] == second["success"] == 2
    assert second["failed"] == 0
    assert second["packing_states"] == {"obfuscated": 2}
    assert {label: stats["success"] for label, stats in second["by_class"].items()} == {
        "benign": 1,
        "ransomware": 1,
    }
    assert len(downloads) == 4  # two metadata CSVs and two PE samples, across both runs
    assert run()["completed"] == 2
    assert len(downloads) == 4
    with sqlite3.connect(job / "state.sqlite3") as db:
        for blob, checksum in db.execute("SELECT evidence_gzip, evidence_sha256 FROM result"):
            assert sha256(blob).hexdigest() == checksum
            evidence = json.loads(gzip.decompress(blob))
            assert evidence["source_hash_status"] == "verified"
            assert evidence["file"]["stdout"]
            assert set(evidence["packing"]["reports"]) == {"recursive", "deep", "heuristic"}
            for mode, record in evidence["packing"]["reports"].items():
                assert record["command"][1:3] == [f"--{mode}scan", "--json"]
                assert record["report"]["detects"][0]["values"][0]["name"] == "Synthetic"
                assert record["status"] == "success"
    progress = json.loads((job / "progress.json").read_text())
    assert progress["phase"] == "complete"
    assert progress["workers"] == 10
    assert json.loads((job / "release-audit.json").read_text())["passed"]


def test_hash_mismatch_never_reaches_tools_and_is_durable(setup_job, monkeypatch):
    run, job, _, _, _, _ = setup_job
    download = rands_die._download

    def corrupt(uri, destination, etag=None):
        download(uri, destination, etag)
        if not uri.endswith(".csv"):
            original = destination.read_bytes()
            destination.write_bytes(b"X" + original[1:])

    monkeypatch.setattr(rands_die, "_download", corrupt)
    monkeypatch.setattr(rands_die, "assess_packing", lambda *a: pytest.fail("scanned corrupt PE"))
    result = run()
    assert result["statuses"] == {"hash_mismatch": 2}
    assert result["success"] == 0
    assert result["packing_states"] == {"unknown": 2}
    assert not list((job / "work").iterdir())
    with sqlite3.connect(job / "state.sqlite3") as db:
        for (blob,) in db.execute("SELECT evidence_gzip FROM result"):
            evidence = json.loads(gzip.decompress(blob))
            assert "file" not in evidence
            assert evidence["error"]


def test_failed_release_audit_blocks_all_pe_downloads(setup_job):
    run, job, downloads, _, _, inventory = setup_job
    inventory.pop()
    with pytest.raises(DataError, match="release audit failed"):
        run()
    assert len(downloads) == 2
    assert not json.loads((job / "release-audit.json").read_text())["passed"]
    assert json.loads((job / "progress.json").read_text())["phase"] == "failed"


def test_s3_failure_leaves_readable_state_without_scanning(setup_job, monkeypatch):
    run, job, _, _, _, _ = setup_job

    def unavailable(*args):
        raise rands_die.S3Unavailable("synthetic network unavailable")

    monkeypatch.setattr(rands_die, "_download", unavailable)
    with pytest.raises(rands_die.S3Unavailable):
        run()
    progress = json.loads((job / "progress.json").read_text())
    assert progress["completed"] == progress["success"] == 0
    assert "synthetic network unavailable" in progress["error"]


def test_resume_rejects_changed_dataset_contract(setup_job):
    run, job, _, config, die, _ = setup_job
    run(limit=1)
    with pytest.raises(DataError, match="changed"):
        rands_die.run_rands_die(
            job,
            replace(config, snapshot="changed"),
            "s3://synthetic-test/metadata",
            die_command=str(die),
            retry_seconds=0,
        )


def test_partial_die_failure_is_unknown_and_keeps_error_evidence(setup_job):
    run, job, _, _, die, _ = setup_job
    die.write_text(
        f"#!{sys.executable}\nimport json, sys\n"
        "if '--version' in sys.argv: print('Synthetic DiE fixture')\n"
        "elif '--deepscan' in sys.argv:\n"
        "    print('synthetic failure', file=sys.stderr)\n"
        "    sys.exit(1)\n"
        "else: print(json.dumps({'detects': [{'filetype': 'PE', 'values': []}]}))\n"
    )
    result = run()
    assert result["statuses"] == {"tool_error": 2}
    assert result["packing_states"] == {"unknown": 2}
    with sqlite3.connect(job / "state.sqlite3") as db:
        for (blob,) in db.execute("SELECT evidence_gzip FROM result"):
            record = json.loads(gzip.decompress(blob))["packing"]["reports"]["deep"]
            assert record["returncode"] == 1
            assert record["stderr"].strip() == "synthetic failure"
