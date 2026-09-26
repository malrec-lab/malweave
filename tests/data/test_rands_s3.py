"""Synthetic-only checks for the read-only, resumable RanDS S3 inventory."""

from __future__ import annotations

import csv
from hashlib import sha256
import io
import json
from pathlib import Path

import pytest
import yaml

from malweave.cli import main
from malweave.data.dataset_config import (
    RandsDatasetConfig,
    RandsExpectedCounts,
    RandsProtocol,
)
from malweave.data.rands import BENIGN_HEADER, RANSOMWARE_DOCUMENTED_HEADER
from malweave.data.s3.client import S3ReadError, read_s3_object
from malweave.data.s3.rands import RandsS3Error, inventory_rands_s3
from malweave.data.s3.rands_metadata import prepare_rands_metadata
from malweave.experiments.rands_raw_manifest import RandsRawError, freeze_rands_raw_manifest


def _source(label: str, year: int) -> str:
    return sha256(f"synthetic-{label}-{year}".encode()).hexdigest()


def _fixture(root: Path) -> RandsDatasetConfig:
    for label, filename, header in (
        ("benign", "Benign.csv", BENIGN_HEADER),
        ("ransomware", "Ransomware.csv", RANSOMWARE_DOCUMENTED_HEADER),
    ):
        with (root / filename).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            for year in (2022, 2023, 2024):
                source = _source(label, year)
                core = [source, "1" * 40, "2" * 32, "10", "EXE", "I386"]
                if label == "benign":
                    writer.writerow([*core, "0", "6.0", str(year), "private/path"])
                else:
                    # The public release has a documented header with this actual row order.
                    writer.writerow(
                        [*core, "0", "6.0", "SyntheticFamily", str(year), "private/path"]
                    )
    return RandsDatasetConfig(
        name="rands",
        snapshot="synthetic",
        root_env="SYNTHETIC_ROOT",
        benign_csv="Benign.csv",
        ransomware_csv="Ransomware.csv",
        samples_dir="dataset",
        expected=RandsExpectedCounts(shards=6, files=6, labels={"benign": 3, "ransomware": 3}),
        protocols={"lmlm_x86_unpacked": RandsProtocol(arch="I386", packed=False)},
    )


class FakeS3:
    def __init__(self, *, fail_second_once: bool = False):
        self.fail_second_once = fail_second_once
        self.calls = 0
        self.rows = [
            {
                "Key": f"raw/{source[:2]}/{source}",
                "Size": 10,
                "ETag": '"synthetic"',
                "LastModified": "2026-01-01T00:00:00Z",
            }
            for label in ("benign", "ransomware")
            for year in (2022, 2023, 2024)
            for source in (_source(label, year),)
        ]

    def list_objects_v2(self, **request: object) -> dict[str, object]:
        self.calls += 1
        if request.get("ContinuationToken") == "next":
            if self.fail_second_once:
                self.fail_second_once = False
                raise RuntimeError("synthetic network failure")
            return {"Contents": self.rows[3:], "IsTruncated": False}
        return {"Contents": self.rows[:3], "IsTruncated": True, "NextContinuationToken": "next"}


class MetadataS3(FakeS3):
    def __init__(self, root: Path):
        super().__init__()
        self.objects = {
            "metadata/" + name: (root / name).read_bytes()
            for name in ("Benign.csv", "Ransomware.csv")
        }
        self.reads: list[str] = []
        self.fail_key: str | None = None

    def head_object(self, *, Bucket: str, Key: str) -> dict:
        return {"ContentLength": len(self.objects[Key]), "ETag": '"test"', "VersionId": "v1"}

    def get_object(self, **request: str) -> dict:
        key = request["Key"]
        assert request["IfMatch"] == '"test"'
        assert request["VersionId"] == "v1"
        self.reads.append(key)
        if key == self.fail_key:
            raise RuntimeError("synthetic download failure")
        return {"Body": io.BytesIO(self.objects[key]), "ETag": '"test"', "VersionId": "v1"}


def test_metadata_cache_is_verified_and_reused_without_s3(tmp_path: Path) -> None:
    config = _fixture(tmp_path)
    s3 = MetadataS3(tmp_path)
    cache = tmp_path / "cache"
    prepare_rands_metadata(config, cache, bucket="test", prefix="metadata/", client=s3)
    assert s3.reads == ["metadata/Benign.csv", "metadata/Ransomware.csv"]
    prepare_rands_metadata(config, cache, bucket="test", prefix="metadata/")
    with pytest.raises(RandsS3Error, match="another source"):
        prepare_rands_metadata(config, cache, bucket="other", prefix="metadata/")
    (cache / "Benign.csv").write_text("changed", encoding="utf-8")
    with pytest.raises(RandsS3Error, match="changed"):
        prepare_rands_metadata(config, cache, bucket="test", prefix="metadata/")


def test_metadata_failure_does_not_publish_partial_cache(tmp_path: Path) -> None:
    config = _fixture(tmp_path)
    s3 = MetadataS3(tmp_path)
    s3.fail_key = "metadata/Ransomware.csv"
    cache = tmp_path / "cache"
    with pytest.raises(S3ReadError):
        prepare_rands_metadata(config, cache, bucket="test", prefix="metadata/", client=s3)
    assert not cache.exists()
    s3.fail_key = None
    prepare_rands_metadata(config, cache, bucket="test", prefix="metadata/", client=s3)
    assert (cache / "provenance.json").is_file()


def test_metadata_download_is_bounded_and_rejects_malformed_csv(tmp_path: Path) -> None:
    config = _fixture(tmp_path)
    s3 = MetadataS3(tmp_path)
    with pytest.raises(S3ReadError):
        read_s3_object(s3, "test", "metadata/Benign.csv", max_bytes=1)
    assert not s3.reads
    s3.objects["metadata/Benign.csv"] = b"not-a-csv"
    with pytest.raises(ValueError):
        prepare_rands_metadata(
            config, tmp_path / "cache", bucket="test", prefix="metadata/", client=s3
        )
    assert not (tmp_path / "cache").exists()


def test_inventory_cli_bootstraps_metadata_from_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from malweave import cli
    from malweave.data.s3 import rands
    import malweave.data.s3.rands_metadata as metadata

    config = _fixture(tmp_path)
    s3 = MetadataS3(tmp_path)
    monkeypatch.setattr(cli, "load_rands_dataset_config", lambda _: config)
    monkeypatch.setattr(rands, "make_s3_client", lambda: s3)
    monkeypatch.setattr(metadata, "make_s3_client", lambda: s3)
    monkeypatch.setattr(cli, "_load_project_environment", lambda: None)
    monkeypatch.setenv("SYNTHETIC_BUCKET", "test")
    experiment = tmp_path / "experiment.yaml"
    _config(experiment)
    settings = yaml.safe_load(experiment.read_text())
    settings["data"].update(
        {
            "bucket_env": "SYNTHETIC_BUCKET",
            "raw_prefix": "raw/",
            "inventory": {
                "metadata_prefix": "metadata/",
                "metadata_cache": str(tmp_path / "cache"),
                "state_db": str(tmp_path / "inventory.sqlite"),
            },
            "manifest_inputs": {
                "inventory": str(tmp_path / "inventory.csv"),
                "inventory_summary": str(tmp_path / "audit.json"),
            },
            "manifest_presets": {
                "full": {
                    "manifest": str(tmp_path / "full.csv"),
                    "summary": str(tmp_path / "full.json"),
                }
            },
        }
    )
    experiment.write_text(yaml.safe_dump(settings), encoding="utf-8")
    s3.fail_second_once = True
    assert main(["data", "inventory-rands-s3", "--experiment", str(experiment)]) == 2
    assert not (tmp_path / "inventory.csv").exists()
    assert (tmp_path / "cache" / "provenance.json").is_file()
    assert main(["data", "inventory-rands-s3", "--experiment", str(experiment), "--resume"]) == 0
    assert (
        main(
            ["experiment", "freeze-rands-raw", "--experiment", str(experiment), "--preset", "full"]
        )
        == 0
    )
    assert json.loads((tmp_path / "full.json").read_text())["selected"] == 6
    assert s3.reads == ["metadata/Benign.csv", "metadata/Ransomware.csv"]


def test_inventory_cli_local_metadata_override_never_downloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from malweave import cli
    from malweave.data.s3 import rands

    config = _fixture(tmp_path)
    monkeypatch.setattr(cli, "load_rands_dataset_config", lambda _: config)
    monkeypatch.setattr(rands, "make_s3_client", FakeS3)
    monkeypatch.setattr(cli, "_load_project_environment", lambda: None)
    monkeypatch.setenv("SYNTHETIC_BUCKET", "test")
    assert (
        main(
            [
                "data",
                "inventory-rands-s3",
                "--metadata-root",
                str(tmp_path),
                "--bucket-env",
                "SYNTHETIC_BUCKET",
                "--prefix",
                "raw/",
                "--state-db",
                str(tmp_path / "scan.sqlite"),
                "--manifest",
                str(tmp_path / "inventory.csv"),
                "--summary",
                str(tmp_path / "audit.json"),
            ]
        )
        == 0
    )


def test_missing_inventory_gives_next_command(tmp_path: Path) -> None:
    with pytest.raises(RandsRawError, match="inventory-rands-s3"):
        freeze_rands_raw_manifest(
            tmp_path / "missing.csv",
            tmp_path / "missing.json",
            tmp_path / "config.yaml",
            tmp_path / "split.csv",
            tmp_path / "split.json",
        )


def _config(path: Path) -> None:
    path.write_text(
        """experiment: {dataset: rands}
references: {rands_snapshot: synthetic}
data:
  metadata_filters: {arch: I386, packed: false}
  cohort: {total: 6, benign: 3, ransomware: 3}
  selection_method: sha256_rank_per_label_within_split
  selection_seed: synthetic
  labels: {benign: 0, ransomware: 1}
split:
  group_key: source_sha256
  method: temporal_by_year
  time_field: Year
  year_ranges: {train: {max: 2022}, validation: {min: 2023, max: 2023}, test: {min: 2024}}
  fractions: {train: 0.3333333333333333, validation: 0.3333333333333333, test: 0.3333333333333334}
  on_class_shortfall: fail
""",
        encoding="utf-8",
    )


def test_inventory_resumes_without_reading_object_bytes(tmp_path: Path) -> None:
    config = _fixture(tmp_path)
    state = tmp_path / "state.sqlite"
    manifest = tmp_path / "inventory.csv"
    summary = tmp_path / "summary.json"
    client = FakeS3(fail_second_once=True)
    options = {
        "bucket": "synthetic-private",
        "prefix": "raw/",
        "protocol": "lmlm_x86_unpacked",
        "state_path": state,
        "manifest_path": manifest,
        "summary_path": summary,
        "client": client,
        "progress_every": 1,
    }
    with pytest.raises(RandsS3Error, match="state is preserved"):
        inventory_rands_s3(config, tmp_path, **options)
    assert state.exists() and not manifest.exists()
    result = inventory_rands_s3(config, tmp_path, resume=True, **options)
    assert result["release_audit"]["passed"] is True
    assert result["eligible_by_label_and_status"] == {
        "benign": {"available": 3},
        "ransomware": {"available": 3},
    }
    assert result["listing_pages"] == 2
    assert result["manifest"]["rows"] == 6
    with manifest.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert {row["obfuscation_status"] for row in rows} == {"not_assessed"}
    assert all(row["availability"] == "available" for row in rows)
    assert "synthetic-private" not in summary.read_text(encoding="utf-8")


def test_temporal_pilot_selects_only_available_records(tmp_path: Path) -> None:
    config = _fixture(tmp_path)
    inventory = tmp_path / "inventory.csv"
    inventory_rands_s3(
        config,
        tmp_path,
        bucket="synthetic-private",
        prefix="raw/",
        protocol="lmlm_x86_unpacked",
        state_path=tmp_path / "state.sqlite",
        manifest_path=inventory,
        summary_path=tmp_path / "inventory-summary.json",
        client=FakeS3(),
    )
    config_path = tmp_path / "experiment.yaml"
    _config(config_path)
    manifest = tmp_path / "split.csv"
    summary = freeze_rands_raw_manifest(
        inventory,
        tmp_path / "inventory-summary.json",
        config_path,
        manifest,
        tmp_path / "split-summary.json",
    )
    assert summary["selected"] == 6
    assert summary["source_hash_verified"] is False
    with manifest.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert {(row["split"], row["year"]) for row in rows} == {
        ("train", "2022"),
        ("validation", "2023"),
        ("test", "2024"),
    }
    assert len({row["group_id"] for row in rows}) == 6


def test_audit_failure_does_not_write_manifest(tmp_path: Path) -> None:
    config = _fixture(tmp_path)
    client = FakeS3()
    client.rows.pop()
    manifest = tmp_path / "inventory.csv"
    summary = tmp_path / "summary.json"
    with pytest.raises(RandsS3Error, match="release audit failed"):
        inventory_rands_s3(
            config,
            tmp_path,
            bucket="synthetic-private",
            prefix="raw/",
            protocol="lmlm_x86_unpacked",
            state_path=tmp_path / "state.sqlite",
            manifest_path=manifest,
            summary_path=summary,
            client=client,
        )
    assert not manifest.exists()
    assert json.loads(summary.read_text(encoding="utf-8"))["release_audit"]["passed"] is False


def test_freeze_refuses_an_inventory_without_a_matching_audit(tmp_path: Path) -> None:
    config = _fixture(tmp_path)
    inventory = tmp_path / "inventory.csv"
    audit = tmp_path / "audit.json"
    inventory_rands_s3(
        config,
        tmp_path,
        bucket="synthetic-private",
        prefix="raw/",
        protocol="lmlm_x86_unpacked",
        state_path=tmp_path / "state.sqlite",
        manifest_path=inventory,
        summary_path=audit,
        client=FakeS3(),
    )
    config_path = tmp_path / "experiment.yaml"
    _config(config_path)
    tampered = json.loads(audit.read_text(encoding="utf-8"))
    tampered["release_audit"]["passed"] = False
    audit.write_text(json.dumps(tampered), encoding="utf-8")
    output = tmp_path / "split.csv"
    with pytest.raises(RandsRawError, match="audit"):
        freeze_rands_raw_manifest(inventory, audit, config_path, output, tmp_path / "split.json")
    assert not output.exists()


def test_cli_uses_yaml_paths_for_full_and_pilot_presets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _fixture(tmp_path)
    inventory = tmp_path / "inventory.csv"
    audit = tmp_path / "audit.json"
    inventory_rands_s3(
        config,
        tmp_path,
        bucket="synthetic-private",
        prefix="raw/",
        protocol="lmlm_x86_unpacked",
        state_path=tmp_path / "state.sqlite",
        manifest_path=inventory,
        summary_path=audit,
        client=FakeS3(),
    )
    config_path = tmp_path / "experiment.yaml"
    _config(config_path)
    experiment = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    experiment["data"]["bucket_env"] = "SYNTHETIC_BUCKET"
    experiment["data"]["manifest_inputs"] = {
        "inventory": str(inventory),
        "inventory_summary": str(audit),
    }
    experiment["data"]["manifest_presets"] = {
        "full": {
            "manifest": str(tmp_path / "full.csv"),
            "summary": str(tmp_path / "full.json"),
        },
        "pilot": {
            "total": 6,
            "balanced": True,
            "manifest": str(tmp_path / "pilot.csv"),
            "summary": str(tmp_path / "pilot.json"),
        },
    }
    config_path.write_text(yaml.safe_dump(experiment), encoding="utf-8")

    assert main(["experiment", "freeze-rands-raw", "--experiment", str(config_path)]) == 0
    assert (
        main(
            [
                "experiment",
                "freeze-rands-raw",
                "--experiment",
                str(config_path),
                "--preset",
                "pilot",
            ]
        )
        == 0
    )
    for name in ("full", "pilot"):
        with (tmp_path / f"{name}.csv").open(newline="", encoding="utf-8") as handle:
            assert len(list(csv.DictReader(handle))) == 6
    assert (
        main(
            [
                "experiment",
                "freeze-rands-raw",
                "--experiment",
                str(config_path),
                "--total",
                "6",
                "--balanced",
                "--manifest",
                str(tmp_path / "custom.csv"),
                "--summary",
                str(tmp_path / "custom.json"),
            ]
        )
        == 0
    )
    assert json.loads((tmp_path / "custom.json").read_text(encoding="utf-8"))["selected"] == 6
    assert main(["experiment", "freeze-rands-raw", "--experiment", str(config_path)]) == 2
    assert "Output exists" in capsys.readouterr().err
