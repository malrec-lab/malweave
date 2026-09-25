"""Synthetic-only checks for the read-only, resumable RanDS S3 inventory."""

from __future__ import annotations

import csv
from hashlib import sha256
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
from malweave.data.s3.rands import RandsS3Error, inventory_rands_s3
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
