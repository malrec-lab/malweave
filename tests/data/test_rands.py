"""Regression tests for RanDS metadata normalization and read-only inspection."""

from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path

import pytest

from malweave import cli
from malweave.cli import main
from malweave.data.dataset_config import (
    RandsDatasetConfig,
    RandsDatasetLocations,
    RandsExpectedCounts,
    RandsProtocol,
)
from malweave.data.rands import (
    BENIGN_HEADER,
    RANSOMWARE_DOCUMENTED_HEADER,
    RandsDataError,
    inspect_rands,
    write_rands_manifest,
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _different_shard_contents() -> tuple[bytes, bytes]:
    first = b"MZ synthetic benign fixture"
    second = b"MZ synthetic ransomware fixture"
    suffix = 0
    while _sha256(first)[:2] == _sha256(second)[:2]:
        suffix += 1
        second = f"MZ synthetic ransomware fixture {suffix}".encode()
    return first, second


def _write_csv(path: Path, header: tuple[str, ...], rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def _write_sample(root: Path, content: bytes) -> str:
    sha256 = _sha256(content)
    shard = root / "dataset" / sha256[:2]
    shard.mkdir(parents=True, exist_ok=True)
    (shard / sha256).write_bytes(content)
    return sha256


def _fixture(tmp_path: Path) -> tuple[Path, RandsDatasetConfig, set[str]]:
    root = tmp_path / "rands"
    (root / "dataset").mkdir(parents=True)
    benign_content, ransomware_content = _different_shard_contents()
    benign_sha = _write_sample(root, benign_content)
    ransomware_sha = _write_sample(root, ransomware_content)
    missing_sha = "f" * 64
    (root / "dataset" / ".DS_Store").write_text("ignored", encoding="utf-8")

    _write_csv(
        root / "Benign.csv",
        BENIGN_HEADER,
        [
            [
                benign_sha,
                "1" * 40,
                "2" * 32,
                str(len(benign_content)),
                "EXE",
                "I386",
                "0",
                "6.25",
                "2024",
                "provider/path/ignored.exe",
            ],
            [
                missing_sha,
                "3" * 40,
                "4" * 32,
                "10",
                "DLL",
                "Amd64",
                "1",
                "7.00",
                "2023",
                "provider/path/missing.dll",
            ],
        ],
    )
    # This reproduces the released CSV bug: the header and row order disagree.
    _write_csv(
        root / "Ransomware.csv",
        RANSOMWARE_DOCUMENTED_HEADER,
        [
            [
                ransomware_sha,
                "5" * 40,
                "6" * 32,
                str(len(ransomware_content)),
                "EXE",
                "I386",
                "1",
                "7.75",
                "SyntheticFamily",
                "2025",
                "provider/path/ignored-ransomware.exe",
            ]
        ],
    )

    shards = {benign_sha[:2], ransomware_sha[:2]}
    config = RandsDatasetConfig(
        name="rands",
        snapshot="test",
        root_env="TEST_RANDS_ROOT",
        benign_csv="Benign.csv",
        ransomware_csv="Ransomware.csv",
        samples_dir="dataset",
        expected=RandsExpectedCounts(
            shards=len(shards), files=2, labels={"benign": 1, "ransomware": 1}
        ),
        protocols={
            "full": RandsProtocol(),
            "x86_unpacked": RandsProtocol(arch="I386", packed=False),
        },
    )
    return root, config, {benign_sha, ransomware_sha, missing_sha}


def test_inspect_normalizes_schema_and_reports_missing_metadata(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)

    summary, metadata, present_shas = inspect_rands(config, root, hash_mode="sample")

    assert summary["contract"]["passed"] is True
    assert summary["schema"]["corrections"]
    assert summary["metadata"]["rows"] == {"benign": 2, "ransomware": 1}
    assert summary["metadata"]["without_file"] == {"benign": 1, "ransomware": 0}
    assert summary["files"]["files"] == 2
    assert summary["files"]["ignored_files"] == 1
    assert summary["files"]["size_mismatches"] == 0
    assert summary["present"]["ransomware"]["families"] == 1
    assert summary["protocols"]["x86_unpacked"]["labels"] == {"benign": 1}
    assert summary["content_hashes"]["checked"] == 2
    assert summary["content_hashes"]["mismatches"] == 0
    assert len(metadata.records) == 3
    assert len(present_shas) == 2


def test_inspect_accepts_separate_raw_and_metadata_roots(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)
    raw_root = tmp_path / "raw"
    metadata_root = tmp_path / "metadata"
    raw_root.mkdir()
    metadata_root.mkdir()
    (root / "dataset").rename(raw_root / "dataset")
    (root / "Benign.csv").rename(metadata_root / "Benign.csv")
    (root / "Ransomware.csv").rename(metadata_root / "Ransomware.csv")

    summary, _, _ = inspect_rands(
        config,
        RandsDatasetLocations(raw_root=raw_root, metadata_root=metadata_root),
    )

    assert summary["contract"]["passed"] is True


def test_inspect_accepts_rows_matching_the_documented_ransomware_header(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)
    with (root / "Ransomware.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    row = rows[1]
    documented_order = row[:6] + [row[8], row[6], row[7]] + row[9:]
    _write_csv(
        root / "Ransomware.csv",
        RANSOMWARE_DOCUMENTED_HEADER,
        [documented_order],
    )

    summary, _, _ = inspect_rands(config, root)

    assert summary["contract"]["passed"] is True
    assert summary["schema"]["corrections"] == []
    assert summary["present"]["ransomware"]["families"] == 1


def test_integrity_failure_makes_release_contract_fail(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)
    sample = next(path for path in (root / "dataset").glob("*/*") if path.is_file())
    sample.write_bytes(sample.read_bytes() + b"changed")

    summary, _, _ = inspect_rands(config, root)

    assert summary["contract"]["passed"] is False
    assert summary["files"]["size_mismatches"] == 1
    assert any("file size mismatches" in item for item in summary["contract"]["mismatches"])


def test_manifest_is_explicit_and_omits_provider_paths(tmp_path: Path) -> None:
    root, config, sample_shas = _fixture(tmp_path)
    _, metadata, present_shas = inspect_rands(config, root)
    manifest = tmp_path / "local" / "manifest.csv"

    write_rands_manifest(manifest, config, metadata, present_shas)

    with manifest.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 3
    assert {row["sha256"] for row in rows} == sample_shas
    assert "Filepath" not in rows[0]
    assert {row["available"] for row in rows} == {"0", "1"}


def test_manifest_refuses_versioned_source_location(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)
    _, metadata, present_shas = inspect_rands(config, root)

    with pytest.raises(RandsDataError, match="data/interim or data/processed"):
        write_rands_manifest(
            Path(__file__).resolve().parents[2] / "sample-inventory.csv",
            config,
            metadata,
            present_shas,
        )


def test_cli_prints_only_aggregate_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, config, sample_shas = _fixture(tmp_path)
    config_path = tmp_path / "rands.yaml"
    config_path.write_text(
        f"""
dataset: {{name: rands, snapshot: test, root_env: TEST_RANDS_ROOT}}
layout: {{benign_csv: Benign.csv, ransomware_csv: Ransomware.csv, samples_dir: dataset}}
expected:
  shards: {config.expected.shards}
  files: 2
  labels: {{benign: 1, ransomware: 1}}
protocols:
  full: {{}}
  x86_unpacked: {{arch: I386, packed: false}}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "data",
            "inspect",
            "--dataset",
            "rands",
            "--config",
            str(config_path),
            "--root",
            str(root),
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert json.loads(output)["contract"]["passed"] is True
    assert all(sha256 not in output for sha256 in sample_shas)


def test_cli_loads_rands_root_from_dotenv_without_overriding_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, config, _ = _fixture(tmp_path)
    config_path = tmp_path / "rands.yaml"
    config_path.write_text(
        f"""
dataset: {{name: rands, snapshot: test, root_env: TEST_RANDS_ROOT}}
layout: {{benign_csv: Benign.csv, ransomware_csv: Ransomware.csv, samples_dir: dataset}}
expected:
  shards: {config.expected.shards}
  files: 2
  labels: {{benign: 1, ransomware: 1}}
protocols:
  full: {{}}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text(f"TEST_RANDS_ROOT={root}\n", encoding="utf-8")
    monkeypatch.delenv("TEST_RANDS_ROOT", raising=False)
    monkeypatch.setattr(cli, "DOTENV_PATH", dotenv_path)

    exit_code = main(
        [
            "data",
            "inspect",
            "--dataset",
            "rands",
            "--config",
            str(config_path),
        ]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["contract"]["passed"] is True

    shell_root = tmp_path / "missing-shell-root"
    monkeypatch.setenv("TEST_RANDS_ROOT", str(shell_root))
    assert cli._load_project_environment(dotenv_path) is None
    assert Path(os.environ["TEST_RANDS_ROOT"]) == shell_root
