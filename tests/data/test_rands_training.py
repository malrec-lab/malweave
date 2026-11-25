"""Synthetic EXE-only data preparation and scoped download regression tests."""

import csv
import json
from pathlib import Path

import pytest
import yaml

from malweave.data.rands_training import RandsTrainingError, load_split, prepare_exe
from tests.training.scratch_fixtures import fixture


def test_preparation_accounts_for_conflicts_duplicates_and_missing(tmp_path: Path):
    data, config = fixture(tmp_path)
    with (data / "metadata/Benign.csv").open() as handle:
        benign = list(csv.DictReader(handle))
    with (data / "metadata/Ransomware.csv").open() as handle:
        ransomware = list(csv.DictReader(handle))

    def path(row):
        source = row["SHA256"]
        return data / "exe" / source[:2] / (source + ".bin")

    # One cross-label group, one same-label group. No majority voting.
    path(ransomware[0]).write_bytes(path(benign[0]).read_bytes())
    path(benign[2]).write_bytes(path(benign[1]).read_bytes())
    path(ransomware[-1]).unlink()
    settings = yaml.safe_load(config.read_text())
    settings["data"]["expected_exe_files"] -= 1
    config.write_text(yaml.safe_dump(settings))
    result = prepare_exe(data, config)
    assert result["conflicting_exe_groups"] == 1
    assert result["excluded_by_reason"] == {
        "conflicting_exe_labels": 2,
        "same_label_exe_duplicate": 1,
        "metadata_without_exe": 1,
    }
    rows, _ = load_split(data, config)
    assert len(rows) == 12
    assert len({r["exe_sha256"] for r in rows}) == len(rows)
    assert {r["source_sha256"] for r in rows}.isdisjoint(
        {benign[0]["SHA256"], ransomware[0]["SHA256"]}
    )
    assert prepare_exe(data, config) == json.loads((data / "prepared.json").read_text())
    (data / "split.csv").write_text("changed")
    with pytest.raises(RandsTrainingError, match="changed"):
        load_split(data, config)


def test_download_only_fetches_exe_and_two_csvs(tmp_path: Path, monkeypatch):
    from malweave.data import rands_training as module

    calls = []

    def fake_aws(*args):
        calls.append(args)
        if args[1] == "cp":
            Path(args[3]).write_bytes(b"synthetic metadata")

    monkeypatch.setattr(module, "aws", fake_aws)
    with module.Progress() as progress:
        module.fetch_exe(
            tmp_path,
            "s3://synthetic/rands/representations/exe",
            "s3://synthetic/metadata",
            progress,
        )
    assert len(calls) == 3
    assert calls[-1][0:2] == ("s3", "sync")
    assert "--delete" not in calls[-1]
    assert calls[0][2].endswith("/Benign.csv")
    with module.Progress() as progress, pytest.raises(RandsTrainingError):
        module.fetch_exe(tmp_path, "s3://synthetic/raw", "s3://synthetic/metadata", progress)
