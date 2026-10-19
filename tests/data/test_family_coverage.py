"""Synthetic coverage for family-overlap reporting without private inputs."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from malweave.data.family_coverage import (
    FamilyCoverageError,
    read_split_manifest,
    reference_families,
    resolve_families,
    seen_unseen_metric_breakdown,
    summarize_family_coverage,
)

FIELDS = ("split", "source_sha256", "label", "family")


def _write_manifest(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _row(split: str, source: str, label: str, family: str) -> dict[str, str]:
    return {"split": split, "source_sha256": source, "label": label, "family": family}


def test_family_coverage_separates_seen_from_unseen_sources() -> None:
    rows = [
        _row("train", "t1", "ransomware", "A"),
        _row("train", "t2", "ransomware", "B"),
        _row("train", "t3", "benign", ""),
        _row("test", "e1", "ransomware", "A"),  # seen family
        _row("test", "e2", "ransomware", "C"),  # unseen family
        _row("test", "e3", "benign", ""),
    ]
    report = summarize_family_coverage(rows)

    test = report["splits"]["test"]
    assert report["reference_families"] == 2
    assert test["sources_in_reference_families"] == 1
    assert test["sources_in_unseen_families"] == 1
    assert test["sources_without_family"] == 1
    assert test["families_only_in_split"] == ["C"]
    # Share is measured over labeled (family-bearing) rows only.
    assert test["unseen_family_source_share"] == pytest.approx(0.5)
    assert test["by_label"]["ransomware"]["sources_in_unseen_families"] == 1
    assert test["by_label"]["benign"]["sources_without_family"] == 1


def test_family_lookup_fills_rows_without_a_family_column() -> None:
    rows = [
        _row("train", "t1", "ransomware", ""),
        _row("test", "e1", "ransomware", ""),
    ]
    lookup = {"t1": "A", "e1": "A"}
    families = resolve_families(rows, lookup)
    assert families == {"t1": "A", "e1": "A"}
    report = summarize_family_coverage(rows, family_lookup=lookup)
    assert report["splits"]["test"]["sources_in_reference_families"] == 1
    assert report["splits"]["test"]["sources_in_unseen_families"] == 0


def test_conflicting_family_for_one_source_fails() -> None:
    rows = [_row("train", "t1", "ransomware", "A"), _row("test", "t1", "ransomware", "B")]
    with pytest.raises(FamilyCoverageError, match="conflicting family"):
        summarize_family_coverage(rows)


def test_missing_required_field_fails(tmp_path: Path) -> None:
    path = tmp_path / "split.csv"
    path.write_text("source_sha256,label,family\ns1,ransomware,A\n", encoding="utf-8")
    with pytest.raises(FamilyCoverageError, match="lacks split"):
        read_split_manifest(path)


def test_seen_unseen_breakdown_splits_metrics() -> None:
    families = {"a1": "A", "a2": "A", "c1": "C", "c2": "C"}
    predictions = [
        {"source_sha256": "a1", "label": "1", "ransomware_probability": "0.9"},
        {"source_sha256": "a2", "label": "0", "ransomware_probability": "0.1"},
        {"source_sha256": "c1", "label": "1", "ransomware_probability": "0.1"},
        {"source_sha256": "c2", "label": "0", "ransomware_probability": "0.9"},
    ]
    breakdown = seen_unseen_metric_breakdown(predictions, families, {"A"})
    assert breakdown["seen_family"]["roc_auc"] == pytest.approx(1.0)
    assert breakdown["unseen_family"]["roc_auc"] == pytest.approx(0.0)
    assert breakdown["unknown_family"]["rows"] == 0


def test_reference_families_ignores_other_splits() -> None:
    rows = [_row("train", "t1", "ransomware", "A"), _row("test", "e1", "ransomware", "C")]
    families = resolve_families(rows)
    assert reference_families(rows, families, "train") == {"A"}


def test_cli_writes_a_hash_free_summary(tmp_path: Path) -> None:
    from malweave import cli

    manifest = tmp_path / "split.csv"
    summary = tmp_path / "summary.json"
    _write_manifest(
        manifest,
        [
            _row("train", "t1", "ransomware", "A"),
            _row("test", "e1", "ransomware", "C"),
            _row("test", "e2", "benign", ""),
        ],
    )
    assert (
        cli.main(
            [
                "data",
                "family-coverage",
                "--manifest",
                str(manifest),
                "--summary",
                str(summary),
            ]
        )
        == 0
    )
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["splits"]["test"]["sources_in_unseen_families"] == 1
    assert "t1" not in summary.read_text(encoding="utf-8")
