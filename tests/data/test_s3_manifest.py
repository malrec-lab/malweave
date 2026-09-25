"""Synthetic-only coverage for reusable S3 inventory and manifest selection."""

from __future__ import annotations

import csv
from decimal import Decimal
from pathlib import Path

import pytest

from malweave.data.s3.inventory import S3InventoryError, inventory_s3_prefix
from malweave.data.s3.manifest import (
    ManifestOptions,
    ManifestSelectionError,
    filter_rows,
    select_labeled_rows,
)


class FakeS3:
    def __init__(self) -> None:
        self.calls = 0

    def list_objects_v2(self, **request: object) -> dict[str, object]:
        self.calls += 1
        assert request["Prefix"] == "other-dataset/samples/"
        return {
            "Contents": [
                {"Key": "other-dataset/samples/a.bin", "Size": 10, "ETag": '"a"'},
                {"Key": "other-dataset/samples/b.txt", "Size": 20, "ETag": '"b"'},
            ],
            "IsTruncated": False,
        }


def test_generic_inventory_accepts_any_prefix_and_size_suffix_filters(tmp_path: Path) -> None:
    client = FakeS3()
    manifest = tmp_path / "objects.csv"
    summary = inventory_s3_prefix(
        bucket="synthetic",
        prefix="other-dataset/samples/",
        state_path=tmp_path / "state.sqlite",
        manifest_path=manifest,
        summary_path=tmp_path / "summary.json",
        suffix=".bin",
        min_size=1,
        max_size=15,
        client=client,
    )
    assert client.calls == 1
    assert summary["listed_objects"] == 2
    assert summary["selected_objects"] == 1
    assert summary["excluded_objects"] == 1
    with manifest.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["object_key"] for row in rows] == ["other-dataset/samples/a.bin"]
    with pytest.raises(S3InventoryError, match="overwrite"):
        inventory_s3_prefix(
            bucket="synthetic",
            prefix="other-dataset/samples/",
            state_path=tmp_path / "state.sqlite",
            manifest_path=manifest,
            summary_path=tmp_path / "summary.json",
            client=client,
            resume=True,
        )


def _rows() -> list[dict[str, str]]:
    return [
        {"source_sha256": str(i), "split": split, "label": label, "family": "synthetic"}
        for split in ("train", "test")
        for label, count in (("benign", 6), ("ransomware", 4))
        for i in range(count)
    ]


def _select(options: ManifestOptions) -> tuple[list[dict[str, str]], dict[str, object]]:
    rows = _rows()
    for index, row in enumerate(rows):
        row["source_sha256"] = f"synthetic-{index}"
    return select_labeled_rows(
        rows,
        splits=("train", "test"),
        labels=("benign", "ransomware"),
        fractions={"train": Decimal("0.5"), "test": Decimal("0.5")},
        options=options,
    )


def test_manifest_options_are_deterministic_and_full_by_default() -> None:
    full, full_summary = _select(ManifestOptions())
    assert len(full) == 20
    assert full_summary["mode"] == "full"
    balanced, balanced_summary = _select(ManifestOptions(balanced=True))
    assert len(balanced) == 16
    assert balanced_summary["selected_by_split_and_label"] == {
        "train": {"benign": 4, "ransomware": 4},
        "test": {"benign": 4, "ransomware": 4},
    }
    pilot, _ = _select(ManifestOptions(total=8, balanced=True, seed="fixed"))
    repeated, _ = _select(ManifestOptions(total=8, balanced=True, seed="fixed"))
    assert pilot == repeated
    assert len(pilot) == 8
    explicit, _ = _select(ManifestOptions(label_counts={"benign": 2, "ransomware": 4}))
    assert len(explicit) == 6
    assert sum(row["label"] == "ransomware" for row in explicit) == 4


def test_manifest_rejects_shortfall_and_ambiguous_options() -> None:
    with pytest.raises(ManifestSelectionError, match="divide evenly"):
        _select(ManifestOptions(total=7, balanced=True))
    with pytest.raises(ManifestSelectionError, match="Insufficient"):
        _select(ManifestOptions(label_counts={"ransomware": 10}))
    with pytest.raises(ManifestSelectionError, match="cannot be combined"):
        _select(ManifestOptions(total=8, label_counts={"benign": 4}))
    rows, rejected = filter_rows(_rows(), (("family", "synthetic"), ("label", "benign")))
    assert len(rows) == 12
    assert rejected == {"label": 8}
    filtered, summary = _select(ManifestOptions(where=(("label", "benign"),)))
    assert len(filtered) == 12
    assert summary["where_exclusions"] == {"label": 8}
