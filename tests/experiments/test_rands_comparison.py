"""Synthetic regression tests for the deduplicated RanDS comparison split."""

from __future__ import annotations

import csv
from hashlib import sha256
import json
from pathlib import Path

import pytest

from malweave.cli import main
from malweave.data.rands_products import PRODUCT_FIELDS
from malweave.experiments.rands_comparison import (
    RandsComparisonConfig,
    RandsComparisonError,
    build_rands_comparison_cohort,
    load_rands_comparison_config,
    load_rands_product_manifest,
    split_rands_comparison_cohort,
    write_rands_comparison_split_outputs,
)


def _digest(value: str) -> str:
    return sha256(value.encode("ascii")).hexdigest()


def _write_products(path: Path, *, cross_label_duplicate: bool = False) -> list[str]:
    rows: list[dict[str, str | int]] = []
    sources: list[str] = []
    for label in ("benign", "ransomware"):
        for index in range(10):
            source = _digest(f"{label}-{index}")
            sources.append(source)
            exe = _digest(f"{label}-exe-{index if index > 1 else 'duplicate'}")
            if cross_label_duplicate and label == "ransomware" and index == 0:
                exe = _digest("benign-exe-duplicate")
            family = "Synthetic" if label == "ransomware" else ""
            rows.extend(
                [
                    {
                        "representation": "raw",
                        "source_sha256": source,
                        "label": label,
                        "family": family,
                        "representation_sha256": source,
                        "leakage_group_sha256": source,
                        "representation_relative_path": "source",
                        "representation_size": 10,
                        "snapshot": "test",
                    },
                    {
                        "representation": "exe",
                        "source_sha256": source,
                        "label": label,
                        "family": family,
                        "representation_sha256": exe,
                        "leakage_group_sha256": exe,
                        "representation_relative_path": f"exe/{source}.bin",
                        "representation_size": 5,
                        "snapshot": "test",
                    },
                ]
            )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PRODUCT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return sources


def _config() -> RandsComparisonConfig:
    return RandsComparisonConfig(
        snapshot="test",
        seed="synthetic-rands-comparison-v1",
        fractions={"train": 0.70, "validation": 0.15, "test": 0.15},
        labels=frozenset({"benign", "ransomware"}),
    )


def _write_comparison_config(path: Path) -> None:
    path.write_text(
        """
experiment: {dataset: rands, kind: benchmark}
references: {rands_snapshot: test}
task: {labels: {benign: 0, ransomware: 1}}
split:
  seed: synthetic-rands-comparison-v1
  fractions: {train: 0.70, validation: 0.15, test: 0.15}
""".strip()
        + "\n",
        encoding="utf-8",
    )


def test_rands_comparison_split_deduplicates_active_exe_groups_and_is_deterministic(
    tmp_path: Path,
) -> None:
    products_path = tmp_path / "products.csv"
    sources = _write_products(products_path)
    entries = load_rands_product_manifest(products_path)
    cohort, cohort_summary = build_rands_comparison_cohort(entries, _config())
    first, split_summary = split_rands_comparison_cohort(cohort, _config())
    second, _ = split_rands_comparison_cohort(cohort, _config())

    assert cohort_summary["comparison_cohort"] == {
        "raw_sources": 20,
        "exe_sources": 20,
        "successful_raw_exe_sources": 20,
        "exact_exe_groups": 18,
        "same_label_duplicate_groups": 2,
        "same_label_duplicate_sources_removed": 2,
        "cross_label_exe_groups": 0,
        "representatives": 18,
        "sources_without_exe": 0,
        "labels": {"benign": 9, "ransomware": 9},
    }
    assert [(row.split, row.comparison.source_sha256) for row in first] == [
        (row.split, row.comparison.source_sha256) for row in second
    ]
    assert split_summary["allocation_by_label"] == {
        "benign": {"train": 6, "validation": 2, "test": 1},
        "ransomware": {"train": 6, "validation": 2, "test": 1},
    }
    assert len({row.comparison.source_sha256 for row in first}) == 18
    assert all(row.comparison.source_sha256 in sources for row in first)
    by_group = {row.comparison.exe.representation_sha256: row.split for row in first}
    assert len(by_group) == 18


def test_rands_comparison_split_rejects_cross_label_exact_exe_duplicates(tmp_path: Path) -> None:
    products_path = tmp_path / "products.csv"
    _write_products(products_path, cross_label_duplicate=True)

    with pytest.raises(RandsComparisonError, match="cross-label EXE representation"):
        build_rands_comparison_cohort(load_rands_product_manifest(products_path), _config())


def test_rands_comparison_split_cli_writes_private_manifest_and_hash_safe_summary(
    tmp_path: Path, capsys
) -> None:
    products_path = tmp_path / "products.csv"
    sources = _write_products(products_path)
    config_path = tmp_path / "comparison.yaml"
    manifest_path = tmp_path / "comparison-split.csv"
    summary_path = tmp_path / "comparison-split.json"
    _write_comparison_config(config_path)

    assert load_rands_comparison_config(config_path).seed == "synthetic-rands-comparison-v1"
    exit_code = main(
        [
            "experiment",
            "freeze-rands-comparison",
            "--products",
            str(products_path),
            "--experiment",
            str(config_path),
            "--manifest",
            str(manifest_path),
            "--summary",
            str(summary_path),
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert json.loads(output)["comparison_cohort"]["representatives"] == 18
    assert manifest_path.exists() is True
    summary = summary_path.read_text(encoding="utf-8")
    assert all(source not in summary for source in sources)

    rows = list(csv.DictReader(manifest_path.open(newline="", encoding="utf-8")))
    assert len(rows) == 18
    assert {row["split"] for row in rows} == {"train", "validation", "test"}
    assert all(row["source_sha256"] in sources for row in rows)


def test_rands_comparison_split_writer_rejects_repository_paths_outside_private_locations(
    tmp_path: Path,
) -> None:
    products_path = tmp_path / "products.csv"
    _write_products(products_path)
    cohort, cohort_summary = build_rands_comparison_cohort(
        load_rands_product_manifest(products_path), _config()
    )
    rows, split_summary = split_rands_comparison_cohort(cohort, _config())

    with pytest.raises(RandsComparisonError, match="Split manifests inside"):
        write_rands_comparison_split_outputs(
            rows,
            cohort_summary,
            split_summary,
            products_path,
            Path.cwd() / "unsafe-comparison-split.csv",
            tmp_path / "summary.json",
        )
