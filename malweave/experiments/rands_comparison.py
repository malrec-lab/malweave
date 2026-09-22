"""Leakage-safe RAW/EXE comparison cohorts and splits for RanDS experiments."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from hashlib import sha256
import io
import json
import math
from pathlib import Path
from typing import Any

import yaml

from malweave.config import PROJECT_ROOT
from malweave.data.rands import SHA256_PATTERN
from malweave.data.rands_products import PRODUCT_FIELDS

SPLIT_FIELDS = (
    "split",
    "source_sha256",
    "label",
    "family",
    "snapshot",
    "raw_representation_sha256",
    "raw_relative_path",
    "raw_size",
    "exe_representation_sha256",
    "exe_relative_path",
    "exe_size",
    "active_leakage_group_sha256",
)


class RandsComparisonError(ValueError):
    """Raised when a RanDS comparison cohort cannot be split safely."""


@dataclass(frozen=True)
class RandsComparisonConfig:
    """The comparison fields needed to freeze a RanDS benchmark split."""

    snapshot: str
    seed: str
    fractions: dict[str, float]
    labels: frozenset[str]


@dataclass(frozen=True)
class ProductManifestEntry:
    representation: str
    source_sha256: str
    label: str
    family: str
    representation_sha256: str
    relative_path: str
    size: int
    snapshot: str


@dataclass(frozen=True)
class ComparisonRow:
    source_sha256: str
    label: str
    family: str
    snapshot: str
    raw: ProductManifestEntry
    exe: ProductManifestEntry


@dataclass(frozen=True)
class SplitRow:
    split: str
    comparison: ComparisonRow


def _as_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RandsComparisonError(f"{field} must be a mapping.")
    return value


def load_rands_comparison_config(path: Path) -> RandsComparisonConfig:
    """Load and validate split-critical fields from a RanDS experiment config."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise RandsComparisonError(f"Could not read RanDS experiment config: {path}") from error
    except yaml.YAMLError as error:
        raise RandsComparisonError(f"Invalid RanDS experiment YAML: {path}") from error
    root = _as_mapping(raw, "RanDS experiment config")
    experiment = _as_mapping(root.get("experiment"), "experiment")
    if experiment.get("dataset") != "rands" or experiment.get("kind") != "benchmark":
        raise RandsComparisonError(
            "RanDS comparison configs must declare experiment.dataset=rands and kind=benchmark."
        )
    references = _as_mapping(root.get("references"), "references")
    snapshot = references.get("rands_snapshot")
    if not isinstance(snapshot, str) or not snapshot:
        raise RandsComparisonError("references.rands_snapshot must be a non-empty string.")
    task = _as_mapping(root.get("task"), "task")
    raw_labels = _as_mapping(task.get("labels"), "task.labels")
    labels = frozenset(raw_labels)
    if labels != {"benign", "ransomware"} or set(raw_labels.values()) != {0, 1}:
        raise RandsComparisonError(
            "RanDS comparison requires binary benign/ransomware labels mapped to 0 and 1."
        )
    split = _as_mapping(root.get("split"), "split")
    seed = split.get("seed")
    if not isinstance(seed, str) or not seed:
        raise RandsComparisonError("split.seed must be a non-empty string.")
    raw_fractions = _as_mapping(split.get("fractions"), "split.fractions")
    if set(raw_fractions) != {"train", "validation", "test"}:
        raise RandsComparisonError("split.fractions must contain train, validation, and test.")
    try:
        fractions = {name: float(value) for name, value in raw_fractions.items()}
    except (TypeError, ValueError) as error:
        raise RandsComparisonError("split.fractions values must be numbers.") from error
    if any(value <= 0 for value in fractions.values()) or not math.isclose(
        sum(fractions.values()), 1.0, abs_tol=1e-9
    ):
        raise RandsComparisonError("split.fractions must be positive and sum to 1.0.")
    return RandsComparisonConfig(snapshot=snapshot, seed=seed, fractions=fractions, labels=labels)


def load_rands_product_manifest(path: Path) -> list[ProductManifestEntry]:
    """Read private RAW/EXE product rows without ambiguous source/representation records."""
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as error:
        raise RandsComparisonError(f"Could not read product manifest: {path}") from error
    with handle:
        reader = csv.DictReader(handle)
        missing = sorted(set(PRODUCT_FIELDS) - set(reader.fieldnames or ()))
        if missing:
            raise RandsComparisonError(
                f"Product manifest is missing required fields: {', '.join(missing)}."
            )
        entries: list[ProductManifestEntry] = []
        seen: set[tuple[str, str]] = set()
        for row_number, row in enumerate(reader, start=2):
            representation = row["representation"]
            source = (row["source_sha256"] or "").lower()
            digest = (row["representation_sha256"] or "").lower()
            key = (representation, source)
            if representation not in {"raw", "exe"}:
                raise RandsComparisonError(f"Invalid representation in product row {row_number}.")
            if not SHA256_PATTERN.fullmatch(source) or not SHA256_PATTERN.fullmatch(digest):
                raise RandsComparisonError(f"Invalid SHA-256 in product row {row_number}.")
            if key in seen:
                raise RandsComparisonError(
                    f"Duplicate source/representation pair in product row {row_number}."
                )
            try:
                size = int(row["representation_size"])
            except ValueError as error:
                raise RandsComparisonError(
                    f"Invalid representation size in product row {row_number}."
                ) from error
            if size < 0 or not row["label"] or not row["snapshot"]:
                raise RandsComparisonError(f"Incomplete product row {row_number}.")
            seen.add(key)
            entries.append(
                ProductManifestEntry(
                    representation=representation,
                    source_sha256=source,
                    label=row["label"],
                    family=row["family"] or "",
                    representation_sha256=digest,
                    relative_path=row["representation_relative_path"],
                    size=size,
                    snapshot=row["snapshot"],
                )
            )
    return entries


def build_rands_comparison_cohort(
    entries: list[ProductManifestEntry], config: RandsComparisonConfig
) -> tuple[list[ComparisonRow], dict[str, Any]]:
    """Intersect RAW/EXE sources, exclude conflicting EXE groups, and select representatives."""
    by_source: dict[str, dict[str, ProductManifestEntry]] = defaultdict(dict)
    for entry in entries:
        if entry.snapshot != config.snapshot:
            raise RandsComparisonError(
                f"Product snapshot {entry.snapshot!r} does not match config {config.snapshot!r}."
            )
        if entry.label not in config.labels:
            raise RandsComparisonError(f"Unexpected label {entry.label!r} in product manifest.")
        by_source[entry.source_sha256][entry.representation] = entry

    raw_sources = {source for source, products in by_source.items() if "raw" in products}
    executable_sources = {source for source, products in by_source.items() if "exe" in products}
    common_sources = sorted(raw_sources & executable_sources)
    candidates: list[ComparisonRow] = []
    for source in common_sources:
        raw = by_source[source]["raw"]
        exe = by_source[source]["exe"]
        if (raw.label, raw.family, raw.snapshot) != (exe.label, exe.family, exe.snapshot):
            raise RandsComparisonError(
                "RAW and EXE product metadata disagree for a shared source."
            )
        candidates.append(ComparisonRow(source, raw.label, raw.family, raw.snapshot, raw, exe))

    by_exe_group: dict[str, list[ComparisonRow]] = defaultdict(list)
    for row in candidates:
        by_exe_group[row.exe.representation_sha256].append(row)
    conflicting_groups = [
        group for group in by_exe_group.values() if len({item.label for item in group}) != 1
    ]
    if conflicting_groups:
        raise RandsComparisonError(
            "RanDS comparison cohort contains "
            f"{len(conflicting_groups)} cross-label EXE representation group(s); no split was written."
        )

    representatives = [
        min(group, key=lambda item: item.source_sha256) for group in by_exe_group.values()
    ]
    representatives.sort(key=lambda item: item.source_sha256)
    duplicate_groups = [group for group in by_exe_group.values() if len(group) > 1]
    summary = {
        "operation": "freeze_rands_comparison",
        "comparison_cohort": {
            "raw_sources": len(raw_sources),
            "exe_sources": len(executable_sources),
            "successful_raw_exe_sources": len(candidates),
            "exact_exe_groups": len(by_exe_group),
            "same_label_duplicate_groups": len(duplicate_groups),
            "same_label_duplicate_sources_removed": sum(
                len(group) - 1 for group in duplicate_groups
            ),
            "cross_label_exe_groups": 0,
            "representatives": len(representatives),
            "sources_without_exe": len(raw_sources - executable_sources),
            "labels": dict(sorted(Counter(row.label for row in representatives).items())),
        },
    }
    return representatives, summary


def _allocate_split_counts(count: int, fractions: dict[str, float]) -> dict[str, int]:
    order = ("train", "validation", "test")
    exact = {name: count * fractions[name] for name in order}
    allocated = {name: math.floor(exact[name]) for name in order}
    remaining = count - sum(allocated.values())
    for name in sorted(
        order, key=lambda item: (-(exact[item] - allocated[item]), order.index(item))
    )[:remaining]:
        allocated[name] += 1
    return allocated


def split_rands_comparison_cohort(
    cohort: list[ComparisonRow], config: RandsComparisonConfig
) -> tuple[list[SplitRow], dict[str, Any]]:
    """Stratify deterministic representative groups without reading a model input."""
    by_label: dict[str, list[ComparisonRow]] = defaultdict(list)
    for row in cohort:
        by_label[row.label].append(row)
    split_rows: list[SplitRow] = []
    allocations: dict[str, dict[str, int]] = {}
    for label in sorted(by_label):
        ranked = sorted(
            by_label[label],
            key=lambda row: sha256(
                f"{config.seed}:{label}:{row.exe.representation_sha256}".encode()
            ).hexdigest(),
        )
        allocation = _allocate_split_counts(len(ranked), config.fractions)
        allocations[label] = allocation
        start = 0
        for split in ("train", "validation", "test"):
            end = start + allocation[split]
            split_rows.extend(SplitRow(split, row) for row in ranked[start:end])
            start = end
    split_rows.sort(
        key=lambda row: (row.split, row.comparison.label, row.comparison.source_sha256)
    )
    split_counts = {
        split: dict(
            sorted(
                Counter(row.comparison.label for row in split_rows if row.split == split).items()
            )
        )
        for split in ("train", "validation", "test")
    }
    return split_rows, {
        "algorithm": "stable_sha256_rank_per_label_after_active_representation_deduplication",
        "seed": config.seed,
        "fractions": config.fractions,
        "allocation_by_label": allocations,
        "counts_by_split_and_label": split_counts,
        "groups_crossing_splits": 0,
    }


def _validate_private_manifest_path(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if tuple(relative.parts[:2]) != ("data", "processed"):
        raise RandsComparisonError(
            "Split manifests inside the repository must be under data/processed."
        )


def _validate_summary_path(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] != "reports":
        raise RandsComparisonError("Split summaries inside the repository must be under reports/.")


def write_rands_comparison_split_outputs(
    rows: list[SplitRow],
    cohort_summary: dict[str, Any],
    split_summary: dict[str, Any],
    product_manifest_path: Path,
    manifest_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    """Write private split rows and a hash-safe aggregate report."""
    _validate_private_manifest_path(manifest_path)
    _validate_summary_path(summary_path)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=SPLIT_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        item = row.comparison
        writer.writerow(
            {
                "split": row.split,
                "source_sha256": item.source_sha256,
                "label": item.label,
                "family": item.family,
                "snapshot": item.snapshot,
                "raw_representation_sha256": item.raw.representation_sha256,
                "raw_relative_path": item.raw.relative_path,
                "raw_size": item.raw.size,
                "exe_representation_sha256": item.exe.representation_sha256,
                "exe_relative_path": item.exe.relative_path,
                "exe_size": item.exe.size,
                "active_leakage_group_sha256": item.exe.representation_sha256,
            }
        )
    payload = output.getvalue().encode("utf-8")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(payload)
    product_digest = sha256(product_manifest_path.read_bytes()).hexdigest()
    completed = {
        **cohort_summary,
        "input_product_manifest": {"sha256": product_digest},
        "split": split_summary,
        "manifest": {"rows": len(rows), "sha256": sha256(payload).hexdigest()},
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(completed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return completed
