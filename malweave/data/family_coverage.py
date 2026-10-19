"""Family-coverage reporting for frozen splits, without exposing sample hashes.

The report answers two questions that an aggregate score cannot:

* how much of a split belongs to families already seen in the reference split
  (which makes a score optimistic), and
* how much belongs to families never seen in the reference split (open-set,
  which makes a score pessimistic).

Only family names and aggregate counts are written; sample identities and
representation digests never enter the report.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
import csv
from pathlib import Path
from typing import Any

SPLITS = ("train", "validation", "test")
REQUIRED_FIELDS = {"split", "source_sha256", "label"}


class FamilyCoverageError(ValueError):
    """A split manifest cannot produce a trustworthy family-coverage report."""


def read_split_manifest(path: Path) -> list[dict[str, str]]:
    """Read a frozen split manifest into plain rows; never touch the raw samples."""
    try:
        handle = path.open(newline="", encoding="utf-8-sig")
    except OSError as error:
        raise FamilyCoverageError("Could not read the split manifest.") from error
    with handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or ())
        if not REQUIRED_FIELDS.issubset(fields):
            raise FamilyCoverageError("Split manifest lacks split, source, or label fields.")
        rows = [dict(row) for row in reader]
    if not rows:
        raise FamilyCoverageError("Split manifest has no selected samples.")
    return rows


def read_predictions(path: Path) -> list[dict[str, str]]:
    """Read a private test-predictions CSV for seen/unseen family breakdowns."""
    try:
        handle = path.open(newline="", encoding="utf-8-sig")
    except OSError as error:
        raise FamilyCoverageError("Could not read the predictions CSV.") from error
    with handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or ())
        if not {"source_sha256", "label", "ransomware_probability"}.issubset(fields):
            raise FamilyCoverageError(
                "Predictions lack source, label, or ransomware_probability fields."
            )
        rows = [dict(row) for row in reader]
    if not rows:
        raise FamilyCoverageError("Predictions CSV has no rows.")
    return rows


def resolve_families(
    rows: Iterable[Mapping[str, str]],
    family_lookup: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Map every source to its family, preferring an explicit manifest column."""
    families: dict[str, str] = {}
    for row in rows:
        source = row["source_sha256"]
        family = (row.get("family") or "").strip()
        if not family and family_lookup is not None:
            family = (family_lookup.get(source) or "").strip()
        previous = families.get(source)
        if previous is not None and previous != family:
            raise FamilyCoverageError("A source carries conflicting family labels.")
        families[source] = family
    return families


def reference_families(
    rows: Iterable[Mapping[str, str]],
    families: Mapping[str, str],
    reference_split: str = "train",
) -> set[str]:
    """Return the non-empty families observed in the reference split."""
    selected = [families[row["source_sha256"]] for row in rows if row["split"] == reference_split]
    return {family for family in selected if family}


def summarize_family_coverage(
    rows: Sequence[Mapping[str, str]],
    *,
    family_lookup: Mapping[str, str] | None = None,
    reference_split: str = "train",
    splits: Sequence[str] = SPLITS,
    top_families: int = 10,
) -> dict[str, Any]:
    """Summarize per-split family coverage relative to one reference split."""
    rows = list(rows)
    if not rows:
        raise FamilyCoverageError("Cannot summarize an empty split.")
    unknown = {row["split"] for row in rows} - set(splits)
    if unknown:
        raise FamilyCoverageError(f"Unexpected splits: {sorted(unknown)}.")
    if reference_split not in {row["split"] for row in rows}:
        raise FamilyCoverageError(f"Reference split {reference_split!r} is absent.")

    families = resolve_families(rows, family_lookup)
    reference = reference_families(rows, families, reference_split)
    labels = sorted({row["label"] for row in rows})

    report: dict[str, Any] = {
        "reference_split": reference_split,
        "reference_families": len(reference),
        "labels": labels,
        "extra_fields_present": bool(any((row.get("family") or "").strip() for row in rows)),
        "splits": {},
    }
    for split in splits:
        subset = [row for row in rows if row["split"] == split]
        if not subset:
            continue
        observed = Counter(families[row["source_sha256"]] for row in subset)
        observed.pop("", None)
        in_reference = [row for row in subset if families[row["source_sha256"]] in reference]
        unseen = [
            row
            for row in subset
            if families[row["source_sha256"]] and families[row["source_sha256"]] not in reference
        ]
        without_family = [row for row in subset if not families[row["source_sha256"]]]
        labeled = len(in_reference) + len(unseen)
        by_label: dict[str, Any] = {}
        for label in labels:
            label_rows = [row for row in subset if row["label"] == label]
            if not label_rows:
                continue
            label_seen = [row for row in label_rows if families[row["source_sha256"]] in reference]
            label_unseen = [
                row
                for row in label_rows
                if families[row["source_sha256"]]
                and families[row["source_sha256"]] not in reference
            ]
            by_label[label] = {
                "rows": len(label_rows),
                "families": len({families[row["source_sha256"]] for row in label_rows} - {""}),
                "sources_in_reference_families": len(label_seen),
                "sources_in_unseen_families": len(label_unseen),
                "sources_without_family": len(label_rows) - len(label_seen) - len(label_unseen),
            }
        report["splits"][split] = {
            "rows": len(subset),
            "families": len(observed),
            "families_shared_with_reference": len(set(observed) & reference),
            "families_only_in_split": sorted(set(observed) - reference),
            "sources_in_reference_families": len(in_reference),
            "sources_in_unseen_families": len(unseen),
            "sources_without_family": len(without_family),
            "unseen_family_source_share": (len(unseen) / labeled if labeled else None),
            "top_families": observed.most_common(top_families),
            "by_label": by_label,
        }
    return report


def _roc_auc(probabilities: list[float], labels: list[int]) -> float | None:
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return None
    ranked = sorted(zip(probabilities, labels), key=lambda item: item[0])
    rank_sum = 0.0
    index = 0
    while index < len(ranked):
        end = index + 1
        while end < len(ranked) and ranked[end][0] == ranked[index][0]:
            end += 1
        rank_sum += (index + 1 + end) / 2 * sum(label for _, label in ranked[index:end])
        index = end
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def _subset_metrics(rows: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    probabilities: list[float] = []
    labels: list[int] = []
    for row in rows:
        labels.append(1 if str(row["label"]).strip() in {"1", "ransomware"} else 0)
        probabilities.append(float(row["ransomware_probability"]))
    return {
        "rows": len(rows),
        "positives": sum(labels),
        "negatives": len(labels) - sum(labels),
        "roc_auc": _roc_auc(probabilities, labels),
    }


def seen_unseen_metric_breakdown(
    predictions: Sequence[Mapping[str, str]],
    families: Mapping[str, str],
    reference: set[str],
) -> dict[str, Any]:
    """Split one split's predictions into seen- versus unseen-family metrics."""
    seen: list[Mapping[str, str]] = []
    unseen: list[Mapping[str, str]] = []
    unknown: list[Mapping[str, str]] = []
    for row in predictions:
        family = (families.get(row["source_sha256"]) or "").strip()
        if not family:
            unknown.append(row)
        elif family in reference:
            seen.append(row)
        else:
            unseen.append(row)
    return {
        "reference_families": len(reference),
        "seen_family": _subset_metrics(seen),
        "unseen_family": _subset_metrics(unseen),
        "unknown_family": {"rows": len(unknown)},
    }
