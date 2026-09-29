"""Deterministic representation deduplication without deleting source objects."""

from collections import Counter, defaultdict
from typing import Any


def deduplicate_temporal_rows(
    rows: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, Any]]:
    """Drop conflicting labels; otherwise keep earliest year, then smallest source SHA.

    Splits are assigned before this step and never changed here. Apply to the entire
    eligible cohort before pilot sampling or class balancing so neither can hide a
    conflicting label or resurrect a duplicate from a later period.
    """
    groups = defaultdict(list)
    for row in rows:
        groups[row["representation_sha256"]].append(row)
    kept, removed = [], []
    by_reason = Counter()
    coverage = Counter()
    crossing = conflicts = same_split = 0
    for digest, group in sorted(groups.items()):
        crossing += len({r["split"] for r in group}) > 1
        conflict = len({r["label"] for r in group}) > 1
        conflicts += conflict
        same_split += len(group) > 1 and len({r["split"] for r in group}) == 1
        winner = (
            None if conflict else min(group, key=lambda r: (int(r["year"]), r["source_sha256"]))
        )
        if winner is not None:
            kept.append(winner)
        for row in sorted(group, key=lambda r: r["source_sha256"]):
            if row is winner:
                continue
            reason = (
                "conflicting_labels"
                if conflict
                else "duplicate_same_split"
                if row["split"] == winner["split"]
                else "duplicate_later_split"
            )
            by_reason[reason] += 1
            coverage[f"{row['split']}/{row['label']}/{reason}"] += 1
            removed.append(
                {
                    "source_sha256": row["source_sha256"],
                    "representation_sha256": digest,
                    "split": row["split"],
                    "label": row["label"],
                    "year": row["year"],
                    "reason": reason,
                    "retained_source_sha256": winner["source_sha256"] if winner else "",
                }
            )
    return (
        kept,
        removed,
        {
            "policy": "earliest_year_drop_conflicts",
            "input_rows": len(rows),
            "retained_rows": len(kept),
            "removed_rows": len(removed),
            "same_split_duplicate_groups": same_split,
            "cross_split_duplicate_groups": crossing,
            "cross_label_duplicate_groups": conflicts,
            "removed_by_reason": dict(by_reason),
            "removed_by_split_label_reason": dict(coverage),
            "tie_break": "year_then_source_sha256",
            "source_objects_deleted": 0,
        },
    )
