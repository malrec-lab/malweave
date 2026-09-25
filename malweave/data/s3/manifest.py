"""Reusable selection policy for labeled private object inventories.

Rows may come from any S3 prefix or dataset adapter; this module never calls S3
and does not assume RanDS key layout or label names.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal
from hashlib import sha256
from typing import Any


class ManifestSelectionError(ValueError):
    """A requested manifest selection is invalid or cannot be satisfied."""


@dataclass(frozen=True)
class ManifestOptions:
    """No size option means all eligible rows; filters always apply first."""

    total: int | None = None
    balanced: bool = False
    label_counts: dict[str, int] = field(default_factory=dict)
    where: tuple[tuple[str, str], ...] = ()
    seed: str = "manifest-v1"


def filter_rows(
    rows: list[dict[str, str]], where: tuple[tuple[str, str], ...]
) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Apply repeatable exact-match column filters, with aggregate rejection counts."""
    if not rows:
        return [], {}
    for column, _ in where:
        if column not in rows[0]:
            raise ManifestSelectionError(f"Unknown manifest filter column: {column}.")
    kept = []
    rejected: Counter[str] = Counter()
    for row in rows:
        failed = next((column for column, value in where if row.get(column) != value), None)
        if failed is None:
            kept.append(row)
        else:
            rejected[failed] += 1
    return kept, dict(rejected)


def _apportion(total: int, weights: dict[str, Decimal], order: tuple[str, ...]) -> dict[str, int]:
    if total < 0 or not weights or sum(weights.values()) <= 0:
        raise ManifestSelectionError(
            "Selection requires a nonnegative total and positive weights."
        )
    weight_total = sum(weights.values())
    quotas = {name: Decimal(total) * weights[name] / weight_total for name in order}
    counts = {name: int(quotas[name]) for name in order}
    remaining = total - sum(counts.values())
    ranked = sorted(order, key=lambda name: (-(quotas[name] - counts[name]), order.index(name)))
    for name in ranked[:remaining]:
        counts[name] += 1
    return counts


def select_labeled_rows(
    rows: list[dict[str, str]],
    *,
    splits: tuple[str, ...],
    labels: tuple[str, ...],
    fractions: dict[str, Decimal],
    options: ManifestOptions,
    split_field: str = "split",
    label_field: str = "label",
    identity_field: str = "source_sha256",
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Select deterministically within split/label while preserving disjoint groups."""
    if not rows or not splits or not labels:
        raise ManifestSelectionError("No eligible rows, splits, or labels were supplied.")
    rows, where_exclusions = filter_rows(rows, options.where)
    if not rows:
        raise ManifestSelectionError("No rows remain after --where filters.")
    if set(fractions) != set(splits) or sum(fractions.values()) <= 0:
        raise ManifestSelectionError(
            "Fractions must cover every split with positive total weight."
        )
    if options.total is not None and options.total < 1:
        raise ManifestSelectionError("--total must be positive.")
    if options.balanced and options.total is not None and options.total % len(labels):
        raise ManifestSelectionError("--total must divide evenly across labels when balanced.")
    if options.label_counts and (options.total is not None or options.balanced):
        raise ManifestSelectionError(
            "--label-count cannot be combined with --total or --balanced."
        )
    if any(label not in labels or count < 0 for label, count in options.label_counts.items()):
        raise ManifestSelectionError("Invalid --label-count value.")

    pools: dict[tuple[str, str], list[dict[str, str]]] = {
        (split, label): [] for split in splits for label in labels
    }
    seen: set[str] = set()
    for row in rows:
        identity = row.get(identity_field)
        split = row.get(split_field)
        label = row.get(label_field)
        if not identity or identity in seen or split not in splits or label not in labels:
            raise ManifestSelectionError(
                "Rows need unique identities and supported split/label values."
            )
        seen.add(identity)
        pools[split, label].append(row)
    available = {split: {label: len(pools[split, label]) for label in labels} for split in splits}
    targets: dict[str, dict[str, int]] = {split: {} for split in splits}

    if options.total is None and not options.balanced and not options.label_counts:
        targets = available
        mode = "full"
    elif options.total is None and options.balanced:
        for split in splits:
            smallest = min(available[split].values())
            if smallest == 0:
                raise ManifestSelectionError(
                    f"Cannot balance {split}: at least one label is absent."
                )
            targets[split] = {label: smallest for label in labels}
        mode = "balanced_full"
    else:
        if options.label_counts:
            label_totals = {label: options.label_counts.get(label, 0) for label in labels}
            mode = "explicit_label_counts"
        elif options.balanced:
            assert options.total is not None
            label_totals = _apportion(
                options.total, {label: Decimal(1) for label in labels}, labels
            )
            mode = "balanced_total"
        else:
            assert options.total is not None
            label_totals = _apportion(
                options.total,
                {label: Decimal(sum(available[s][label] for s in splits)) for label in labels},
                labels,
            )
            mode = "proportional_total"
        for label in labels:
            allocation = _apportion(label_totals[label], fractions, splits)
            for split in splits:
                targets[split][label] = allocation[split]

    selected: list[dict[str, str]] = []
    for split in splits:
        for label in labels:
            target = targets[split][label]
            pool = pools[split, label]
            if target > len(pool):
                raise ManifestSelectionError(
                    f"Insufficient {label} in {split}: need {target}, have {len(pool)}."
                )
            ranked = sorted(
                pool,
                key=lambda row: (
                    sha256(f"{options.seed}:{row[identity_field]}".encode()).digest(),
                    row[identity_field],
                ),
            )
            selected.extend(ranked[:target])
    return selected, {
        "mode": mode,
        "requested_total": options.total,
        "balanced": options.balanced,
        "explicit_label_counts": options.label_counts,
        "seed": options.seed,
        "available_by_split_and_label": available,
        "selected_by_split_and_label": targets,
        "selected": len(selected),
        "where_exclusions": where_exclusions,
    }
