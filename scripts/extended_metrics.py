#!/usr/bin/env python3
"""Backfill extended evaluation metrics from existing run artifacts (no retraining).

Reads metrics.json, test-predictions.csv and best.pt from each run directory and
writes extended-metrics.json next to metrics.json. Computes MCC, TPR at fixed FPR,
bootstrap confidence intervals and parameter counts.

Usage:
    uv run --locked python scripts/extended_metrics.py --reports-root reports/runpod-reports
    uv run --locked python scripts/extended_metrics.py --run-dir path/to/run
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import torch


def _auc(probabilities: list[float], labels: list[int]) -> float | None:
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


def _mcc(predictions: list[int], labels: list[int]) -> float:
    tp = sum(p == 1 and l == 1 for p, l in zip(predictions, labels))
    tn = sum(p == 0 and l == 0 for p, l in zip(predictions, labels))
    fp = sum(p == 1 and l == 0 for p, l in zip(predictions, labels))
    fn = sum(p == 0 and l == 1 for p, l in zip(predictions, labels))
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    if denominator == 0:
        return 0.0
    return (tp * tn - fp * fn) / denominator


def _tpr_at_fpr(
    probabilities: list[float], labels: list[int], fpr: float
) -> dict[str, float] | None:
    benign = [p for p, l in zip(probabilities, labels) if l == 0]
    positives = sum(labels)
    if not benign or positives == 0:
        return None
    # Sweep complete tied-score groups. Never exceed the requested empirical FPR.
    # The previous ceil-based implementation incorrectly allowed >=1 FP even at 1e-4.
    ranked = sorted(zip(probabilities, labels), reverse=True)
    threshold = math.nextafter(ranked[0][0], math.inf)
    tp = fp = current_tp = current_fp = index = 0
    while index < len(ranked):
        score = ranked[index][0]
        end = index
        while end < len(ranked) and ranked[end][0] == score:
            current_tp += ranked[end][1] == 1
            current_fp += ranked[end][1] == 0
            end += 1
        if current_fp / len(benign) > fpr:
            break
        tp, fp, threshold = current_tp, current_fp, score
        index = end
    return {
        "requested_fpr": fpr,
        "achieved_fpr": fp / len(benign),
        "tpr": tp / positives,
        "threshold": threshold,
        "false_positives": fp,
        "benign": len(benign),
        "positives": positives,
        "empirical_fpr_resolution": 1 / len(benign),
    }


def _bootstrap(
    probabilities: list[float], labels: list[int], threshold: float, n_boot: int, seed: int
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    probs = np.asarray(probabilities, dtype=np.float64)
    ys = np.asarray(labels, dtype=np.int64)
    n = len(ys)
    aucs, mccs, tprs = [], [], []
    for _ in range(n_boot):
        idx = rng.integers(0, n, size=n)
        p = probs[idx]
        y = ys[idx]
        if y.sum() == 0 or y.sum() == n:
            continue
        aucs.append(_auc(p.tolist(), y.tolist()))
        preds = (p >= threshold).astype(int)
        mccs.append(_mcc(preds.tolist(), y.tolist()))
        result = _tpr_at_fpr(p.tolist(), y.tolist(), 1e-3)
        if result is not None:
            tprs.append(result["tpr"])

    def interval(values: list[float]) -> list[float] | None:
        if not values:
            return None
        arr = np.asarray(values, dtype=np.float64)
        return [float(np.percentile(arr, 2.5)), float(np.percentile(arr, 97.5))]

    return {
        "n_boot": n_boot,
        "roc_auc_95ci": interval(aucs),
        "mcc_95ci": interval(mccs),
        "tpr_at_fpr_1e-3_95ci": interval(tprs),
    }


def _parameter_count(checkpoint: Path) -> int | None:
    if not checkpoint.is_file():
        return None
    payload = torch.load(checkpoint, map_location="cpu", weights_only=True)
    state = payload.get("model", payload)
    return sum(int(value.numel()) for value in state.values())


def _read_predictions(path: Path) -> tuple[list[float], list[int]]:
    probabilities: list[float] = []
    labels: list[int] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            probabilities.append(float(row["ransomware_probability"]))
            labels.append(1 if str(row["label"]).strip() in {"1", "ransomware"} else 0)
    return probabilities, labels


def extend_run(run_dir: Path, *, n_boot: int, seed: int) -> dict[str, Any]:
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    probabilities, labels = _read_predictions(run_dir / "test-predictions.csv")
    threshold = float(metrics.get("selection", {}).get("threshold", 0.5))
    predictions = [int(p >= threshold) for p in probabilities]
    source = metrics.get("source", {})
    run_manifest = json.loads((run_dir / "run-manifest.json").read_text())
    device = run_manifest.get("device", "unknown")
    reads = sum(source.get("reads_by_label", {}).values()) or 0
    extended: dict[str, Any] = {
        "run": run_dir.name,
        "test_rows": len(labels),
        "threshold": threshold,
        "mcc": _mcc(predictions, labels),
        "roc_auc": _auc(probabilities, labels),
        "tpr_at_fpr": [
            result
            for fpr in (1e-2, 1e-3, 1e-4)
            if (result := _tpr_at_fpr(probabilities, labels, fpr)) is not None
        ],
        "bootstrap": _bootstrap(probabilities, labels, threshold, n_boot, seed),
        "parameter_count": _parameter_count(run_dir / "best.pt"),
        "wall_hours": round(float(metrics.get("runtime_seconds", 0.0)) / 3600, 4),
        "device": device,
        "peak_memory_bytes": metrics.get("peak_memory_bytes"),
        "read_hash_seconds_per_read": (
            round(float(source.get("read_seconds", 0.0)) / reads, 6) if reads else None
        ),
        "note": (
            "Wall time includes validation/test; not training-only GPU hours. "
            "Read/hash timing is not EXE extraction or tokenization time. "
            "Low-FPR thresholds are descriptive test ROC operating points, not "
            "validation-calibrated deployment thresholds. Bootstrap conditions on "
            "this fitted model; it does not measure training-seed variability."
        ),
    }
    (run_dir / "extended-metrics.json").write_text(
        json.dumps(extended, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return extended


def _discover(reports_root: Path) -> list[Path]:
    return sorted(path.parent for path in reports_root.glob("*/runs/*/metrics.json"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-root", type=Path)
    parser.add_argument("--run-dir", type=Path, action="append", default=[])
    parser.add_argument("--n-boot", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    run_dirs = list(args.run_dir)
    if args.reports_root is not None:
        run_dirs.extend(_discover(args.reports_root))
    if not run_dirs:
        parser.error("Provide --reports-root or at least one --run-dir.")
    for run_dir in run_dirs:
        extended = extend_run(run_dir, n_boot=args.n_boot, seed=args.seed)
        print(json.dumps(extended, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
