"""Deterministic non-temporal Active/Latent ratio manifests from audited groups."""

from collections import defaultdict
import csv
from hashlib import sha256
import json
from pathlib import Path
import random


def export_ratio_splits(
    candidates: Path, membership: Path, output: Path, seeds: list[int], holdout_seed: int
) -> dict:
    """Apply approved option A; numeric seeds must be explicitly supplied."""
    if len(seeds) != 3 or len(set(seeds)) != 3:
        raise ValueError("Supply three distinct approved sampling seeds")

    def read(path):
        with path.open(newline="") as stream:
            return list(csv.DictReader(stream))

    rows = read(candidates)
    states = defaultdict(set)
    for row in read(membership):
        if row["state"] in {"Active", "Latent"}:
            states[row["model_input_sha256"]].add(row["state"])
    pools = {state: [] for state in ("Active", "Latent", "benign")}
    seen_tokens, seen_exe, seen_sources = set(), set(), set()
    ambiguous = []
    for row in rows:
        token, exe, source = row["model_input_sha256"], row["exe_sha256"], row["source_sha256"]
        if token in seen_tokens or exe in seen_exe or source in seen_sources:
            raise ValueError("Input must already be source/EXE/token deduplicated")
        seen_tokens.add(token)
        seen_exe.add(exe)
        seen_sources.add(source)
        if row["label"] == "benign":
            if states[token]:
                raise ValueError("Conflicting class membership")
            state = "benign"
        elif row["label"] == "ransomware":
            if len(states[token]) > 1:
                ambiguous.append(row)
                continue
            if len(states[token]) != 1:
                raise ValueError("Missing ransomware state membership")
            state = next(iter(states[token]))
        else:
            raise ValueError("Unsupported class")
        pools[state].append({**row, "state": state})
    for pool in pools.values():
        pool.sort(key=lambda r: r["model_input_sha256"])
    h = min(len(pools["Active"]), len(pools["Latent"])) // 10
    if h < 1 or len(pools["benign"]) < 4 * h:
        raise ValueError("Insufficient balanced holdout capacity")
    rng = random.Random(holdout_seed)
    holdouts = {name: [] for name in ("validation", "test")}
    training = {}
    for state, pool in pools.items():
        shuffled = pool.copy()
        rng.shuffle(shuffled)
        size = 2 * h if state == "benign" else h
        holdouts["validation"].extend({**r, "split": "validation"} for r in shuffled[:size])
        holdouts["test"].extend({**r, "split": "test"} for r in shuffled[size : 2 * size])
        training[state] = shuffled[2 * size :]
    ransomware = min(map(len, training.values())) // 10 * 10
    if ransomware < 10:
        raise ValueError("Insufficient common train capacity")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    fields = list(rows[0])
    for field in ("state", "split"):
        if field not in fields:
            fields.append(field)

    def write(path, values):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(
                sorted(values, key=lambda r: (r.get("split", ""), r["model_input_sha256"]))
            )
        path.chmod(0o600)

    for name, values in holdouts.items():
        write(output / (name + ".csv"), values)
    write(output / "ambiguous-excluded.csv", ambiguous)
    for seed in seeds:
        rng = random.Random(seed)
        shuffled = {}
        for state in ("Active", "Latent", "benign"):
            shuffled[state] = sorted(training[state], key=lambda r: r["model_input_sha256"])
            rng.shuffle(shuffled[state])
        for percentage in (0, 10, 30, 50, 70, 90, 100):
            a = ransomware * percentage // 100
            train = (
                shuffled["Active"][:a]
                + shuffled["Latent"][: ransomware - a]
                + shuffled["benign"][:ransomware]
            )
            values = (
                [{**r, "split": "train"} for r in train]
                + holdouts["validation"]
                + holdouts["test"]
            )
            write(output / f"seed-{seed}" / f"active-{percentage:03d}" / "split.csv", values)
    summary = {
        "status": "ratio_membership_export_not_training_release",
        "policy": "approved_question_15_A_non_temporal",
        "eligible_groups": {k: len(v) for k, v in pools.items()},
        "ambiguous_groups_excluded": len(ambiguous),
        "holdout_per_state": h,
        "validation_total": 4 * h,
        "test_total": 4 * h,
        "train_ransomware": ransomware,
        "train_benign": ransomware,
        "ratios": [0, 10, 30, 50, 70, 90, 100],
        "seeds": seeds,
        "holdout_seed": holdout_seed,
        "runs": 21,
        "input_sha256": {
            "candidates": sha256(candidates.read_bytes()).hexdigest(),
            "membership": sha256(membership.read_bytes()).hexdigest(),
        },
        "output_sha256": {
            str(p.relative_to(output)): sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob("*.csv"))
        },
        "limitations": [
            "Not a temporal benchmark",
            "Original MLM pretraining overlap unknown",
            "No project-level grouping",
            "Training-loader schema adaptation and release audit required",
        ],
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
