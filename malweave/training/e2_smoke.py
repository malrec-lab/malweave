"""Synthetic-only baseline capacity and cross-process recovery fixtures."""

from __future__ import annotations

import csv
from hashlib import sha256
from pathlib import Path
import random

import yaml

from malweave.config import PROJECT_ROOT
from malweave.experiments.rands_comparison import SPLIT_FIELDS
from malweave.training.contracts import SupervisedTrainingError, _private_path


def prepare_e1_smoke(root: Path, *, sample_bytes: int = 4096, tiny_model: bool = False) -> dict:
    """Generate E1 fixtures; sample_bytes sizes test inputs, never caps its reader."""
    if type(sample_bytes) is not int or sample_bytes < 64:
        raise SupervisedTrainingError("Synthetic sample_bytes must be an integer >= 64.")
    config = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-e1.yaml").read_text())
    config["experiment"].update(kind="feasibility", name="e1-synthetic-recovery")
    config.pop("cohort")
    # Share deterministic synthetic byte/split generation, not E2's input encoding.
    result = prepare_e2_smoke(
        root, max_tokens=sample_bytes + 2, tiny_model=tiny_model, full_length=True
    )
    batch = 1 if tiny_model else 128
    config["tracks"]["malconvgct"]["training"].update(
        epochs=3, batch_size=batch, effective_batch_size=4 if tiny_model else 128
    )
    config["supervision"]["bootstrap"]["replicates"] = 20
    if tiny_model:
        config["tracks"]["malconvgct"]["architecture"].update(
            embedding_size=2, channels=4, chunk_size=1024, min_chunk_size=256
        )
    (root / "config.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
    result.pop("max_tokens")
    return {
        **result,
        "sample_bytes": sample_bytes,
        "batch_size": batch,
        "protocol": "malconvgct_e1",
    }


def prepare_e2_smoke(
    root: Path,
    *,
    max_tokens: int = 4096,
    tiny_model: bool = False,
    full_length: bool = False,
) -> dict:
    """Generate non-PE byte strings; never inspect existing dataset or credentials.

    The real architecture uses batch 64 without accumulation; tiny_model retains
    batch one/effective batch four for CPU recovery regressions. Both use three
    epochs and fewer bootstrap draws, so neither is a scientific E2 result.
    full_length creates distinct, deterministic random payloads at the token limit.
    """
    _private_path(root, "synthetic_root")
    if root.exists() or type(max_tokens) is not int or max_tokens < 66:
        raise SupervisedTrainingError("Use a new synthetic directory and max_tokens >= 66.")
    config = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-e2.yaml").read_text())
    config["experiment"].update(kind="feasibility", name="e2-synthetic-recovery")
    config.pop("cohort")
    config["inputs"]["raw"]["max_tokens"] = max_tokens
    training = config["tracks"]["malconvgct"]["training"]
    batch_size = 1 if tiny_model else 64
    training.update(epochs=3, batch_size=batch_size, effective_batch_size=4 if tiny_model else 64)
    config["supervision"]["bootstrap"]["replicates"] = 20
    if tiny_model:
        config["tracks"]["malconvgct"]["architecture"].update(
            embedding_size=2, channels=4, chunk_size=256, min_chunk_size=64
        )
    root.mkdir(parents=True, exist_ok=False)
    (root / "config.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
    rows = []
    index = 0
    train_count = 6 if tiny_model else 128
    for split, count in (("train", train_count), ("validation", 2), ("test", 2)):
        for local_index in range(count):
            # The longest input reaches the token limit, including in train.
            size = (
                max_tokens - 2
                if full_length or local_index == count - 1
                else min(128 + index * 64, max_tokens - 2)
            )
            if full_length:
                marker = b"E2-SYNTHETIC\x00"
                content = marker + random.Random(index).randbytes(size - len(marker))
            else:
                content = bytes((index * 19 + j * 13) % 256 for j in range(size))
            source = sha256(content).hexdigest()
            path = root / "raw" / "dataset" / source[:2] / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            row = dict.fromkeys(SPLIT_FIELDS, "")
            row.update(
                split=split,
                source_sha256=source,
                label="ransomware" if local_index % 2 else "benign",
                family="synthetic-family" if local_index % 2 else "",
                snapshot="synthetic-only",
                raw_representation_sha256=source,
                raw_relative_path=f"{source[:2]}/{source}",
                raw_size=size,
                exe_representation_sha256=source,
                exe_relative_path=f"{source}.bin",
                exe_size=size,
                active_leakage_group_sha256=source,
            )
            rows.append(row)
            index += 1
    with (root / "split.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SPLIT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return {
        "synthetic_only": True,
        "root": str(root),
        "max_tokens": max_tokens,
        "tiny_model": tiny_model,
        "full_length": full_length,
        "batch_size": batch_size,
        "gradient_accumulation_steps": 4 if tiny_model else 1,
        "rows": len(rows),
    }
