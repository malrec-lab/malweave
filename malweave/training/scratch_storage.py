"""Immutable training snapshots with a last-written S3 pointer; no dataset upload."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
from uuid import uuid4

from malweave.data.rands_training import (
    RandsTrainingError,
    atomic_json,
    aws,
    file_digest,
    validate_experiment_prefix,
)

ARTIFACTS = (
    "last.pt",
    "best.pt",
    "tokenizer.json",
    "run-manifest.json",
    "config.yaml",
    "split.csv",
    "excluded.csv",
    "prepared.json",
    "history.json",
    "metrics.json",
    "test-predictions.csv",
    "completed.json",
)


def publish(run: Path, prefix: str) -> None:
    """Upload committed artifacts, then replace the pointer. A failed upload keeps local state."""
    prefix = validate_experiment_prefix(prefix) + "/" + run.name
    files = {name: file_digest(run / name) for name in ARTIFACTS if (run / name).is_file()}
    generation = uuid4().hex
    for name, digest in files.items():
        aws(
            "s3",
            "cp",
            str(run / name),
            prefix + "/objects/" + digest + "/" + name,
            "--only-show-errors",
        )
    pointer = {"schema": 2, "generation": generation, "files": files}
    atomic_json(run / "remote-latest.json", pointer)
    aws("s3", "cp", str(run / "remote-latest.json"), prefix + "/latest.json", "--only-show-errors")


def restore(run: Path, prefix: str) -> None:
    """Only restore into a fresh run; checksum every artifact before making it visible."""
    if run.exists():
        raise RandsTrainingError("Remote restore requires a missing local run directory.")
    prefix = validate_experiment_prefix(prefix) + "/" + run.name
    temporary = run.parent / ("." + run.name + "-restore")
    temporary.mkdir(parents=True, exist_ok=True)
    pointer_path = temporary / "remote-latest.json"
    aws("s3", "cp", prefix + "/latest.json", str(pointer_path), "--only-show-errors")
    pointer = json.loads(pointer_path.read_text())
    generation = pointer["generation"]
    if (
        pointer.get("schema") != 2
        or len(generation) != 32
        or any(c not in "0123456789abcdef" for c in generation)
        or not {"last.pt", "tokenizer.json", "run-manifest.json"} <= pointer["files"].keys()
        or not set(pointer["files"]) <= set(ARTIFACTS)
    ):
        raise RandsTrainingError("Invalid remote training pointer.")
    for name, digest in pointer["files"].items():
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise RandsTrainingError("Invalid artifact digest in remote pointer.")
        destination = temporary / name
        aws(
            "s3",
            "cp",
            prefix + "/objects/" + digest + "/" + name,
            str(destination),
            "--only-show-errors",
        )
        if file_digest(destination) != digest:
            raise RandsTrainingError("Remote training artifact checksum mismatch.")
    # Remove leftovers from a previously interrupted restore of a newer generation.
    for name in ARTIFACTS:
        if name not in pointer["files"] and (temporary / name).exists():
            (temporary / name).unlink()
    os.replace(temporary, run)


def copy_preparation(data: Path, run: Path) -> None:
    for name in ["prepared.json", "split.csv", "excluded.csv"]:
        shutil.copyfile(data / name, run / name)
