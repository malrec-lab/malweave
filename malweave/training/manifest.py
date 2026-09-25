"""Normalize private split manifests before any representation is read or fitted."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
import re


class TrainingManifestError(ValueError):
    """A frozen split cannot safely be used for supervised training."""


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
LABELS = {"benign": 0, "ransomware": 1}
SPLITS = {"train", "validation", "test"}
TRACK_REPRESENTATIONS = {"malconvgct": "raw", "hrrformer": "exe", "mamba": "exe"}


@dataclass(frozen=True)
class TrainingSample:
    split: str
    source_sha256: str
    label: int
    representation: str
    representation_sha256: str
    group_id: str
    relative_path: str | None
    object_key: str | None
    object_size: int | None
    object_etag: str | None
    object_version: str | None


def load_training_manifest(
    path: Path, representation: str, *, raw_samples_dir: str = "dataset"
) -> list[TrainingSample]:
    """Accept legacy local comparison or representation-specific S3 split CSVs."""
    if representation not in {"raw", "exe"}:
        raise TrainingManifestError("Unsupported training representation.")
    try:
        handle = path.open(newline="", encoding="utf-8-sig")
    except OSError as error:
        raise TrainingManifestError("Could not read the private training manifest.") from error
    with handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or ())
        common = {"split", "source_sha256", "label"}
        if not common.issubset(fields):
            raise TrainingManifestError("Training manifest lacks split, source, or label fields.")
        legacy = {"raw_relative_path", "exe_relative_path"}.issubset(fields)
        if legacy:
            required = {"exe_representation_sha256", "active_leakage_group_sha256"}
        else:
            required = {"group_id", "object_key"}
        if not required.issubset(fields):
            raise TrainingManifestError(
                "Training manifest lacks representation or grouping fields."
            )

        samples: list[TrainingSample] = []
        seen_sources: set[str] = set()
        group_splits: dict[str, str] = {}
        digest_splits: dict[str, str] = {}
        for line_number, row in enumerate(reader, start=2):
            source = (row["source_sha256"] or "").lower()
            split = row["split"]
            label = row["label"]
            if not SHA256_PATTERN.fullmatch(source) or source in seen_sources:
                raise TrainingManifestError(f"Invalid or duplicate source at row {line_number}.")
            if split not in SPLITS or label not in LABELS:
                raise TrainingManifestError(f"Invalid split or label at row {line_number}.")
            if legacy:
                group = row["active_leakage_group_sha256"] or ""
                digest = source if representation == "raw" else row["exe_representation_sha256"]
                relative = (
                    f"{raw_samples_dir}/{source[:2]}/{source}"
                    if representation == "raw"
                    else row["exe_relative_path"]
                )
                key = None
                size = None
                etag = None
                version = None
            else:
                declared = row.get("representation") or "raw"
                if declared != representation:
                    raise TrainingManifestError(
                        f"Representation does not match the model at row {line_number}."
                    )
                if row.get("availability") and row["availability"] != "available":
                    raise TrainingManifestError(f"Unavailable object at row {line_number}.")
                group = row["group_id"] or ""
                digest = row.get("representation_sha256") or (
                    source if representation == "raw" else ""
                )
                relative = row.get("relative_path") or (
                    f"{raw_samples_dir}/{source[:2]}/{source}" if representation == "raw" else None
                )
                key = row["object_key"] or None
                etag = row.get("object_etag") or None
                version = row.get("object_version") or None
                try:
                    size = int(row["object_size"]) if row.get("object_size") else None
                except ValueError as error:
                    raise TrainingManifestError(
                        f"Invalid object size at row {line_number}."
                    ) from error
                if not key or size is None or size < 1 or not (etag or version):
                    raise TrainingManifestError(f"Invalid S3 object at row {line_number}.")
            if not group or not SHA256_PATTERN.fullmatch(digest or ""):
                raise TrainingManifestError(f"Invalid group or digest at row {line_number}.")
            if representation == "raw" and digest != source:
                raise TrainingManifestError(
                    f"RAW digest differs from source at row {line_number}."
                )
            if group in group_splits and group_splits[group] != split:
                raise TrainingManifestError("An equivalent group crosses train/validation/test.")
            if digest in digest_splits and digest_splits[digest] != split:
                raise TrainingManifestError("An equivalent representation crosses splits.")
            group_splits[group] = split
            digest_splits[digest] = split
            seen_sources.add(source)
            samples.append(
                TrainingSample(
                    split=split,
                    source_sha256=source,
                    label=LABELS[label],
                    representation=representation,
                    representation_sha256=digest,
                    group_id=group,
                    relative_path=relative,
                    object_key=key,
                    object_size=size,
                    object_etag=etag,
                    object_version=version,
                )
            )
    if not samples:
        raise TrainingManifestError("Training manifest has no selected samples.")
    return samples
