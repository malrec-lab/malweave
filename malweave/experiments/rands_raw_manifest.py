"""Freeze a year-disjoint RAW cohort from a private RanDS S3 inventory."""

from __future__ import annotations

from collections import Counter
import csv
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
import io
import json
from pathlib import Path
from typing import Any

import yaml

from malweave.config import PROJECT_ROOT
from malweave.data.s3.manifest import (
    ManifestOptions,
    ManifestSelectionError,
    select_labeled_rows,
)
from malweave.data.s3.rands import INVENTORY_FIELDS, SHA_PATTERN, validate_private_path


class RandsRawError(ValueError):
    """The RAW experiment cannot be frozen safely."""


SPLIT_FIELDS = (*INVENTORY_FIELDS, "split", "group_id")
SPLITS = ("train", "validation", "test")
LABELS = ("benign", "ransomware")


@dataclass(frozen=True)
class RandsRawManifestPreset:
    """Project-relative paths and cohort sizing declared by the experiment YAML."""

    inventory: Path
    inventory_summary: Path
    manifest: Path
    summary: Path
    total: int | None
    balanced: bool


def _load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    try:
        assert config["experiment"]["dataset"] == "rands"
        assert config["split"]["method"] == "temporal_by_year"
        assert config["split"]["time_field"] == "Year"
        assert config["split"]["group_key"] == "source_sha256"
        assert config["split"]["on_class_shortfall"] == "fail"
        assert config["data"]["selection_method"] == "sha256_rank_per_label_within_split"
        assert config["data"]["labels"] == {"benign": 0, "ransomware": 1}
        assert set(config["split"]["year_ranges"]) == set(SPLITS)
        assert set(config["split"]["fractions"]) == set(SPLITS)
        assert sum(Decimal(str(config["split"]["fractions"][s])) for s in SPLITS) == 1
        ranges = config["split"]["year_ranges"]
        assert int(ranges["train"]["max"]) < int(ranges["validation"]["min"])
        assert int(ranges["validation"]["min"]) <= int(ranges["validation"]["max"])
        assert int(ranges["validation"]["max"]) < int(ranges["test"]["min"])
    except (AssertionError, KeyError, TypeError, ValueError) as error:
        raise RandsRawError("Invalid or unsupported RAW experiment selection contract.") from error
    return config


def load_rands_raw_manifest_preset(path: Path, preset: str) -> RandsRawManifestPreset:
    """Resolve a named preset without reading samples or creating directories."""
    config = _load_config(path)
    try:
        inputs = config["data"]["manifest_inputs"]
        selection = config["data"]["manifest_presets"][preset]
        values = {
            "inventory": inputs["inventory"],
            "inventory_summary": inputs["inventory_summary"],
            "manifest": selection["manifest"],
            "summary": selection["summary"],
        }
        if any(not isinstance(value, str) or not value for value in values.values()):
            raise ValueError("Preset paths must be nonempty strings.")
        total = selection.get("total")
        balanced = selection.get("balanced", False)
        if total is not None and (
            isinstance(total, bool) or not isinstance(total, int) or total < 1
        ):
            raise ValueError("Preset total must be a positive integer.")
        if not isinstance(balanced, bool):
            raise TypeError("Preset balanced must be boolean.")
    except (KeyError, TypeError, ValueError) as error:
        raise RandsRawError(f"Invalid RAW manifest preset: {preset}.") from error

    def resolve(value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate

    return RandsRawManifestPreset(
        inventory=resolve(values["inventory"]),
        inventory_summary=resolve(values["inventory_summary"]),
        manifest=resolve(values["manifest"]),
        summary=resolve(values["summary"]),
        total=total,
        balanced=balanced,
    )


def _split_for_year(year: int, ranges: dict[str, dict[str, int]]) -> str | None:
    for split in SPLITS:
        bounds = ranges[split]
        if year >= int(bounds.get("min", -9999)) and year <= int(bounds.get("max", 9999)):
            return split
    return None


def freeze_rands_raw_manifest(
    inventory_path: Path,
    inventory_summary_path: Path,
    config_path: Path,
    manifest_path: Path,
    summary_path: Path,
    *,
    total: int | None = None,
    balanced: bool = False,
    label_counts: dict[str, int] | None = None,
    where: tuple[tuple[str, str], ...] = (),
    seed: str | None = None,
    min_year: int | None = None,
    max_year: int | None = None,
) -> dict[str, Any]:
    """Freeze all eligible rows by default, or an option-selected RAW cohort."""
    validate_private_path(manifest_path)
    validate_private_path(summary_path, summary=True)
    if manifest_path.exists() or summary_path.exists():
        raise RandsRawError("Output exists; use new paths to avoid changing a frozen split.")
    config = _load_config(config_path)
    payload = inventory_path.read_bytes()
    inventory_digest = sha256(payload).hexdigest()
    try:
        inventory_summary = json.loads(inventory_summary_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RandsRawError("Cannot read the RanDS inventory audit summary.") from error
    if (
        inventory_summary.get("release_audit", {}).get("passed") is not True
        or inventory_summary.get("manifest", {}).get("sha256") != inventory_digest
    ):
        raise RandsRawError("Inventory release audit or manifest digest is invalid.")
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()
    exclusions: Counter[str] = Counter()
    reader = csv.DictReader(io.StringIO(payload.decode("utf-8-sig")))
    if not reader.fieldnames or not set(INVENTORY_FIELDS).issubset(reader.fieldnames):
        raise RandsRawError("Inventory manifest is missing required fields.")
    filters = config["data"]["metadata_filters"]
    desired_obfuscation = filters.get("obfuscated")
    if desired_obfuscation is not None and not isinstance(desired_obfuscation, bool):
        raise RandsRawError("obfuscated filter must be true or false when present.")
    for row in reader:
        source = row["source_sha256"]
        if not SHA_PATTERN.fullmatch(source) or source in seen:
            raise RandsRawError("Inventory contains an invalid or duplicate source identity.")
        seen.add(source)
        label = row["label"]
        if label not in LABELS or row["snapshot"] != config["references"]["rands_snapshot"]:
            raise RandsRawError("Inventory label or snapshot does not match the experiment.")
        if row["arch"] != filters["arch"] or (row["metadata_packed"] == "1") != filters["packed"]:
            exclusions["metadata_filter"] += 1
            continue
        if desired_obfuscation is not None:
            desired = "obfuscated" if desired_obfuscation else "clear"
            if row["obfuscation_status"] != desired:
                exclusions["obfuscation_filter_or_unassessed"] += 1
                continue
        if row["availability"] != "available":
            exclusions[f"s3_{row['availability']}"] += 1
            continue
        try:
            valid_size = int(row["object_size"]) > 0
        except (TypeError, ValueError):
            valid_size = False
        if not row["object_key"] or not row["object_etag"] or not valid_size:
            raise RandsRawError("Available inventory row lacks S3 object metadata.")
        try:
            year = int(row["year"])
        except ValueError:
            exclusions["invalid_year"] += 1
            continue
        if (min_year is not None and year < min_year) or (
            max_year is not None and year > max_year
        ):
            exclusions["outside_requested_year_range"] += 1
            continue
        split = _split_for_year(year, config["split"]["year_ranges"])
        if split is None:
            exclusions["outside_year_ranges"] += 1
            continue
        candidates.append({**row, "split": split, "group_id": source})
    if min_year is not None and max_year is not None and min_year > max_year:
        raise RandsRawError("--min-year cannot exceed --max-year.")
    if len(seen) != inventory_summary["manifest"]["rows"]:
        raise RandsRawError("Inventory row count differs from its audited summary.")
    try:
        options = ManifestOptions(
            total=total,
            balanced=balanced,
            label_counts=label_counts or {},
            where=where,
            seed=seed or str(config["data"]["selection_seed"]),
        )
        selected, selection_summary = select_labeled_rows(
            candidates,
            splits=SPLITS,
            labels=LABELS,
            fractions={
                split: Decimal(str(config["split"]["fractions"][split])) for split in SPLITS
            },
            options=options,
        )
    except ManifestSelectionError as error:
        raise RandsRawError(str(error)) from error
    assert len({row["source_sha256"] for row in selected}) == len(selected)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=SPLIT_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(selected)
    split_payload = output.getvalue().encode("utf-8")
    summary = {
        "inventory_sha256": inventory_digest,
        "inventory_audit_passed": True,
        "experiment_config_sha256": sha256(config_path.read_bytes()).hexdigest(),
        "selection": selection_summary,
        "where_columns": [column for column, _ in where],
        "where_exclusions": selection_summary["where_exclusions"],
        "min_year": min_year,
        "max_year": max_year,
        "year_ranges": config["split"]["year_ranges"],
        "exclusions": dict(exclusions),
        "selected": len(selected),
        "group_overlap": 0,
        "source_hash_verified": False,
        "manifest": {
            "rows": len(selected),
            "bytes": len(split_payload),
            "sha256": sha256(split_payload).hexdigest(),
        },
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(split_payload)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
