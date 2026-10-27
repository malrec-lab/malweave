"""Freeze paired, evaluation-balanced manifests without touching sample bytes."""

from collections import Counter
import csv
from decimal import Decimal
from hashlib import sha256
import io
import json
from pathlib import Path

import yaml

from malweave.data.s3.inventory import validate_private_path
from malweave.data.s3.manifest import ManifestOptions, select_labeled_rows
from malweave.training.manifest import load_training_manifest

SPLITS = ("train", "validation", "test")
LABELS = ("benign", "ransomware")


class CommonCohortError(ValueError):
    """Input metadata cannot support a leakage-safe paired cohort."""


def _read(path: Path, audit: Path, representation: str):
    payload = path.read_bytes()
    digest = sha256(payload).hexdigest()
    report = json.loads(audit.read_text())
    if (
        report.get("inventory_audit_passed") is not True
        or report.get("manifest", {}).get("sha256") != digest
        or report.get("passed") is False
    ):
        raise CommonCohortError("Input manifest lacks a matching passing metadata audit.")
    # Validate the entire input BEFORE intersection/selection, so filtering cannot hide leakage.
    load_training_manifest(path, representation)
    reader = csv.DictReader(io.StringIO(payload.decode("utf-8-sig")))
    fields = list(reader.fieldnames or ())
    if not {"year", "snapshot"}.issubset(fields):
        raise CommonCohortError("Input manifests must contain year and snapshot.")
    rows = list(reader)
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise CommonCohortError("Malformed CSV row.")
    if report["manifest"].get("rows") != len(rows):
        raise CommonCohortError("Input manifest row count differs from its audit.")
    return fields, rows, digest


def _counts(rows):
    counts = Counter((row["split"], row["label"]) for row in rows)
    return {split: {label: counts[split, label] for label in LABELS} for split in SPLITS}


def _csv(fields, rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def freeze_balanced_common_cohort(
    raw_manifest: Path,
    exe_manifest: Path,
    raw_audit: Path,
    exe_audit: Path,
    config_path: Path,
    output_dir: Path,
) -> dict:
    """Preserve training rows; downsample validation/test identically for RAW and EXE.

    Outputs are new immutable manifests plus metadata audits, NOT staging reports.
    The shared stager must verify bytes before training, even when reusing old files.
    """
    validate_private_path(output_dir)
    if output_dir.exists():
        raise CommonCohortError("Output directory already exists; choose a new cohort path.")
    config_payload = config_path.read_bytes()
    config = yaml.safe_load(config_payload)
    if (
        not isinstance(config, dict)
        or config.get("balance_splits") != ["validation", "test"]
        or not isinstance(config.get("selection_seed"), str)
        or not config["selection_seed"]
        or not isinstance(config.get("year_ranges"), dict)
        or set(config["year_ranges"]) != set(SPLITS)
    ):
        raise CommonCohortError("Unsupported paired cohort configuration.")
    raw_fields, raw_rows, raw_digest = _read(raw_manifest, raw_audit, "raw")
    exe_fields, exe_rows, exe_digest = _read(exe_manifest, exe_audit, "exe")
    raw = {row["source_sha256"]: row for row in raw_rows}
    exe = {row["source_sha256"]: row for row in exe_rows}
    if len({row["representation_sha256"] for row in exe_rows}) != len(exe_rows):
        raise CommonCohortError("EXE manifest must already be representation-deduplicated.")
    if not set(exe).issubset(raw):
        raise CommonCohortError("Every EXE source must be available in the RAW manifest.")
    for row in raw_rows + exe_rows:
        try:
            year = int(row["year"])
            bounds = config["year_ranges"][row["split"]]
            valid_year = bounds.get("min", year) <= year <= bounds.get("max", year)
        except (ValueError, TypeError):
            valid_year = False
        if not valid_year or row["snapshot"] != config.get("snapshot"):
            raise CommonCohortError("A row violates the configured year range or snapshot.")
    years = {split: [int(r["year"]) for r in exe_rows if r["split"] == split] for split in SPLITS}
    if any(not values for values in years.values()) or not (
        max(years["train"]) < min(years["validation"])
        and max(years["validation"]) < min(years["test"])
    ):
        raise CommonCohortError("Splits must be nonempty and strictly chronological.")
    for source, row in exe.items():
        if any(raw[source][key] != row[key] for key in ("split", "label", "year", "snapshot")):
            raise CommonCohortError("RAW/EXE source metadata disagree.")
    before = _counts(exe_rows)
    if before["train"]["benign"] != before["train"]["ransomware"]:
        raise CommonCohortError("Training must already be balanced; this command preserves it.")
    if any(before[split][label] == 0 for split in SPLITS for label in LABELS):
        raise CommonCohortError("Every split must contain both labels.")
    # Canonical ordering keeps training shuffle/order identical between the representations.
    selected, selection = select_labeled_rows(
        exe_rows,
        splits=SPLITS,
        labels=LABELS,
        fractions={split: Decimal(1) for split in SPLITS},
        options=ManifestOptions(
            balance_splits=tuple(config["balance_splits"]), seed=config["selection_seed"]
        ),
    )
    kept_sources = {row["source_sha256"] for row in selected}
    after = _counts(selected)
    raw_selected = []
    for row in selected:
        source = row["source_sha256"]
        # Apply the EXE leakage group to BOTH views.
        raw_selected.append({**raw[source], "group_id": row["group_id"]})
    excluded = [
        {
            "source_sha256": source,
            "split": row["split"],
            "label": row["label"],
            "reason": "raw_only_no_exe" if source not in exe else "balance_downsample",
        }
        for source, row in sorted(raw.items())
        if source not in kept_sources
    ]
    summary = {
        "schema": 1,
        "inventory_audit_passed": True,
        "passed": True,
        "sample_bytes_read": False,
        "staging_required": True,
        "input_sha256": {"raw": raw_digest, "exe": exe_digest},
        "input_audit_sha256": {
            "raw": sha256(raw_audit.read_bytes()).hexdigest(),
            "exe": sha256(exe_audit.read_bytes()).hexdigest(),
        },
        "config_sha256": sha256(config_payload).hexdigest(),
        "policy": config,
        "before": before,
        "after": after,
        "removed_by_split_label": {
            split: {label: before[split][label] - after[split][label] for label in LABELS}
            for split in SPLITS
        },
        "raw_only_excluded": len(raw) - len(exe),
        "training_sources_unchanged": True,
        "source_and_representation_cross_split_groups": 0,
        "selection": selection,
        "verification": "metadata only; no new byte verification or staging certificate",
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    for name, fields, rows in (("raw", raw_fields, raw_selected), ("exe", exe_fields, selected)):
        payload = _csv(fields, rows)
        (output_dir / f"{name}-split.csv").write_bytes(payload)
        report = {
            **summary,
            "representation": name,
            "manifest": {"rows": len(rows), "sha256": sha256(payload).hexdigest()},
            "representation_bytes": sum(int(r["object_size"]) for r in rows),
        }
        (output_dir / f"{name}-summary.json").write_text(json.dumps(report, indent=2) + "\n")
    payload = _csv(["source_sha256", "split", "label", "reason"], excluded)
    (output_dir / "excluded.csv").write_bytes(payload)
    summary["exclusions_sha256"] = sha256(payload).hexdigest()
    (output_dir / "cohort-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
