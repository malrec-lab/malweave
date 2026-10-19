"""Create a filtered view of a completed SOREL static-assessment pilot."""

from __future__ import annotations

from collections import Counter
import csv
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from malweave.data.s3.inventory import S3InventoryError, validate_private_path


def _digest(path: Path) -> str:
    result = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def filter_sorel_assessment(
    *,
    input_path: Path,
    input_summary_path: Path,
    output_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    """Keep complete samples with vendor packed count zero and no DiE detection."""
    input_path = input_path.expanduser().resolve()
    input_summary_path = input_summary_path.expanduser().resolve()
    output_path = output_path.expanduser().resolve()
    summary_path = summary_path.expanduser().resolve()
    validate_private_path(output_path)
    validate_private_path(summary_path, summary=True)
    if not input_path.is_file() or not input_summary_path.is_file():
        raise S3InventoryError("Assessment CSV and summary must both exist.")
    if output_path.exists() or summary_path.exists():
        raise S3InventoryError("Filtered outputs must use new paths.")

    source_summary = json.loads(input_summary_path.read_text(encoding="utf-8"))
    actual_digest = _digest(input_path)
    if source_summary.get("output_sha256") != actual_digest:
        raise S3InventoryError("Assessment CSV digest does not match its summary.")

    with input_path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise S3InventoryError("Assessment CSV has no header.")
        fields = list(reader.fieldnames)
        required = {"packed", "die_obfuscated", "die_status", "assessment_status"}
        if not required.issubset(fields):
            raise S3InventoryError("Assessment CSV is missing required filter fields.")
        rows = list(reader)

    counts: Counter[str] = Counter()
    kept: list[dict[str, str]] = []
    for row in rows:
        counts["input"] += 1
        try:
            packed_count = float(row["packed"])
        except (TypeError, ValueError):
            counts["missing_or_invalid_packed"] += 1
            continue
        if row["assessment_status"] != "complete" or row["die_status"] != "success":
            counts["incomplete_assessment"] += 1
            continue
        if packed_count != 0:
            counts["vendor_packed_nonzero"] += 1
            continue
        if row["die_obfuscated"] == "true":
            counts["die_obfuscated"] += 1
            continue
        if row["die_obfuscated"] != "false":
            counts["die_unknown"] += 1
            continue
        counts["kept"] += 1
        kept.append(row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(kept)
    summary = {
        "dataset": source_summary.get("dataset", "SOREL-20M"),
        "scope": "filtered view of the completed static-assessment pilot; no new S3 reads",
        "input_csv_sha256": actual_digest,
        "input_rows": len(rows),
        "output_rows": len(kept),
        "output_sha256": _digest(output_path),
        "filter": {
            "packed": "vendor meta.db count equals 0",
            "die_obfuscated": "false (all three DiE modes completed)",
            "architecture": "not filtered",
        },
        "counts": dict(counts),
        "limitations": [
            "Vendor packed tag and DiE detections are different signals; both are filtered separately.",
            "DiE not detected does not prove that a sample is unpacked or unobfuscated.",
            "Architecture remains unknown for this SOREL release and was not filtered.",
        ],
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary
