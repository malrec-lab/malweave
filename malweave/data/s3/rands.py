"""Read-only, resumable S3 inventory of RanDS RAW metadata candidates.

Candidate rows include missing S3 objects so selection failures remain auditable.
This module lists object metadata only. It never downloads or opens a PE file.
"""

from __future__ import annotations

from collections import Counter
import csv
from hashlib import sha256
import io
import json
from pathlib import Path
import re
from typing import Any

from malweave.data.dataset_config import RandsDatasetConfig
from malweave.data.rands import LoadedRandsMetadata, load_rands_metadata
from malweave.data.s3.client import S3Object, make_s3_client
from malweave.data.s3.inventory import (
    S3InventoryError,
    open_scan_state,
    scan_s3_prefix,
    state_setting,
    validate_private_path,
)


class RandsS3Error(ValueError):
    """A restricted inventory cannot be completed safely."""


INVENTORY_FIELDS = (
    "source_sha256",
    "label",
    "family",
    "year",
    "arch",
    "metadata_packed",
    "obfuscation_status",
    "availability",
    "object_key",
    "object_size",
    "object_etag",
    "object_last_modified",
    "snapshot",
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _metadata_digest(config: RandsDatasetConfig, root: Path) -> str:
    digest = sha256()
    for name in (config.benign_csv, config.ransomware_csv):
        path = root / name
        digest.update(name.encode("utf-8"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _rands_object_row(obj: S3Object, prefix: str) -> tuple[str, str, int, str, str] | None:
    suffix = obj.key[len(prefix) :] if obj.key.startswith(prefix) else ""
    parts = suffix.split("/")
    if len(parts) != 2 or not SHA_PATTERN.fullmatch(parts[1]) or parts[0] != parts[1][:2]:
        return None
    return parts[1], obj.key, obj.size, obj.etag, obj.last_modified


def inventory_rands_s3(
    config: RandsDatasetConfig,
    metadata_root: Path,
    *,
    bucket: str,
    prefix: str,
    protocol: str,
    state_path: Path,
    manifest_path: Path,
    summary_path: Path,
    resume: bool = False,
    client: Any = None,
    progress_every: int = 25,
) -> dict[str, Any]:
    """Audit S3 availability and write metadata candidates, including missing objects."""
    for path in (state_path, manifest_path):
        validate_private_path(path)
    validate_private_path(summary_path, summary=True)
    if len({p.expanduser().resolve() for p in (state_path, manifest_path, summary_path)}) != 3:
        raise RandsS3Error("State, manifest, and summary paths must differ.")
    if not bucket or not prefix.endswith("/") or progress_every < 1:
        raise RandsS3Error(
            "A bucket, slash-terminated prefix, and positive progress interval are required."
        )
    if protocol not in config.protocols:
        raise RandsS3Error("Unknown dataset protocol.")
    selected_protocol = config.protocols[protocol]
    metadata: LoadedRandsMetadata = load_rands_metadata(config, metadata_root)
    if metadata.class_overlap:
        raise RandsS3Error(
            "Cross-label source identities exist; resolve them before inventory export."
        )
    settings = {
        "bucket": bucket,
        "prefix": prefix,
        "snapshot": config.snapshot,
        "protocol": protocol,
        "arch": selected_protocol.arch or "",
        "packed": str(selected_protocol.packed),
        "metadata_sha256": _metadata_digest(config, metadata_root),
    }
    schema = (
        "CREATE TABLE IF NOT EXISTS objects ("
        "source_sha256 TEXT PRIMARY KEY, object_key TEXT NOT NULL, size INTEGER NOT NULL, "
        "etag TEXT NOT NULL, last_modified TEXT NOT NULL)"
    )
    try:
        connection = open_scan_state(state_path, settings, schema, resume=resume)
    except S3InventoryError as error:
        raise RandsS3Error(str(error)) from error
    try:
        if client is None:
            client = make_s3_client()
        try:
            scan_s3_prefix(
                connection,
                client,
                bucket,
                prefix,
                lambda obj: _rands_object_row(obj, prefix),
                progress_every=progress_every,
            )
        except S3InventoryError as error:
            raise RandsS3Error(str(error)) from error
        objects = {
            row[0]: row[1:]
            for row in connection.execute(
                "SELECT source_sha256, object_key, size, etag, last_modified FROM objects"
            )
        }
        pages = int(state_setting(connection, "pages"))
        unexpected_keys = int(state_setting(connection, "unexpected_keys"))
        scan_seconds = float(state_setting(connection, "scan_seconds"))
    finally:
        connection.close()

    available_all: Counter[str] = Counter()
    missing_all: Counter[str] = Counter()
    size_mismatch_all: Counter[str] = Counter()
    eligible_status: dict[str, Counter[str]] = {"benign": Counter(), "ransomware": Counter()}
    rows: list[dict[str, str | int]] = []
    for source, record in sorted(metadata.records.items()):
        obj = objects.get(source)
        if obj is None:
            status = "missing"
            missing_all[record.label] += 1
        elif int(obj[1]) != record.size_bytes:
            status = "size_mismatch"
            size_mismatch_all[record.label] += 1
        else:
            status = "available"
            available_all[record.label] += 1
        if selected_protocol.arch is not None and record.arch != selected_protocol.arch:
            continue
        if selected_protocol.packed is not None and record.packed != selected_protocol.packed:
            continue
        eligible_status[record.label][status] += 1
        rows.append(
            {
                "source_sha256": source,
                "label": record.label,
                "family": record.family or "",
                "year": record.year,
                "arch": record.arch,
                "metadata_packed": int(record.packed),
                "obfuscation_status": "not_assessed",
                "availability": status,
                "object_key": obj[0] if obj else f"{prefix}{source[:2]}/{source}",
                "object_size": int(obj[1]) if obj else "",
                "object_etag": obj[2] if obj else "",
                "object_last_modified": obj[3] if obj else "",
                "snapshot": config.snapshot,
            }
        )

    unknown_metadata = len(set(objects) - set(metadata.records))
    audit_passed = (
        len(objects) == config.expected.files
        and dict(available_all) == config.expected.labels
        and not size_mismatch_all
        and unknown_metadata == 0
        and not metadata.class_overlap
    )
    summary: dict[str, Any] = {
        "snapshot": config.snapshot,
        "protocol": protocol,
        "filter": {
            "arch": selected_protocol.arch,
            "packed": selected_protocol.packed,
            "obfuscation": "not_assessed",
        },
        "source_verification": "S3 key and size only; SHA-256 bytes not read",
        "s3_versioning": "not_frozen_by_this_inventory",
        "release_audit": {
            "passed": audit_passed,
            "listed_objects": len(objects),
            "expected_objects": config.expected.files,
            "available_by_label": dict(available_all),
            "missing_by_label": dict(missing_all),
            "size_mismatch_by_label": dict(size_mismatch_all),
            "objects_without_metadata": unknown_metadata,
            "unexpected_key_shapes": unexpected_keys,
        },
        "eligible_by_label_and_status": {k: dict(v) for k, v in eligible_status.items()},
        "metadata_duplicate_rows": metadata.duplicate_rows,
        "listing_pages": pages,
        "scan_seconds": round(scan_seconds, 3) if scan_seconds else None,
    }
    if summary["release_audit"]["unexpected_key_shapes"]:
        summary["release_audit"]["passed"] = False
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    if not summary["release_audit"]["passed"]:
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        raise RandsS3Error(
            "S3 release audit failed; see aggregate summary. No manifest was written."
        )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=INVENTORY_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    payload = output.getvalue().encode("utf-8")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    if manifest_path.exists():
        raise RandsS3Error("Inventory manifest already exists; refusing to overwrite it.")
    manifest_path.write_bytes(payload)
    summary["manifest"] = {
        "rows": len(rows),
        "bytes": len(payload),
        "sha256": sha256(payload).hexdigest(),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
