"""Freeze a listing-only SOREL source snapshot without reading sample bytes."""

from __future__ import annotations

import csv
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

from malweave.data.s3.inventory import OBJECT_FIELDS, S3InventoryError, validate_private_path
from malweave.data.s3.sorel import (
    SOREL_BINARIES_PREFIX,
    SOREL_BUCKET,
    SOREL_SHA256_PATTERN,
    write_json_atomic,
)


def freeze_sorel_sources(inventory: Path, audit: Path, output: Path, summary: Path) -> dict:
    """Validate and copy the complete ordered inventory into a private snapshot.

    ETags are object metadata, not content digests. The snapshot freezes what was
    listed, not remote object versions; later readers must detect source changes.
    """
    validate_private_path(output)
    validate_private_path(summary, summary=True)
    paths = [path.resolve() for path in (inventory, audit, output, summary)]
    if len(set(paths)) != 4 or output.exists() or summary.exists():
        raise S3InventoryError("Use distinct paths and new snapshot outputs; never overwrite.")
    report = json.loads(audit.read_text(encoding="utf-8"))
    if (
        report.get("inventory_complete") is not True
        or report.get("bucket") != SOREL_BUCKET
        or report.get("prefix") != SOREL_BINARIES_PREFIX
        or report.get("excluded_objects") != 0
    ):
        raise S3InventoryError("Expected a complete, unfiltered official SOREL inventory.")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=output.parent, prefix=".sources-")
    digest = sha256()
    size = 0
    try:
        with inventory.open("rb") as source, os.fdopen(descriptor, "wb") as target:
            while block := source.read(1024 * 1024):
                digest.update(block)
                size += len(block)
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        expected = report["manifest"]
        if digest.hexdigest() != expected["sha256"] or size != expected["bytes"]:
            raise S3InventoryError("Inventory bytes do not match the completed audit.")
        count = total = 0
        previous = ""
        with Path(temporary).open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != OBJECT_FIELDS:
                raise S3InventoryError("Unexpected inventory schema.")
            for row in reader:
                key = row["object_key"]
                if (
                    None in row
                    or not key.startswith(SOREL_BINARIES_PREFIX)
                    or not SOREL_SHA256_PATTERN.fullmatch(key[len(SOREL_BINARIES_PREFIX) :])
                    or key <= previous
                ):
                    raise S3InventoryError("Invalid, duplicate, or unordered source key.")
                object_size = int(row["object_size"])
                if object_size < 0 or any(value is None for value in row.values()):
                    raise S3InventoryError("Invalid source metadata.")
                previous = key
                count += 1
                total += object_size
        if count != expected["rows"] or count != report["listed_objects"]:
            raise S3InventoryError("Source count does not match the audit.")
        if total != report["object_sizes"]["total_bytes"]:
            raise S3InventoryError("Source sizes do not match the audit.")
        result = {
            "schema_version": 1,
            "dataset": "SOREL-20M",
            "release": "09-DEC-2020",
            "bucket": SOREL_BUCKET,
            "prefix": SOREL_BINARIES_PREFIX,
            "snapshot_id": digest.hexdigest(),
            "manifest": {"rows": count, "bytes": size, "sha256": digest.hexdigest()},
            "total_object_bytes": total,
            "sample_bytes_read": False,
            "labels_verified": False,
            "remote_versions_pinned": False,
            "source_identity": "Original pre-disarming SHA-256 encoded in object key",
            "verification": "Listing metadata only; ETag is not a sample SHA-256",
        }
        os.replace(temporary, output)
        write_json_atomic(summary, result)
        return result
    finally:
        Path(temporary).unlink(missing_ok=True)
