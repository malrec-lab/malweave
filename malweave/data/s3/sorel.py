"""Public SOREL-20M S3 inventory helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Any

from malweave.data.s3.inventory import inventory_s3_prefix

SOREL_BUCKET = "sorel-20m"
SOREL_RELEASE_PREFIX = "09-DEC-2020/"
SOREL_BINARIES_PREFIX = f"{SOREL_RELEASE_PREFIX}binaries/"
SOREL_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def make_unsigned_s3_client(
    *, region_name: str | None = None, max_pool_connections: int = 10
) -> Any:
    """Create an S3 client that never signs requests or uses local credentials."""
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config

    return boto3.client(
        "s3",
        region_name=region_name,
        config=Config(
            signature_version=UNSIGNED,
            retries={"mode": "standard", "max_attempts": 5},
            max_pool_connections=max_pool_connections,
        ),
    )


def summarize_sorel_binary_inventory(
    state_path: Path,
    *,
    bucket: str,
    prefix: str,
    inventory_summary: dict[str, Any],
) -> dict[str, Any]:
    """Add SOREL key-shape and size aggregates to a completed generic inventory."""
    if inventory_summary.get("source_verification") != (
        "S3 listing only; object bytes and labels not verified"
    ):
        raise ValueError("Expected a completed S3 listing-only inventory summary.")
    if not prefix.endswith("/"):
        raise ValueError("SOREL sample prefix must end with '/'.")

    connection = sqlite3.connect(state_path)
    try:
        row = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(size), 0), MIN(size), MAX(size), "
            "COALESCE(AVG(size), 0), SUM(CASE WHEN size = 0 THEN 1 ELSE 0 END) "
            "FROM objects"
        ).fetchone()
        listed, total_bytes, minimum, maximum, mean, zero_bytes = row
        valid_sha256 = connection.execute(
            "SELECT COUNT(*) FROM objects "
            "WHERE substr(object_key, ?) NOT GLOB '*[^0-9a-f]*' "
            "AND length(substr(object_key, ?)) = 64",
            (len(prefix) + 1, len(prefix) + 1),
        ).fetchone()[0]
    finally:
        connection.close()

    result = dict(inventory_summary)
    result.update(
        {
            "dataset": "SOREL-20M",
            "bucket": bucket,
            "prefix": prefix,
            "inventory_complete": True,
            "labels_verified": False,
            "sample_bytes_read": False,
            "key_shape": {
                "expected": "64 lowercase hexadecimal characters after the prefix",
                "valid_sha256_keys": valid_sha256,
                "other_keys": listed - valid_sha256,
            },
            "object_sizes": {
                "total_bytes": total_bytes,
                "minimum_bytes": minimum,
                "maximum_bytes": maximum,
                "mean_bytes": round(mean, 2),
                "zero_byte_objects": zero_bytes,
            },
            "audit_scope": (
                "Complete S3 object listing and key/size metadata only. This does not verify "
                "PE content, labels, or PE format."
            ),
        }
    )
    return result


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Atomically replace a private aggregate report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".sorel-audit-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def audit_sorel_binary_prefix(
    *,
    bucket: str,
    prefix: str,
    state_path: Path,
    manifest_path: Path,
    summary_path: Path,
    client: Any,
    resume: bool = False,
    progress_every: int = 100,
    workers: int = 1,
) -> dict[str, Any]:
    """Create a resumable private inventory of SOREL binary objects."""
    if workers < 1:
        raise ValueError("workers must be a positive integer.")
    listing = inventory_s3_prefix(
        bucket=bucket,
        prefix=prefix,
        state_path=state_path,
        manifest_path=manifest_path,
        summary_path=summary_path,
        client=client,
        resume=resume,
        progress_every=progress_every,
        workers=workers,
        # SOREL object keys under the binaries prefix are lowercase SHA-256 hex
        # (plus a possible directory marker), so the ASCII key-shard contract holds.
        shard_by_ascii=True,
    )
    result = summarize_sorel_binary_inventory(
        state_path,
        bucket=bucket,
        prefix=prefix,
        inventory_summary=listing,
    )
    write_json_atomic(summary_path, result)
    return result
