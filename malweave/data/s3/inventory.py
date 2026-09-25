"""Resumable, dataset-neutral S3 prefix inventory state and export."""

from __future__ import annotations

from collections.abc import Callable
import csv
from hashlib import sha256
import io
import json
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any

from malweave.config import PROJECT_ROOT
from malweave.data.s3.client import S3ListingError, S3Object, list_s3_page, make_s3_client


class S3InventoryError(ValueError):
    """A restricted S3 inventory cannot be completed safely."""


OBJECT_FIELDS = ("object_key", "object_size", "object_etag", "object_last_modified")


def validate_private_path(path: Path, *, summary: bool = False) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    allowed = (
        relative.parts[:1] == ("reports",)
        if summary
        else relative.parts[:2] in {("data", "interim"), ("data", "processed")}
        or relative.parts[:1] == ("work",)
    )
    if not allowed:
        kind = "summary" if summary else "restricted manifest/state"
        raise S3InventoryError(f"{kind} must be placed in an ignored repository directory.")


def open_scan_state(
    path: Path, settings: dict[str, str], objects_schema: str, *, resume: bool
) -> sqlite3.Connection:
    """Create or verify a durable scan; caller owns and closes the connection."""
    validate_private_path(path)
    if resume != path.exists():
        raise S3InventoryError(
            "Use --resume only for an existing state DB; never overwrite a scan."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(objects_schema)
    if resume:
        saved = dict(connection.execute("SELECT name, value FROM settings"))
        if any(saved.get(key) != value for key, value in settings.items()):
            connection.close()
            raise S3InventoryError("The scan settings changed; use a new state DB.")
    else:
        connection.executemany("INSERT INTO settings VALUES (?, ?)", settings.items())
        connection.executemany(
            "INSERT INTO settings VALUES (?, ?)",
            (
                ("next_token", ""),
                ("complete", "0"),
                ("pages", "0"),
                ("unexpected_keys", "0"),
                ("scan_seconds", "0"),
            ),
        )
        connection.commit()
    return connection


def state_setting(connection: sqlite3.Connection, name: str) -> str:
    row = connection.execute("SELECT value FROM settings WHERE name = ?", (name,)).fetchone()
    return str(row[0]) if row is not None else "0"


def scan_s3_prefix(
    connection: sqlite3.Connection,
    client: Any,
    bucket: str,
    prefix: str,
    row_for_object: Callable[[S3Object], tuple[Any, ...] | None],
    *,
    progress_every: int = 25,
) -> None:
    """Commit each listing page and its continuation token atomically."""
    if progress_every < 1:
        raise S3InventoryError("Progress interval must be positive.")
    if state_setting(connection, "complete") == "1":
        return
    token = state_setting(connection, "next_token")
    pages = int(state_setting(connection, "pages"))
    unexpected = int(state_setting(connection, "unexpected_keys"))
    seconds = float(state_setting(connection, "scan_seconds"))
    while True:
        started = time.monotonic()
        try:
            page = list_s3_page(client, bucket, prefix, continuation_token=token or None)
        except S3ListingError as error:
            raise S3InventoryError(
                "S3 listing failed; durable scan state is preserved."
            ) from error
        rows = []
        for item in page.objects:
            row = row_for_object(item)
            if row is None:
                unexpected += 1
            else:
                rows.append(row)
        next_token = page.next_token or ""
        pages += 1
        seconds += time.monotonic() - started
        with connection:
            if rows:
                placeholders = ", ".join("?" for _ in rows[0])
                connection.executemany(f"INSERT INTO objects VALUES ({placeholders})", rows)
            connection.executemany(
                "INSERT OR REPLACE INTO settings VALUES (?, ?)",
                (
                    ("next_token", next_token),
                    ("complete", str(int(not bool(next_token)))),
                    ("pages", str(pages)),
                    ("unexpected_keys", str(unexpected)),
                    ("scan_seconds", str(seconds)),
                ),
            )
        if pages % progress_every == 0 or not next_token:
            count = connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
            print(
                f"S3 inventory: pages={pages} objects={count} unexpected={unexpected}",
                file=sys.stderr,
            )
        if not next_token:
            return
        token = next_token


def inventory_s3_prefix(
    *,
    bucket: str,
    prefix: str,
    state_path: Path,
    manifest_path: Path,
    summary_path: Path,
    resume: bool = False,
    suffix: str | None = None,
    min_size: int = 0,
    max_size: int | None = None,
    client: Any = None,
    progress_every: int = 25,
) -> dict[str, Any]:
    """List any S3 folder to a private object inventory; labels require a dataset adapter."""
    for path in (state_path, manifest_path):
        validate_private_path(path)
    validate_private_path(summary_path, summary=True)
    if len({p.expanduser().resolve() for p in (state_path, manifest_path, summary_path)}) != 3:
        raise S3InventoryError("State, manifest, and summary paths must differ.")
    if not bucket or not prefix or min_size < 0 or (max_size is not None and max_size < min_size):
        raise S3InventoryError("Invalid bucket, prefix, or object-size filter.")
    if manifest_path.exists():
        raise S3InventoryError("Object manifest already exists; refusing to overwrite it.")
    settings = {"bucket": bucket, "prefix": prefix}
    schema = (
        "CREATE TABLE IF NOT EXISTS objects (object_key TEXT PRIMARY KEY, size INTEGER NOT NULL, "
        "etag TEXT NOT NULL, last_modified TEXT NOT NULL)"
    )
    connection = open_scan_state(state_path, settings, schema, resume=resume)
    try:
        scan_s3_prefix(
            connection,
            client or make_s3_client(),
            bucket,
            prefix,
            lambda obj: (obj.key, obj.size, obj.etag, obj.last_modified),
            progress_every=progress_every,
        )
        listed = int(connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0])
        pages = int(state_setting(connection, "pages"))
        seconds = float(state_setting(connection, "scan_seconds"))
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=OBJECT_FIELDS, lineterminator="\n")
        writer.writeheader()
        selected = 0
        excluded = 0
        for key, size, etag, modified in connection.execute(
            "SELECT object_key, size, etag, last_modified FROM objects ORDER BY object_key"
        ):
            if (
                (suffix is not None and not key.endswith(suffix))
                or size < min_size
                or (max_size is not None and size > max_size)
            ):
                excluded += 1
                continue
            writer.writerow(dict(zip(OBJECT_FIELDS, (key, size, etag, modified), strict=True)))
            selected += 1
    finally:
        connection.close()
    payload = output.getvalue().encode("utf-8")
    summary = {
        "listed_objects": listed,
        "selected_objects": selected,
        "excluded_objects": excluded,
        "listing_pages": pages,
        "scan_seconds": round(seconds, 3),
        "filters": {"suffix": suffix, "min_size": min_size, "max_size": max_size},
        "source_verification": "S3 listing only; object bytes and labels not verified",
        "manifest": {
            "rows": selected,
            "bytes": len(payload),
            "sha256": sha256(payload).hexdigest(),
        },
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(payload)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
