"""Resumable, dataset-neutral S3 prefix inventory state and export."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from hashlib import sha256
import io
import json
from pathlib import Path
import sqlite3
import sys
import threading
import time
from typing import Any

from malweave.config import PROJECT_ROOT
from malweave.data.s3.client import S3ListingError, S3Object, list_s3_page, make_s3_client


class S3InventoryError(ValueError):
    """A restricted S3 inventory cannot be completed safely."""


OBJECT_FIELDS = ("object_key", "object_size", "object_etag", "object_last_modified")

HEX_DIGITS = "0123456789abcdef"
ASCII_FIRST_BYTES = tuple(chr(byte) for byte in range(1, 128))


def shard_prefixes() -> list[str]:
    """Deterministic ASCII key shards for parallel listing.

    Coverage of keys under a prefix whose first byte is ASCII: two-character hex
    pairs cover every hex key of length two or longer, each remaining single ASCII
    byte covers all keys starting with that byte, a per-hex probe covers single
    hex-character keys, and a base probe covers a key equal to the prefix itself.
    Keys whose first byte is not ASCII are not enumerated; callers must declare
    that dataset contract before enabling parallel listing.
    """
    shards = [first + second for first in HEX_DIGITS for second in HEX_DIGITS]
    shards += [char for char in ASCII_FIRST_BYTES if char not in HEX_DIGITS]
    return shards


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
    # check_same_thread=False: sharded scans share one connection across worker
    # threads, serialized by a caller-held lock. WAL plus synchronous=NORMAL keeps
    # commits cheap on network filesystems: a host crash may drop the tail after
    # the last checkpoint, which a resume recovers by re-listing those pages.
    connection = sqlite3.connect(path, check_same_thread=False)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
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
    """Commit each listing page and its continuation token atomically.

    One S3 continuation token chains every page of a prefix, so a single-prefix
    scan cannot be parallelized; callers wanting concurrency use
    ``scan_s3_prefix_sharded`` instead.
    """
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


def scan_s3_prefix_sharded(
    connection: sqlite3.Connection,
    client: Any,
    bucket: str,
    prefix: str,
    row_for_object: Callable[[S3Object], tuple[Any, ...] | None],
    *,
    workers: int,
    progress_every: int = 25,
    commit_pages: int = 30,
) -> None:
    """Scan independent key shards concurrently with durable, resumable progress.

    Each shard keeps its own continuation token in ``shard_state``. Pages are
    flushed every ``commit_pages`` pages per shard; a crash re-fetches at most
    that many pages and ``INSERT OR IGNORE`` keeps the object table exact.
    Keys outside the declared ASCII contract cannot be enumerated here.
    """
    if workers < 2:
        raise S3InventoryError("Sharded listing requires at least two workers.")
    if progress_every < 1 or commit_pages < 1:
        raise S3InventoryError("Progress and commit intervals must be positive.")
    shards = shard_prefixes()
    mode = f"sharded-ascii:{len(shards)}"
    saved_mode = connection.execute(
        "SELECT value FROM settings WHERE name = 'scan_mode'"
    ).fetchone()
    if saved_mode is not None and saved_mode[0] != mode:
        raise S3InventoryError("The scan mode changed; use a new state DB.")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS shard_state ("
        "shard TEXT PRIMARY KEY, token TEXT NOT NULL, pages INTEGER NOT NULL, "
        "unexpected INTEGER NOT NULL, seconds REAL NOT NULL, complete INTEGER NOT NULL)"
    )
    connection.execute("INSERT OR REPLACE INTO settings VALUES ('scan_mode', ?)", (mode,))
    connection.commit()

    def probe(target: str, key_length: int) -> None:
        """Include edge keys a shard split would otherwise miss."""
        try:
            response = client.list_objects_v2(Bucket=bucket, Prefix=target, MaxKeys=1)
        except Exception as error:
            raise S3InventoryError(
                "S3 listing failed; durable shard state is preserved."
            ) from error
        contents = response.get("Contents") or []
        if not contents:
            return
        item = contents[0]
        key = str(item["Key"])
        if len(key) != key_length:
            return
        row = row_for_object(
            S3Object(
                key=key,
                size=int(item["Size"]),
                etag=str(item.get("ETag", "")),
                last_modified=str(item.get("LastModified", "")),
            )
        )
        if row is None:
            return
        placeholders = ", ".join("?" for _ in row)
        with connection:
            connection.execute(f"INSERT OR IGNORE INTO objects VALUES ({placeholders})", row)

    probe(prefix, len(prefix))
    for digit in HEX_DIGITS:
        probe(prefix + digit, len(prefix) + 1)

    saved = {
        row[0]: row
        for row in connection.execute(
            "SELECT shard, token, pages, unexpected, seconds, complete FROM shard_state"
        )
    }
    lock = threading.Lock()
    stop = threading.Event()
    state: dict[str, dict[str, Any]] = {}
    for shard in shards:
        row = saved.get(shard)
        state[shard] = {
            "token": row[1] if row else "",
            "pages": int(row[2]) if row else 0,
            "unexpected": int(row[3]) if row else 0,
            "seconds": float(row[4]) if row else 0.0,
            "complete": bool(row[5]) if row else False,
            "rows": [],
            "pending_pages": 0,
        }
    totals = {
        "pages": sum(item["pages"] for item in state.values()),
        "unexpected": sum(item["unexpected"] for item in state.values()),
        "seconds": sum(item["seconds"] for item in state.values()),
        "objects": int(connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0]),
        "shards_done": sum(1 for item in state.values() if item["complete"]),
        "printed_pages": 0,
    }
    pending = [shard for shard in shards if not state[shard]["complete"]]

    def flush() -> None:
        """Persist buffered rows and shard tokens; caller holds the lock."""
        changed = False
        for shard, item in state.items():
            if not item["rows"] and not item["pending_pages"]:
                continue
            if item["rows"]:
                placeholders = ", ".join("?" for _ in item["rows"][0])
                before = connection.total_changes
                connection.executemany(
                    f"INSERT OR IGNORE INTO objects VALUES ({placeholders})", item["rows"]
                )
                totals["objects"] += connection.total_changes - before
                item["rows"] = []
            connection.execute(
                "INSERT OR REPLACE INTO shard_state VALUES (?, ?, ?, ?, ?, ?)",
                (
                    shard,
                    item["token"],
                    item["pages"],
                    item["unexpected"],
                    item["seconds"],
                    int(item["complete"]),
                ),
            )
            item["pending_pages"] = 0
            changed = True
        if changed:
            connection.commit()

    def scan_shard(shard: str) -> None:
        item = state[shard]
        target = prefix + shard
        while not stop.is_set():
            started = time.monotonic()
            page = list_s3_page(client, bucket, target, continuation_token=item["token"] or None)
            elapsed = time.monotonic() - started
            rows = []
            unexpected = 0
            for obj in page.objects:
                row = row_for_object(obj)
                if row is None:
                    unexpected += 1
                else:
                    rows.append(row)
            next_token = page.next_token or ""
            with lock:
                item["token"] = next_token
                item["pages"] += 1
                item["unexpected"] += unexpected
                item["seconds"] += elapsed
                item["rows"].extend(rows)
                item["pending_pages"] += 1
                totals["pages"] += 1
                totals["unexpected"] += unexpected
                totals["seconds"] += elapsed
                if not next_token:
                    item["complete"] = True
                    totals["shards_done"] += 1
                if item["pending_pages"] >= commit_pages or not next_token:
                    flush()
                if totals["pages"] - totals["printed_pages"] >= progress_every or all(
                    entry["complete"] for entry in state.values()
                ):
                    totals["printed_pages"] = totals["pages"]
                    print(
                        "S3 inventory(sharded): "
                        f"pages={totals['pages']} objects={totals['objects']} "
                        f"shards_done={totals['shards_done']}/{len(shards)} "
                        f"unexpected={totals['unexpected']}",
                        file=sys.stderr,
                    )
            if not next_token:
                return

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_shard, shard): shard for shard in pending}
        for future in as_completed(futures):
            try:
                future.result()
            except S3ListingError as error:
                stop.set()
                for remaining in futures:
                    remaining.cancel()
                with lock:
                    flush()
                raise S3InventoryError(
                    "S3 listing failed; durable shard state is preserved."
                ) from error
    with connection:
        connection.executemany(
            "INSERT OR REPLACE INTO settings VALUES (?, ?)",
            (
                ("next_token", ""),
                ("complete", "1"),
                ("pages", str(totals["pages"])),
                ("unexpected_keys", str(totals["unexpected"])),
                ("scan_seconds", str(totals["seconds"])),
            ),
        )


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
    workers: int = 1,
    shard_by_ascii: bool = False,
) -> dict[str, Any]:
    """List any S3 folder to a private object inventory; labels require a dataset adapter.

    ``workers > 1`` scans independent ASCII key shards concurrently and requires
    ``shard_by_ascii=True``, the caller's declaration that every key under the
    prefix starts with an ASCII byte. Sequential state cannot be resumed in
    sharded mode or vice versa; the recorded scan mode enforces that.
    """
    for path in (state_path, manifest_path):
        validate_private_path(path)
    validate_private_path(summary_path, summary=True)
    if len({p.expanduser().resolve() for p in (state_path, manifest_path, summary_path)}) != 3:
        raise S3InventoryError("State, manifest, and summary paths must differ.")
    if not bucket or not prefix or min_size < 0 or (max_size is not None and max_size < min_size):
        raise S3InventoryError("Invalid bucket, prefix, or object-size filter.")
    if workers < 1:
        raise S3InventoryError("workers must be a positive integer.")
    if workers > 1 and not shard_by_ascii:
        raise S3InventoryError(
            "Parallel listing requires the ASCII key-shard contract (shard_by_ascii)."
        )
    if manifest_path.exists():
        raise S3InventoryError("Object manifest already exists; refusing to overwrite it.")
    settings = {"bucket": bucket, "prefix": prefix}
    schema = (
        "CREATE TABLE IF NOT EXISTS objects (object_key TEXT PRIMARY KEY, size INTEGER NOT NULL, "
        "etag TEXT NOT NULL, last_modified TEXT NOT NULL)"
    )
    connection = open_scan_state(state_path, settings, schema, resume=resume)
    try:
        scan_mode_row = connection.execute(
            "SELECT value FROM settings WHERE name = 'scan_mode'"
        ).fetchone()
        if workers == 1:
            if scan_mode_row is not None:
                raise S3InventoryError(
                    "This state DB was scanned in parallel mode; resume with the same "
                    "--workers setting."
                )
            scan_s3_prefix(
                connection,
                client or make_s3_client(),
                bucket,
                prefix,
                lambda obj: (obj.key, obj.size, obj.etag, obj.last_modified),
                progress_every=progress_every,
            )
            scan_mode = "sequential"
        else:
            scan_s3_prefix_sharded(
                connection,
                client or make_s3_client(max_pool_connections=max(10, workers)),
                bucket,
                prefix,
                lambda obj: (obj.key, obj.size, obj.etag, obj.last_modified),
                workers=workers,
                progress_every=progress_every,
            )
            scan_mode = f"sharded-ascii:{len(shard_prefixes())}"
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
        "scan_mode": scan_mode,
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
