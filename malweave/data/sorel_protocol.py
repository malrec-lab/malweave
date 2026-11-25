"""Version-three SOREL protocol, consecutive selection, history and fixed exports.

The legacy runner remains exportable. Its round-robin jobs cannot be resumed as v3.
All large selections and current/history records live in SQLite, never Python lists.
"""

from __future__ import annotations

from contextlib import closing
import csv
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time
from typing import Any

import yaml

from malweave.data.sorel_io import SorelError, digest, json_write

PROTOCOL = "sorel-exe-v3.1"
NAMESPACE = "v3.1"
METADATA_FIELDS = (
    "sha256",
    "is_malware",
    "rl_fs_t",
    "rl_ls_const_positives",
    "adware",
    "flooder",
    "ransomware",
    "dropper",
    "spyware",
    "packed",
    "crypto_miner",
    "file_infector",
    "installer",
    "worm",
    "downloader",
)
CSV_FIELDS = (
    "original_sha256",
    "dataset",
    "release",
    "partition_index",
    "partition_count",
    "protocol_sha256",
    "attempt",
    "run_id",
    "status",
    "error_stage",
    "error",
    "storage_status",
    "is_malware",
    "rl_fs_t",
    "rl_ls_const_positives",
    "adware",
    "flooder",
    "ransomware",
    "dropper",
    "spyware",
    "sorel_packed",
    "crypto_miner",
    "file_infector",
    "installer",
    "worm",
    "downloader",
    "compressed_sha256",
    "released_pe_sha256",
    "exe_sha256",
    "architecture",
    "architecture_status",
    "architecture_method",
    "original_machine",
    "original_subsystem",
    "pe_format",
    "file_status",
    "file_description",
    "file_seconds",
    "packing",
    "die_types",
    "die_names",
    "die_recursive_status",
    "die_recursive_attempts",
    "die_recursive_seconds",
    "die_deep_status",
    "die_deep_attempts",
    "die_deep_seconds",
    "die_heuristic_status",
    "die_heuristic_attempts",
    "die_heuristic_seconds",
    "lief_status",
    "lief_attempts",
    "section_count",
    "executable_section_count",
    "warnings",
    "compressed_bytes",
    "pe_bytes",
    "exe_bytes",
    "network_received_bytes",
    "download_attempts",
    "download_http_status",
    "download_seconds",
    "decompress_seconds",
    "identity_seconds",
    "screen_seconds",
    "extract_seconds",
    "runtime_seconds",
    "started_at_utc",
    "finished_at_utc",
    "exe_s3_uri",
    "details_s3_uri",
    "details_sha256",
    "details_member_root",
    "published_at_utc",
    "resource_reason",
    "local_evidence_status",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class Rules:
    protocol: str = PROTOCOL
    release: str = "09-DEC-2020"
    partition_count: int = 5
    partition_index: int = 1
    architecture_policy: str = "x86_verified"
    file_timeout_seconds: int = 10
    die_timeout_seconds: int = 10
    die_attempts: int = 3
    lief_timeout_seconds: int = 10
    lief_attempts: int = 3
    request_timeout_seconds: int = 120
    connect_timeout_seconds: int = 20
    request_attempts: int = 3


@dataclass(frozen=True)
class Runtime:
    # Zero means resolve from actual CPU/cgroup/RAM/disk limits. Nonzero defaults below
    # seed the benchmark, not a claim that they are optimal on a rented host.
    workers: int = 0
    fetch_batch: int = 0
    upload_workers: int = 2
    upload_sources: int = 64
    upload_bytes: int = 32 * 1024**2
    upload_interval_seconds: int = 10
    upload_queue_sources: int = 0
    upload_timeout_seconds: int = 900
    checkpoint_seconds: int = 1800
    progress_seconds: int = 5
    memory_budget_bytes: int = 0
    memory_per_task_bytes: int = 0
    disk_budget_bytes: int = 0
    min_free_bytes: int = 5 * 1024**3


def load(path: Path, *, part: int | None = None) -> tuple[Rules, Runtime]:
    try:
        document = yaml.safe_load(path.read_text())
        values = dict(document)
        runtime = Runtime(**values.pop("runtime", {}))
        if part is not None:
            values["partition_index"] = part
        rules = Rules(**values)
        if rules.protocol != PROTOCOL or rules.release != "09-DEC-2020":
            raise ValueError("Unsupported protocol/release")
        if not 1 <= rules.partition_index <= rules.partition_count:
            raise ValueError("Invalid partition index/count")
        if rules.architecture_policy not in ("x86_verified", "annotate"):
            raise ValueError("Unknown architecture policy")
        for config in (rules, runtime):
            for field in fields(config):
                value = getattr(config, field.name)
                default = getattr(type(config)(), field.name)
                if type(value) is not type(default):
                    raise ValueError(f"Invalid type: {field.name}")
                if isinstance(value, int) and (value < 0 or (default > 0 and value == 0)):
                    raise ValueError(f"Invalid value: {field.name}")
        return rules, runtime
    except (TypeError, ValueError, OSError, yaml.YAMLError) as error:
        raise SorelError(f"Invalid SOREL v3 configuration: {error}") from error


def partition_bounds(total: int, count: int, index: int) -> tuple[int, int]:
    """Half-open consecutive bounds; earlier parts receive any remainder."""
    if total < 0 or count < 1 or not 1 <= index <= count:
        raise ValueError("Invalid partition bounds")
    size, remainder = divmod(total, count)
    start = (index - 1) * size + min(index - 1, remainder)
    return start, start + size + (index <= remainder)


def available_memory() -> int:
    physical = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    values = {}
    try:
        values = dict(
            line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines()
        )
        physical = min(physical, int(values["MemAvailable"].split()[0]) * 1024)
    except (OSError, KeyError, ValueError):
        pass
    for limit, used in (("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current"),):
        try:
            maximum = Path(limit).read_text().strip()
            if maximum != "max":
                physical = min(physical, max(0, int(maximum) - int(Path(used).read_text())))
        except (OSError, ValueError):
            pass
    return physical


def resolve_runtime(runtime: Runtime, job: Path) -> Runtime:
    values = asdict(runtime)
    cpu = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 1
    try:
        quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
        if quota != "max":
            cpu = min(cpu, max(1, math.ceil(int(quota) / int(period))))
    except (OSError, ValueError):
        pass
    memory = runtime.memory_budget_bytes or int(available_memory() * 0.7)
    if memory < 256 * 1024**2:
        raise SorelError("Insufficient memory for the conversion worker")
    workers = runtime.workers or min(cpu, max(1, memory // (1024**3)))
    values.update(
        workers=workers,
        fetch_batch=runtime.fetch_batch or workers * 4,
        memory_budget_bytes=memory,
        memory_per_task_bytes=runtime.memory_per_task_bytes or memory // workers,
        upload_queue_sources=runtime.upload_queue_sources
        or max(2 * runtime.upload_sources + workers, workers * 4),
    )
    free = shutil.disk_usage(job).free
    disk = runtime.disk_budget_bytes or max(0, free - runtime.min_free_bytes)
    if disk <= 0:
        raise SorelError("Insufficient free disk; work has not been scheduled")
    values["disk_budget_bytes"] = min(disk, max(0, free - runtime.min_free_bytes))
    return Runtime(**values)


def connect(job: Path) -> sqlite3.Connection:
    db = sqlite3.connect(job / "state.sqlite", timeout=60)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS sources (
            id TEXT PRIMARY KEY, ordinal INTEGER NOT NULL UNIQUE, metadata TEXT NOT NULL,
            done INTEGER NOT NULL DEFAULT 0, retry_requested INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS pending ON sources(done,ordinal);
        CREATE TABLE IF NOT EXISTS current (
            id TEXT PRIMARY KEY, attempt INTEGER NOT NULL, value TEXT NOT NULL,
            published INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS history (
            id TEXT, attempt INTEGER, value TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(id,attempt));
        CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS counters (
            scope TEXT, name TEXT, value REAL NOT NULL, PRIMARY KEY(scope,name));
        CREATE TABLE IF NOT EXISTS outputs (digest TEXT PRIMARY KEY, bytes INTEGER,
            published INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS unpublished_history ON history(published,id,attempt);
        CREATE INDEX IF NOT EXISTS unpublished_outputs ON outputs(published);
    """)
    return db


def _add(db: sqlite3.Connection, scope: str, name: str, value: float) -> None:
    db.execute(
        "INSERT INTO counters VALUES(?,?,?) ON CONFLICT(scope,name) "
        "DO UPDATE SET value=value+excluded.value",
        (scope, name, value),
    )


def prepare(metadata: Path, job: Path, rules: Rules) -> dict[str, Any]:
    if rules.partition_count != 5:
        raise SorelError("The v3 protocol requires five consecutive processing parts")
    if (job / "selection.json").exists() or (job / "state.sqlite").exists():
        raise SorelError("Job already exists; legacy jobs require a new v3 directory")
    job.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    last = started
    with closing(sqlite3.connect(metadata.resolve().as_uri() + "?mode=ro", uri=True)) as source:

        def heartbeat() -> int:
            nonlocal last
            if time.monotonic() - last >= 5:
                print(
                    canonical(
                        {"event": "preparing", "seconds": round(time.monotonic() - started, 2)}
                    ),
                    file=__import__("sys").stderr,
                    flush=True,
                )
                last = time.monotonic()
            return 0

        source.set_progress_handler(heartbeat, 100_000)
        if source.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise SorelError("Metadata integrity check failed")
        columns = {row[1] for row in source.execute("PRAGMA table_info(meta)")}
        if not set(METADATA_FIELDS).issubset(columns):
            raise SorelError("Metadata must include all 15 official SOREL fields")
        labels = dict(source.execute("SELECT is_malware,COUNT(*) FROM meta GROUP BY is_malware"))
        if set(labels) - {0, 1}:
            raise SorelError("Unexpected malware labels")
        total = labels.get(1, 0)
        start, end = partition_bounds(total, rules.partition_count, rules.partition_index)
        selection_digest = sha256()
        query = (
            "SELECT "
            + ",".join(METADATA_FIELDS)
            + (" FROM meta WHERE is_malware=1 ORDER BY sha256 LIMIT ? OFFSET ?")
        )
        with closing(connect(job)) as db, db:
            for ordinal, values in enumerate(source.execute(query, (end - start, start)), start):
                row = dict(zip(METADATA_FIELDS, values, strict=True))
                identifier = row["sha256"]
                if not isinstance(identifier, str) or not re.fullmatch(
                    r"[0-9a-f]{64}", identifier
                ):
                    raise SorelError("Invalid source identifier in metadata")
                value = canonical(row)
                db.execute(
                    "INSERT INTO sources(id,ordinal,metadata) VALUES(?,?,?)",
                    (identifier, ordinal, value),
                )
                selection_digest.update(value.encode() + b"\n")
                if ordinal % 10_000 == 0:
                    heartbeat()
            selected = db.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
            if selected != end - start:
                raise SorelError("Source partition count mismatch")
    result = {
        "schema": 3,
        "protocol": PROTOCOL,
        "rules": asdict(rules),
        "selected": selected,
        "total_malware": total,
        "rank_start_inclusive": start + 1,
        "rank_end_inclusive": end,
        "selection_method": "sha256_sorted_consecutive",
        "sources_sha256": selection_digest.hexdigest(),
        "metadata_sha256": digest(metadata),
        "metadata_columns": list(METADATA_FIELDS),
        "prepared_at_utc": now(),
        "prepare_seconds": round(time.monotonic() - started, 3),
    }
    json_write(job / "selection.json", result)
    return result


def selection(job: Path, rules: Rules | None = None) -> dict[str, Any]:
    value = json.loads((job / "selection.json").read_text())
    if value.get("schema") != 3 or value.get("protocol") != PROTOCOL:
        raise SorelError("Legacy/round-robin job cannot resume as v3; use a new job directory")
    if rules is not None and value["rules"] != asdict(rules):
        raise SorelError("Scientific rules changed; an explicit new protocol/job is required")
    return value


def pending(db: sqlite3.Connection, count: int, after: int = -1) -> list[dict[str, Any]]:
    return [
        {
            "ordinal": ordinal,
            "source_metadata": json.loads(metadata),
            "original_sha256": identifier,
            "attempt": attempt,
        }
        for identifier, ordinal, metadata, attempt in db.execute(
            "SELECT s.id,s.ordinal,s.metadata,COALESCE((SELECT MAX(h.attempt) FROM history h "
            "WHERE h.id=s.id),0)+1 FROM sources s WHERE s.done=0 AND s.ordinal>? "
            "ORDER BY s.ordinal LIMIT ?",
            (after, count),
        )
    ]


def record(db: sqlite3.Connection, row: dict[str, Any]) -> None:
    identifier, attempt = row["original_sha256"], row["attempt"]
    with db:
        old = db.execute(
            "SELECT attempt,value,published FROM current WHERE id=?", (identifier,)
        ).fetchone()
        if not db.execute("SELECT 1 FROM sources WHERE id=?", (identifier,)).fetchone():
            raise SorelError("Outcome outside frozen selection")
        existing = db.execute(
            "SELECT value FROM history WHERE id=? AND attempt=?", (identifier, attempt)
        ).fetchone()
        if existing:
            # Replay is idempotent; a processing attempt is never silently overwritten.
            prior = json.loads(existing[0])
            if any(
                prior.get(key) != row.get(key)
                for key in ("status", "exe_sha256", "released_pe_sha256", "protocol_sha256")
            ):
                raise SorelError("Conflicting outcome for the same source attempt")
            return
        db.execute("INSERT INTO history VALUES(?,?,?,0)", (identifier, attempt, canonical(row)))
        _add(db, "total", "processing_attempts", 1)
        for key in (
            "runtime_seconds",
            "download_seconds",
            "decompress_seconds",
            "identity_seconds",
            "screen_seconds",
            "file_seconds",
            "extract_seconds",
            "network_received_bytes",
            "compressed_bytes",
            "pe_bytes",
            "exe_bytes",
            "download_attempts",
            "lief_attempts",
            "die_recursive_attempts",
            "die_deep_attempts",
            "die_heuristic_attempts",
        ):
            value = row.get(key, 0)
            _add(db, "cost", key, value if isinstance(value, (int, float)) else 0)
        for stage in ("file", "die_recursive", "die_deep", "die_heuristic", "lief"):
            _add(db, "tool_coverage_" + stage, row.get(stage + "_status") or "not_run", 1)
        for label in METADATA_FIELDS[4:]:
            key = "sorel_packed" if label == "packed" else label
            if isinstance(row.get(key), (int, float)) and row[key] > 0:
                _add(db, "class_coverage_" + label, row["status"], 1)
        if old and old[0] > attempt:
            return
        if old:
            previous = json.loads(old[1])
            for scope, key in (
                ("status", "status"),
                ("architecture", "architecture"),
                ("packing", "packing"),
            ):
                _add(db, scope, previous.get(key, "unknown"), -1)
            if old[2]:
                _add(db, "total", "published_sources", -1)
        else:
            _add(db, "total", "processed_sources", 1)
        for scope, key in (
            ("status", "status"),
            ("architecture", "architecture"),
            ("packing", "packing"),
        ):
            _add(db, scope, row.get(key, "unknown"), 1)
        db.execute(
            "INSERT OR REPLACE INTO current VALUES(?,?,?,0)", (identifier, attempt, canonical(row))
        )
        db.execute("UPDATE sources SET done=1,retry_requested=0 WHERE id=?", (identifier,))
        if row["status"] == "success":
            db.execute(
                "INSERT OR IGNORE INTO outputs VALUES(?,?,0)",
                (row["exe_sha256"], row["exe_bytes"]),
            )


def publish(db: sqlite3.Connection, rows: list[dict[str, Any]], group: dict[str, Any]) -> None:
    # Import each recovered outcome durably, then commit the whole publication index atomically.
    for row in rows:
        record(db, row)
    with db:
        for row in rows:
            identifier, attempt = row["original_sha256"], row["attempt"]
            row = {
                **row,
                "storage_status": "published",
                "details_s3_uri": group["archive_uri"],
                "details_sha256": group["archive_sha256"],
                "published_at_utc": group["published_at_utc"],
            }
            row.pop("local_work_dir", None)
            db.execute(
                "UPDATE history SET value=?,published=1 WHERE id=? AND attempt=?",
                (canonical(row), identifier, attempt),
            )
            current = db.execute(
                "SELECT attempt,published FROM current WHERE id=?", (identifier,)
            ).fetchone()
            if current and current[0] == attempt:
                db.execute(
                    "UPDATE current SET value=?,published=1 WHERE id=?",
                    (canonical(row), identifier),
                )
                if not current[1]:
                    _add(db, "total", "published_sources", 1)
            if row["status"] == "success":
                db.execute("UPDATE outputs SET published=1 WHERE digest=?", (row["exe_sha256"],))
        db.execute("INSERT OR REPLACE INTO groups VALUES(?,?)", (group["id"], canonical(group)))


def summary(db: sqlite3.Connection, selected: int) -> dict[str, Any]:
    values: dict[str, dict[str, float]] = {}
    for scope, name, value in db.execute("SELECT scope,name,value FROM counters WHERE value!=0"):
        values.setdefault(scope, {})[name] = value
    totals = values.get("total", {})
    statuses = {k: int(v) for k, v in values.get("status", {}).items()}
    processed = int(totals.get("processed_sources", 0))
    published = int(totals.get("published_sources", 0))
    distinct, unique_bytes = db.execute(
        "SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM outputs WHERE published=1"
    ).fetchone()
    pending_count = db.execute("SELECT COUNT(*) FROM sources WHERE done=0").fetchone()[0]
    upload_pending = db.execute(
        "SELECT COUNT(*) FROM history WHERE published=0 AND "
        "json_extract(value,'$.storage_status')!='missing_local_evidence'"
    ).fetchone()[0]
    return {
        "selected": selected,
        "processed_sources": processed,
        "published_sources": published,
        "pending_sources": pending_count,
        "upload_pending_sources": upload_pending,
        "processing_attempts": int(totals.get("processing_attempts", 0)),
        "successful_sources": statuses.get("success", 0),
        "unique_exe_s3": distinct,
        "unique_exe_bytes_s3": unique_bytes,
        "status_counts": statuses,
        "architecture_counts": {k: int(v) for k, v in values.get("architecture", {}).items()},
        "packing_counts": {k: int(v) for k, v in values.get("packing", {}).items()},
        "cost_totals": values.get("cost", {}),
        "tool_coverage_attempts": {
            key.removeprefix("tool_coverage_"): value
            for key, value in values.items()
            if key.startswith("tool_coverage_")
        },
        "class_coverage_attempts": {
            key.removeprefix("class_coverage_"): value
            for key, value in values.items()
            if key.startswith("class_coverage_")
        },
    }


def csv_export(db: sqlite3.Connection, path: Path) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for (value,) in db.execute("SELECT value FROM current ORDER BY id"):
            row = json.loads(value)
            for key in CSV_FIELDS:
                item = row.get(key, "")
                if isinstance(item, (dict, list)):
                    item = canonical(item)
                if isinstance(item, str) and item.lstrip().startswith(("=", "+", "-", "@")):
                    item = "'" + item
                row[key] = item
            writer.writerow(row)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
