"""Disk-backed selection, indexed scheduling and transactional aggregate accounting."""

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from typing import Any


def connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS sources (
            slot INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, value TEXT NOT NULL,
            done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0, 1)));
        CREATE INDEX IF NOT EXISTS pending_sources ON sources(done, id);
        CREATE TABLE IF NOT EXISTS outcomes (id TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS totals (
            category TEXT, name TEXT, value REAL NOT NULL, PRIMARY KEY(category, name));
        CREATE TABLE IF NOT EXISTS outputs (digest TEXT PRIMARY KEY, size INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS contract (value TEXT NOT NULL);
    """)
    return connection


def selection_digest(connection: sqlite3.Connection) -> str:
    result = sha256()
    for (value,) in connection.execute("SELECT value FROM sources ORDER BY id"):
        result.update(value.encode() + b"\n")
    return result.hexdigest()


def pending(connection: sqlite3.Connection, count: int) -> list[dict[str, Any]]:
    return [
        json.loads(value)
        for (value,) in connection.execute(
            "SELECT value FROM sources WHERE done=0 ORDER BY id LIMIT ?", (count,)
        )
    ]


def _add(connection: sqlite3.Connection, category: str, name: str, value: float) -> None:
    connection.execute(
        "INSERT INTO totals VALUES (?, ?, ?) ON CONFLICT(category, name) "
        "DO UPDATE SET value=value+excluded.value",
        (category, name, value),
    )


def record(connection: sqlite3.Connection, row: dict[str, Any]) -> None:
    """Outcome, scheduling flag, unique EXE and aggregate deltas share one commit."""
    with connection:
        connection.execute(
            "INSERT INTO outcomes VALUES (?, ?)",
            (row["original_sha256"], json.dumps(row, sort_keys=True)),
        )
        changed = connection.execute(
            "UPDATE sources SET done=1 WHERE id=? AND done=0", (row["original_sha256"],)
        ).rowcount
        if changed != 1:
            raise ValueError("Outcome is outside pending selection")
        for category, key in (
            ("status_counts", "status"),
            ("architecture_counts", "architecture"),
            ("packing_counts", "packing"),
        ):
            _add(connection, category, row[key], 1)
        for warning, count in Counter(row.get("warnings", [])).items():
            _add(connection, "warning_counts", warning, count)
        for key in (
            "compressed_bytes",
            "pe_bytes",
            "exe_bytes",
            "download_seconds",
            "decompress_seconds",
            "screen_seconds",
            "extract_seconds",
            "network_received_bytes",
        ):
            _add(connection, "sums", key, row.get(key, 0))
        if row["status"] == "success":
            changed = connection.execute(
                "INSERT OR IGNORE INTO outputs VALUES (?, ?)",
                (row["exe_sha256"], row["exe_bytes"]),
            ).rowcount
            if changed:
                _add(connection, "sums", "distinct_exe", 1)
                _add(connection, "sums", "unique_exe_bytes", row["exe_bytes"])


def summary(connection: sqlite3.Connection, selected: int) -> dict[str, Any]:
    groups: dict[str, dict[str, float]] = {}
    for category, name, value in connection.execute("SELECT category, name, value FROM totals"):
        groups.setdefault(category, {})[name] = value
    result: dict[str, Any] = {}
    for category in ("status_counts", "architecture_counts", "packing_counts", "warning_counts"):
        result[category] = {key: int(value) for key, value in groups.get(category, {}).items()}
    sums = groups.get("sums", {})
    result.update(selected=selected, completed=sum(result["status_counts"].values()))
    result["pending"] = selected - result["completed"]
    for name in (
        "compressed_bytes",
        "pe_bytes",
        "distinct_exe",
        "unique_exe_bytes",
        "network_received_bytes",
    ):
        result[name] = int(sums.get(name, 0))
    result["exe_bytes_per_source"] = int(sums.get("exe_bytes", 0))
    result["phase_seconds_sum"] = {
        key: round(sums.get(key, 0), 6)
        for key in (
            "download_seconds",
            "decompress_seconds",
            "screen_seconds",
            "extract_seconds",
        )
    }
    return result


class SavedRows:
    """Re-iterable snapshot without loading outcomes into memory."""

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def __iter__(self):
        for (value,) in self.connection.execute("SELECT value FROM outcomes ORDER BY id"):
            yield json.loads(value)

    def __len__(self):
        return self.connection.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0]
