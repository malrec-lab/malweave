"""Resumable static EXE-section extraction for an audited full RanDS corpus."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from hashlib import sha256
import io
import json
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any

from malweave.config import PROJECT_ROOT
from malweave.data.dataset_config import RandsDatasetConfig, RandsDatasetLocations
from malweave.data.pe_sections import extract_executable_sections
from malweave.data.rands import _validate_manifest_path, inspect_rands

EXE_MANIFEST_FIELDS = (
    "source_sha256",
    "label",
    "family",
    "source_hash_status",
    "extraction_status",
    "extraction_warnings",
    "section_count",
    "executable_section_count",
    "extracted_size",
    "representation_sha256",
    "representation_relative_path",
    "representation_reused",
    "runtime_ms",
    "snapshot",
)


class RandsExeError(ValueError):
    """Raised when the full-corpus extraction job is unsafe or malformed."""


@dataclass(frozen=True)
class RandsSource:
    """Canonical provenance for one available source in the audited corpus."""

    source_sha256: str
    label: str
    family: str
    relative_path: Path
    snapshot: str


@dataclass(frozen=True)
class ExeManifestRow:
    """One completed source attempt, including extraction failures."""

    source_sha256: str
    label: str
    family: str
    source_hash_status: str
    extraction_status: str
    extraction_warnings: tuple[str, ...]
    section_count: int
    executable_section_count: int
    extracted_size: int
    representation_sha256: str | None
    representation_relative_path: str | None
    representation_reused: bool
    runtime_ms: float
    snapshot: str


@dataclass(frozen=True)
class _SourceAttempt:
    row: ExeManifestRow
    source_bytes_read: int


def _validate_representation_root(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if tuple(relative.parts[:2]) != ("data", "processed"):
        raise RandsExeError(
            "Representation output inside the repository must be under data/processed."
        )


def _validate_state_path(path: Path) -> None:
    _validate_representation_root(path.parent)


def _validate_summary_path(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] != "reports":
        raise RandsExeError("Summary paths inside the repository must be under reports/.")


def enumerate_rands_sources(
    config: RandsDatasetConfig, root: Path | RandsDatasetLocations
) -> list[RandsSource]:
    """Return all available sources only after the release contract passes."""
    summary, metadata, present_shas = inspect_rands(config, root, hash_mode="none")
    if not summary["contract"]["passed"]:
        details = "; ".join(summary["contract"]["mismatches"])
        raise RandsExeError(
            f"RanDS release contract failed; resolve the audit findings first: {details}"
        )
    return [
        RandsSource(
            record.sha256, record.label, record.family or "", record.relative_path, config.snapshot
        )
        for source_sha256, record in sorted(metadata.records.items())
        if source_sha256 in present_shas
    ]


def _source_list_digest(sources: list[RandsSource]) -> str:
    digest = sha256()
    for source in sources:
        digest.update(
            f"{source.source_sha256}\t{source.label}\t{source.family}\t"
            f"{source.relative_path.as_posix()}\t{source.snapshot}".encode()
        )
        digest.update(b"\n")
    return digest.hexdigest()


def _connect_state(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    return connection


def _initialize_state(
    state_path: Path, sources: list[RandsSource], *, resume: bool
) -> sqlite3.Connection:
    _validate_state_path(state_path)
    existed = state_path.exists()
    if existed and not resume:
        raise RandsExeError(
            "Extraction state already exists; pass --resume to continue that exact job."
        )
    if not existed and resume:
        raise RandsExeError("Cannot resume because the extraction state database does not exist.")
    connection = _connect_state(state_path)
    digest = _source_list_digest(sources)
    if existed:
        try:
            stored = dict(connection.execute("SELECT key, value FROM job").fetchall())
        except sqlite3.DatabaseError as error:
            connection.close()
            raise RandsExeError(f"Invalid extraction state database: {state_path}") from error
        snapshot = sources[0].snapshot if sources else ""
        if stored.get("source_list_digest") != digest or stored.get("snapshot") != snapshot:
            connection.close()
            raise RandsExeError(
                "Extraction state does not match the audited source list or dataset snapshot. "
                "Start a new job with a new --state-db path."
            )
        return connection
    connection.executescript(
        """
        CREATE TABLE job (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE source (
          source_sha256 TEXT PRIMARY KEY, label TEXT NOT NULL, family TEXT NOT NULL,
          relative_path TEXT NOT NULL, snapshot TEXT NOT NULL, completed INTEGER NOT NULL DEFAULT 0,
          source_hash_status TEXT, extraction_status TEXT, extraction_warnings TEXT,
          section_count INTEGER, executable_section_count INTEGER, extracted_size INTEGER,
          representation_sha256 TEXT, representation_relative_path TEXT,
          representation_reused INTEGER, runtime_ms REAL, source_bytes_read INTEGER
        );
        CREATE INDEX source_pending ON source(completed, source_sha256);
        """
    )
    connection.executemany(
        "INSERT INTO source (source_sha256, label, family, relative_path, snapshot) VALUES (?, ?, ?, ?, ?)",
        [
            (s.source_sha256, s.label, s.family, s.relative_path.as_posix(), s.snapshot)
            for s in sources
        ],
    )
    connection.executemany(
        "INSERT INTO job (key, value) VALUES (?, ?)",
        (
            ("snapshot", sources[0].snapshot if sources else ""),
            ("source_list_digest", digest),
            ("source_count", str(len(sources))),
        ),
    )
    connection.commit()
    return connection


def _write_representation(path: Path, content: bytes, digest: str) -> bool:
    """Write once, retaining an existing identical output for a safe restart."""
    if path.exists():
        if sha256(path.read_bytes()).hexdigest() != digest:
            raise RandsExeError(f"Existing representation conflicts with extracted bytes: {path}")
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_bytes(content)
    temporary_path.replace(path)
    return False


def _failure_row(
    source: RandsSource, *, source_hash_status: str, extraction_status: str, runtime_ms: float
) -> ExeManifestRow:
    return ExeManifestRow(
        source.source_sha256,
        source.label,
        source.family,
        source_hash_status,
        extraction_status,
        (),
        0,
        0,
        0,
        None,
        None,
        False,
        runtime_ms,
        source.snapshot,
    )


def _extract_one_source(
    dataset_config: RandsDatasetConfig, root: Path, source: RandsSource, representation_root: Path
) -> _SourceAttempt:
    started = time.perf_counter()
    try:
        content = (root / dataset_config.samples_dir / source.relative_path).read_bytes()
    except OSError:
        return _SourceAttempt(
            _failure_row(
                source,
                source_hash_status="read_error",
                extraction_status="read_error",
                runtime_ms=(time.perf_counter() - started) * 1000,
            ),
            0,
        )
    source_bytes_read = len(content)
    if sha256(content).hexdigest() != source.source_sha256:
        return _SourceAttempt(
            _failure_row(
                source,
                source_hash_status="mismatch",
                extraction_status="source_hash_mismatch",
                runtime_ms=(time.perf_counter() - started) * 1000,
            ),
            source_bytes_read,
        )
    extracted = extract_executable_sections(content)
    reused = False
    relative_path: str | None = None
    if extracted.status == "success":
        assert (
            extracted.extracted_bytes is not None and extracted.representation_sha256 is not None
        )
        relative_path = (Path(source.source_sha256[:2]) / f"{source.source_sha256}.bin").as_posix()
        reused = _write_representation(
            representation_root / relative_path,
            extracted.extracted_bytes,
            extracted.representation_sha256,
        )
    return _SourceAttempt(
        ExeManifestRow(
            source.source_sha256,
            source.label,
            source.family,
            "verified",
            extracted.status,
            extracted.warnings,
            extracted.section_count,
            extracted.executable_section_count,
            extracted.extracted_size,
            extracted.representation_sha256,
            relative_path,
            reused,
            (time.perf_counter() - started) * 1000,
            source.snapshot,
        ),
        source_bytes_read,
    )


def _store_attempt(connection: sqlite3.Connection, attempt: _SourceAttempt) -> None:
    row = attempt.row
    connection.execute(
        """
        UPDATE source SET completed=1, source_hash_status=?, extraction_status=?, extraction_warnings=?, section_count=?, executable_section_count=?, extracted_size=?, representation_sha256=?, representation_relative_path=?, representation_reused=?, runtime_ms=?, source_bytes_read=? WHERE source_sha256=?
        """,
        (
            row.source_hash_status,
            row.extraction_status,
            ";".join(row.extraction_warnings),
            row.section_count,
            row.executable_section_count,
            row.extracted_size,
            row.representation_sha256,
            row.representation_relative_path,
            int(row.representation_reused),
            row.runtime_ms,
            attempt.source_bytes_read,
            row.source_sha256,
        ),
    )
    connection.commit()


def _row_from_state(row: sqlite3.Row) -> ExeManifestRow:
    return ExeManifestRow(
        row["source_sha256"],
        row["label"],
        row["family"],
        row["source_hash_status"],
        row["extraction_status"],
        tuple(filter(None, (row["extraction_warnings"] or "").split(";"))),
        row["section_count"],
        row["executable_section_count"],
        row["extracted_size"],
        row["representation_sha256"],
        row["representation_relative_path"],
        bool(row["representation_reused"]),
        row["runtime_ms"],
        row["snapshot"],
    )


def _completed_rows(connection: sqlite3.Connection) -> list[ExeManifestRow]:
    return [
        _row_from_state(row)
        for row in connection.execute(
            "SELECT * FROM source WHERE completed=1 ORDER BY source_sha256"
        )
    ]


def _summary(connection: sqlite3.Connection, rows: list[ExeManifestRow]) -> dict[str, Any]:
    total = connection.execute("SELECT COUNT(*) FROM source").fetchone()[0]
    source_bytes = connection.execute(
        "SELECT COALESCE(SUM(source_bytes_read), 0) FROM source"
    ).fetchone()[0]
    statuses = Counter(row.extraction_status for row in rows)
    warnings = Counter(warning for row in rows for warning in row.extraction_warnings)
    successful = [row for row in rows if row.extraction_status == "success"]
    groups: dict[str, list[ExeManifestRow]] = defaultdict(list)
    for row in successful:
        assert row.representation_sha256 is not None
        groups[row.representation_sha256].append(row)
    duplicates = [group for group in groups.values() if len(group) > 1]
    return {
        "job": {
            "sources_total": total,
            "sources_completed": len(rows),
            "sources_pending": total - len(rows),
            "complete": total == len(rows),
        },
        "sources": {
            "attempted": len(rows),
            "source_bytes_read": source_bytes,
            "source_hash_verified": sum(row.source_hash_status == "verified" for row in rows),
            "source_hash_mismatches": sum(row.source_hash_status == "mismatch" for row in rows),
            "read_errors": sum(row.source_hash_status == "read_error" for row in rows),
        },
        "extraction": {
            "statuses": dict(sorted(statuses.items())),
            "warnings": dict(sorted(warnings.items())),
            "successful": len(successful),
            "failed": len(rows) - len(successful),
            "representation_bytes": sum(row.extracted_size for row in successful),
            "reused_representations": sum(row.representation_reused for row in successful),
            "runtime_ms_total": round(sum(row.runtime_ms for row in rows), 3),
        },
        "labels": {
            label: dict(
                sorted(
                    Counter(row.extraction_status for row in rows if row.label == label).items()
                )
            )
            for label in ("benign", "ransomware")
        },
        "representation_duplicates": {
            "groups": len(duplicates),
            "extra_sources": sum(len(group) - 1 for group in duplicates),
            "cross_label_groups": sum(
                len({row.label for row in group}) > 1 for group in duplicates
            ),
        },
    }


def _format_duration(seconds: float) -> str:
    """Render a compact elapsed or estimated duration for terminal progress."""
    rounded = max(0, round(seconds))
    hours, remainder = divmod(rounded, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:d}:{seconds:02d}"


def _write_progress(
    connection: sqlite3.Connection,
    *,
    total: int,
    initial_completed: int,
    initial_bytes: int,
    started: float,
) -> None:
    """Write aggregate progress to stderr while preserving JSON stdout for automation."""
    completed, bytes_read, successful = connection.execute(
        """
        SELECT COUNT(*), COALESCE(SUM(source_bytes_read), 0),
          COALESCE(SUM(extraction_status = 'success'), 0)
        FROM source WHERE completed=1
        """
    ).fetchone()
    elapsed = time.perf_counter() - started
    processed = completed - initial_completed
    rate = processed / elapsed if elapsed else 0.0
    eta = (total - completed) / rate if rate else None
    mib_per_second = (bytes_read - initial_bytes) / elapsed / (1024 * 1024) if elapsed else 0.0
    percentage = completed / total * 100 if total else 100.0
    failed = completed - successful
    eta_text = _format_duration(eta) if eta is not None else "calculating"
    print(
        f"[extract-exe] {completed:,}/{total:,} ({percentage:.1f}%) | "
        f"success: {successful:,} | failed: {failed:,} | "
        f"{mib_per_second:.1f} MiB/s | elapsed: {_format_duration(elapsed)} | eta: {eta_text}",
        file=sys.stderr,
        flush=True,
    )


def extract_rands_exe(
    dataset_config: RandsDatasetConfig,
    root: Path | RandsDatasetLocations,
    representation_root: Path,
    state_path: Path,
    *,
    resume: bool = False,
    limit: int | None = None,
    progress_every: int = 100,
) -> tuple[list[ExeManifestRow], dict[str, Any]]:
    """Extract the audited corpus, committing every source result before continuing."""
    if limit is not None and limit <= 0:
        raise RandsExeError("--limit must be a positive integer.")
    if progress_every <= 0:
        raise RandsExeError("--progress-every must be a positive integer.")
    _validate_representation_root(representation_root)
    locations = (
        root
        if isinstance(root, RandsDatasetLocations)
        else RandsDatasetLocations(raw_root=root, metadata_root=root)
    )
    sources = enumerate_rands_sources(dataset_config, locations)
    connection = _initialize_state(state_path, sources, resume=resume)
    try:
        total = len(sources)
        initial_completed, initial_bytes = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(source_bytes_read), 0) FROM source WHERE completed=1"
        ).fetchone()
        started = time.perf_counter()
        query = "SELECT source_sha256, label, family, relative_path, snapshot FROM source WHERE completed=0 ORDER BY source_sha256"
        pending = (
            connection.execute(query + " LIMIT ?", (limit,))
            if limit is not None
            else connection.execute(query)
        )
        processed = 0
        for item in pending:
            source = RandsSource(
                item["source_sha256"],
                item["label"],
                item["family"],
                Path(item["relative_path"]),
                item["snapshot"],
            )
            _store_attempt(
                connection,
                _extract_one_source(
                    dataset_config, locations.raw_root, source, representation_root
                ),
            )
            processed += 1
            if processed % progress_every == 0:
                _write_progress(
                    connection,
                    total=total,
                    initial_completed=initial_completed,
                    initial_bytes=initial_bytes,
                    started=started,
                )
        if processed and processed % progress_every:
            _write_progress(
                connection,
                total=total,
                initial_completed=initial_completed,
                initial_bytes=initial_bytes,
                started=started,
            )
        rows = _completed_rows(connection)
        return rows, _summary(connection, rows)
    finally:
        connection.close()


def _render_exe_manifest(rows: list[ExeManifestRow]) -> bytes:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=EXE_MANIFEST_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "source_sha256": row.source_sha256,
                "label": row.label,
                "family": row.family,
                "source_hash_status": row.source_hash_status,
                "extraction_status": row.extraction_status,
                "extraction_warnings": ";".join(row.extraction_warnings),
                "section_count": row.section_count,
                "executable_section_count": row.executable_section_count,
                "extracted_size": row.extracted_size,
                "representation_sha256": row.representation_sha256 or "",
                "representation_relative_path": row.representation_relative_path or "",
                "representation_reused": int(row.representation_reused),
                "runtime_ms": f"{row.runtime_ms:.3f}",
                "snapshot": row.snapshot,
            }
        )
    return handle.getvalue().encode("utf-8")


def write_rands_exe_outputs(
    rows: list[ExeManifestRow], summary: dict[str, Any], manifest_path: Path, summary_path: Path
) -> dict[str, Any]:
    """Export durable completed state as a private manifest and safe summary."""
    _validate_manifest_path(manifest_path)
    _validate_summary_path(summary_path)
    manifest = _render_exe_manifest(rows)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(manifest)
    completed = {
        **summary,
        "manifest": {"rows": len(rows), "sha256": sha256(manifest).hexdigest()},
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(completed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return completed


def exe_console_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Return only aggregate extraction evidence for terminal output."""
    return summary
