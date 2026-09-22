"""Resumable metadata-filtered Ghidra extraction for RanDS DIS and DEC views."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
import csv
from dataclasses import dataclass
from functools import partial
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Literal

from unidecode import unidecode

from malweave.config import PROJECT_ROOT
from malweave.data.dataset_config import RandsDatasetConfig, RandsDatasetLocations
from malweave.data.rands import _validate_manifest_path, inspect_rands
from malweave.data.rands_exe import (
    _format_duration,
    _validate_representation_root,
    _validate_summary_path,
)

GhidraRepresentation = Literal["dis", "dec"]
GHIDRA_MANIFEST_FIELDS = (
    "source_sha256",
    "label",
    "family",
    "metadata_arch",
    "metadata_packed",
    "source_hash_status",
    "extraction_status",
    "representation_size",
    "representation_sha256",
    "representation_relative_path",
    "representation_reused",
    "runtime_ms",
    "snapshot",
)
SCRIPT_NAMES = {
    "dis": ("SetAnalysisOptionsForDisassembly.java", "Disassembler.java"),
    "dec": ("Decompiler.java",),
}
SCRIPT_ROOT = PROJECT_ROOT / "ghidra_scripts"
_ACTIVE_PROCESSES: set[subprocess.Popen[bytes]] = set()
_ACTIVE_PROCESSES_LOCK = threading.Lock()


class RandsGhidraError(ValueError):
    """Raised when a Ghidra extraction job is unsafe or malformed."""


@dataclass(frozen=True)
class GhidraSource:
    """One metadata-selected I386 source, retaining the packing annotation."""

    source_sha256: str
    label: str
    family: str
    metadata_arch: str
    metadata_packed: bool
    relative_path: Path
    snapshot: str


@dataclass(frozen=True)
class GhidraManifestRow:
    """One completed Ghidra attempt, including source and analysis failures."""

    source_sha256: str
    label: str
    family: str
    metadata_arch: str
    metadata_packed: bool
    source_hash_status: str
    extraction_status: str
    representation_size: int
    representation_sha256: str | None
    representation_relative_path: str | None
    representation_reused: bool
    runtime_ms: float
    snapshot: str


@dataclass(frozen=True)
class _SourceAttempt:
    row: GhidraManifestRow
    source_bytes_read: int


def normalize_disassembly(content: bytes) -> bytes:
    """Apply RawByteClf's DIS normalizer exactly to a Ghidra assembly artifact."""
    text = content.decode()
    instructions = [line.split("\t")[-1].strip() for line in text.split("\n") if "\t" in line]
    return "\n".join(unidecode(line) for line in instructions).encode("ascii")


def normalize_decompilation(content: bytes) -> bytes:
    """Apply RawByteClf's DEC normalizer exactly to a Ghidra C-like artifact."""
    text = re.sub(r"/\\*.*?\\*/", "", content.decode(), flags=re.DOTALL)
    return "\n".join(unidecode(line) for line in text.split("\n")).encode("ascii")


def _normalizer(representation: GhidraRepresentation) -> Any:
    if representation == "dis":
        return normalize_disassembly
    if representation == "dec":
        return normalize_decompilation
    raise RandsGhidraError(f"Unsupported Ghidra representation: {representation}")


def _extension(representation: GhidraRepresentation) -> str:
    return ".asm" if representation == "dis" else ".c"


def enumerate_rands_i386_metadata_sources(
    config: RandsDatasetConfig, root: Path | RandsDatasetLocations
) -> list[GhidraSource]:
    """Select available metadata-I386 samples without filtering either packing value."""
    summary, metadata, present_shas = inspect_rands(config, root, hash_mode="none")
    if not summary["contract"]["passed"]:
        details = "; ".join(summary["contract"]["mismatches"])
        raise RandsGhidraError(
            f"RanDS release contract failed; resolve the audit findings first: {details}"
        )
    return [
        GhidraSource(
            record.sha256,
            record.label,
            record.family or "",
            record.arch,
            record.packed,
            record.relative_path,
            config.snapshot,
        )
        for source_sha256, record in sorted(metadata.records.items())
        if source_sha256 in present_shas and record.arch == "I386"
    ]


def _source_list_digest(sources: Iterable[GhidraSource]) -> str:
    digest = sha256()
    for source in sources:
        digest.update(
            f"{source.source_sha256}\t{source.label}\t{source.family}\t{source.metadata_arch}\t"
            f"{int(source.metadata_packed)}\t{source.relative_path.as_posix()}\t{source.snapshot}".encode()
        )
        digest.update(b"\n")
    return digest.hexdigest()


def _script_digest(script_root: Path, representation: GhidraRepresentation) -> str:
    required = ("Lifter.java", *SCRIPT_NAMES[representation])
    digest = sha256()
    for name in required:
        path = script_root / name
        try:
            content = path.read_bytes()
        except OSError as error:
            raise RandsGhidraError(f"Required Ghidra script is unavailable: {path}") from error
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _file_digest(path: Path, *, description: str) -> str:
    try:
        return sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise RandsGhidraError(f"Could not read {description}: {path}") from error


def _job_contract(
    *,
    representation: GhidraRepresentation,
    analyze_headless: Path,
    script_root: Path,
    timeout_per_file_seconds: int,
    timeout_per_function_seconds: int,
    analysis_timeout_per_file_seconds: int,
    max_cpu: int,
    process_timeout_seconds: int,
    section: int | None = None,
    total_sections: int | None = None,
    section_source_list_digest: str | None = None,
) -> dict[str, str]:
    contract = {
        "representation": representation,
        "analyze_headless": str(analyze_headless.expanduser().resolve()),
        "analyze_headless_sha256": _file_digest(
            analyze_headless, description="analyzeHeadless launcher"
        ),
        "script_root": str(script_root.expanduser().resolve()),
        "script_digest": _script_digest(script_root, representation),
        "timeout_per_file_seconds": str(timeout_per_file_seconds),
        "timeout_per_function_seconds": str(timeout_per_function_seconds),
        "analysis_timeout_per_file_seconds": str(analysis_timeout_per_file_seconds),
        "max_cpu": str(max_cpu),
        "process_timeout_seconds": str(process_timeout_seconds),
        "normalizer": "rawbyteclf-prepare_data_for_esp-v1",
        "cohort": "rands_metadata_i386_all_packing",
    }
    if section is not None:
        contract["section"] = str(section)
        contract["total_sections"] = str(total_sections)
        contract["section_source_list_digest"] = section_source_list_digest or ""
    return contract


def _connect_state(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    return connection


def _initialize_state(
    state_path: Path,
    sources: list[GhidraSource],
    contract: dict[str, str],
    *,
    resume: bool,
) -> sqlite3.Connection:
    _validate_representation_root(state_path.parent)
    existed = state_path.exists()
    if existed and not resume:
        raise RandsGhidraError(
            "Ghidra extraction state already exists; pass --resume to continue that exact job."
        )
    if not existed and resume:
        raise RandsGhidraError("Cannot resume because the Ghidra state database does not exist.")
    connection = _connect_state(state_path)
    source_digest = _source_list_digest(sources)
    job_values = {
        "snapshot": sources[0].snapshot if sources else "",
        "source_list_digest": source_digest,
        "source_count": str(len(sources)),
        **contract,
    }
    if existed:
        try:
            stored = dict(connection.execute("SELECT key, value FROM job").fetchall())
        except sqlite3.DatabaseError as error:
            connection.close()
            raise RandsGhidraError(f"Invalid Ghidra state database: {state_path}") from error
        if any(stored.get(key) != value for key, value in job_values.items()):
            connection.close()
            raise RandsGhidraError(
                "Ghidra state does not match the dataset cohort or extraction contract. "
                "Start a new job with a new --state-db path."
            )
        return connection
    connection.executescript(
        """
        CREATE TABLE job (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE source (
          source_sha256 TEXT PRIMARY KEY, label TEXT NOT NULL, family TEXT NOT NULL,
          metadata_arch TEXT NOT NULL, metadata_packed INTEGER NOT NULL, relative_path TEXT NOT NULL,
          snapshot TEXT NOT NULL, source_hash_status TEXT, source_bytes_read INTEGER,
          dis_completed INTEGER NOT NULL DEFAULT 0, dis_extraction_status TEXT,
          dis_representation_size INTEGER, dis_representation_sha256 TEXT,
          dis_representation_relative_path TEXT, dis_representation_reused INTEGER,
          dis_runtime_ms REAL, dec_completed INTEGER NOT NULL DEFAULT 0,
          dec_extraction_status TEXT, dec_representation_size INTEGER,
          dec_representation_sha256 TEXT, dec_representation_relative_path TEXT,
          dec_representation_reused INTEGER, dec_runtime_ms REAL,
          completed INTEGER NOT NULL DEFAULT 0, extraction_status TEXT,
          representation_size INTEGER, representation_sha256 TEXT,
          representation_relative_path TEXT, representation_reused INTEGER,
          runtime_ms REAL
        );
        CREATE INDEX source_pending ON source(completed, source_sha256);
        CREATE INDEX source_pending_dis ON source(dis_completed, source_sha256);
        CREATE INDEX source_pending_dec ON source(dec_completed, source_sha256);
        """
    )
    connection.executemany(
        """INSERT INTO source
        (source_sha256, label, family, metadata_arch, metadata_packed, relative_path, snapshot)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                source.source_sha256,
                source.label,
                source.family,
                source.metadata_arch,
                int(source.metadata_packed),
                source.relative_path.as_posix(),
                source.snapshot,
            )
            for source in sources
        ],
    )
    connection.executemany("INSERT INTO job (key, value) VALUES (?, ?)", job_values.items())
    connection.commit()
    return connection


def _write_representation(path: Path, content: bytes, digest: str) -> bool:
    """Write normalized output atomically, rejecting a conflicting prior result."""
    if path.exists():
        if sha256(path.read_bytes()).hexdigest() != digest:
            raise RandsGhidraError(f"Existing representation conflicts with Ghidra output: {path}")
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_bytes(content)
    temporary_path.replace(path)
    return False


def _failure_row(
    source: GhidraSource, *, source_hash_status: str, extraction_status: str, runtime_ms: float
) -> GhidraManifestRow:
    return GhidraManifestRow(
        source.source_sha256,
        source.label,
        source.family,
        source.metadata_arch,
        source.metadata_packed,
        source_hash_status,
        extraction_status,
        0,
        None,
        None,
        False,
        runtime_ms,
        source.snapshot,
    )


def _run_headless(command: list[str], timeout_seconds: int) -> str:
    """Run Ghidra in its own process group so a timeout cannot strand child processes."""
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    with _ACTIVE_PROCESSES_LOCK:
        _ACTIVE_PROCESSES.add(process)
    try:
        try:
            process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            _terminate_process(process)
            return "timeout"
        except KeyboardInterrupt:
            _terminate_process(process)
            raise
        if process.returncode:
            return "failed"
        return "success"
    finally:
        with _ACTIVE_PROCESSES_LOCK:
            _ACTIVE_PROCESSES.discard(process)


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate one Ghidra process group, escalating if it ignores SIGTERM."""
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _terminate_active_processes() -> None:
    """Stop all in-flight headless jobs before the worker pool shuts down."""
    with _ACTIVE_PROCESSES_LOCK:
        processes = tuple(_ACTIVE_PROCESSES)
    for process in processes:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    for process in processes:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _ghidra_command(
    *,
    analyze_headless: Path,
    representation: GhidraRepresentation,
    script_root: Path,
    source_path: Path,
    project_root: Path,
    output_root: Path,
    timeout_per_file_seconds: int,
    timeout_per_function_seconds: int,
    analysis_timeout_per_file_seconds: int,
    max_cpu: int,
) -> list[str]:
    target_script = "Disassembler.java" if representation == "dis" else "Decompiler.java"
    command = [
        str(analyze_headless),
        str(project_root),
        "malweave",
        "-import",
        str(source_path),
        "-processor",
        "x86:LE:32:default",
        "-loader",
        "PeLoader",
        "-analysisTimeoutPerFile",
        str(analysis_timeout_per_file_seconds),
        "-max-cpu",
        str(max_cpu),
        "-scriptPath",
        str(script_root),
    ]
    if representation == "dis":
        command.extend(("-preScript", "SetAnalysisOptionsForDisassembly.java"))
    command.extend(
        (
            "-postScript",
            target_script,
            str(output_root),
            str(timeout_per_file_seconds),
            str(timeout_per_function_seconds),
            "-deleteProject",
            "-okToDelete",
        )
    )
    return command


def _extract_one_source(
    dataset_config: RandsDatasetConfig,
    raw_root: Path,
    source: GhidraSource,
    representation_root: Path,
    *,
    analyze_headless: Path,
    representation: GhidraRepresentation,
    script_root: Path,
    work_root: Path,
    timeout_per_file_seconds: int,
    timeout_per_function_seconds: int,
    analysis_timeout_per_file_seconds: int,
    max_cpu: int,
    process_timeout_seconds: int,
) -> _SourceAttempt:
    started = time.perf_counter()
    source_path = raw_root / dataset_config.samples_dir / source.relative_path
    try:
        content = source_path.read_bytes()
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
    work_root.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="ghidra-", dir=work_root) as temporary:
            temporary_root = Path(temporary)
            output_root = temporary_root / "output"
            output_root.mkdir()
            project_root = temporary_root / "project"
            project_root.mkdir()
            outcome = _run_headless(
                _ghidra_command(
                    analyze_headless=analyze_headless,
                    representation=representation,
                    script_root=script_root,
                    source_path=source_path,
                    project_root=project_root,
                    output_root=output_root,
                    timeout_per_file_seconds=timeout_per_file_seconds,
                    timeout_per_function_seconds=timeout_per_function_seconds,
                    analysis_timeout_per_file_seconds=analysis_timeout_per_file_seconds,
                    max_cpu=max_cpu,
                ),
                process_timeout_seconds,
            )
            if outcome != "success":
                return _SourceAttempt(
                    _failure_row(
                        source,
                        source_hash_status="verified",
                        extraction_status=f"ghidra_{outcome}",
                        runtime_ms=(time.perf_counter() - started) * 1000,
                    ),
                    source_bytes_read,
                )
            output_path = output_root / f"{source.source_sha256}{_extension(representation)}"
            try:
                normalized = _normalizer(representation)(output_path.read_bytes())
            except FileNotFoundError:
                return _SourceAttempt(
                    _failure_row(
                        source,
                        source_hash_status="verified",
                        extraction_status="missing_output",
                        runtime_ms=(time.perf_counter() - started) * 1000,
                    ),
                    source_bytes_read,
                )
            except UnicodeError:
                return _SourceAttempt(
                    _failure_row(
                        source,
                        source_hash_status="verified",
                        extraction_status="normalization_error",
                        runtime_ms=(time.perf_counter() - started) * 1000,
                    ),
                    source_bytes_read,
                )
    except OSError:
        return _SourceAttempt(
            _failure_row(
                source,
                source_hash_status="verified",
                extraction_status="ghidra_launch_error",
                runtime_ms=(time.perf_counter() - started) * 1000,
            ),
            source_bytes_read,
        )
    if not normalized:
        return _SourceAttempt(
            _failure_row(
                source,
                source_hash_status="verified",
                extraction_status="empty_representation",
                runtime_ms=(time.perf_counter() - started) * 1000,
            ),
            source_bytes_read,
        )
    digest = sha256(normalized).hexdigest()
    relative_path = (
        Path(source.source_sha256[:2]) / f"{source.source_sha256}{_extension(representation)}"
    ).as_posix()
    reused = _write_representation(representation_root / relative_path, normalized, digest)
    return _SourceAttempt(
        GhidraManifestRow(
            source.source_sha256,
            source.label,
            source.family,
            source.metadata_arch,
            source.metadata_packed,
            "verified",
            "success",
            len(normalized),
            digest,
            relative_path,
            reused,
            (time.perf_counter() - started) * 1000,
            source.snapshot,
        ),
        source_bytes_read,
    )


def _store_attempt(
    connection: sqlite3.Connection,
    attempt: _SourceAttempt,
    representation: GhidraRepresentation,
) -> None:
    """Persist a legacy single-representation attempt."""
    row = attempt.row
    columns = {
        "source_hash_status": row.source_hash_status,
        "source_bytes_read": attempt.source_bytes_read,
        "completed": 1,
        "extraction_status": row.extraction_status,
        "representation_size": row.representation_size,
        "representation_sha256": row.representation_sha256,
        "representation_relative_path": row.representation_relative_path,
        "representation_reused": int(row.representation_reused),
        "runtime_ms": row.runtime_ms,
        f"{representation}_completed": 1,
        f"{representation}_extraction_status": row.extraction_status,
        f"{representation}_representation_size": row.representation_size,
        f"{representation}_representation_sha256": row.representation_sha256,
        f"{representation}_representation_relative_path": row.representation_relative_path,
        f"{representation}_representation_reused": int(row.representation_reused),
        f"{representation}_runtime_ms": row.runtime_ms,
    }
    assignments = ", ".join(f"{column}=?" for column in columns)
    connection.execute(
        f"UPDATE source SET {assignments} WHERE source_sha256=?",
        (*columns.values(), row.source_sha256),
    )
    connection.commit()


def _store_unified_attempts(
    connection: sqlite3.Connection,
    attempts: dict[GhidraRepresentation, _SourceAttempt],
    requested: tuple[GhidraRepresentation, ...],
) -> None:
    """Persist terminal results per representation before completing a source."""
    if not attempts:
        return
    source_sha256 = next(iter(attempts.values())).row.source_sha256
    source_status = next(iter(attempts.values())).row.source_hash_status
    source_bytes_read = max(attempt.source_bytes_read for attempt in attempts.values())
    columns: dict[str, Any] = {
        "source_hash_status": source_status,
        "source_bytes_read": source_bytes_read,
    }
    for representation, attempt in attempts.items():
        row = attempt.row
        prefix = f"{representation}_"
        columns.update(
            {
                f"{prefix}completed": 1,
                f"{prefix}extraction_status": row.extraction_status,
                f"{prefix}representation_size": row.representation_size,
                f"{prefix}representation_sha256": row.representation_sha256,
                f"{prefix}representation_relative_path": row.representation_relative_path,
                f"{prefix}representation_reused": int(row.representation_reused),
                f"{prefix}runtime_ms": row.runtime_ms,
            }
        )
    assignments = ", ".join(f"{column}=?" for column in columns)
    connection.execute(
        f"UPDATE source SET {assignments} WHERE source_sha256=?",
        (*columns.values(), source_sha256),
    )
    completed_columns = " AND ".join(
        f"{representation}_completed=1" for representation in requested
    )
    connection.execute(
        f"UPDATE source SET completed=CASE WHEN {completed_columns} THEN 1 ELSE 0 END "
        "WHERE source_sha256=?",
        (source_sha256,),
    )
    connection.commit()


def _row_from_state(row: sqlite3.Row) -> GhidraManifestRow:
    return GhidraManifestRow(
        row["source_sha256"],
        row["label"],
        row["family"],
        row["metadata_arch"],
        bool(row["metadata_packed"]),
        row["source_hash_status"],
        row["extraction_status"],
        row["representation_size"],
        row["representation_sha256"],
        row["representation_relative_path"],
        bool(row["representation_reused"]),
        row["runtime_ms"],
        row["snapshot"],
    )


def _completed_rows(connection: sqlite3.Connection) -> list[GhidraManifestRow]:
    return [
        _row_from_state(row)
        for row in connection.execute(
            "SELECT * FROM source WHERE completed=1 ORDER BY source_sha256"
        )
    ]


def _representation_rows(
    connection: sqlite3.Connection, representation: GhidraRepresentation
) -> list[GhidraManifestRow]:
    """Render one representation's completed state as manifest rows."""
    prefix = f"{representation}_"
    return [
        GhidraManifestRow(
            row["source_sha256"],
            row["label"],
            row["family"],
            row["metadata_arch"],
            bool(row["metadata_packed"]),
            row["source_hash_status"],
            row[f"{prefix}extraction_status"],
            row[f"{prefix}representation_size"] or 0,
            row[f"{prefix}representation_sha256"],
            row[f"{prefix}representation_relative_path"],
            bool(row[f"{prefix}representation_reused"]),
            row[f"{prefix}runtime_ms"] or 0.0,
            row["snapshot"],
        )
        for row in connection.execute(
            f"SELECT * FROM source WHERE {prefix}completed=1 ORDER BY source_sha256"
        )
    ]


def _summary(connection: sqlite3.Connection, rows: list[GhidraManifestRow]) -> dict[str, Any]:
    total = connection.execute("SELECT COUNT(*) FROM source").fetchone()[0]
    source_bytes = connection.execute(
        "SELECT COALESCE(SUM(source_bytes_read), 0) FROM source"
    ).fetchone()[0]
    statuses = Counter(row.extraction_status for row in rows)
    successful = [row for row in rows if row.extraction_status == "success"]
    packing = {
        name: [row for row in rows if row.metadata_packed == packed]
        for name, packed in (("unpacked", False), ("packed", True))
    }
    return {
        "job": {
            "sources_total": total,
            "sources_completed": len(rows),
            "sources_pending": total - len(rows),
            "complete": total == len(rows),
        },
        "cohort": {
            "selection": "metadata_arch == I386; packed metadata retained, not filtered",
            "metadata_arch": "I386",
            "unpacked": len(packing["unpacked"]),
            "packed": len(packing["packed"]),
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
            "successful": len(successful),
            "failed": len(rows) - len(successful),
            "representation_bytes": sum(row.representation_size for row in successful),
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
        "packing": {
            name: dict(sorted(Counter(row.extraction_status for row in group).items()))
            for name, group in packing.items()
        },
    }


def _write_progress(
    connection: sqlite3.Connection,
    *,
    representation: GhidraRepresentation,
    total: int,
    initial_completed: int,
    started: float,
) -> None:
    completed, successful = connection.execute(
        "SELECT COUNT(*), COALESCE(SUM(extraction_status = 'success'), 0) FROM source WHERE completed=1"
    ).fetchone()
    elapsed = time.perf_counter() - started
    processed = completed - initial_completed
    rate = processed / elapsed if elapsed else 0.0
    eta = (total - completed) / rate if rate else None
    percentage = completed / total * 100 if total else 100.0
    eta_text = _format_duration(eta) if eta is not None else "calculating"
    print(
        f"[extract-{representation}] {completed:,}/{total:,} ({percentage:.1f}%) | "
        f"success: {successful:,} | failed: {completed - successful:,} | "
        f"{rate:.2f} samples/s | elapsed: {_format_duration(elapsed)} | eta: {eta_text}",
        file=sys.stderr,
        flush=True,
    )


def _extract_single_rands_ghidra(
    dataset_config: RandsDatasetConfig,
    root: Path | RandsDatasetLocations,
    representation_root: Path,
    state_path: Path,
    *,
    representation: GhidraRepresentation,
    analyze_headless: Path,
    script_root: Path = SCRIPT_ROOT,
    work_root: Path | None = None,
    timeout_per_file_seconds: int | None = None,
    timeout_per_function_seconds: int | None = None,
    analysis_timeout_per_file_seconds: int = 300,
    max_cpu: int = 1,
    process_timeout_seconds: int | None = None,
    workers: int = 1,
    resume: bool = False,
    limit: int | None = None,
    progress_every: int = 10,
    shard_plan_dir: Path | None = None,
    section: int | None = None,
) -> tuple[
    list[GhidraManifestRow] | dict[GhidraRepresentation, list[GhidraManifestRow]], dict[str, Any]
]:
    """Extract one representation with durable state."""
    if representation not in {"dis", "dec"}:
        raise RandsGhidraError("--representation must be dis or dec.")
    if limit is not None and limit <= 0:
        raise RandsGhidraError("--limit must be a positive integer.")
    if progress_every <= 0:
        raise RandsGhidraError("--progress-every must be a positive integer.")
    if workers <= 0:
        raise RandsGhidraError("--workers must be a positive integer.")
    if (shard_plan_dir is None) != (section is None):
        raise RandsGhidraError("--shard-plan and --section must be used together.")
    if timeout_per_file_seconds is None:
        timeout_per_file_seconds = 60 if representation == "dis" else 300
    if timeout_per_function_seconds is None:
        timeout_per_function_seconds = 30 if representation == "dis" else 60
    if (
        timeout_per_file_seconds <= 0
        or timeout_per_function_seconds <= 0
        or analysis_timeout_per_file_seconds <= 0
        or max_cpu <= 0
    ):
        raise RandsGhidraError("Ghidra timeouts must be positive integers.")
    minimum_process_timeout = analysis_timeout_per_file_seconds + timeout_per_file_seconds
    process_timeout_seconds = process_timeout_seconds or minimum_process_timeout + 120
    if process_timeout_seconds <= minimum_process_timeout:
        raise RandsGhidraError(
            "--process-timeout-seconds must exceed analysis plus representation timeouts."
        )
    analyze_headless = analyze_headless.expanduser()
    if not analyze_headless.is_file() or not os.access(analyze_headless, os.X_OK):
        raise RandsGhidraError(f"--analyze-headless is not an executable file: {analyze_headless}")
    script_root = script_root.expanduser()
    _validate_representation_root(representation_root)
    _validate_representation_root(work_root or state_path.parent / "ghidra-work")
    locations = (
        root
        if isinstance(root, RandsDatasetLocations)
        else RandsDatasetLocations(raw_root=root, metadata_root=root)
    )
    sources = enumerate_rands_i386_metadata_sources(dataset_config, locations)

    section_source_list_digest = None
    total_sections = None
    if shard_plan_dir is not None and section is not None:
        sources, section_source_list_digest, total_sections = _load_section_sources(
            shard_plan_dir, section
        )

    contract = _job_contract(
        representation=representation,
        analyze_headless=analyze_headless,
        script_root=script_root,
        timeout_per_file_seconds=timeout_per_file_seconds,
        timeout_per_function_seconds=timeout_per_function_seconds,
        analysis_timeout_per_file_seconds=analysis_timeout_per_file_seconds,
        max_cpu=max_cpu,
        process_timeout_seconds=process_timeout_seconds,
        section=section,
        total_sections=total_sections,
        section_source_list_digest=section_source_list_digest,
    )
    connection = _initialize_state(state_path, sources, contract, resume=resume)
    try:
        total = len(sources)
        initial_completed = connection.execute(
            "SELECT COUNT(*) FROM source WHERE completed=1"
        ).fetchone()[0]
        started = time.perf_counter()
        query = """SELECT source_sha256, label, family, metadata_arch, metadata_packed,
          relative_path, snapshot FROM source WHERE completed=0 ORDER BY source_sha256"""
        pending_rows = (
            connection.execute(query + " LIMIT ?", (limit,))
            if limit
            else connection.execute(query)
        ).fetchall()
        processed = 0
        extractor = partial(
            _extract_one_source,
            dataset_config,
            locations.raw_root,
            representation_root=representation_root,
            analyze_headless=analyze_headless,
            representation=representation,
            script_root=script_root,
            work_root=work_root or state_path.parent / "ghidra-work",
            timeout_per_file_seconds=timeout_per_file_seconds,
            timeout_per_function_seconds=timeout_per_function_seconds,
            analysis_timeout_per_file_seconds=analysis_timeout_per_file_seconds,
            max_cpu=max_cpu,
            process_timeout_seconds=process_timeout_seconds,
        )
        pending_sources = [
            GhidraSource(
                item["source_sha256"],
                item["label"],
                item["family"],
                item["metadata_arch"],
                bool(item["metadata_packed"]),
                Path(item["relative_path"]),
                item["snapshot"],
            )
            for item in pending_rows
        ]
        executor = ThreadPoolExecutor(max_workers=workers)
        futures: set[Future[_SourceAttempt]] = set()
        source_iterator = iter(pending_sources)
        try:
            for _ in range(min(workers, len(pending_sources))):
                futures.add(executor.submit(extractor, next(source_iterator)))
            while futures:
                completed, futures = wait(futures, return_when=FIRST_COMPLETED)
                for future in completed:
                    _store_attempt(connection, future.result(), representation)
                    processed += 1
                    if processed % progress_every == 0:
                        _write_progress(
                            connection,
                            representation=representation,
                            total=total,
                            initial_completed=initial_completed,
                            started=started,
                        )
                    try:
                        futures.add(executor.submit(extractor, next(source_iterator)))
                    except StopIteration:
                        pass
        except BaseException:
            for future in futures:
                future.cancel()
            _terminate_active_processes()
            executor.shutdown(wait=True, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)
        if processed and processed % progress_every:
            _write_progress(
                connection,
                representation=representation,
                total=total,
                initial_completed=initial_completed,
                started=started,
            )
        return _completed_rows(connection), _summary(connection, _completed_rows(connection))
    finally:
        connection.close()


def _unified_summary(
    connection: sqlite3.Connection,
    requested: tuple[GhidraRepresentation, ...],
) -> tuple[dict[GhidraRepresentation, list[GhidraManifestRow]], dict[str, Any]]:
    """Summarize a shared source job without hiding a partial representation result."""
    rows = {
        representation: _representation_rows(connection, representation)
        for representation in requested
    }
    total = connection.execute("SELECT COUNT(*) FROM source").fetchone()[0]
    completed = connection.execute("SELECT COUNT(*) FROM source WHERE completed=1").fetchone()[0]
    source_bytes = connection.execute(
        "SELECT COALESCE(SUM(source_bytes_read), 0) FROM source"
    ).fetchone()[0]
    source_statuses = Counter(
        row[0]
        for row in connection.execute(
            "SELECT source_hash_status FROM source WHERE source_hash_status IS NOT NULL"
        )
    )
    representation_summaries = {}
    for representation, representation_rows in rows.items():
        summary = _summary(connection, representation_rows)
        representation_summaries[representation] = summary["extraction"]
    return rows, {
        "job": {
            "sources_total": total,
            "sources_completed": completed,
            "sources_pending": total - completed,
            "complete": total == completed,
            "representations": list(requested),
        },
        "cohort": {
            "selection": "metadata_arch == I386; packed metadata retained, not filtered",
            "metadata_arch": "I386",
        },
        "sources": {
            "source_bytes_read": source_bytes,
            "source_hash_statuses": dict(sorted(source_statuses.items())),
        },
        "representations": representation_summaries,
    }


def _extract_unified_source(
    dataset_config: RandsDatasetConfig,
    raw_root: Path,
    source: GhidraSource,
    pending_representations: tuple[GhidraRepresentation, ...],
    representation_roots: dict[GhidraRepresentation, Path],
    *,
    analyze_headless: Path,
    script_root: Path,
    work_root: Path,
    timeout_per_file_seconds: dict[GhidraRepresentation, int],
    timeout_per_function_seconds: dict[GhidraRepresentation, int],
    analysis_timeout_per_file_seconds: int,
    max_cpu: int,
    process_timeout_seconds: int,
) -> dict[GhidraRepresentation, _SourceAttempt]:
    """Run each missing view as one source transaction with independent terminal results."""
    attempts: dict[GhidraRepresentation, _SourceAttempt] = {}
    for representation in pending_representations:
        attempt = _extract_one_source(
            dataset_config,
            raw_root,
            source,
            representation_roots[representation],
            analyze_headless=analyze_headless,
            representation=representation,
            script_root=script_root,
            work_root=work_root,
            timeout_per_file_seconds=timeout_per_file_seconds[representation],
            timeout_per_function_seconds=timeout_per_function_seconds[representation],
            analysis_timeout_per_file_seconds=analysis_timeout_per_file_seconds,
            max_cpu=max_cpu,
            process_timeout_seconds=process_timeout_seconds,
        )
        attempts[representation] = attempt
        if attempt.row.source_hash_status != "verified":
            # A corrupt or unreadable source cannot have a valid sibling representation.
            for sibling in pending_representations:
                if sibling not in attempts:
                    attempts[sibling] = _SourceAttempt(
                        _failure_row(
                            source,
                            source_hash_status=attempt.row.source_hash_status,
                            extraction_status=attempt.row.extraction_status,
                            runtime_ms=0.0,
                        ),
                        attempt.source_bytes_read,
                    )
            break
    return attempts


def _extract_unified_rands_ghidra(
    dataset_config: RandsDatasetConfig,
    root: Path | RandsDatasetLocations,
    state_path: Path,
    *,
    representations: tuple[GhidraRepresentation, ...],
    dis_representation_root: Path | None,
    dec_representation_root: Path | None,
    analyze_headless: Path,
    script_root: Path,
    work_root: Path | None,
    timeout_per_file_seconds: int | None,
    timeout_per_function_seconds: int | None,
    analysis_timeout_per_file_seconds: int,
    max_cpu: int,
    process_timeout_seconds: int | None,
    workers: int,
    resume: bool,
    limit: int | None,
    progress_every: int,
    shard_plan_dir: Path | None,
    section: int | None,
) -> tuple[dict[GhidraRepresentation, list[GhidraManifestRow]], dict[str, Any]]:
    """Extract DIS and DEC under one durable source state database."""
    if limit is not None and limit <= 0:
        raise RandsGhidraError("--limit must be a positive integer.")
    if progress_every <= 0 or workers <= 0:
        raise RandsGhidraError("--progress-every and --workers must be positive integers.")
    if (shard_plan_dir is None) != (section is None):
        raise RandsGhidraError("--shard-plan and --section must be used together.")
    if analysis_timeout_per_file_seconds <= 0 or max_cpu <= 0:
        raise RandsGhidraError("Ghidra timeouts and --max-cpu must be positive integers.")
    representation_roots = {"dis": dis_representation_root, "dec": dec_representation_root}
    for representation in representations:
        if representation_roots[representation] is None:
            raise RandsGhidraError(
                f"--{representation}-representation-dir is required when extracting {representation}."
            )
        _validate_representation_root(representation_roots[representation])
    typed_roots = {key: value for key, value in representation_roots.items() if value is not None}
    file_timeouts = {
        "dis": timeout_per_file_seconds or 60,
        "dec": timeout_per_file_seconds or 300,
    }
    function_timeouts = {
        "dis": timeout_per_function_seconds or 30,
        "dec": timeout_per_function_seconds or 60,
    }
    if any(file_timeouts[item] <= 0 or function_timeouts[item] <= 0 for item in representations):
        raise RandsGhidraError("Ghidra timeouts must be positive integers.")
    minimum_process_timeout = sum(
        analysis_timeout_per_file_seconds + file_timeouts[item] for item in representations
    )
    effective_process_timeout = process_timeout_seconds or minimum_process_timeout + 120
    if effective_process_timeout <= minimum_process_timeout:
        raise RandsGhidraError(
            "--process-timeout-seconds must exceed the combined analysis and representation timeouts."
        )
    analyze_headless = analyze_headless.expanduser()
    if not analyze_headless.is_file() or not os.access(analyze_headless, os.X_OK):
        raise RandsGhidraError(f"--analyze-headless is not an executable file: {analyze_headless}")
    script_root = script_root.expanduser()
    effective_work_root = work_root or state_path.parent / "ghidra-work"
    _validate_representation_root(effective_work_root)
    locations = (
        root
        if isinstance(root, RandsDatasetLocations)
        else RandsDatasetLocations(raw_root=root, metadata_root=root)
    )
    sources = enumerate_rands_i386_metadata_sources(dataset_config, locations)
    section_digest = None
    total_sections = None
    if shard_plan_dir is not None and section is not None:
        sources, section_digest, total_sections = _load_section_sources(shard_plan_dir, section)
    contract = _job_contract(
        representation="dis",
        analyze_headless=analyze_headless,
        script_root=script_root,
        timeout_per_file_seconds=file_timeouts["dis"],
        timeout_per_function_seconds=function_timeouts["dis"],
        analysis_timeout_per_file_seconds=analysis_timeout_per_file_seconds,
        max_cpu=max_cpu,
        process_timeout_seconds=effective_process_timeout,
        section=section,
        total_sections=total_sections,
        section_source_list_digest=section_digest,
    )
    contract.update(
        {
            "representation": "+".join(representations),
            "representations": ",".join(representations),
            "dis_script_digest": _script_digest(script_root, "dis"),
            "dec_script_digest": _script_digest(script_root, "dec"),
            "dis_timeout_per_file_seconds": str(file_timeouts["dis"]),
            "dec_timeout_per_file_seconds": str(file_timeouts["dec"]),
            "dis_timeout_per_function_seconds": str(function_timeouts["dis"]),
            "dec_timeout_per_function_seconds": str(function_timeouts["dec"]),
        }
    )
    connection = _initialize_state(state_path, sources, contract, resume=resume)
    try:
        pending_clause = " OR ".join(f"{item}_completed=0" for item in representations)
        query = (
            "SELECT source_sha256, label, family, metadata_arch, metadata_packed, relative_path, snapshot, "
            "dis_completed, dec_completed FROM source WHERE "
            f"({pending_clause}) ORDER BY source_sha256"
        )
        pending_rows = (
            connection.execute(query + " LIMIT ?", (limit,))
            if limit
            else connection.execute(query)
        ).fetchall()
        source_jobs = [
            (
                GhidraSource(
                    row["source_sha256"],
                    row["label"],
                    row["family"],
                    row["metadata_arch"],
                    bool(row["metadata_packed"]),
                    Path(row["relative_path"]),
                    row["snapshot"],
                ),
                tuple(item for item in representations if not row[f"{item}_completed"]),
            )
            for row in pending_rows
        ]
        extractor = partial(
            _extract_one_source,
            dataset_config,
            locations.raw_root,
            analyze_headless=analyze_headless,
            script_root=script_root,
            work_root=effective_work_root,
            analysis_timeout_per_file_seconds=analysis_timeout_per_file_seconds,
            max_cpu=max_cpu,
            process_timeout_seconds=effective_process_timeout,
        )
        executor = ThreadPoolExecutor(max_workers=workers)
        futures: dict[Future[_SourceAttempt], tuple[GhidraSource, GhidraRepresentation]] = {}
        source_iterator = iter(source_jobs)

        def submit_representation(
            source: GhidraSource, representation: GhidraRepresentation
        ) -> None:
            future = executor.submit(
                extractor,
                source,
                typed_roots[representation],
                representation=representation,
                timeout_per_file_seconds=file_timeouts[representation],
                timeout_per_function_seconds=function_timeouts[representation],
            )
            futures[future] = (source, representation)

        def start_source() -> bool:
            try:
                source, pending = next(source_iterator)
            except StopIteration:
                return False
            pending_by_source[source.source_sha256] = list(pending)
            submit_representation(source, pending_by_source[source.source_sha256].pop(0))
            return True

        pending_by_source: dict[str, list[GhidraRepresentation]] = {}
        try:
            for _ in range(min(workers, len(source_jobs))):
                start_source()
            while futures:
                completed, _ = wait(futures, return_when=FIRST_COMPLETED)
                for future in completed:
                    source, representation = futures.pop(future)
                    attempt = future.result()
                    attempts = {representation: attempt}
                    remaining = pending_by_source[source.source_sha256]
                    if attempt.row.source_hash_status != "verified":
                        for sibling in remaining:
                            attempts[sibling] = _SourceAttempt(
                                _failure_row(
                                    source,
                                    source_hash_status=attempt.row.source_hash_status,
                                    extraction_status=attempt.row.extraction_status,
                                    runtime_ms=0.0,
                                ),
                                attempt.source_bytes_read,
                            )
                        remaining.clear()
                    _store_unified_attempts(connection, attempts, representations)
                    if remaining:
                        submit_representation(source, remaining.pop(0))
                    else:
                        del pending_by_source[source.source_sha256]
                        start_source()
        except BaseException:
            for future in futures:
                future.cancel()
            _terminate_active_processes()
            executor.shutdown(wait=True, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)
        return _unified_summary(connection, representations)
    finally:
        connection.close()


def extract_rands_ghidra(
    dataset_config: RandsDatasetConfig,
    root: Path | RandsDatasetLocations,
    representation_root_or_state: Path,
    state_path: Path | None = None,
    *,
    representation: GhidraRepresentation | None = None,
    representations: list[GhidraRepresentation] | None = None,
    dis_representation_root: Path | None = None,
    dec_representation_root: Path | None = None,
    analyze_headless: Path,
    script_root: Path = SCRIPT_ROOT,
    work_root: Path | None = None,
    timeout_per_file_seconds: int | None = None,
    timeout_per_function_seconds: int | None = None,
    analysis_timeout_per_file_seconds: int = 300,
    max_cpu: int = 1,
    process_timeout_seconds: int | None = None,
    workers: int = 1,
    resume: bool = False,
    limit: int | None = None,
    progress_every: int = 10,
    shard_plan_dir: Path | None = None,
    section: int | None = None,
) -> tuple[
    list[GhidraManifestRow] | dict[GhidraRepresentation, list[GhidraManifestRow]], dict[str, Any]
]:
    """Extract requested representations using one shared deterministic source plan."""
    unified_request = representations is not None
    if representations is None:
        if representation is None:
            raise RandsGhidraError("A representation must be requested.")
        if state_path is None:
            raise RandsGhidraError("A state database path is required.")
        representations = [representation]
        representation_root = representation_root_or_state
        actual_state_path = state_path
    else:
        actual_state_path = representation_root_or_state
    requested = list(dict.fromkeys(representations))
    if not requested or any(item not in {"dis", "dec"} for item in requested):
        raise RandsGhidraError("--representations must contain dis, dec, or both.")
    if unified_request:
        return _extract_unified_rands_ghidra(
            dataset_config,
            root,
            actual_state_path,
            representations=tuple(requested),
            dis_representation_root=dis_representation_root,
            dec_representation_root=dec_representation_root,
            analyze_headless=analyze_headless,
            script_root=script_root,
            work_root=work_root,
            timeout_per_file_seconds=timeout_per_file_seconds,
            timeout_per_function_seconds=timeout_per_function_seconds,
            analysis_timeout_per_file_seconds=analysis_timeout_per_file_seconds,
            max_cpu=max_cpu,
            process_timeout_seconds=process_timeout_seconds,
            workers=workers,
            resume=resume,
            limit=limit,
            progress_every=progress_every,
            shard_plan_dir=shard_plan_dir,
            section=section,
        )
    if len(requested) == 1:
        rep = requested[0]
        return _extract_single_rands_ghidra(
            dataset_config,
            root,
            representation_root
            or (dis_representation_root if rep == "dis" else dec_representation_root),
            actual_state_path,
            representation=rep,
            analyze_headless=analyze_headless,
            script_root=script_root,
            work_root=work_root,
            timeout_per_file_seconds=timeout_per_file_seconds,
            timeout_per_function_seconds=timeout_per_function_seconds,
            analysis_timeout_per_file_seconds=analysis_timeout_per_file_seconds,
            max_cpu=max_cpu,
            process_timeout_seconds=process_timeout_seconds,
            workers=workers,
            resume=resume,
            limit=limit,
            progress_every=progress_every,
            shard_plan_dir=shard_plan_dir,
            section=section,
        )
    raise RandsGhidraError("A legacy extraction accepts exactly one representation.")


def _render_manifest(rows: Iterable[GhidraManifestRow]) -> bytes:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=GHIDRA_MANIFEST_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "source_sha256": row.source_sha256,
                "label": row.label,
                "family": row.family,
                "metadata_arch": row.metadata_arch,
                "metadata_packed": int(row.metadata_packed),
                "source_hash_status": row.source_hash_status,
                "extraction_status": row.extraction_status,
                "representation_size": row.representation_size,
                "representation_sha256": row.representation_sha256 or "",
                "representation_relative_path": row.representation_relative_path or "",
                "representation_reused": int(row.representation_reused),
                "runtime_ms": f"{row.runtime_ms:.3f}",
                "snapshot": row.snapshot,
            }
        )
    return handle.getvalue().encode("utf-8")


def write_rands_ghidra_outputs(
    rows: list[GhidraManifestRow] | dict[GhidraRepresentation, list[GhidraManifestRow]],
    summary: dict[str, Any],
    representations_or_manifest: list[GhidraRepresentation] | Path,
    dis_manifest_path: Path | None = None,
    dec_manifest_path: Path | None = None,
    summary_path: Path | None = None,
) -> dict[str, Any]:
    """Write private per-view manifests and one aggregate-only report.

    The four-argument form remains available for existing single-view callers.
    """
    if isinstance(rows, list):
        manifest_path = representations_or_manifest
        if not isinstance(manifest_path, Path) or dis_manifest_path is None:
            raise RandsGhidraError("A manifest and summary path are required for a single view.")
        _validate_manifest_path(manifest_path)
        _validate_summary_path(dis_manifest_path)
        manifest = _render_manifest(rows)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(manifest)
        completed = {
            **summary,
            "manifest": {"rows": len(rows), "sha256": sha256(manifest).hexdigest()},
        }
        dis_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        dis_manifest_path.write_text(
            json.dumps(completed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return completed

    if summary_path is None or not isinstance(representations_or_manifest, list):
        raise RandsGhidraError(
            "Unified extraction requires representations, manifests, and a summary."
        )
    _validate_summary_path(summary_path)
    paths = {"dis": dis_manifest_path, "dec": dec_manifest_path}
    manifest_metadata: dict[str, dict[str, Any]] = {}
    for representation in representations_or_manifest:
        manifest_path = paths[representation]
        if manifest_path is None:
            raise RandsGhidraError(
                f"--{representation}-manifest is required when extracting {representation}."
            )
        _validate_manifest_path(manifest_path)
        manifest = _render_manifest(rows[representation])
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(manifest)
        manifest_metadata[representation] = {
            "rows": len(rows[representation]),
            "sha256": sha256(manifest).hexdigest(),
        }
    completed = {**summary, "manifests": manifest_metadata}
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(completed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return completed


def _load_section_sources(
    shard_plan_dir: Path, section: int
) -> tuple[list[GhidraSource], str, int]:
    """Load section sources from a shard plan."""
    plan_file = shard_plan_dir / "plan.json"
    if not plan_file.exists():
        raise RandsGhidraError(f"Shard plan not found: {plan_file}")
    try:
        plan = json.loads(plan_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RandsGhidraError(f"Invalid shard plan: {plan_file}") from error
    total_sections = plan.get("total_sections")
    if not isinstance(total_sections, int) or total_sections <= 0:
        raise RandsGhidraError(f"Invalid total_sections in shard plan: {total_sections}")
    if section < 1 or section > total_sections:
        raise RandsGhidraError(
            f"--section must be between 1 and {total_sections} (from shard plan)."
        )
    section_file = shard_plan_dir / f"section-{section}.csv"
    if not section_file.exists():
        raise RandsGhidraError(f"Section file not found: {section_file}")
    try:
        with section_file.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            sources = [
                GhidraSource(
                    row["source_sha256"],
                    row["label"],
                    row["family"],
                    row["metadata_arch"],
                    bool(int(row["metadata_packed"])),
                    Path(row["relative_path"]),
                    row["snapshot"],
                )
                for row in reader
            ]
    except (OSError, csv.Error, KeyError, ValueError) as error:
        raise RandsGhidraError(f"Could not read section file: {section_file}") from error
    section_digest = _source_list_digest(sources)
    section_metadata = plan.get("sections", {}).get(str(section), {})
    expected_digest = section_metadata.get("source_list_digest")
    if expected_digest and expected_digest != section_digest:
        raise RandsGhidraError(
            f"Section {section} source list digest mismatch. Plan may have been modified."
        )
    return sources, section_digest, total_sections


def plan_rands_ghidra_shards(
    dataset_config: RandsDatasetConfig,
    root: Path | RandsDatasetLocations,
    *,
    total_sections: int,
    output_dir: Path,
) -> dict[str, Any]:
    """Split I386 metadata sources into one representation-agnostic plan."""
    if total_sections <= 0:
        raise RandsGhidraError("--sections must be a positive integer.")
    locations = (
        root
        if isinstance(root, RandsDatasetLocations)
        else RandsDatasetLocations(raw_root=root, metadata_root=root)
    )
    sources = enumerate_rands_i386_metadata_sources(dataset_config, locations)
    if not sources:
        raise RandsGhidraError("No I386 metadata sources found.")
    output_dir.mkdir(parents=True, exist_ok=True)
    base, remainder = divmod(len(sources), total_sections)
    sections_metadata: dict[str, Any] = {}
    offset = 0
    for section_num in range(1, total_sections + 1):
        section_sources = sources[offset : offset + base + (section_num <= remainder)]
        offset += len(section_sources)
        section_file = output_dir / f"section-{section_num}.csv"
        with section_file.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "source_sha256",
                    "label",
                    "family",
                    "metadata_arch",
                    "metadata_packed",
                    "relative_path",
                    "snapshot",
                ],
                lineterminator="\n",
            )
            writer.writeheader()
            for source in section_sources:
                writer.writerow(
                    {
                        "source_sha256": source.source_sha256,
                        "label": source.label,
                        "family": source.family,
                        "metadata_arch": source.metadata_arch,
                        "metadata_packed": int(source.metadata_packed),
                        "relative_path": source.relative_path.as_posix(),
                        "snapshot": source.snapshot,
                    }
                )
        sections_metadata[str(section_num)] = {
            "source_count": len(section_sources),
            "source_list_digest": _source_list_digest(section_sources),
        }
    plan = {
        "total_sections": total_sections,
        "total_sources": len(sources),
        "snapshot": sources[0].snapshot,
        "full_source_list_digest": _source_list_digest(sources),
        "sections": sections_metadata,
    }
    plan_file = output_dir / "plan.json"
    plan_file.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "total_sections": total_sections,
        "total_sources": len(sources),
        "output_dir": str(output_dir),
        "plan_file": str(plan_file),
    }
