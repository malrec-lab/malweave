"""Resumable static PE architecture and DiE assessment for the full RanDS corpus."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import csv
from dataclasses import dataclass
from functools import partial
from hashlib import sha256
import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
from typing import Any

from malweave.config import PROJECT_ROOT
from malweave.data.dataset_config import RandsDatasetConfig, RandsDatasetLocations
from malweave.data.rands import _validate_manifest_path, hash_file_sha256, inspect_rands

ASSESSMENT_SCHEMA_VERSION = "1"
DIEC_MODES = ("recursive", "deep", "heuristic")
OBFUSCATION_TYPES = frozenset(
    {
        "Packer",
        "Protector",
        "Protection",
        "Crypter",
        "Cryptor",
        "patcher",
        "scrambler",
        "sfx",
        "Archive",
        "Joiner",
    }
)
PE_ASSESSMENT_FIELDS = (
    "source_sha256",
    "label",
    "family",
    "metadata_arch",
    "metadata_packed",
    "source_hash_status",
    "file_status",
    "file_description",
    "pe_architecture",
    "i386_unobfuscated_eligible",
    "die_status",
    "die_obfuscated",
    "die_detected_types",
    "die_modes",
    "tool_error",
    "runtime_ms",
    "source_bytes_read",
    "snapshot",
)


class RandsPeAssessmentError(ValueError):
    """Raised when a PE assessment job cannot safely start or resume."""


@dataclass(frozen=True)
class AssessmentSource:
    """One available source and its provider-supplied descriptive metadata."""

    source_sha256: str
    label: str
    family: str
    metadata_arch: str
    metadata_packed: bool
    relative_path: Path
    snapshot: str


@dataclass(frozen=True)
class PeAssessmentRow:
    """Durable static-assessment result for one source."""

    source_sha256: str
    label: str
    family: str
    metadata_arch: str
    metadata_packed: bool
    source_hash_status: str
    file_status: str
    file_description: str
    pe_architecture: str
    i386_unobfuscated_eligible: str
    die_status: str
    die_obfuscated: str
    die_detected_types: tuple[str, ...]
    die_modes: dict[str, str]
    tool_error: str
    runtime_ms: float
    source_bytes_read: int
    snapshot: str


def _validate_state_path(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if tuple(relative.parts[:2]) != ("data", "processed"):
        raise RandsPeAssessmentError(
            "Assessment state inside the repository must be under data/processed."
        )


def _validate_summary_path(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] != "reports":
        raise RandsPeAssessmentError(
            "Assessment summaries inside the repository must be under reports/."
        )


def _resolve_executable(value: str, label: str) -> str:
    candidate = Path(value).expanduser()
    if candidate.parent != Path("."):
        if candidate.is_file() and candidate.stat().st_mode & 0o111:
            return str(candidate.resolve())
    elif resolved := shutil.which(value):
        return resolved
    raise RandsPeAssessmentError(
        f"Could not locate {label} executable {value!r}. Install it in the isolated worker "
        f"or pass its absolute path."
    )


def _assessment_sources(
    config: RandsDatasetConfig, locations: RandsDatasetLocations
) -> list[AssessmentSource]:
    summary, metadata, present_shas = inspect_rands(config, locations, hash_mode="none")
    if not summary["contract"]["passed"]:
        details = "; ".join(summary["contract"]["mismatches"])
        raise RandsPeAssessmentError(
            f"RanDS release contract failed; resolve the audit findings first: {details}"
        )
    return [
        AssessmentSource(
            record.sha256,
            record.label,
            record.family or "",
            record.arch,
            record.packed,
            record.relative_path,
            config.snapshot,
        )
        for source_sha256, record in sorted(metadata.records.items())
        if source_sha256 in present_shas
    ]


def _source_list_digest(sources: list[AssessmentSource]) -> str:
    digest = sha256()
    for source in sources:
        digest.update(
            f"{source.source_sha256}\t{source.label}\t{source.family}\t"
            f"{source.metadata_arch}\t{int(source.metadata_packed)}\t"
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
    state_path: Path,
    sources: list[AssessmentSource],
    *,
    file_command: str,
    die_command: str,
    file_timeout_seconds: float,
    die_timeout_seconds: float,
    resume: bool,
) -> sqlite3.Connection:
    _validate_state_path(state_path)
    existed = state_path.exists()
    if existed and not resume:
        raise RandsPeAssessmentError(
            "Assessment state already exists; pass --resume to continue that exact job."
        )
    if not existed and resume:
        raise RandsPeAssessmentError(
            "Cannot resume because the assessment state database does not exist."
        )

    connection = _connect_state(state_path)
    digest = _source_list_digest(sources)
    job = {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "snapshot": sources[0].snapshot if sources else "",
        "source_list_digest": digest,
        "source_count": str(len(sources)),
        "file_command": file_command,
        "die_command": die_command,
        "die_modes": ",".join(DIEC_MODES),
        "file_timeout_seconds": str(file_timeout_seconds),
        "die_timeout_seconds": str(die_timeout_seconds),
    }
    if existed:
        try:
            stored = dict(connection.execute("SELECT key, value FROM job").fetchall())
        except sqlite3.DatabaseError as error:
            connection.close()
            raise RandsPeAssessmentError(
                f"Invalid assessment state database: {state_path}"
            ) from error
        if any(stored.get(key) != value for key, value in job.items()):
            connection.close()
            raise RandsPeAssessmentError(
                "Assessment state does not match the audited source list or tool contract. "
                "Start a new job with a new --state-db path."
            )
        return connection

    connection.executescript(
        """
        CREATE TABLE job (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE source (
          source_sha256 TEXT PRIMARY KEY, label TEXT NOT NULL, family TEXT NOT NULL,
          metadata_arch TEXT NOT NULL, metadata_packed INTEGER NOT NULL, relative_path TEXT NOT NULL,
          snapshot TEXT NOT NULL, completed INTEGER NOT NULL DEFAULT 0,
          source_hash_status TEXT, file_status TEXT, file_description TEXT, pe_architecture TEXT,
          i386_unobfuscated_eligible TEXT, die_status TEXT, die_obfuscated TEXT,
          die_detected_types TEXT, die_modes TEXT,
          tool_error TEXT, runtime_ms REAL, source_bytes_read INTEGER
        );
        CREATE INDEX source_pending ON source(completed, source_sha256);
        """
    )
    connection.executemany(
        """
        INSERT INTO source (
          source_sha256, label, family, metadata_arch, metadata_packed, relative_path, snapshot
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
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
    connection.executemany("INSERT INTO job (key, value) VALUES (?, ?)", job.items())
    connection.commit()
    return connection


def _architecture_from_file(description: str) -> str:
    normalized = description.lower()
    if "intel 80386" in normalized or "i386" in normalized:
        return "i386"
    if "x86-64" in normalized or "x86_64" in normalized or "amd64" in normalized:
        return "amd64"
    if "aarch64" in normalized or "arm64" in normalized:
        return "arm64"
    if "arm" in normalized:
        return "arm"
    if "pe" in normalized:
        return "other_pe"
    return "not_pe"


def _find_obfuscation_types(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        type_name = value.get("type")
        if isinstance(type_name, str) and type_name in OBFUSCATION_TYPES:
            found.add(type_name)
        for child in value.values():
            found.update(_find_obfuscation_types(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_find_obfuscation_types(child))
    return found


def _json_from_diec(stdout: str) -> Any:
    start, end = stdout.find("{"), stdout.rfind("}")
    if start < 0 or end < start:
        raise ValueError("missing_json")
    report = json.loads(stdout[start : end + 1])
    if not isinstance(report, dict):
        raise TypeError("unexpected_json_shape")
    return report


def _run_file(command: str, path: Path, timeout_seconds: float) -> tuple[str, str, str]:
    try:
        completed = subprocess.run(
            [command, "-b", str(path)],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return "timeout", "", "file_timeout"
    except OSError:
        return "error", "", "file_error"
    description = completed.stdout.strip()
    if completed.returncode != 0 or not description:
        return "error", "", f"file_exit_{completed.returncode}"
    return "success", description, ""


def _run_diec(
    command: str, path: Path, timeout_seconds: float
) -> tuple[str, str, tuple[str, ...], dict[str, str], str]:
    modes: dict[str, str] = {}
    detected_types: set[str] = set()
    errors: list[str] = []
    for mode in DIEC_MODES:
        try:
            completed = subprocess.run(
                [command, f"--{mode}scan", "--json", str(path)],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            modes[mode] = "timeout"
            errors.append(f"die_{mode}_timeout")
            continue
        except OSError:
            modes[mode] = "error"
            errors.append(f"die_{mode}_error")
            continue
        if completed.returncode != 0:
            modes[mode] = "error"
            errors.append(f"die_{mode}_exit_{completed.returncode}")
            continue
        try:
            report = _json_from_diec(completed.stdout)
        except (TypeError, ValueError):
            modes[mode] = "invalid_json"
            errors.append(f"die_{mode}_invalid_json")
            continue
        modes[mode] = "success"
        detected_types.update(_find_obfuscation_types(report))

    if len(modes) == len(DIEC_MODES) and all(status == "success" for status in modes.values()):
        status = "success"
        obfuscated = "true" if detected_types else "false"
    else:
        status = "incomplete"
        obfuscated = "true" if detected_types else "unknown"
    return status, obfuscated, tuple(sorted(detected_types)), modes, ";".join(errors)


def _i386_unobfuscated_eligibility(architecture: str, die_obfuscated: str) -> str:
    """Mark the upstream i386/unobfuscated cohort without dropping any source."""
    if architecture != "i386":
        return "false" if architecture != "unknown" else "unknown"
    if die_obfuscated == "false":
        return "true"
    if die_obfuscated == "true":
        return "false"
    return "unknown"


def _failure_row(
    source: AssessmentSource,
    *,
    source_hash_status: str,
    tool_error: str,
    runtime_ms: float,
    source_bytes_read: int,
) -> PeAssessmentRow:
    return PeAssessmentRow(
        source.source_sha256,
        source.label,
        source.family,
        source.metadata_arch,
        source.metadata_packed,
        source_hash_status,
        "not_run",
        "",
        "unknown",
        "unknown",
        "not_run",
        "unknown",
        (),
        {},
        tool_error,
        runtime_ms,
        source_bytes_read,
        source.snapshot,
    )


def _assess_one_source(
    raw_root: Path,
    config: RandsDatasetConfig,
    source: AssessmentSource,
    *,
    file_command: str,
    die_command: str,
    file_timeout_seconds: float,
    die_timeout_seconds: float,
) -> PeAssessmentRow:
    started = time.perf_counter()
    path = raw_root / config.samples_dir / source.relative_path
    try:
        digest, source_bytes_read = hash_file_sha256(path)
    except OSError:
        return _failure_row(
            source,
            source_hash_status="read_error",
            tool_error="read_error",
            runtime_ms=(time.perf_counter() - started) * 1000,
            source_bytes_read=0,
        )
    if digest != source.source_sha256:
        return _failure_row(
            source,
            source_hash_status="mismatch",
            tool_error="source_hash_mismatch",
            runtime_ms=(time.perf_counter() - started) * 1000,
            source_bytes_read=source_bytes_read,
        )

    file_status, description, file_error = _run_file(file_command, path, file_timeout_seconds)
    die_status, die_obfuscated, detected_types, modes, die_error = _run_diec(
        die_command, path, die_timeout_seconds
    )
    pe_architecture = (
        _architecture_from_file(description) if file_status == "success" else "unknown"
    )
    return PeAssessmentRow(
        source.source_sha256,
        source.label,
        source.family,
        source.metadata_arch,
        source.metadata_packed,
        "verified",
        file_status,
        description,
        pe_architecture,
        _i386_unobfuscated_eligibility(pe_architecture, die_obfuscated),
        die_status,
        die_obfuscated,
        detected_types,
        modes,
        ";".join(item for item in (file_error, die_error) if item),
        (time.perf_counter() - started) * 1000,
        source_bytes_read,
        source.snapshot,
    )


def _store_attempt(connection: sqlite3.Connection, row: PeAssessmentRow) -> None:
    connection.execute(
        """
        UPDATE source SET completed=1, source_hash_status=?, file_status=?, file_description=?,
          pe_architecture=?, i386_unobfuscated_eligible=?, die_status=?, die_obfuscated=?,
          die_detected_types=?, die_modes=?,
          tool_error=?, runtime_ms=?, source_bytes_read=? WHERE source_sha256=?
        """,
        (
            row.source_hash_status,
            row.file_status,
            row.file_description,
            row.pe_architecture,
            row.i386_unobfuscated_eligible,
            row.die_status,
            row.die_obfuscated,
            ";".join(row.die_detected_types),
            json.dumps(row.die_modes, sort_keys=True, separators=(",", ":")),
            row.tool_error,
            row.runtime_ms,
            row.source_bytes_read,
            row.source_sha256,
        ),
    )
    connection.commit()


def _row_from_state(row: sqlite3.Row) -> PeAssessmentRow:
    return PeAssessmentRow(
        row["source_sha256"],
        row["label"],
        row["family"],
        row["metadata_arch"],
        bool(row["metadata_packed"]),
        row["source_hash_status"],
        row["file_status"],
        row["file_description"],
        row["pe_architecture"],
        row["i386_unobfuscated_eligible"],
        row["die_status"],
        row["die_obfuscated"],
        tuple(filter(None, (row["die_detected_types"] or "").split(";"))),
        json.loads(row["die_modes"] or "{}"),
        row["tool_error"],
        row["runtime_ms"],
        row["source_bytes_read"],
        row["snapshot"],
    )


def _completed_rows(connection: sqlite3.Connection) -> list[PeAssessmentRow]:
    return [
        _row_from_state(row)
        for row in connection.execute(
            "SELECT * FROM source WHERE completed=1 ORDER BY source_sha256"
        )
    ]


def _format_duration(seconds: float) -> str:
    rounded = max(0, round(seconds))
    hours, remainder = divmod(rounded, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:d}:{seconds:02d}"


def _write_progress(connection: sqlite3.Connection, total: int, started: float) -> None:
    completed = connection.execute("SELECT COUNT(*) FROM source WHERE completed=1").fetchone()[0]
    verified = connection.execute(
        "SELECT COUNT(*) FROM source WHERE source_hash_status='verified'"
    ).fetchone()[0]
    die_success = connection.execute(
        "SELECT COUNT(*) FROM source WHERE die_status='success'"
    ).fetchone()[0]
    elapsed = time.perf_counter() - started
    eta = elapsed / completed * (total - completed) if completed else 0.0
    percentage = completed / total * 100 if total else 100.0
    print(
        f"[assess-pe] {completed:,}/{total:,} ({percentage:.1f}%) | hash verified: {verified:,} "
        f"| DiE complete: {die_success:,} | elapsed: {_format_duration(elapsed)} "
        f"| eta: {_format_duration(eta)}",
        file=sys.stderr,
        flush=True,
    )


def _summary(connection: sqlite3.Connection, rows: list[PeAssessmentRow]) -> dict[str, Any]:
    total = connection.execute("SELECT COUNT(*) FROM source").fetchone()[0]

    def counts(attribute: str) -> dict[str, int]:
        return dict(sorted(Counter(getattr(row, attribute) for row in rows).items()))

    return {
        "job": {
            "sources_total": total,
            "sources_completed": len(rows),
            "sources_pending": total - len(rows),
            "complete": total == len(rows),
        },
        "sources": {
            "source_hash_statuses": counts("source_hash_status"),
            "source_bytes_read": sum(row.source_bytes_read for row in rows),
        },
        "file": {"statuses": counts("file_status"), "architectures": counts("pe_architecture")},
        "i386_unobfuscated_eligible": counts("i386_unobfuscated_eligible"),
        "die": {
            "statuses": counts("die_status"),
            "obfuscated": counts("die_obfuscated"),
            "detected_types": dict(
                sorted(Counter(kind for row in rows for kind in row.die_detected_types).items())
            ),
        },
        "metadata_comparison": {
            "metadata_packed": {
                "false": sum(not row.metadata_packed for row in rows),
                "true": sum(row.metadata_packed for row in rows),
            },
            "metadata_architectures": dict(
                sorted(Counter(row.metadata_arch for row in rows).items())
            ),
        },
        "runtime_ms_total": round(sum(row.runtime_ms for row in rows), 3),
    }


def assess_rands_pe(
    config: RandsDatasetConfig,
    locations: RandsDatasetLocations,
    state_path: Path,
    *,
    file_command: str = "file",
    die_command: str = "diec",
    file_timeout_seconds: float = 10.0,
    die_timeout_seconds: float = 10.0,
    workers: int = 1,
    resume: bool = False,
    limit: int | None = None,
    progress_every: int = 100,
) -> tuple[list[PeAssessmentRow], dict[str, Any]]:
    """Assess all audited sources without choosing or dropping a future training cohort."""
    if workers < 1 or progress_every < 1:
        raise RandsPeAssessmentError("workers and progress_every must be positive.")
    if limit is not None and limit < 1:
        raise RandsPeAssessmentError("limit must be positive when provided.")
    if file_timeout_seconds <= 0 or die_timeout_seconds <= 0:
        raise RandsPeAssessmentError("Tool timeouts must be positive.")

    resolved_file = _resolve_executable(file_command, "file")
    resolved_diec = _resolve_executable(die_command, "DiE")
    sources = _assessment_sources(config, locations)
    connection = _initialize_state(
        state_path,
        sources,
        file_command=resolved_file,
        die_command=resolved_diec,
        file_timeout_seconds=file_timeout_seconds,
        die_timeout_seconds=die_timeout_seconds,
        resume=resume,
    )
    try:
        pending = [
            AssessmentSource(
                row["source_sha256"],
                row["label"],
                row["family"],
                row["metadata_arch"],
                bool(row["metadata_packed"]),
                Path(row["relative_path"]),
                row["snapshot"],
            )
            for row in connection.execute(
                "SELECT * FROM source WHERE completed=0 ORDER BY source_sha256"
            )
        ]
        if limit is not None:
            pending = pending[:limit]
        started = time.perf_counter()
        assess_source = partial(
            _assess_one_source,
            locations.raw_root,
            config,
            file_command=resolved_file,
            die_command=resolved_diec,
            file_timeout_seconds=file_timeout_seconds,
            die_timeout_seconds=die_timeout_seconds,
        )
        with ThreadPoolExecutor(max_workers=workers) as executor:
            attempts = executor.map(assess_source, pending)
            for index, row in enumerate(attempts, start=1):
                _store_attempt(connection, row)
                if index % progress_every == 0 or index == len(pending):
                    _write_progress(connection, len(sources), started)
        rows = _completed_rows(connection)
        return rows, _summary(connection, rows)
    finally:
        connection.close()


def write_rands_pe_assessment_outputs(
    rows: list[PeAssessmentRow], summary: dict[str, Any], manifest_path: Path, summary_path: Path
) -> dict[str, Any]:
    """Write the private per-source assessment manifest and public-safe aggregate summary."""
    _validate_manifest_path(manifest_path)
    _validate_summary_path(summary_path)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=PE_ASSESSMENT_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "source_sha256": row.source_sha256,
                "label": row.label,
                "family": row.family,
                "metadata_arch": row.metadata_arch,
                "metadata_packed": str(row.metadata_packed).lower(),
                "source_hash_status": row.source_hash_status,
                "file_status": row.file_status,
                "file_description": row.file_description,
                "pe_architecture": row.pe_architecture,
                "i386_unobfuscated_eligible": row.i386_unobfuscated_eligible,
                "die_status": row.die_status,
                "die_obfuscated": row.die_obfuscated,
                "die_detected_types": ";".join(row.die_detected_types),
                "die_modes": json.dumps(row.die_modes, sort_keys=True, separators=(",", ":")),
                "tool_error": row.tool_error,
                "runtime_ms": f"{row.runtime_ms:.3f}",
                "source_bytes_read": row.source_bytes_read,
                "snapshot": row.snapshot,
            }
        )
    payload = output.getvalue().encode()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(payload)
    completed = {**summary, "manifest": {"rows": len(rows), "sha256": sha256(payload).hexdigest()}}
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(completed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return completed
