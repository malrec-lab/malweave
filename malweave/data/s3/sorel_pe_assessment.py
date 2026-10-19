"""Bounded, resumable static assessment for a private SOREL pilot."""

from __future__ import annotations

from collections import Counter
import csv
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
from typing import Any
import zlib

from botocore.exceptions import BotoCoreError, ClientError

from malweave.data.s3.inventory import S3InventoryError, validate_private_path
from malweave.data.s3.sorel import (
    SOREL_BINARIES_PREFIX,
    SOREL_BUCKET,
    SOREL_SHA256_PATTERN,
    make_unsigned_s3_client,
)

DIEC_MODES = ("recursivescan", "deepscan", "heuristicscan")
OBFUSCATION_TYPES = frozenset(
    {
        "packer",
        "protector",
        "protection",
        "crypter",
        "cryptor",
        "patcher",
        "scrambler",
        "sfx",
        "archive",
        "joiner",
    }
)
OUTPUT_FIELDS = (
    "selection_order",
    "source_sha256",
    "is_malware",
    "packed",
    "rl_fs_t",
    "first_seen_utc",
    "object_key",
    "object_etag",
    "compressed_bytes",
    "released_bytes",
    "released_bytes_sha256",
    "zlib_status",
    "file_status",
    "file_description",
    "architecture",
    "architecture_status",
    "die_status",
    "die_obfuscated",
    "die_detected_types",
    "die_modes",
    "paper_cohort_status",
    "assessment_status",
    "error",
    "runtime_seconds",
)


def _sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _find_types(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        kind = value.get("type")
        if isinstance(kind, str) and kind.casefold() in OBFUSCATION_TYPES:
            found.add(kind)
        for child in value.values():
            found.update(_find_types(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_find_types(child))
    return found


def _parse_diec(stdout: str) -> dict[str, Any]:
    start, end = stdout.find("{"), stdout.rfind("}")
    if start < 0 or end < start:
        raise ValueError("diec_json_missing")
    value = json.loads(stdout[start : end + 1])
    if not isinstance(value, dict):
        raise TypeError("diec_json_shape")
    return value


def _run_file(path: Path, timeout: float) -> tuple[str, str, str, str]:
    try:
        result = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "timeout", "", "unknown", "file_timeout"
    except OSError:
        return "error", "", "unknown", "file_error"
    description = result.stdout.strip()
    if result.returncode or not description:
        return "error", description, "unknown", f"file_exit_{result.returncode}"
    lower = description.casefold()
    if "intel 80386" in lower or "i386" in lower:
        architecture = "i386"
    elif any(token in lower for token in ("x86-64", "x86_64", "amd64")):
        architecture = "amd64"
    elif "aarch64" in lower or "arm64" in lower:
        architecture = "arm64"
    elif "arm" in lower:
        architecture = "arm"
    else:
        architecture = "unknown"
    return "success", description, architecture, ""


def _run_diec(path: Path, timeout: float) -> tuple[str, str, str, dict[str, str], str]:
    modes: dict[str, str] = {}
    found: set[str] = set()
    errors: list[str] = []
    for mode in DIEC_MODES:
        try:
            result = subprocess.run(
                ["diec", f"--{mode}", "--json", str(path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            modes[mode] = "timeout"
            errors.append(f"die_{mode}_timeout")
            continue
        except OSError:
            modes[mode] = "error"
            errors.append(f"die_{mode}_error")
            continue
        if result.returncode:
            modes[mode] = "error"
            errors.append(f"die_{mode}_exit_{result.returncode}")
            continue
        try:
            parsed = _parse_diec(result.stdout)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            modes[mode] = "invalid_json"
            errors.append(str(error))
            continue
        modes[mode] = "success"
        found.update(_find_types(parsed))
    complete = len(modes) == len(DIEC_MODES) and all(v == "success" for v in modes.values())
    status = "success" if complete else "incomplete"
    obfuscated = "true" if found else "false" if complete else "unknown"
    return status, obfuscated, ";".join(sorted(found)), modes, ";".join(errors)


def _decompress_to_file(
    compressed: bytes, path: Path, *, max_output_bytes: int
) -> tuple[int, str, str]:
    decoder = zlib.decompressobj()
    output_hash = sha256()
    output_size = 0
    try:
        with path.open("xb") as target:
            for offset in range(0, len(compressed), 64 * 1024):
                pending = compressed[offset : offset + 64 * 1024]
                while pending:
                    room = max_output_bytes - output_size
                    block = decoder.decompress(pending, room + 1)
                    pending = decoder.unconsumed_tail
                    output_size += len(block)
                    if output_size > max_output_bytes:
                        raise ValueError("decompressed_size_limit")
                    target.write(block)
                    output_hash.update(block)
            tail = decoder.flush(max_output_bytes - output_size + 1)
            output_size += len(tail)
            if output_size > max_output_bytes:
                raise ValueError("decompressed_size_limit")
            target.write(tail)
            output_hash.update(tail)
        if not decoder.eof:
            raise ValueError("zlib_stream_incomplete")
        if decoder.unused_data:
            raise ValueError("zlib_trailing_data")
    except (zlib.error, OSError, ValueError) as error:
        path.unlink(missing_ok=True)
        return output_size, "failed", str(error)
    return output_size, "success", output_hash.hexdigest()


def _initialize_state(
    state_path: Path,
    source_digest: str,
    *,
    resume: bool,
    max_compressed: int,
    max_decompressed: int,
    die_version: str,
) -> sqlite3.Connection:
    validate_private_path(state_path)
    exists = state_path.exists()
    if exists != resume:
        raise S3InventoryError("Use --resume only with the existing assessment state.")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(state_path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    settings = {
        "source_digest": source_digest,
        "max_compressed_bytes": str(max_compressed),
        "max_decompressed_bytes": str(max_decompressed),
        "die_version": die_version,
        "die_modes": ",".join(DIEC_MODES),
    }
    if exists:
        stored = dict(db.execute("SELECT name, value FROM settings"))
        if stored != settings:
            db.close()
            raise S3InventoryError("Resume inputs or tool contract changed; use a new state DB.")
        return db
    db.executescript("""
      CREATE TABLE settings(name TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE outcomes(
        selection_order INTEGER PRIMARY KEY, source_sha256 TEXT UNIQUE NOT NULL,
        input_json TEXT NOT NULL, result_json TEXT NOT NULL, completed INTEGER NOT NULL
      );
    """)
    db.executemany("INSERT INTO settings VALUES (?, ?)", settings.items())
    db.commit()
    return db


def _assess_one(
    client: Any, row: dict[str, str], *, max_compressed: int, max_decompressed: int, timeout: float
) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {**row}
    result.update(
        {
            "released_bytes": 0,
            "released_bytes_sha256": "",
            "zlib_status": "not_run",
            "file_status": "not_run",
            "file_description": "",
            "architecture": "unknown",
            "architecture_status": "unknown",
            "die_status": "not_run",
            "die_obfuscated": "unknown",
            "die_detected_types": "",
            "die_modes": "{}",
            "paper_cohort_status": "unknown",
            "assessment_status": "failed",
            "error": "",
            "runtime_seconds": 0.0,
        }
    )
    try:
        expected_size = int(row["object_size"])
        if not 0 < expected_size <= max_compressed:
            raise ValueError("compressed_size_limit")
        response = client.get_object(
            Bucket=SOREL_BUCKET, Key=row["object_key"], IfMatch=row["object_etag"]
        )
        body = response["Body"]
        chunks: list[bytes] = []
        received = 0
        try:
            while chunk := body.read(1024 * 1024):
                received += len(chunk)
                if received > expected_size:
                    raise ValueError("compressed_size_overrun")
                chunks.append(chunk)
        finally:
            body.close()
        if received != expected_size or response.get("ETag") != row["object_etag"]:
            raise ValueError("remote_object_identity_changed")
        compressed = b"".join(chunks)
        result["compressed_bytes"] = received
        with tempfile.TemporaryDirectory(prefix="sorel-static-") as temp_dir:
            sample = Path(temp_dir) / "sample.pe"
            size, zlib_status, digest_or_error = _decompress_to_file(
                compressed, sample, max_output_bytes=max_decompressed
            )
            result["released_bytes"] = size
            result["zlib_status"] = zlib_status
            if zlib_status != "success":
                result["error"] = digest_or_error
            else:
                result["released_bytes_sha256"] = digest_or_error
                file_status, description, architecture, file_error = _run_file(sample, timeout)
                result["file_status"] = file_status
                result["file_description"] = description
                result["architecture"] = architecture
                result["architecture_status"] = (
                    "identified"
                    if architecture != "unknown"
                    else "unknown_disarmed_or_unrecognized"
                )
                die_status, obfuscated, types, modes, die_error = _run_diec(sample, timeout)
                result["die_status"] = die_status
                result["die_obfuscated"] = obfuscated
                result["die_detected_types"] = types
                result["die_modes"] = json.dumps(modes, sort_keys=True, separators=(",", ":"))
                if architecture == "i386" and obfuscated == "false":
                    result["paper_cohort_status"] = "eligible_candidate"
                elif architecture != "i386" and architecture != "unknown":
                    result["paper_cohort_status"] = "excluded_non_i386"
                elif obfuscated == "true":
                    result["paper_cohort_status"] = "excluded_obfuscated"
                else:
                    result["paper_cohort_status"] = "unknown"
                result["assessment_status"] = "complete" if die_status == "success" else "partial"
                errors = [value for value in (file_error, die_error) if value]
                result["error"] = ";".join(errors)
    except (BotoCoreError, ClientError, OSError, ValueError, TypeError) as error:
        result["error"] = f"{type(error).__name__}:{error}"
    result["runtime_seconds"] = round(time.monotonic() - started, 3)
    return result


def assess_sorel_pilot(
    input_csv: Path,
    input_summary: Path,
    output_csv: Path,
    summary_path: Path,
    state_path: Path,
    *,
    count: int = 1000,
    resume: bool = False,
    max_compressed_bytes: int = 300 * 1024 * 1024,
    max_decompressed_bytes: int = 1024 * 1024 * 1024,
    timeout_seconds: float = 10.0,
    progress_every: int = 10,
) -> dict[str, Any]:
    """Fetch and statically classify a bounded SOREL metadata pilot, with durable progress."""
    for path, is_summary in ((output_csv, False), (state_path, False), (summary_path, True)):
        validate_private_path(path, summary=is_summary)
    if count < 1 or timeout_seconds <= 0 or progress_every < 1:
        raise S3InventoryError("count, timeouts and progress interval must be positive.")
    if (
        len(
            {p.resolve() for p in (input_csv, input_summary, output_csv, summary_path, state_path)}
        )
        != 5
    ):
        raise S3InventoryError("Inputs and outputs must have distinct paths.")
    if output_csv.exists() or summary_path.exists():
        raise S3InventoryError("Assessment outputs exist; use new output paths.")
    source_report = json.loads(input_summary.read_text(encoding="utf-8"))
    expected_csv_digest = source_report.get("output_sha256")
    if not expected_csv_digest or _sha256(input_csv) != expected_csv_digest:
        raise S3InventoryError("Metadata audit CSV digest differs from its summary.")
    rows: list[dict[str, str]] = []
    with input_csv.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for number, row in enumerate(reader, 1):
            identity = row.get("source_sha256", "")
            if number > count:
                break
            if (
                row.get("metadata_join_status") != "matched"
                or row.get("bucket") != SOREL_BUCKET
                or row.get("object_key") != SOREL_BINARIES_PREFIX + identity
                or not SOREL_SHA256_PATTERN.fullmatch(identity)
                or row.get("snapshot_id") != source_report.get("source_snapshot_id")
            ):
                raise S3InventoryError(f"Invalid or mismatched input provenance at row {number}.")
            rows.append(
                {
                    key: row.get(key, "")
                    for key in (
                        "selection_order",
                        "source_sha256",
                        "is_malware",
                        "packed",
                        "rl_fs_t",
                        "first_seen_utc",
                        "object_key",
                        "object_etag",
                        "object_size",
                        "snapshot_id",
                    )
                }
            )
            rows[-1]["selection_order"] = str(number)
    if len(rows) != count:
        raise S3InventoryError("Metadata audit CSV has fewer selected rows than requested.")
    if any(row["is_malware"] != "1" or not row["object_etag"] for row in rows):
        raise S3InventoryError("Expected malware labels and nonempty source ETags.")
    source_digest = sha256("\n".join(r["source_sha256"] for r in rows).encode()).hexdigest()
    try:
        version = subprocess.run(
            ["diec", "--version"], capture_output=True, text=True, timeout=5, check=False
        )
        if version.returncode != 0:
            raise OSError("diec version check failed")
        die_version = version.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        raise S3InventoryError("diec is required; install it and ensure it is on PATH.") from error
    db = _initialize_state(
        state_path,
        source_digest,
        resume=resume,
        max_compressed=max_compressed_bytes,
        max_decompressed=max_decompressed_bytes,
        die_version=die_version,
    )
    client = make_unsigned_s3_client(max_pool_connections=2)
    try:
        existing = {row[0] for row in db.execute("SELECT source_sha256 FROM outcomes")}
        for index, row in enumerate(rows, 1):
            if row["source_sha256"] not in existing:
                assessed = _assess_one(
                    client,
                    row,
                    max_compressed=max_compressed_bytes,
                    max_decompressed=max_decompressed_bytes,
                    timeout=timeout_seconds,
                )
                result_copy = {key: assessed.get(key, "") for key in OUTPUT_FIELDS}
                db.execute(
                    "INSERT INTO outcomes VALUES (?, ?, ?, ?, 1)",
                    (
                        index,
                        row["source_sha256"],
                        json.dumps(row, sort_keys=True),
                        json.dumps(result_copy, sort_keys=True),
                    ),
                )
                db.commit()
            if index % progress_every == 0 or index == count:
                complete = db.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0]
                print(f"[sorel-static] {complete}/{count} records assessed", flush=True)
        results = [
            json.loads(row[0])
            for row in db.execute("SELECT result_json FROM outcomes ORDER BY selection_order")
        ]
    finally:
        db.close()
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("x", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(results)
    counts = {
        field: dict(sorted(Counter(str(r[field]) for r in results).items()))
        for field in (
            "assessment_status",
            "zlib_status",
            "file_status",
            "architecture",
            "die_status",
            "die_obfuscated",
            "paper_cohort_status",
        )
    }
    report = {
        "dataset": "SOREL-20M",
        "scope": "bounded static pilot; no sample execution",
        "selected_rows": count,
        "statuses": counts,
        "packed_metadata_nonzero": sum(float(r["packed"] or 0) > 0 for r in rows),
        "released_bytes_total": sum(int(r["released_bytes"]) for r in results),
        "released_bytes_sha256_values_are_disarmed_content": True,
        "source_sha256_identifies_original_pre_disarm_file": True,
        "x86_limit": "SOREL sets PE FileHeader.Machine to 0; unidentified architecture stays unknown",
        "packed_policy": "meta.db packed count is retained separately; eligibility uses static DiE only",
        "tool": {
            "diec_version": die_version,
            "die_modes": list(DIEC_MODES),
            "file": shutil.which("file"),
        },
        "limits": {
            "max_compressed_bytes_per_object": max_compressed_bytes,
            "max_decompressed_bytes_per_object": max_decompressed_bytes,
            "timeout_seconds_per_tool_mode": timeout_seconds,
        },
        "source_metadata_audit_sha256": expected_csv_digest,
        "output_sha256": _sha256(output_csv),
        "all_objects_version_pinned": False,
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return report
