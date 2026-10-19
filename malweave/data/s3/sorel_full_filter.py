"""Full-corpus SOREL filtering with metadata preselection and resumable static scans."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import csv
import fcntl
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
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
    write_json_atomic,
)
from malweave.data.s3.sorel_pe_assessment import (
    DIEC_MODES,
    _run_diec,
    _run_file,
)

CANDIDATE_FIELDS = (
    "selection_order",
    "source_sha256",
    "bucket",
    "object_key",
    "object_size",
    "object_etag",
    "object_last_modified",
    "is_malware",
    "packed",
    "rl_fs_t",
    "snapshot_id",
)
RESULT_FIELDS = (
    *CANDIDATE_FIELDS,
    "compressed_bytes",
    "released_bytes",
    "released_bytes_sha256",
    "zlib_status",
    "file_status",
    "file_description",
    "architecture",
    "die_status",
    "die_obfuscated",
    "die_detected_types",
    "die_modes",
    "assessment_status",
    "error",
    "runtime_seconds",
)


def _digest(path: Path) -> str:
    value = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _decompress_body_to_file(
    body: Any,
    path: Path,
    *,
    max_compressed: int,
    max_output: int,
) -> tuple[int, int, str, str]:
    """Stream one S3 zlib object to a bounded temporary file without buffering it all."""
    decoder = zlib.decompressobj()
    output_hash = sha256()
    compressed_size = output_size = 0
    try:
        with path.open("xb") as target:
            while block := body.read(1024 * 1024):
                compressed_size += len(block)
                if compressed_size > max_compressed:
                    raise ValueError("compressed_size_limit")
                pending = block
                while pending:
                    room = max_output - output_size
                    decoded = decoder.decompress(pending, room + 1)
                    pending = decoder.unconsumed_tail
                    output_size += len(decoded)
                    if output_size > max_output:
                        raise ValueError("decompressed_size_limit")
                    target.write(decoded)
                    output_hash.update(decoded)
            tail = decoder.flush(max_output - output_size + 1)
            output_size += len(tail)
            if output_size > max_output:
                raise ValueError("decompressed_size_limit")
            target.write(tail)
            output_hash.update(tail)
        if not decoder.eof:
            raise ValueError("zlib_stream_incomplete")
        if decoder.unused_data:
            raise ValueError("zlib_trailing_data")
    except (zlib.error, OSError, ValueError) as error:
        path.unlink(missing_ok=True)
        return compressed_size, output_size, "failed", str(error)
    return compressed_size, output_size, "success", output_hash.hexdigest()


def _read_candidate_with_retries(
    row: dict[str, str],
    *,
    client: Any,
    path: Path,
    max_compressed: int,
    max_output: int,
    attempts: int = 3,
) -> tuple[int, int, str, str, str]:
    """Fetch and decompress an S3 object, retrying short or transient reads."""
    expected_size = int(row["object_size"])
    last_error = ""
    received = output_size = 0
    zlib_status = "failed"
    for attempt in range(1, attempts + 1):
        body = None
        keep_sample = False
        try:
            response = client.get_object(
                Bucket=SOREL_BUCKET, Key=row["object_key"], IfMatch=row["object_etag"]
            )
            body = response["Body"]
            if response.get("ETag") != row["object_etag"]:
                return 0, 0, "failed", "", "remote_object_identity_changed"
            received, output_size, zlib_status, digest_or_error = _decompress_body_to_file(
                body,
                path,
                max_compressed=max_compressed,
                max_output=max_output,
            )
            if received == expected_size:
                keep_sample = zlib_status == "success"
                return (
                    received,
                    output_size,
                    zlib_status,
                    digest_or_error if zlib_status == "success" else "",
                    "" if zlib_status == "success" else digest_or_error,
                )
            last_error = f"remote_object_size_mismatch:{received}/{expected_size}"
        except (BotoCoreError, ClientError, OSError) as error:
            retryable = True
            if isinstance(error, ClientError):
                code = str(error.response.get("Error", {}).get("Code", ""))
                retryable = code in {
                    "InternalError",
                    "RequestTimeout",
                    "ServiceUnavailable",
                    "SlowDown",
                    "500",
                    "502",
                    "503",
                    "504",
                }
            last_error = f"{type(error).__name__}:{error}"
            if not retryable:
                break
        finally:
            if body is not None:
                body.close()
            if not keep_sample:
                path.unlink(missing_ok=True)
        if attempt < attempts:
            time.sleep(0.25 * attempt)
    return received, output_size, "failed", "", f"{last_error}; attempts={attempts}"


def _validate_dirs(output: Path, summary: Path, state: Path | None = None) -> None:
    validate_private_path(output)
    validate_private_path(summary, summary=True)
    if state is not None:
        validate_private_path(state)


def prepare_sorel_packed_candidates(
    sources: Path,
    snapshot_summary: Path,
    metadata: Path,
    pilot_csv: Path,
    pilot_summary: Path,
    output: Path,
    summary: Path,
) -> dict[str, Any]:
    """Join all frozen S3 keys to meta.db and write only packed-count-zero sources."""
    for path in (sources, snapshot_summary, metadata, pilot_csv, pilot_summary, output, summary):
        if not path.is_file() and path in (
            sources,
            snapshot_summary,
            metadata,
            pilot_csv,
            pilot_summary,
        ):
            raise S3InventoryError(f"Required SOREL input does not exist: {path}")
    _validate_dirs(output, summary)
    if (
        len(
            {
                p.resolve()
                for p in (
                    sources,
                    snapshot_summary,
                    metadata,
                    pilot_csv,
                    pilot_summary,
                    output,
                    summary,
                )
            }
        )
        != 7
    ):
        raise S3InventoryError("Inputs and outputs must use distinct paths.")
    if output.exists() or summary.exists():
        raise S3InventoryError("Candidate outputs exist; refusing to overwrite.")

    snapshot = json.loads(snapshot_summary.read_text(encoding="utf-8"))
    pilot = json.loads(pilot_summary.read_text(encoding="utf-8"))
    pilot_count = int(pilot.get("selected_rows", 0))
    pilot_passed = (
        pilot.get("scope") == "bounded static pilot; no sample execution"
        and pilot_count > 0
        and pilot.get("statuses", {}).get("zlib_status", {}).get("success") == pilot_count
        and pilot.get("statuses", {}).get("file_status", {}).get("success") == pilot_count
        and pilot.get("statuses", {}).get("die_status", {}).get("success") == pilot_count
        and pilot.get("statuses", {}).get("assessment_status", {}).get("complete") == pilot_count
        and pilot.get("output_sha256") == _digest(pilot_csv)
    )
    if not pilot_passed:
        raise S3InventoryError("The bounded static release-audit pilot did not pass.")
    expected = snapshot.get("manifest", {})
    if (
        snapshot.get("dataset") != "SOREL-20M"
        or snapshot.get("bucket") != SOREL_BUCKET
        or snapshot.get("prefix") != SOREL_BINARIES_PREFIX
        or snapshot.get("snapshot_id") != expected.get("sha256")
        or _digest(sources) != expected.get("sha256")
        or sources.stat().st_size != expected.get("bytes")
    ):
        raise S3InventoryError("Source listing does not match the frozen SOREL snapshot.")

    metadata_digest = _digest(metadata)
    counts: Counter[str] = Counter()
    compressed = Counter()
    output.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(metadata.resolve().as_uri() + "?mode=ro", uri=True)
    temp_path = output.with_name(f".{output.name}.partial")
    if temp_path.exists():
        db.close()
        raise S3InventoryError(
            "A partial candidate file already exists; inspect it before continuing."
        )
    try:
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise S3InventoryError("meta.db quick_check failed.")
        columns = {row[1] for row in db.execute("PRAGMA table_info(meta)")}
        if not {"sha256", "is_malware", "packed", "rl_fs_t"}.issubset(columns):
            raise S3InventoryError("meta.db does not contain required join fields.")
        indexes = []
        for item in db.execute("PRAGMA index_list(meta)"):
            name = item[1].replace('"', '""')
            indexes.append([row[2] for row in db.execute(f'PRAGMA index_info("{name}")')])
        if not any(index and index[0] == "sha256" for index in indexes):
            raise S3InventoryError("meta.db requires an existing sha256 index.")
        metadata_before = metadata_digest
        query = "SELECT is_malware, packed, rl_fs_t FROM meta WHERE sha256 = ? LIMIT 2"
        previous_key = ""
        with (
            sources.open(newline="", encoding="utf-8") as source,
            temp_path.open("x", newline="", encoding="utf-8-sig") as target,
        ):
            reader = csv.DictReader(source)
            if tuple(reader.fieldnames or ()) != (
                "object_key",
                "object_size",
                "object_etag",
                "object_last_modified",
            ):
                raise S3InventoryError("Unexpected frozen source schema.")
            writer = csv.DictWriter(target, fieldnames=CANDIDATE_FIELDS, lineterminator="\n")
            writer.writeheader()
            for row in reader:
                counts["source_objects"] += 1
                if counts["source_objects"] % 500_000 == 0:
                    print(
                        f"[sorel-full-filter] metadata_join={counts['source_objects']}/"
                        f"{expected.get('rows')} packed_zero={counts['packed_zero_candidates']}",
                        file=sys.stderr,
                        flush=True,
                    )
                key = row["object_key"]
                if (
                    None in row
                    or any(value is None for value in row.values())
                    or key <= previous_key
                    or not key.startswith(SOREL_BINARIES_PREFIX)
                    or not SOREL_SHA256_PATTERN.fullmatch(key[len(SOREL_BINARIES_PREFIX) :])
                ):
                    raise S3InventoryError("Malformed, duplicate, or unordered S3 source row.")
                previous_key = key
                try:
                    size = int(row["object_size"])
                except (ValueError, TypeError) as error:
                    raise S3InventoryError(
                        "Invalid object size in frozen source listing."
                    ) from error
                if size <= 0 or not row["object_etag"]:
                    raise S3InventoryError("Source listing contains invalid size or missing ETag.")
                counts["source_compressed_bytes"] += size
                hits = db.execute(query, (key[len(SOREL_BINARIES_PREFIX) :],)).fetchall()
                if len(hits) != 1:
                    counts["metadata_missing_or_duplicate"] += 1
                    continue
                label, packed, first_seen = hits[0]
                if label != 1 or packed is None or packed < 0 or first_seen is None:
                    counts["invalid_metadata"] += 1
                    continue
                counts["metadata_matched_malware"] += 1
                if packed == 0:
                    counts["packed_zero_candidates"] += 1
                    compressed["packed_zero_candidate_bytes"] += size
                    writer.writerow(
                        {
                            "selection_order": counts["packed_zero_candidates"],
                            "source_sha256": key[len(SOREL_BINARIES_PREFIX) :],
                            "bucket": SOREL_BUCKET,
                            "object_key": key,
                            **row,
                            "is_malware": label,
                            "packed": packed,
                            "rl_fs_t": first_seen,
                            "snapshot_id": snapshot["snapshot_id"],
                        }
                    )
                else:
                    counts["packed_nonzero_excluded"] += 1
            target.flush()
        if counts["source_objects"] != expected.get("rows"):
            raise S3InventoryError("Source row count differs from frozen snapshot.")
        if (
            counts["metadata_matched_malware"]
            + counts["metadata_missing_or_duplicate"]
            + counts["invalid_metadata"]
            != counts["source_objects"]
        ):
            raise S3InventoryError("Full-corpus metadata accounting is incomplete.")
        if counts["metadata_missing_or_duplicate"] or counts["invalid_metadata"]:
            raise S3InventoryError(
                "Release audit failed: metadata missing, duplicate, or invalid rows were found."
            )
        if counts["source_compressed_bytes"] != snapshot.get("total_object_bytes"):
            raise S3InventoryError("Source byte total differs from frozen snapshot.")
        if _digest(metadata) != metadata_before:
            raise S3InventoryError("meta.db changed during the full-corpus metadata audit.")
        temp_path.replace(output)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
    finally:
        db.close()

    result = {
        "dataset": "SOREL-20M",
        "release": snapshot.get("release"),
        "scope": "complete frozen S3 listing joined to local SOREL metadata; packed prefilter only",
        "release_audit_passed": True,
        "snapshot_id": snapshot["snapshot_id"],
        "sources_sha256": expected["sha256"],
        "metadata_sha256": metadata_digest,
        "pilot_csv_sha256": _digest(pilot_csv),
        "pilot_assessment_sha256": pilot.get("output_sha256"),
        "pilot_release_audit_passed": True,
        "candidate_manifest_sha256": _digest(output),
        "counts": dict(counts),
        "candidate_compressed_bytes": compressed["packed_zero_candidate_bytes"],
        "remote_versions_pinned": False,
        "binary_bytes_read": False,
        "filter": "meta.db packed count equals zero; obfuscation requires subsequent DiE scan",
        "failure_policy": "metadata missing, duplicate, or invalid is a release-audit failure",
    }
    write_json_atomic(summary, result)
    return result


def _assess_candidate(
    row: dict[str, str],
    *,
    client: Any,
    max_compressed: int,
    max_decompressed: int,
    timeout: float,
) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {**row}
    result.update(
        {
            "compressed_bytes": 0,
            "released_bytes": 0,
            "released_bytes_sha256": "",
            "zlib_status": "not_run",
            "file_status": "not_run",
            "file_description": "",
            "architecture": "unknown",
            "die_status": "not_run",
            "die_obfuscated": "unknown",
            "die_detected_types": "",
            "die_modes": "{}",
            "assessment_status": "failed",
            "error": "",
        }
    )
    try:
        if int(row["packed"]) != 0:
            result["assessment_status"] = "excluded_packed"
            return result
        expected_size = int(row["object_size"])
        if not 0 < expected_size <= max_compressed:
            raise ValueError("compressed_size_limit")
        with tempfile.TemporaryDirectory(prefix="sorel-full-filter-") as folder:
            sample = Path(folder) / "sample.pe"
            received, size, zlib_status, digest, read_error = _read_candidate_with_retries(
                row,
                client=client,
                path=sample,
                max_compressed=max_compressed,
                max_output=max_decompressed,
            )
            result["compressed_bytes"] = received
            result["released_bytes"] = size
            result["zlib_status"] = zlib_status
            if read_error and zlib_status == "failed":
                result["error"] = read_error
                return result
            if zlib_status != "success":
                result["error"] = read_error or "zlib_decompression_failed"
            else:
                result["released_bytes_sha256"] = digest
                file_status, description, architecture, file_error = _run_file(sample, timeout)
                result["file_status"] = file_status
                result["file_description"] = description
                result["architecture"] = architecture
                if file_status != "success":
                    result["assessment_status"] = "partial"
                    result["error"] = file_error or "file_detection_failed"
                    return result
                if "PE32 executable" not in description:
                    result["assessment_status"] = "excluded_not_pe32"
                    return result
                die_status, obfuscated, types, modes, die_error = _run_diec(sample, timeout)
                result["die_status"] = die_status
                result["die_obfuscated"] = obfuscated
                result["die_detected_types"] = types
                result["die_modes"] = json.dumps(modes, sort_keys=True, separators=(",", ":"))
                result["assessment_status"] = "complete" if die_status == "success" else "partial"
                result["error"] = ";".join(value for value in (file_error, die_error) if value)
    except (BotoCoreError, ClientError, OSError, ValueError, TypeError) as error:
        result["error"] = f"{type(error).__name__}:{error}"
    finally:
        result["runtime_seconds"] = round(time.monotonic() - started, 3)
    return result


def assess_sorel_full_candidates(
    candidate_csv: Path,
    candidate_summary: Path,
    output_csv: Path,
    summary_path: Path,
    state_path: Path,
    *,
    resume: bool = False,
    count: int | None = None,
    workers: int = 4,
    max_compressed_bytes: int = 1024 * 1024 * 1024,
    max_decompressed_bytes: int = 2 * 1024 * 1024 * 1024,
    timeout_seconds: float = 10.0,
    progress_every: int = 1000,
) -> dict[str, Any]:
    """Read packed-zero objects from public S3 and keep complete DiE-negative results."""
    _validate_dirs(output_csv, summary_path, state_path)
    if workers < 1 or timeout_seconds <= 0 or progress_every < 1:
        raise S3InventoryError("workers, timeout, and progress interval must be positive.")
    if count is not None and count < 1:
        raise S3InventoryError("count must be positive when provided.")
    if output_csv.exists() or summary_path.exists():
        raise S3InventoryError("Final outputs exist; choose new paths.")
    if not candidate_csv.is_file() or not candidate_summary.is_file():
        raise S3InventoryError("Candidate manifest and summary are required.")
    source_report = json.loads(candidate_summary.read_text(encoding="utf-8"))
    manifest_digest = _digest(candidate_csv)
    if (
        source_report.get("release_audit_passed") is not True
        or source_report.get("candidate_manifest_sha256") != manifest_digest
    ):
        raise S3InventoryError("Candidate manifest does not pass its full-corpus release audit.")
    candidate_total = int(source_report["counts"]["packed_zero_candidates"])
    target_count = min(count, candidate_total) if count is not None else candidate_total
    version = subprocess.run(
        ["diec", "--version"], capture_output=True, text=True, timeout=5, check=False
    )
    if version.returncode:
        raise S3InventoryError("diec --version failed.")
    settings = {
        "manifest_sha256": manifest_digest,
        "die_version": version.stdout.strip(),
        "die_modes": ",".join(DIEC_MODES),
        "max_compressed": str(max_compressed_bytes),
        "max_decompressed": str(max_decompressed_bytes),
        "timeout_seconds": str(timeout_seconds),
    }
    validate_private_path(state_path)
    exists = state_path.exists()
    if exists != resume:
        raise S3InventoryError("Use --resume only with the existing full-corpus state database.")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_path.with_name(f"{state_path.name}.lock")
    validate_private_path(lock_path)
    lock_handle = lock_path.open("a", encoding="utf-8")
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        lock_handle.close()
        raise S3InventoryError(
            "Another SOREL assessment is already using this state database."
        ) from error
    db = sqlite3.connect(state_path)
    db.execute("PRAGMA busy_timeout=30000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    if exists:
        saved = dict(db.execute("SELECT name, value FROM settings"))
        if {key: value for key, value in saved.items() if key != "workers"} != settings:
            db.close()
            raise S3InventoryError("Resume settings differ from the existing state database.")
        if "workers" in saved:
            db.execute("DELETE FROM settings WHERE name = 'workers'")
            db.commit()
    else:
        db.executescript(
            "CREATE TABLE settings(name TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "CREATE TABLE outcomes(selection_order INTEGER PRIMARY KEY, "
            "source_sha256 TEXT UNIQUE NOT NULL, result_json TEXT NOT NULL);"
        )
        db.executemany("INSERT INTO settings VALUES (?, ?)", settings.items())
        db.commit()

    client = make_unsigned_s3_client(max_pool_connections=workers + 1)
    started = time.monotonic()
    completed_since_progress = 0
    seen = 0
    pending: dict[Any, tuple[int, str]] = {}
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    def save_completed(future: Any) -> None:
        nonlocal completed_since_progress
        order, identity = pending.pop(future)
        result = future.result()
        db.execute(
            "INSERT INTO outcomes VALUES (?, ?, ?)",
            (order, identity, json.dumps(result, sort_keys=True, separators=(",", ":"))),
        )
        db.commit()
        completed_since_progress += 1
        if completed_since_progress >= progress_every:
            complete = db.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0]
            print(
                f"[sorel-full-filter] complete={complete}/{target_count} "
                f"elapsed_seconds={time.monotonic() - started:.0f}",
                flush=True,
            )
            completed_since_progress = 0

    try:
        with candidate_csv.open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            if tuple(reader.fieldnames or ()) != CANDIDATE_FIELDS:
                raise S3InventoryError("Unexpected packed-zero candidate manifest schema.")
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for row in reader:
                    if seen >= target_count:
                        break
                    seen += 1
                    identity = row["source_sha256"]
                    if (
                        int(row["selection_order"]) != seen
                        or row["bucket"] != SOREL_BUCKET
                        or row["object_key"] != SOREL_BINARIES_PREFIX + identity
                        or not SOREL_SHA256_PATTERN.fullmatch(identity)
                        or row["snapshot_id"] != source_report.get("snapshot_id")
                        or int(row["packed"]) != 0
                    ):
                        raise S3InventoryError(f"Invalid candidate row {seen}.")
                    existing = db.execute(
                        "SELECT result_json FROM outcomes WHERE selection_order = ?", (seen,)
                    ).fetchone()
                    if existing is not None:
                        previous_result = json.loads(existing[0])
                        if previous_result.get("assessment_status") != "failed":
                            continue
                        db.execute("DELETE FROM outcomes WHERE selection_order = ?", (seen,))
                        db.commit()
                    future = pool.submit(
                        _assess_candidate,
                        row,
                        client=client,
                        max_compressed=max_compressed_bytes,
                        max_decompressed=max_decompressed_bytes,
                        timeout=timeout_seconds,
                    )
                    pending[future] = (seen, identity)
                    if len(pending) >= workers * 2:
                        done, _ = wait(pending, return_when=FIRST_COMPLETED)
                        for item in done:
                            save_completed(item)
                    if seen >= target_count:
                        break
                while pending:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for item in done:
                        save_completed(item)
        if seen != target_count:
            raise S3InventoryError(
                "Candidate row count differs from the requested assessment count."
            )
        total = db.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0]
        if total != target_count:
            raise S3InventoryError("Assessment state is incomplete; resume before exporting.")
        eligible_count = 0
        outcome_counts: dict[str, Counter[str]] = {
            key: Counter()
            for key in (
                "assessment_status",
                "zlib_status",
                "file_status",
                "die_status",
                "die_obfuscated",
            )
        }
        runtime_total = 0.0
        released_bytes = 0
        with output_csv.open("x", newline="", encoding="utf-8-sig") as output:
            writer = csv.DictWriter(output, fieldnames=RESULT_FIELDS, lineterminator="\n")
            writer.writeheader()
            for (payload,) in db.execute(
                "SELECT result_json FROM outcomes ORDER BY selection_order"
            ):
                result = json.loads(payload)
                for key, counter in outcome_counts.items():
                    counter[str(result[key])] += 1
                runtime_total += float(result["runtime_seconds"])
                released_bytes += int(result["released_bytes"])
                if (
                    result["assessment_status"] == "complete"
                    and result["die_obfuscated"] == "false"
                    and result["die_status"] == "success"
                    and result["file_status"] == "success"
                    and "PE32 executable" in result["file_description"]
                    and int(result["packed"]) == 0
                    and not result.get("error")
                    and all(
                        json.loads(result["die_modes"]).get(mode) == "success"
                        for mode in DIEC_MODES
                    )
                ):
                    writer.writerow(result)
                    eligible_count += 1
        report = {
            "dataset": "SOREL-20M",
            "scope": (
                "all S3 sources whose SOREL packed metadata count is zero"
                if target_count == candidate_total
                else f"first {target_count} packed-zero candidates in frozen manifest order"
            ),
            "release_audit_passed": True,
            "candidate_count": seen,
            "candidate_population_count": candidate_total,
            "selection": (
                "complete packed-zero candidate manifest"
                if target_count == candidate_total
                else "prefix of deterministic frozen manifest order; not a random or representative sample"
            ),
            "eligible_count": eligible_count,
            "excluded_or_unknown_count": seen - eligible_count,
            "eligible_filter": "packed=0, successful file detection containing PE32 executable, all DiE modes successful and unflagged, no reported error",
            "architecture_filter": "PE32 format proxy from file; not independently verified x86",
            "prefilter_policy": "new candidates run DiE only after packed=0 and PE32 checks; existing checkpoint results are reused and filtered at export",
            "counts": {
                key: dict(sorted(counter.items())) for key, counter in outcome_counts.items()
            },
            "released_bytes_total": released_bytes,
            "worker_runtime_seconds_total": round(runtime_total, 3),
            "wall_runtime_seconds": round(time.monotonic() - started, 3),
            "diec_version": version.stdout.strip(),
            "die_modes": list(DIEC_MODES),
            "workers": workers,
            "limits": {
                "max_compressed_bytes_per_object": max_compressed_bytes,
                "max_decompressed_bytes_per_object": max_decompressed_bytes,
                "timeout_seconds_per_tool_mode": timeout_seconds,
            },
            "candidate_manifest_sha256": manifest_digest,
            "output_sha256": _digest(output_csv),
            "remote_versions_pinned": False,
            "failure_policy": "failed, partial, or unknown DiE outcomes are excluded and retained in SQLite state",
            "raw_sample_bytes_retained": False,
        }
        write_json_atomic(summary_path, report)
        return report
    finally:
        try:
            db.close()
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            lock_handle.close()
