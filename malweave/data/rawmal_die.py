"""Stream RawMal PEs from S3 through the shared LMLM DiE checks.

The downloader and scanner share one bounded worker pool: every worker fetches one
PE, verifies its size and SHA-256, runs ``file`` plus the three DiE modes, records
complete evidence, exports CSV state and deletes the temporary PE. Only metadata,
evidence and the two local CSV exports are retained; source objects stay on S3.
"""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import closing
import csv
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from malweave.data.pe_assessment import assess_file, assess_packing
from malweave.data.rands_die import DiskProgress, _stop_signals
from malweave.data.rands_pe_assessment import _resolve_executable
from malweave.data.sorel_io import SorelError, digest, durable_replace, job_lock, json_write
from malweave.data.sorel_tools import rule_digest
from malweave.training.contracts import _private_path

DEFAULT_MANIFEST_KEY = "main/samples.csv"
PRE_RETRY_RUNNER = "a8f5fa060828521669157859986de81cc1f1b49bb4a520e8587921bafc6df499"
DIEC_TIMEOUT_SECONDS = 10
ASSESSMENT_FIELDS = (
    "source_sha256",
    "source_key",
    "bytes",
    "format",
    "pe_machine",
    "pe_subsystem",
    "clr_present",
    "type_labels",
    "family_labels",
    "file_status",
    "file_description",
    "die_state",
    "die_types",
    "recursive_status",
    "deep_status",
    "heuristic_status",
    "status",
    "runtime_ms",
    "error",
    "evidence_sha256",
)


class InflightBudget:
    """Bound concurrent downloads by bytes and keep a free-space reserve."""

    def __init__(self, limit: int, job: Path, reserve: int = 2 * 1024**3) -> None:
        self.limit = limit
        self.job = job
        self.reserve = reserve
        self.current = 0

    def acquire(self, size: int) -> bool:
        if self.current + size > self.limit:
            return False
        if shutil.disk_usage(self.job).free < self.reserve + self.current + size:
            return False
        self.current += size
        return True

    def release(self, size: int) -> None:
        self.current -= size


def _cohort_filters(value: str) -> dict[str, str]:
    filters: dict[str, str] = {}
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise SorelError("Cohort filters must use column=value pairs.")
        key, expected = item.split("=", 1)
        key = key.strip()
        if key not in {
            "format",
            "pe_machine",
            "pe_subsystem",
            "clr_present",
            "type_label",
            "family_label",
        }:
            raise SorelError(f"Unsupported cohort filter: {key}")
        filters[key] = expected.strip()
    return filters


def _labels_match(value: str, expected: str) -> bool:
    try:
        labels = json.loads(value or "[]")
    except json.JSONDecodeError:
        return False
    return any(str(label) == expected for label in labels)


def _select(row: dict[str, str], filters: dict[str, str]) -> bool:
    for key, expected in filters.items():
        if key == "type_label":
            if not _labels_match(row.get("type_labels", ""), expected):
                return False
        elif key == "family_label":
            if not _labels_match(row.get("family_labels", ""), expected):
                return False
        elif row.get(key, "") != expected:
            return False
    return True


def _download_manifest(client, bucket: str, key: str, target: Path) -> str:
    temporary = target.with_suffix(".tmp")
    result = sha256()
    with (
        closing(client.get_object(Bucket=bucket, Key=key)["Body"]) as incoming,
        temporary.open("wb") as outgoing,
    ):
        for block in iter(lambda: incoming.read(4 * 1024**2), b""):
            result.update(block)
            outgoing.write(block)
    temporary.replace(target)
    return result.hexdigest()


def _prepare(
    db: sqlite3.Connection,
    client,
    job: Path,
    bucket: str,
    manifest_key: str,
    manifest_path: Path | None,
    filters: dict[str, str],
) -> str:
    manifest = job / "manifest.csv"
    if manifest_path is not None:
        manifest_sha = digest(manifest_path)
        if manifest.exists() and digest(manifest) != manifest_sha:
            raise SorelError("Manifest changed; use a new job directory.")
        if not manifest.exists():
            shutil.copyfile(manifest_path, manifest)
    elif not manifest.exists():
        manifest_sha = _download_manifest(client, bucket, manifest_key, manifest)
    else:
        manifest_sha = digest(manifest)
    if db.execute("SELECT 1 FROM job WHERE key='sources_loaded'").fetchone():
        if (
            db.execute("SELECT value FROM job WHERE key='manifest_sha256'").fetchone()[0]
            != manifest_sha
        ):
            raise SorelError("Manifest changed; use a new job directory.")
        return manifest_sha
    selected = []
    with manifest.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if not _select(row, filters):
                continue
            sha = row["sha256"]
            if not re.fullmatch(r"[0-9a-f]{64}", sha) or row["s3_key"] != f"raw/{sha[:2]}/{sha}":
                raise SorelError("Invalid source identity in RawMal manifest.")
            if int(row["bytes"]) < 1:
                raise SorelError("Invalid source size in RawMal manifest.")
            for field in ("type_labels", "family_labels"):
                labels = json.loads(row[field])
                if not isinstance(labels, list) or not all(isinstance(x, str) for x in labels):
                    raise SorelError("Invalid labels in RawMal manifest.")
            selected.append(
                (
                    row["sha256"],
                    row["s3_key"],
                    int(row["bytes"]),
                    row.get("format", ""),
                    row.get("pe_machine", ""),
                    row.get("pe_subsystem", ""),
                    row.get("clr_present", ""),
                    row.get("type_labels", ""),
                    row.get("family_labels", ""),
                )
            )
    if not selected:
        raise SorelError("Cohort filters selected no sources.")
    with db:
        db.executemany("INSERT INTO source VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", selected)
        db.execute("INSERT INTO job VALUES ('sources_loaded', ?)", (str(len(selected)),))
        db.execute("INSERT INTO job VALUES ('manifest_sha256', ?)", (manifest_sha,))
    return manifest_sha


def _download(
    client, bucket: str, key: str, path: Path, expected_size: int, expected_sha: str
) -> str:
    temporary = path.with_suffix(".part")
    result = sha256()
    total = 0
    response = client.get_object(Bucket=bucket, Key=key)
    with closing(response["Body"]) as incoming, temporary.open("xb") as outgoing:
        os.fchmod(outgoing.fileno(), 0o600)
        for block in iter(lambda: incoming.read(4 * 1024**2), b""):
            total += len(block)
            if total > expected_size:
                raise SorelError("Downloaded PE exceeds its manifest size.")
            result.update(block)
            outgoing.write(block)
    if total != expected_size:
        temporary.unlink(missing_ok=True)
        raise SorelError("Downloaded PE size does not match the manifest.")
    actual = result.hexdigest()
    if actual != expected_sha:
        temporary.unlink(missing_ok=True)
        raise SorelError("Downloaded PE SHA-256 does not match the manifest.")
    temporary.chmod(0o600)
    temporary.replace(path)
    return response["ETag"]


def _evidence(row: dict[str, Any], packing: dict[str, Any], file_result: dict[str, Any]) -> bytes:
    payload = {
        "source_sha256": row["sha256"],
        "source_key": row["s3_key"],
        "bytes": row["size"],
        "format": row["format"],
        "pe_machine": row["pe_machine"],
        "pe_subsystem": row["pe_subsystem"],
        "clr_present": row["clr_present"],
        "type_labels": json.loads(row["type_labels"] or "[]"),
        "family_labels": json.loads(row["family_labels"] or "[]"),
        "etag": row["etag"],
        "status": row["status"],
        "error": row["error"],
        "file": file_result,
        "packing": packing,
    }
    return gzip.compress(json.dumps(payload, sort_keys=True).encode(), mtime=0)


def _attempt(
    row: dict[str, Any],
    job: Path,
    bucket: str,
    client,
    die: str,
    file: str,
    max_file_bytes: int,
    reserved: int,
) -> tuple:
    started = time.monotonic()
    sha = row["sha256"]
    path = job / "work" / (sha + ".pe")
    status = "download_error"
    error = ""
    file_result: dict[str, Any] = {"status": "not_run"}
    packing: dict[str, Any] = {"state": "unknown", "types": [], "modes": {}, "reports": {}}
    etag = ""
    if row["size"] > max_file_bytes:
        status, error = "deferred_size", "File exceeds --max-file-bytes."
    else:
        try:
            etag = _download(client, bucket, row["s3_key"], path, row["size"], sha)
            status = "tool_error"
            file_result = assess_file(file, path, DIEC_TIMEOUT_SECONDS)
            packing = assess_packing(die, path, DIEC_TIMEOUT_SECONDS)
            if file_result["status"] == "success" and all(
                value == "success" for value in packing["modes"].values()
            ):
                status = "success"
        except (SorelError, OSError, ValueError, ClientError, BotoCoreError) as caught:
            error = str(caught)
    blob = _evidence({**row, "etag": etag, "status": status, "error": error}, packing, file_result)
    elapsed_ms = round((time.monotonic() - started) * 1000, 3)
    types = ";".join(packing.get("types", []))
    modes = packing.get("modes", {})
    return reserved, (
        sha,
        status,
        packing.get("state", "unknown"),
        types,
        json.dumps(modes, sort_keys=True),
        elapsed_ms,
        blob,
        sha256(blob).hexdigest(),
        error,
        etag,
        file_result["status"],
        file_result.get("stdout", "").strip(),
    )


def _counts(db: sqlite3.Connection) -> dict[str, Any]:
    total = db.execute("SELECT COUNT(*) FROM source").fetchone()[0]
    completed = db.execute("SELECT COUNT(*) FROM result").fetchone()[0]
    states = dict(
        db.execute("SELECT die_state, COUNT(*) FROM result GROUP BY die_state").fetchall()
    )
    statuses = dict(db.execute("SELECT status, COUNT(*) FROM result GROUP BY status").fetchall())
    return {
        "total": total,
        "completed": completed,
        "pending": total - completed,
        "packing_states": states,
        "statuses": statuses,
        "downloaded_bytes_verified": db.execute(
            "SELECT COALESCE(SUM(s.size), 0) FROM source s JOIN result r USING(sha256) "
            "WHERE r.etag != ''"
        ).fetchone()[0],
        "evidence_bytes": db.execute(
            "SELECT COALESCE(SUM(LENGTH(evidence_gzip)), 0) FROM result"
        ).fetchone()[0],
    }


def _csv_rows(db: sqlite3.Connection, filtered: bool) -> list[dict[str, Any]]:
    clause = "WHERE r.die_state = 'not_detected' AND r.status = 'success'" if filtered else ""
    rows = db.execute(
        f"""
        SELECT s.sha256, s.s3_key, s.size, s.format, s.pe_machine, s.pe_subsystem,
               s.clr_present, s.type_labels, s.family_labels, r.status, r.die_state,
               r.die_types, r.modes, r.seconds, r.evidence_sha256, r.error,
               r.file_status, r.file_description
        FROM source s JOIN result r ON s.sha256 = r.sha256 {clause}
        ORDER BY s.sha256
        """
    )
    output = []
    for row in rows:
        try:
            modes = json.loads(row["modes"] or "{}")
        except json.JSONDecodeError:
            modes = {}
        output.append(
            {
                "source_sha256": row["sha256"],
                "source_key": row["s3_key"],
                "bytes": row["size"],
                "format": row["format"],
                "pe_machine": row["pe_machine"],
                "pe_subsystem": row["pe_subsystem"],
                "clr_present": row["clr_present"],
                "type_labels": ";".join(json.loads(row["type_labels"] or "[]")),
                "family_labels": ";".join(json.loads(row["family_labels"] or "[]")),
                "file_status": row["file_status"],
                "file_description": row["file_description"],
                "die_state": row["die_state"],
                "die_types": row["die_types"],
                "recursive_status": modes.get("recursive", ""),
                "deep_status": modes.get("deep", ""),
                "heuristic_status": modes.get("heuristic", ""),
                "status": row["status"],
                "runtime_ms": row["seconds"],
                "error": row["error"],
                "evidence_sha256": row["evidence_sha256"],
            }
        )
    return output


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=ASSESSMENT_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        stream.flush()
        os.fsync(stream.fileno())
    durable_replace(temporary, path)


def export_csv(db: sqlite3.Connection, job: Path) -> dict[str, Any]:
    assessment = _csv_rows(db, filtered=False)
    filtered = _csv_rows(db, filtered=True)
    _write_csv(job / "assessment.csv", assessment)
    _write_csv(job / "filtered.csv", filtered)
    return {"assessment_rows": len(assessment), "filtered_rows": len(filtered)}


def _publish(
    job: Path, db: sqlite3.Connection, bucket: str, dest_prefix: str, copy_workers: int
) -> dict[str, Any]:
    dest_prefix = dest_prefix.strip("/")
    if not re.fullmatch(r"rawmal-filtered-[a-z0-9-]+", dest_prefix):
        raise SorelError("Invalid destination prefix.")
    client = boto3.client("s3")
    rows = db.execute(
        "SELECT s.sha256, s.s3_key, s.size, r.etag FROM source s JOIN result r "
        "ON s.sha256 = r.sha256 WHERE r.die_state = 'not_detected' "
        "AND r.status = 'success' ORDER BY s.sha256"
    ).fetchall()
    copied = skipped = failed = 0
    lock = threading.Lock()

    def copy_one(row: sqlite3.Row) -> None:
        nonlocal copied, skipped, failed
        key = f"{dest_prefix}/raw/{row['sha256'][:2]}/{row['sha256']}"
        try:
            existing = client.head_object(Bucket=bucket, Key=key)
            if (
                existing["ContentLength"] == row["size"]
                and existing.get("Metadata", {}).get("sha256") == row["sha256"]
            ):
                with lock:
                    skipped += 1
                return
            raise SorelError("Destination object conflicts with verified source.")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"404", "NotFound", "NoSuchKey"}:
                raise
        client.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": row["s3_key"]},
            CopySourceIfMatch=row["etag"],
            MetadataDirective="REPLACE",
            Metadata={"sha256": row["sha256"]},
            ServerSideEncryption="AES256",
        )
        verified = client.head_object(Bucket=bucket, Key=key)
        if (
            verified["ContentLength"] != row["size"]
            or verified.get("Metadata", {}).get("sha256") != row["sha256"]
        ):
            raise SorelError("Copied object failed verification.")
        with lock:
            copied += 1

    with ThreadPoolExecutor(max_workers=copy_workers) as pool:
        futures = {pool.submit(copy_one, row): row for row in rows}
        for future in futures:
            try:
                future.result()
            except (SorelError, ClientError, BotoCoreError, OSError):
                with lock:
                    failed += 1
    if failed:
        raise SorelError(f"{failed} S3 copies failed; publication manifest was not uploaded.")
    for name in ("assessment.csv", "summary.json", "tools.json", "filtered.csv"):
        path = job / name
        if path.exists():
            client.upload_file(
                str(path),
                bucket,
                f"{dest_prefix}/{name}",
                ExtraArgs={"ServerSideEncryption": "AES256"},
            )
    return {"copied": copied, "skipped": skipped, "failed": failed, "total": len(rows)}


def run_rawmal_die(
    job: Path,
    *,
    bucket: str,
    manifest_key: str = DEFAULT_MANIFEST_KEY,
    manifest_path: Path | None = None,
    cohort: str = "format=pe,pe_machine=0x014c",
    workers: int = 64,
    limit: int | None = None,
    max_file_bytes: int = 256 * 1024**2,
    max_inflight_bytes: int = 4 * 1024**3,
    die_command: str = "diec",
    retry_unknown: bool = False,
) -> dict[str, Any]:
    if workers < 1 or not 0 < max_file_bytes <= max_inflight_bytes:
        raise SorelError("workers and byte limits must be positive.")
    if limit is not None and limit < 1:
        raise SorelError("--limit must be positive.")
    _private_path(job, "RawMal DiE job")
    job = job.expanduser().resolve()
    filters = _cohort_filters(cohort)
    die = _resolve_executable(die_command, "DiE")
    file = _resolve_executable("file", "file")
    version = subprocess.run(
        [die, "--version"], capture_output=True, text=True, check=True, timeout=10
    ).stdout.strip()
    client = boto3.client(
        "s3",
        config=Config(
            max_pool_connections=workers,
            connect_timeout=10,
            read_timeout=30,
            retries={"total_max_attempts": 3},
        ),
    )
    rules = Path("/usr/lib/die/db") if die == "/usr/bin/diec" else Path(die).parent / "db"
    if not rules.is_dir():
        raise SorelError("Cannot identify the DiE signature database.")
    contract = {
        "schema": 1,
        "bucket": bucket,
        "manifest_key": manifest_key,
        "cohort": filters,
        "die_version": version,
        "die_sha256": digest(Path(die)),
        "rules_sha256": rule_digest(rules),
        "custom_rules_sha256": rule_digest(rules.with_name("db_custom")),
        "file_sha256": digest(Path(file)),
        "protocol_sha256": digest(Path(__file__).with_name("pe_assessment.py")),
        "runner_sha256": digest(Path(__file__)),
        "modes": ["recursive", "deep", "heuristic"],
        "timeout_per_mode_seconds": DIEC_TIMEOUT_SECONDS,
        "max_file_bytes": max_file_bytes,
    }
    encoded = json.dumps(contract, sort_keys=True)
    job.mkdir(parents=True, exist_ok=True)
    job.chmod(0o700)
    with job_lock(job), _stop_signals(), DiskProgress(job) as progress:
        json_write(job / "pid.json", {"pid": os.getpid()})
        (job / "work").mkdir(mode=0o700, exist_ok=True)
        for stale in (job / "work").iterdir():
            if re.fullmatch(r"[0-9a-f]{64}\.(pe|part)", stale.name):
                stale.unlink()
        db = sqlite3.connect(job / "state.sqlite3")
        db.row_factory = sqlite3.Row
        db.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS job (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS source (
              sha256 TEXT PRIMARY KEY, s3_key TEXT NOT NULL, size INTEGER NOT NULL,
              format TEXT NOT NULL, pe_machine TEXT NOT NULL, pe_subsystem TEXT NOT NULL,
              clr_present TEXT NOT NULL, type_labels TEXT NOT NULL, family_labels TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS result (
              sha256 TEXT PRIMARY KEY REFERENCES source(sha256), status TEXT NOT NULL,
              die_state TEXT NOT NULL, die_types TEXT NOT NULL, modes TEXT NOT NULL,
              seconds REAL NOT NULL, evidence_gzip BLOB NOT NULL,
              evidence_sha256 TEXT NOT NULL, error TEXT NOT NULL, etag TEXT NOT NULL,
              file_status TEXT NOT NULL, file_description TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS retry_history (
              sha256 TEXT PRIMARY KEY, previous_result TEXT NOT NULL,
              evidence_gzip BLOB NOT NULL);
            """
        )
        try:
            saved = db.execute("SELECT value FROM job WHERE key='contract'").fetchone()
            if saved and saved[0] != encoded:
                if json.loads(saved[0]) != {**contract, "runner_sha256": PRE_RETRY_RUNNER}:
                    raise SorelError("Job settings changed; choose a new job directory.")
                with db:
                    db.execute("INSERT OR IGNORE INTO job VALUES ('original_contract', ?)", saved)
                    db.execute("UPDATE job SET value=? WHERE key='contract'", (encoded,))
            with db:
                db.execute("INSERT OR IGNORE INTO job VALUES ('contract', ?)", (encoded,))
            json_write(job / "tools.json", contract)
            progress.emit(phase="manifest", workers=workers, **_counts(db))
            _prepare(db, client, job, bucket, manifest_key, manifest_path, filters)
            if limit is None:
                _audit(db, client, job, bucket)
            if retry_unknown:
                pending = db.execute(
                    "SELECT s.* FROM source s JOIN result r USING(sha256) "
                    "LEFT JOIN retry_history h USING(sha256) WHERE h.sha256 IS NULL "
                    "AND r.die_state='unknown' AND r.status IN ('download_error','tool_error') "
                    "ORDER BY s.sha256"
                ).fetchall()
            else:
                pending = db.execute(
                    "SELECT s.* FROM source s LEFT JOIN result r USING(sha256) "
                    "WHERE r.sha256 IS NULL ORDER BY s.sha256"
                ).fetchall()
            if limit is not None:
                pending = pending[:limit]
            sources = iter(pending)
            budget = InflightBudget(max_inflight_bytes, job)
            phase = "retrying" if retry_unknown else "scanning"
            retry_done = 0
            retry_progress = (
                {"retry_total": len(pending), "retry_done": 0} if retry_unknown else {}
            )
            progress.emit(phase=phase, workers=workers, **retry_progress, **_counts(db))
            last_export = time.monotonic()
            with ThreadPoolExecutor(max_workers=workers) as pool:
                active = set()

                source = next(sources, None)
                while source is not None or active:
                    while source is not None and len(active) < workers:
                        reserved = source["size"] if source["size"] <= max_file_bytes else 0
                        if reserved and not budget.acquire(reserved):
                            if not active:
                                raise SorelError(
                                    "Disk space reserve reached; free space and resume."
                                )
                            break
                        active.add(
                            pool.submit(
                                _attempt,
                                dict(source),
                                job,
                                bucket,
                                client,
                                die,
                                file,
                                max_file_bytes,
                                reserved,
                            )
                        )

                        source = next(sources, None)
                    done, active = wait(active, timeout=5, return_when=FIRST_COMPLETED)
                    for future in done:
                        reserved, row = future.result()
                        with db:
                            if retry_unknown:
                                old = dict(
                                    db.execute(
                                        "SELECT * FROM result WHERE sha256=?", (row[0],)
                                    ).fetchone()
                                )
                                evidence = old.pop("evidence_gzip")
                                db.execute(
                                    "INSERT INTO retry_history VALUES (?,?,?)",
                                    (row[0], json.dumps(old), evidence),
                                )
                                db.execute("DELETE FROM result WHERE sha256=?", (row[0],))
                            db.execute("INSERT INTO result VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", row)
                        retry_done += 1
                        for suffix in (".pe", ".part"):
                            (job / "work" / (row[0] + suffix)).unlink(missing_ok=True)
                        budget.release(reserved)
                    if time.monotonic() - last_export >= 30:
                        export_csv(db, job)
                        last_export = time.monotonic()
                        if retry_unknown:
                            retry_progress["retry_done"] = retry_done
                        progress.emit(
                            phase=phase, workers=workers, **retry_progress, **_counts(db)
                        )
            summary = _counts(db)
            if retry_unknown:
                summary.update(retry_total=len(pending), retry_done=retry_done)
            summary["csv"] = export_csv(db, job)
            json_write(job / "summary.json", summary)
            progress.emit(
                phase="limited" if summary["pending"] else "complete", workers=workers, **summary
            )
            return summary
        except BaseException as error:
            export_csv(db, job)
            progress.emit(
                phase="interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                workers=workers,
                error=str(error),
                **_counts(db),
            )
            raise
        finally:
            db.close()


def _audit(db, client, job, bucket):
    expected = dict(db.execute("SELECT s3_key, size FROM source"))
    total = len(expected)
    for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="raw/"):
        for item in page.get("Contents", []):
            size = expected.pop(item["Key"], None)
            if size is not None and size != item["Size"]:
                raise SorelError("RawMal inventory size differs from the manifest.")
    if expected:
        raise SorelError(f"RawMal inventory missing {len(expected)} selected objects.")
    json_write(job / "release-audit.json", {"passed": True, "selected_sources": total})


def publish_rawmal_die(job: Path, prefix: str, workers: int = 8):
    _private_path(job, "RawMal DiE job")
    if workers < 1 or not (job / "state.sqlite3").is_file():
        raise SorelError("A completed job and positive worker count are required.")
    with job_lock(job), closing(sqlite3.connect(job / "state.sqlite3")) as db:
        db.row_factory = sqlite3.Row
        if _counts(db)["pending"] or not (job / "release-audit.json").is_file():
            raise SorelError("Complete the audited run before publication.")
        contract = json.loads(
            db.execute("SELECT value FROM job WHERE key='contract'").fetchone()[0]
        )
        export_csv(db, job)
        return _publish(job, db, contract["bucket"], prefix, workers)
