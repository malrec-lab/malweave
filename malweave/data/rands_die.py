"""Stream audited RanDS PEs from S3 through the LMLM static packing checks.

Reuses pe_assessment's RawByteClf packing protocol (recursive/deep/heuristic,
10 seconds per mode, union of obfuscation types). Complete reports, including
errors, are compressed in SQLite; temporary PE bytes are never executed.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import asdict
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import time
from typing import Any
from urllib.parse import urlsplit

from malweave.data.dataset_config import RandsDatasetConfig
from malweave.data.die_tools import rule_digest
from malweave.data.pe_assessment import assess_file, assess_packing
from malweave.data.rands import SHA256_PATTERN, load_rands_metadata
from malweave.data.rands_pe_assessment import _resolve_executable
from malweave.data.rands_training import Progress, validate_s3
from malweave.data.s3_layout import METADATA_PREFIX, RAW_PREFIX
from malweave.data.storage_io import DataError, digest, job_lock, json_write
from malweave.training.contracts import _private_path


class S3Unavailable(DataError):
    """A bounded AWS request failed; startup can be retried without losing state."""


def _aws(*arguments: str, timeout: float = 90) -> str:
    try:
        result = subprocess.run(
            [
                "aws",
                *arguments,
                "--no-cli-pager",
                "--cli-connect-timeout",
                "5",
                "--cli-read-timeout",
                "30",
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env={**os.environ, "AWS_MAX_ATTEMPTS": "2", "AWS_RETRY_MODE": "standard"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise S3Unavailable(str(error)) from error
    if result.returncode:
        raise S3Unavailable(result.stderr.strip())
    return result.stdout


def _download(uri: str, path: Path, etag: str | None = None) -> None:
    path.touch(mode=0o600, exist_ok=True)
    parsed = urlsplit(uri)
    arguments = [
        "s3api",
        "get-object",
        "--bucket",
        parsed.netloc,
        "--key",
        parsed.path.lstrip("/"),
    ]
    if etag:
        arguments += ["--if-match", etag]
    _aws(*arguments, str(path), timeout=300)


def _inventory(prefix: str):
    parsed = urlsplit(prefix)
    token = None
    while True:
        arguments = [
            "s3api",
            "list-objects-v2",
            "--bucket",
            parsed.netloc,
            "--prefix",
            parsed.path.lstrip("/") + "/",
            "--no-paginate",
        ]
        if token:
            arguments += ["--continuation-token", token]
        page = json.loads(_aws(*arguments))
        yield from page.get("Contents", [])
        if not page.get("IsTruncated"):
            return
        token = page["NextContinuationToken"]


class DiskProgress(Progress):
    """Keep a readable heartbeat even while S3 preparation is waiting on a request."""

    def __init__(self, job: Path):
        super().__init__(5)
        self.job = job

    def emit(self, **values: Any) -> None:
        super().emit(**values)
        with self.lock:
            json_write(
                self.job / "progress.json",
                {
                    **self.state,
                    "pid": os.getpid(),
                    "updated_at_unix": time.time(),
                    "elapsed_seconds": round(time.monotonic() - self.started, 2),
                },
            )


def _prepare(
    db: sqlite3.Connection,
    job: Path,
    config: RandsDatasetConfig,
    prefix: str,
    progress: Progress,
    *,
    raw_prefix: str,
) -> None:
    if db.execute("SELECT 1 FROM job WHERE key='release_audit'").fetchone():
        return
    progress.emit(phase="download_metadata", workers=progress.state.get("workers", 10))
    metadata_root = job / "metadata"
    metadata_root.mkdir(exist_ok=True)
    for name in (config.benign_csv, config.ransomware_csv):
        destination = metadata_root / name
        temporary = destination.with_suffix(".download")
        _download(prefix + "/" + name, temporary)
        temporary.replace(destination)
    metadata = load_rands_metadata(config, metadata_root)
    if metadata.class_overlap or metadata.duplicate_rows:
        raise DataError("RanDS metadata contains duplicate or cross-class sources.")

    progress.emit(phase="audit_s3_release", listed=0)
    root_key = urlsplit(raw_prefix).path.lstrip("/") + "/"
    sources, seen, shards, labels = [], set(), set(), Counter()
    for item in _inventory(raw_prefix):
        key = item["Key"]
        if key.endswith(("/", "/.DS_Store")):
            continue
        parts = key.removeprefix(root_key).split("/")
        sha = parts[-1]
        if (
            len(parts) != 2
            or not SHA256_PATTERN.fullmatch(sha)
            or parts[0] != sha[:2]
            or sha in seen
        ):
            raise DataError("Invalid, misplaced or duplicate PE in S3 release.")
        record = metadata.records.get(sha)
        if record is None or record.size_bytes != item["Size"]:
            raise DataError("S3 PE has missing metadata or mismatched size.")
        sources.append(
            (
                sha,
                record.label,
                key,
                item["Size"],
                item["ETag"],
                json.dumps(record.__dict__, sort_keys=True),
            )
        )
        seen.add(sha)
        shards.add(parts[0])
        labels[record.label] += 1
        if len(sources) % 1000 == 0:
            progress.emit(phase="audit_s3_release", listed=len(sources))
    passed = (
        len(sources) == config.expected.files
        and len(shards) == config.expected.shards
        and dict(labels) == config.expected.labels
    )
    audit = {
        "passed": passed,
        "files": len(sources),
        "shards": len(shards),
        "labels": dict(labels),
        "metadata_without_file": {
            label: metadata.rows_by_label[label] - labels[label]
            for label in config.expected.labels
        },
        "schema_corrections": metadata.schema_corrections,
        "source_list_sha256": sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
        "metadata_sha256": {
            name: digest(metadata_root / name)
            for name in (config.benign_csv, config.ransomware_csv)
        },
        "content_verification": "SHA256 checked on every PE after download, before scanning",
    }
    json_write(job / "release-audit.json", audit)
    if not passed:
        raise DataError("S3 release audit failed; see release-audit.json. No PEs scanned.")
    with db:
        db.executemany("INSERT INTO source VALUES (?, ?, ?, ?, ?, ?)", sources)
        db.execute("INSERT INTO job VALUES ('release_audit', ?)", (json.dumps(audit),))


def _attempt(
    source: dict[str, Any],
    job: Path,
    bucket: str,
    die: str,
    file: str,
) -> tuple[str, str, str, float, int, bytes, str]:
    started = time.monotonic()
    sha = source["sha256"]
    path = job / "work" / (sha + ".pe")
    evidence: dict[str, Any] = {
        "source_sha256": sha,
        "label": source["label"],
        "metadata": json.loads(source["metadata"]),
        "s3_key": source["s3_key"],
        "s3_etag": source["etag"],
        "started_at_unix": time.time(),
        "source_hash_status": "not_checked",
        "packing": {"state": "unknown"},
    }
    status = "download_error"
    downloaded = 0
    try:
        # Reserve headroom for ten concurrent samples plus evidence/SQLite output.
        if shutil.disk_usage(job).free < 1024**3 + source["size"] * 10:
            status = "disk_space_error"
            raise DataError("Insufficient free disk space for bounded PE staging.")
        _download("s3://" + bucket + "/" + source["s3_key"], path, source["etag"])
        path.chmod(0o600)
        downloaded = path.stat().st_size
        status = "size_mismatch"
        if downloaded != source["size"]:
            raise DataError("Downloaded PE size does not match audited S3 object.")
        evidence["input_sha256"] = digest(path)
        status = "hash_mismatch"
        if evidence["input_sha256"] != sha:
            evidence["source_hash_status"] = "mismatch"
            raise DataError("Downloaded PE SHA256 does not match source identity.")
        evidence["source_hash_status"] = "verified"
        evidence["file"] = assess_file(file, path, 10)
        evidence["packing"] = assess_packing(die, path, 10)
        status = (
            "success"
            if all(v == "success" for v in evidence["packing"]["modes"].values())
            and evidence["file"]["status"] == "success"
            else "tool_error"
        )
    except (OSError, DataError) as error:
        evidence["error"] = str(error)
    finally:
        if path.exists():
            downloaded = path.stat().st_size
        path.unlink(missing_ok=True)
    elapsed = time.monotonic() - started
    evidence.update(status=status, runtime_seconds=elapsed, downloaded_bytes=downloaded)
    blob = gzip.compress(json.dumps(evidence, sort_keys=True).encode(), mtime=0)
    return (
        sha,
        status,
        evidence["packing"]["state"],
        elapsed,
        downloaded,
        blob,
        sha256(blob).hexdigest(),
    )


def _counts(db: sqlite3.Connection) -> dict[str, Any]:
    total = db.execute("SELECT COUNT(*) FROM source").fetchone()[0]
    completed = db.execute("SELECT COUNT(*) FROM result").fetchone()[0]
    success = db.execute("SELECT COUNT(*) FROM result WHERE status='success'").fetchone()[0]
    runtime, downloaded, output = db.execute(
        "SELECT COALESCE(SUM(seconds),0), COALESCE(SUM(bytes),0), "
        "COALESCE(SUM(LENGTH(evidence_gzip)),0) FROM result"
    ).fetchone()
    by_class = {}
    for label, available, done, ok in db.execute(
        "SELECT label, COUNT(*), COUNT(r.sha256), "
        "SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) "
        "FROM source s LEFT JOIN result r ON s.sha256=r.sha256 GROUP BY label"
    ):
        by_class[label] = {
            "total": available,
            "completed": done,
            "success": ok,
            "failed": done - ok,
        }
    return {
        "total": total,
        "completed": completed,
        "pending": total - completed,
        "success": success,
        "failed": completed - success,
        "by_class": by_class,
        "statuses": dict(db.execute("SELECT status, COUNT(*) FROM result GROUP BY status")),
        "packing_states": dict(
            db.execute("SELECT packing, COUNT(*) FROM result GROUP BY packing")
        ),
        "summed_sample_seconds": runtime,
        "downloaded_bytes": downloaded,
        "compressed_evidence_bytes": output,
    }


@contextmanager
def _stop_signals():
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in previous:
            signal.signal(sig, signal.default_int_handler)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run_rands_die(
    job: Path,
    config: RandsDatasetConfig,
    prefix: str,
    *,
    raw_prefix: str | None = None,
    workers: int = 10,
    die_command: str = "diec",
    retry_seconds: float = 60,
    limit: int | None = None,
) -> dict[str, Any]:
    """Resume the exact audited job, skipping all durably recorded source attempts."""
    _private_path(job, "RanDS DiE job")
    job = job.expanduser().resolve()
    prefix = validate_s3(prefix)
    metadata = urlsplit(prefix)
    if metadata.path.strip("/") != METADATA_PREFIX:
        raise DataError("RanDS labels must use the metadata/ prefix.")
    expected_raw = f"s3://{metadata.netloc}/{RAW_PREFIX}"
    if raw_prefix is not None and validate_s3(raw_prefix) != expected_raw:
        raise DataError("RanDS RAW must use representations/raw/ in the same bucket.")
    raw_prefix = expected_raw
    if workers < 1 or retry_seconds < 0 or (limit is not None and limit < 1):
        raise DataError("Require positive workers/limit and nonnegative retry seconds.")
    die = _resolve_executable(die_command, "DiE")
    file = _resolve_executable("file", "file")
    version = subprocess.run(
        [die, "--version"], capture_output=True, text=True, check=True, timeout=10
    ).stdout.strip()
    contract = {
        "schema": 1,
        "prefix": prefix,
        "dataset": asdict(config),
        "die_version": version,
        "die_sha256": digest(Path(die)),
        "rules_sha256": rule_digest(Path(die).parent / "db"),
        "file_sha256": digest(Path(file)),
        "protocol_sha256": digest(Path(__file__).with_name("pe_assessment.py")),
        "runner_sha256": digest(Path(__file__)),
        "modes": ["recursive", "deep", "heuristic"],
        "timeout_per_mode_seconds": 10,
    }
    contract["raw_prefix"] = raw_prefix
    encoded_contract = json.dumps(contract, sort_keys=True)
    with job_lock(job), _stop_signals(), DiskProgress(job) as progress:
        job.chmod(0o700)
        json_write(job / "pid.json", {"pid": os.getpid()})
        (job / "work").mkdir(exist_ok=True)
        for stale in (job / "work").glob("*.pe"):
            stale.unlink()
        db = sqlite3.connect(job / "state.sqlite3")
        db.row_factory = sqlite3.Row
        db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS job (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS source (
                sha256 TEXT PRIMARY KEY, label TEXT NOT NULL, s3_key TEXT NOT NULL,
                size INTEGER NOT NULL, etag TEXT NOT NULL, metadata TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS result (
                sha256 TEXT PRIMARY KEY REFERENCES source(sha256), status TEXT NOT NULL,
                packing TEXT NOT NULL, seconds REAL NOT NULL, bytes INTEGER NOT NULL,
                evidence_gzip BLOB NOT NULL, evidence_sha256 TEXT NOT NULL);
        """)
        try:
            saved = db.execute("SELECT value FROM job WHERE key='contract'").fetchone()
            if saved and saved[0] != encoded_contract:
                raise DataError("Job source/config/tools changed; choose a new job directory.")
            with db:
                db.execute("INSERT OR IGNORE INTO job VALUES ('contract', ?)", (encoded_contract,))
            json_write(job / "tools.json", json.loads(saved[0]) if saved else contract)
            progress.emit(phase="starting", workers=workers)
            while True:
                try:
                    _prepare(db, job, config, prefix, progress, raw_prefix=raw_prefix)
                    break
                except S3Unavailable as error:
                    progress.emit(
                        phase="waiting_for_s3",
                        error=str(error),
                        workers=workers,
                        retry_seconds=retry_seconds,
                        **_counts(db),
                    )
                    if not retry_seconds:
                        raise
                    time.sleep(retry_seconds)
            pending = db.execute(
                "SELECT s.* FROM source s LEFT JOIN result r ON s.sha256=r.sha256 "
                "WHERE r.sha256 IS NULL ORDER BY s.sha256"
            ).fetchall()
            if limit is not None:
                pending = pending[:limit]
            sources = iter(pending)
            progress.emit(phase="scanning", workers=workers, **_counts(db))
            last_progress = time.monotonic()
            with ThreadPoolExecutor(max_workers=workers) as pool:
                active = set()

                def submit() -> None:
                    source = next(sources, None)
                    if source is not None:
                        active.add(
                            pool.submit(
                                _attempt, dict(source), job, urlsplit(prefix).netloc, die, file
                            )
                        )

                for _ in range(workers):
                    submit()
                while active:
                    done, active = wait(active, timeout=5, return_when=FIRST_COMPLETED)
                    for future in done:
                        with db:
                            row = future.result()
                            db.execute("INSERT INTO result VALUES (?, ?, ?, ?, ?, ?, ?)", row)
                        if row[1] == "disk_space_error":
                            raise DataError("Disk space reserve reached; free space and resume.")
                        submit()
                    if time.monotonic() - last_progress >= 5:
                        progress.emit(phase="scanning", workers=workers, **_counts(db))
                        last_progress = time.monotonic()
            summary = _counts(db)
            progress.emit(
                phase="complete" if not summary["pending"] else "limited",
                workers=workers,
                **summary,
            )
            json_write(job / "summary.json", summary)
            return summary
        except BaseException as error:
            progress.emit(
                phase="interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                error=str(error),
                workers=workers,
                **_counts(db),
            )
            raise
        finally:
            db.close()
