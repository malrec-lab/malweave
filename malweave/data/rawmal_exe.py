"""RawMal-TF release inventory and static LMLM EXE extraction primitives."""

from __future__ import annotations

import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import csv
from dataclasses import dataclass
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any

from malweave.data.s3_layout import (
    DATASET_RECEIPT,
    EXE_MANIFEST,
    EXE_PREFIX,
    RAW_PREFIX,
    sharded_key,
)
from malweave.data.storage_io import DataError, digest, job_lock
from malweave.training.contracts import _private_path

INGESTION = "metadata/ingestion.sqlite"
STATE = "audit/jobs/rawmal-exe/state.sqlite3"
MIGRATION_PLAN = "_migration/plan.json"
MISSING_OBJECT = {"404", "NoSuchKey", "NotFound"}


@dataclass(frozen=True)
class RawMalSource:
    """One unique source object; source labels remain in the original database."""

    sha256: str
    s3_key: str
    size: int
    detected_format: str


def load_inventory(path: Path) -> tuple[list[RawMalSource], dict[str, int]]:
    """Validate the completed ingestion snapshot and preserve all source occurrences."""
    if not path.is_file():
        raise DataError("RawMal-TF ingestion state is missing.")
    uri = path.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise DataError("RawMal-TF ingestion state failed integrity check.")
        counts = {
            (source, status): count
            for source, status, count in db.execute(
                "SELECT source,status,COUNT(*) FROM members GROUP BY source,status"
            )
        }
        required = {
            ("type", "uploaded"): 152494,
            ("family", "uploaded"): 44607,
            ("features-type", "uploaded"): 98,
            ("features-type", "ignored"): 115,
            ("features-family", "uploaded"): 119,
        }
        if counts != required:
            raise DataError("RawMal-TF ingestion is incomplete or differs from the known release.")
        rows = db.execute(
            "SELECT sha256,s3_key,size,audit_json FROM members "
            "WHERE kind='raw' AND status='uploaded' ORDER BY sha256"
        )
        sources: dict[str, RawMalSource] = {}
        for digest, key, size, audit in rows:
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
                or key not in {sharded_key("raw", digest), sharded_key(RAW_PREFIX, digest)}
                or not isinstance(size, int)
                or size < 0
            ):
                raise DataError("Invalid source identity in RawMal-TF ingestion state.")
            evidence = json.loads(audit)
            source = RawMalSource(
                digest, sharded_key(RAW_PREFIX, digest), size, evidence.get("format", "unknown")
            )
            old = sources.get(digest)
            if old and old != source:
                raise DataError("Conflicting source identity or format evidence.")
            sources[digest] = source
    if len(sources) != 188951:
        raise DataError("RawMal-TF unique source count differs from the known release.")
    formats = Counter(source.detected_format for source in sources.values())
    return list(sources.values()), dict(sorted(formats.items()))


def verify_content(content: bytes, source: RawMalSource) -> None:
    """Require the downloaded source bytes to match their content-addressed key."""
    if len(content) != source.size or sha256(content).hexdigest() != source.sha256:
        raise DataError("Downloaded RawMal-TF source differs from its recorded identity.")


def audit_objects(
    client: Any,
    bucket: str,
    owner: str,
    sources: list[RawMalSource],
) -> None:
    """Require the raw S3 inventory to match the completed source snapshot exactly."""
    expected = {source.s3_key: source.size for source in sources}
    seen: set[str] = set()
    paginator = client.get_paginator("list_objects_v2")
    for page_number, page in enumerate(
        paginator.paginate(Bucket=bucket, Prefix=RAW_PREFIX + "/", ExpectedBucketOwner=owner),
        start=1,
    ):
        for item in page.get("Contents", []):
            key = item["Key"]
            if key in seen or expected.get(key) != item["Size"]:
                raise DataError("S3 raw inventory differs from the ingestion snapshot.")
            seen.add(key)
        if page_number % 50 == 0:
            print(json.dumps({"phase": "audit_s3", "objects_checked": len(seen)}), flush=True)
    if len(seen) != len(expected):
        raise DataError("S3 raw inventory is incomplete.")


def _put_immutable(
    client: Any,
    bucket: str,
    owner: str,
    key: str,
    payload: bytes,
    *,
    content_type: str = "application/octet-stream",
) -> None:
    """Write a content-addressed representation only once and verify its metadata."""
    import hashlib

    from botocore.exceptions import ClientError

    digest = sha256(payload).hexdigest()
    for attempt in range(3):
        try:
            client.put_object(
                Bucket=bucket,
                Key=key,
                Body=payload,
                ContentMD5=base64.b64encode(hashlib.md5(payload).digest()).decode(),
                ContentType=content_type,
                Metadata={"sha256": digest},
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
                ExpectedBucketOwner=owner,
            )
            break
        except ClientError as error:
            code = error.response["Error"]["Code"]
            if code in {"PreconditionFailed", "412"}:
                break
            if code not in {"ConditionalRequestConflict", "409"} or attempt == 2:
                raise
            time.sleep(0.2 * (attempt + 1))
    head = client.head_object(Bucket=bucket, Key=key, ExpectedBucketOwner=owner)
    if head["ContentLength"] != len(payload) or head.get("Metadata", {}).get("sha256") != digest:
        raise DataError("Existing EXE object does not match its content address.")


def convert_one(
    client: Any,
    bucket: str,
    owner: str,
    source: RawMalSource,
    scratch: Path,
) -> dict[str, Any]:
    """Download and parse one source in an isolated subprocess without executing it."""
    started = time.monotonic()
    head = client.head_object(Bucket=bucket, Key=source.s3_key, ExpectedBucketOwner=owner)
    if head["ContentLength"] != source.size:
        raise DataError("Raw object size differs from the ingestion snapshot.")
    root = scratch / "staging" / source.sha256
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    source_path, output_path, report_path = root / "raw", root / "exe", root / "report.json"
    if source_path.exists():
        verify_content(source_path.read_bytes(), source)
    else:
        response = client.get_object(
            Bucket=bucket,
            Key=source.s3_key,
            IfMatch=head["ETag"],
            ExpectedBucketOwner=owner,
        )
        try:
            content = response["Body"].read(source.size + 1)
        finally:
            response["Body"].close()
        verify_content(content, source)
        temporary = root / "raw.part"
        with temporary.open("wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(source_path)
        del content
    command = [
        sys.executable,
        "-m",
        "malweave.data.pe_worker",
        "--input",
        str(source_path),
        "--output",
        str(output_path),
        "--report",
        str(report_path),
        "--memory-limit",
        str(1024**3),
    ]
    result = subprocess.run(command, capture_output=True, timeout=120, check=False)
    if result.returncode or not report_path.is_file():
        raise DataError(f"LIEF worker failed with exit code {result.returncode}.")
    audit = json.loads(report_path.read_text())
    audit.update(
        command=command[:4] + ["<private scratch paths>"],
        stdout=result.stdout.decode("utf-8", errors="replace"),
        stderr=result.stderr.decode("utf-8", errors="replace"),
        packing="not_checked",
        file_tool="not_run",
    )
    status = audit.get("status")
    if status == "deferred_resource":
        raise DataError("LIEF exceeded its resource limit; source retained for retry.")
    key = None
    if status == "success":
        payload = output_path.read_bytes()
        output_digest = sha256(payload).hexdigest()
        if output_digest != audit.get("representation_sha256"):
            raise DataError("LIEF output hash differs from its report.")
        key = sharded_key(EXE_PREFIX, output_digest)
        _put_immutable(client, bucket, owner, key, payload)
    return {
        "status": status,
        "exe_key": key,
        "exe_sha256": audit.get("representation_sha256"),
        "exe_bytes": audit.get("extracted_bytes", 0),
        "audit": gzip.compress(json.dumps(audit, sort_keys=True).encode()),
        "seconds": round(time.monotonic() - started, 3),
    }


def run_batch(
    client: Any,
    bucket: str,
    owner: str,
    sources: list[RawMalSource],
    db: sqlite3.Connection,
    scratch: Path,
    *,
    workers: int,
    run_started: float | None = None,
) -> None:
    """Commit independently verified outcomes, leaving errors resumable."""

    def attempt(source: RawMalSource) -> tuple[RawMalSource, dict[str, Any] | Exception]:
        try:
            return source, convert_one(client, bucket, owner, source, scratch)
        except Exception as error:  # noqa: BLE001 - retain per-source transfer and parser failures.
            return source, error

    processed = db.execute(
        "SELECT COUNT(*) FROM source WHERE status NOT IN ('pending','error')"
    ).fetchone()[0]
    total = db.execute("SELECT COUNT(*) FROM source").fetchone()[0]
    converted = db.execute("SELECT COUNT(*) FROM source WHERE status='success'").fetchone()[0]
    skipped = db.execute(
        "SELECT COUNT(*) FROM source WHERE status='skipped_non_pe_header'"
    ).fetchone()[0]
    run_started = run_started or time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for source, outcome in pool.map(attempt, sources):
            if isinstance(outcome, Exception):
                db.execute(
                    "UPDATE source SET status='error',error=? WHERE sha256=?",
                    (f"{type(outcome).__name__}: {outcome}", source.sha256),
                )
            else:
                db.execute(
                    "UPDATE source SET status=?,exe_key=?,exe_sha256=?,exe_bytes=?,"
                    "audit=?,seconds=?,error=NULL WHERE sha256=?",
                    (
                        outcome["status"],
                        outcome["exe_key"],
                        outcome["exe_sha256"],
                        outcome["exe_bytes"],
                        outcome["audit"],
                        outcome["seconds"],
                        source.sha256,
                    ),
                )
                processed += 1
                if outcome["status"] == "success":
                    converted += 1
            db.commit()
            if not isinstance(outcome, Exception):
                shutil.rmtree(scratch / "staging" / source.sha256)
            print(
                json.dumps(
                    {
                        "accounted": processed,
                        "total_sources": total,
                        "converted": converted,
                        "skipped_non_pe_header": skipped,
                        "elapsed_seconds": round(time.monotonic() - run_started, 1),
                        "workers": workers,
                        "status": "error" if isinstance(outcome, Exception) else outcome["status"],
                    }
                ),
                flush=True,
            )


def _download_snapshot(client: Any, bucket: str, owner: str, key: str, path: Path) -> str:
    """Download a stable, checksum-verified SQLite snapshot."""
    head = client.head_object(Bucket=bucket, Key=key, ExpectedBucketOwner=owner)
    expected = head.get("Metadata", {}).get("sha256")
    if not expected:
        raise DataError(f"S3 snapshot lacks SHA-256 metadata: {key}")
    response = client.get_object(
        Bucket=bucket, Key=key, IfMatch=head["ETag"], ExpectedBucketOwner=owner
    )
    temporary = path.with_suffix(path.suffix + ".download")
    try:
        with temporary.open("wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            received = 0
            last_report = 0
            for chunk in response["Body"].iter_chunks(chunk_size=1024**2):
                stream.write(chunk)
                received += len(chunk)
                if received - last_report >= 32 * 1024**2:
                    print(json.dumps({"phase": "download_state", "bytes": received}), flush=True)
                    last_report = received
            stream.flush()
            os.fsync(stream.fileno())
        if temporary.stat().st_size != head["ContentLength"] or digest(temporary) != expected:
            raise DataError(f"S3 snapshot checksum mismatch: {key}")
        temporary.replace(path)
    finally:
        response["Body"].close()
        temporary.unlink(missing_ok=True)
    return expected


def _put_snapshot(client: Any, bucket: str, owner: str, path: Path, key: str) -> None:
    import hashlib

    sha = sha256()
    md5 = hashlib.md5()
    with path.open("rb") as stream:
        while chunk := stream.read(1024**2):
            sha.update(chunk)
            md5.update(chunk)
    with path.open("rb") as stream:
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=stream,
            ContentLength=path.stat().st_size,
            ContentMD5=base64.b64encode(md5.digest()).decode(),
            Metadata={"sha256": sha.hexdigest()},
            ServerSideEncryption="AES256",
            ExpectedBucketOwner=owner,
        )
    head = client.head_object(Bucket=bucket, Key=key, ExpectedBucketOwner=owner)
    if (
        head["ContentLength"] != path.stat().st_size
        or head.get("Metadata", {}).get("sha256") != sha.hexdigest()
    ):
        raise DataError(f"S3 snapshot verification failed: {key}")


def _publish(
    client: Any,
    bucket: str,
    owner: str,
    db: sqlite3.Connection,
    job: Path,
    *,
    complete: bool = False,
) -> None:
    """Publish a SQLite backup and a derived one-row-per-source CSV."""
    print(json.dumps({"phase": "publish_state", "status": "started"}), flush=True)
    with tempfile.TemporaryDirectory(prefix="snapshot-", dir=job) as temporary:
        root = Path(temporary)
        snapshot = root / "state.sqlite"
        with sqlite3.connect(snapshot) as backup:
            db.backup(backup)
        _put_snapshot(client, bucket, owner, snapshot, STATE)
        if complete:
            with sqlite3.connect(snapshot) as backup:
                csv_path = root / "exe.csv"
                with csv_path.open("w", newline="", encoding="utf-8") as stream:
                    columns = [
                        "source_sha256",
                        "source_key",
                        "source_bytes",
                        "source_format",
                        "status",
                        "exe_sha256",
                        "exe_key",
                        "exe_bytes",
                        "source_appearances",
                        "error",
                    ]
                    writer = csv.writer(stream)
                    writer.writerow(columns)
                    cursor = backup.execute(
                        "SELECT sha256,source_key,size,format,status,exe_sha256,exe_key,exe_bytes,"
                        "error FROM source ORDER BY sha256"
                    )
                    for row in cursor:
                        appearances = [
                            {"source": source, "member": member, "label": label}
                            for source, member, label in backup.execute(
                                "SELECT source,member,label FROM appearance WHERE sha256=? "
                                "ORDER BY source,member",
                                (row[0],),
                            )
                        ]
                        writer.writerow([*row[:8], json.dumps(appearances), row[8]])
            _put_immutable(
                client, bucket, owner, EXE_MANIFEST, csv_path.read_bytes(), content_type="text/csv"
            )
    print(json.dumps({"phase": "publish_state", "status": "complete"}), flush=True)


def _initialize(
    db: sqlite3.Connection,
    inventory: Path,
    sources: list[RawMalSource],
    identity: str,
    destination: str,
    extractor: str,
) -> None:
    db.executescript(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;"
        "CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
        "CREATE TABLE source(sha256 TEXT PRIMARY KEY,source_key TEXT NOT NULL,size INTEGER NOT NULL,"
        "format TEXT NOT NULL,status TEXT NOT NULL,exe_key TEXT,exe_sha256 TEXT,exe_bytes INTEGER,"
        "audit BLOB,seconds REAL,error TEXT);"
        "CREATE INDEX source_status ON source(status);"
        "CREATE TABLE appearance(sha256 TEXT NOT NULL,source TEXT NOT NULL,member TEXT NOT NULL,"
        "label TEXT,PRIMARY KEY(source,member));"
        "CREATE INDEX appearance_sha ON appearance(sha256);"
    )
    db.execute("INSERT INTO settings VALUES('input_sha256',?)", (identity,))
    db.execute("INSERT INTO settings VALUES('destination',?)", (destination,))
    db.execute("INSERT INTO settings VALUES('extractor',?)", (extractor,))
    db.executemany(
        "INSERT INTO source(sha256,source_key,size,format,status) VALUES(?,?,?,?,?)",
        [
            (
                source.sha256,
                source.s3_key,
                source.size,
                source.detected_format,
                "skipped_non_pe_header"
                if source.detected_format in {"pdf", "html", "elf"}
                else "pending",
            )
            for source in sources
        ],
    )
    db.execute("ATTACH DATABASE ? AS input", (str(inventory),))
    db.execute(
        "INSERT INTO appearance SELECT sha256,source,name,label_group FROM input.members "
        "WHERE kind='raw' AND status='uploaded'"
    )
    db.commit()
    db.execute("DETACH DATABASE input")


def run_rawmal_exe(
    job: Path,
    bucket: str,
    owner: str,
    profile: str,
    *,
    batch_size: int = 16,
    workers: int = 16,
    limit: int | None = None,
) -> dict[str, Any]:
    """Process a verified release in bounded batches and publish resumable state."""
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    import lief

    if batch_size != 16 or workers != 16 or (limit is not None and limit < 1):
        raise DataError("Use the approved batch size and worker count of 16.")
    destination = f"{owner}:{bucket}:representations"
    _private_path(job, "RawMal-TF conversion job")
    started = time.monotonic()
    session = boto3.Session(profile_name=profile)
    config = Config(
        connect_timeout=10,
        read_timeout=90,
        max_pool_connections=32,
        retries={"mode": "standard", "max_attempts": 3},
    )
    if session.client("sts", config=config).get_caller_identity()["Account"] != owner:
        raise DataError("AWS profile belongs to a different account.")
    client = session.client("s3", config=config)
    client.head_bucket(Bucket=bucket, ExpectedBucketOwner=owner)
    for key in (DATASET_RECEIPT, MIGRATION_PLAN):
        try:
            client.head_object(Bucket=bucket, Key=key, ExpectedBucketOwner=owner)
        except ClientError as error:
            if error.response["Error"]["Code"] not in MISSING_OBJECT:
                raise
        else:
            raise DataError("Use the migration or release workflow for this RawMal-TF bucket.")
    extractor = sha256(
        (
            lief.__version__
            + digest(Path(__file__).with_name("pe_sections.py"))
            + digest(Path(__file__).with_name("pe_worker.py"))
        ).encode()
    ).hexdigest()
    with job_lock(job):
        if shutil.disk_usage(job).free < 5 * 1024**3:
            raise DataError("At least 5 GiB of free scratch space is required.")
        inventory = job / "ingestion.sqlite"
        input_head = client.head_object(Bucket=bucket, Key=INGESTION, ExpectedBucketOwner=owner)
        identity = input_head.get("Metadata", {}).get("sha256")
        if not identity:
            raise DataError("Input state has no checksum.")
        if not inventory.is_file() or digest(inventory) != identity:
            identity = _download_snapshot(client, bucket, owner, INGESTION, inventory)
        sources, formats = load_inventory(inventory)
        audit_objects(client, bucket, owner, sources)
        print(json.dumps({"release_audit": "passed", "source_formats": formats}), flush=True)
        state_path = job / "state.sqlite"
        if not state_path.exists():
            try:
                _download_snapshot(client, bucket, owner, STATE, state_path)
                print("Restored conversion state from S3.", flush=True)
            except ClientError as error:
                if error.response["Error"]["Code"] not in MISSING_OBJECT:
                    raise
        db = sqlite3.connect(state_path)
        try:
            if not db.execute("SELECT name FROM sqlite_master WHERE name='settings'").fetchone():
                _initialize(db, inventory, sources, identity, destination, extractor)
            else:
                if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise DataError("Conversion state failed integrity check.")
                settings = dict(db.execute("SELECT key,value FROM settings"))
                if settings != {
                    "input_sha256": identity,
                    "destination": destination,
                    "extractor": extractor,
                }:
                    raise DataError(
                        "Conversion state belongs to a different input, bucket or extractor."
                    )
                if db.execute("SELECT COUNT(*) FROM source").fetchone()[0] != len(sources):
                    raise DataError("Conversion state has an incomplete source inventory.")
            by_sha = {source.sha256: source for source in sources}
            remaining = limit
            last_publish = time.monotonic()
            since_publish = 0
            while remaining is None or remaining > 0:
                count = batch_size if remaining is None else min(batch_size, remaining)
                pending = db.execute(
                    "SELECT sha256 FROM source WHERE status IN ('pending','error') "
                    "ORDER BY CASE WHEN status='error' THEN 0 ELSE 1 END,sha256 LIMIT ?",
                    (count,),
                ).fetchall()
                if not pending:
                    break
                batch = [by_sha[row[0]] for row in pending]
                required = 5 * 1024**3 + 3 * sum(source.size for source in batch)
                if shutil.disk_usage(job).free < required:
                    raise DataError("Insufficient scratch space for this batch and reserve.")
                run_batch(
                    client,
                    bucket,
                    owner,
                    batch,
                    db,
                    job,
                    workers=workers,
                    run_started=started,
                )
                since_publish += len(pending)
                if remaining is not None:
                    remaining -= len(pending)
                placeholders = ",".join("?" for _ in batch)
                errors = db.execute(
                    f"SELECT COUNT(*) FROM source WHERE status='error' AND sha256 IN ({placeholders})",
                    tuple(source.sha256 for source in batch),
                ).fetchone()[0]
                if errors or since_publish >= 1000 or time.monotonic() - last_publish >= 300:
                    _publish(client, bucket, owner, db, job)
                    since_publish = 0
                    last_publish = time.monotonic()
                if errors:
                    raise DataError(f"{errors} sources failed; rerun to retry.")
            pending = db.execute(
                "SELECT 1 FROM source WHERE status IN ('pending','error') LIMIT 1"
            ).fetchone()
            _publish(client, bucket, owner, db, job, complete=pending is None)
            return {
                "status": dict(db.execute("SELECT status,COUNT(*) FROM source GROUP BY status")),
                "exe_bytes_before_dedup": db.execute(
                    "SELECT COALESCE(SUM(exe_bytes),0) FROM source WHERE status='success'"
                ).fetchone()[0],
                "unique_exe": db.execute(
                    "SELECT COUNT(DISTINCT exe_sha256) FROM source WHERE status='success'"
                ).fetchone()[0],
                "label_coverage": [
                    {"source": source, "label": label, "status": status, "count": count}
                    for source, label, status, count in db.execute(
                        "SELECT a.source,a.label,s.status,COUNT(*) FROM appearance a "
                        "JOIN source s ON a.sha256=s.sha256 GROUP BY a.source,a.label,s.status"
                    )
                ],
                "run_seconds": round(time.monotonic() - started, 2),
            }
        finally:
            db.close()
