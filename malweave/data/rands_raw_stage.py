"""Stage a frozen original-PE cohort as non-executable data from scoped HTTPS URLs."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time

from botocore.awsrequest import AWSPreparedRequest
from botocore.exceptions import BotoCoreError
from botocore.httpsession import URLLib3Session
from urllib3.exceptions import HTTPError

from malweave.data.rands import SHA256_PATTERN
from malweave.training.contracts import SupervisedTrainingError, _private_path
from malweave.training.session_storage import file_sha


def _open_source(session, row):
    request = AWSPreparedRequest(
        method="GET",
        url=row["url"],
        headers={"If-Match": row["etag"]},
        body=None,
        stream_output=True,
    )
    response = session.send(request)
    if response.status_code != 200:
        response.raw.close()
        raise OSError(f"Original transfer HTTP status {response.status_code}")
    return closing(response.raw)


def stage_raw_sources(manifest: dict, root: Path, *, workers=16, progress=None):
    """Verify complete originals and durably account for every attempted source."""
    _private_path(root, "RAW staging root")
    rows = manifest["sources"]
    if not rows or not manifest["release_audit"]["passed"] or not 1 <= workers <= 32:
        raise SupervisedTrainingError(
            "Staging requires a passing release audit and bounded workers."
        )
    if len({r["sha256"] for r in rows}) != len(rows):
        raise SupervisedTrainingError("Duplicate frozen staging sources.")
    for row in rows:
        source = row["sha256"]
        if (
            not SHA256_PATTERN.fullmatch(source)
            or row["relative_path"] != f"dataset/{source[:2]}/{source}"
            or type(row["bytes"]) is not int
            or row["bytes"] < 1
            or row["label"] not in {"benign", "ransomware"}
            or not row["url"].startswith("https://")
        ):
            raise SupervisedTrainingError("Invalid frozen RAW staging row.")
    for row in rows:
        if not (root / row["relative_path"]).resolve().is_relative_to(root.resolve()):
            raise SupervisedTrainingError("RAW staging path escapes its root.")
    root.mkdir(parents=True, exist_ok=True)
    needed = sum(r["bytes"] for r in rows if not (root / r["relative_path"]).exists())
    if shutil.disk_usage(root).free < needed + 2 * 1024**3:
        raise SupervisedTrainingError("Insufficient disk for original inputs plus 2GiB reserve.")
    identity = json.dumps(manifest["identity"], sort_keys=True)
    db = sqlite3.connect(root / "stage.sqlite3")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS identity (value TEXT)")
    old = db.execute("SELECT value FROM identity").fetchone()
    if old and old[0] != identity:
        db.close()
        raise SupervisedTrainingError("Staging identity changed.")
    if not old:
        db.execute("INSERT INTO identity VALUES (?)", (identity,))
    db.execute(
        "CREATE TABLE IF NOT EXISTS source "
        "(sha TEXT PRIMARY KEY,label TEXT,status TEXT,bytes INTEGER,attempts INTEGER,error TEXT)"
    )
    db.commit()
    start = last = time.monotonic()
    counts, by_class = Counter(), {label: Counter() for label in ("benign", "ransomware")}
    transferred = 0

    session = URLLib3Session(max_pool_connections=workers, timeout=(10, 60))

    def fetch(row):
        path = root / row["relative_path"]
        if path.exists():
            if path.stat().st_size != row["bytes"] or file_sha(path) != row["sha256"]:
                raise SupervisedTrainingError("Existing original input failed integrity check.")
            return "reused", 0
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".download")
        for attempt in range(3):
            try:
                digest, size = sha256(), 0
                with _open_source(session, row) as incoming, temporary.open("wb") as outgoing:
                    for block in iter(lambda: incoming.read(1024 * 1024), b""):
                        size += len(block)
                        if size > row["bytes"]:
                            raise SupervisedTrainingError("Original exceeds its frozen size.")
                        outgoing.write(block)
                        digest.update(block)
                if size != row["bytes"] or digest.hexdigest() != row["sha256"]:
                    raise SupervisedTrainingError("Downloaded original failed integrity check.")
                temporary.chmod(0o400)
                os.replace(temporary, path)
                return "downloaded", size
            except SupervisedTrainingError:
                temporary.unlink(missing_ok=True)
                raise
            except (OSError, TimeoutError, BotoCoreError, HTTPError) as error:
                temporary.unlink(missing_ok=True)
                if attempt == 2:
                    code = getattr(error, "code", type(error).__name__)
                    raise SupervisedTrainingError(
                        f"Original HTTPS transfer failed ({code}) after retries."
                    ) from None
                time.sleep(2**attempt)
        raise AssertionError("Unreachable RAW transfer state")

    def emit(phase):
        report = {
            "phase": phase,
            "total": len(rows),
            "completed": sum(counts.values()),
            "pending": len(rows) - sum(counts.values()),
            "statuses": dict(counts),
            "by_class": {k: dict(v) for k, v in by_class.items()},
            "downloaded_bytes": transferred,
            "elapsed_seconds": time.monotonic() - start,
        }
        temporary = root / "stage-progress.json.tmp"
        temporary.write_text(json.dumps(report, sort_keys=True) + "\n")
        temporary.replace(root / "stage-progress.json")
        if progress:
            progress(report)
        return report

    failed = False
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            iterator, active = iter(rows), {}
            while True:
                while not failed and len(active) < workers * 2:
                    row = next(iterator, None)
                    if row is None:
                        break
                    active[pool.submit(fetch, row)] = row
                if not active:
                    break
                done, _ = wait(active, timeout=5, return_when=FIRST_COMPLETED)
                for future in done:
                    row = active.pop(future)
                    try:
                        status, size = future.result()
                        error = None
                    except (SupervisedTrainingError, OSError, ValueError) as exc:
                        status, size, error = (
                            "failed",
                            0,
                            str(exc)
                            if isinstance(exc, SupervisedTrainingError)
                            else type(exc).__name__,
                        )
                        failed = True
                    counts[status] += 1
                    by_class[row["label"]][status] += 1
                    transferred += size
                    db.execute(
                        "INSERT INTO source VALUES (?,?,?,?,1,?) ON CONFLICT(sha) DO UPDATE SET "
                        "status=excluded.status,bytes=excluded.bytes,attempts=attempts+1,error=excluded.error",
                        (row["sha256"], row["label"], status, size, error),
                    )
                    db.commit()
                if time.monotonic() - last >= 5:
                    emit("staging_failed" if failed else "staging")
                    last = time.monotonic()
        report = emit("staging_failed" if failed else "staged")
    finally:
        db.close()
        session.close()
    if failed:
        raise SupervisedTrainingError("Frozen RAW staging failed; inspect durable stage records.")
    return report
