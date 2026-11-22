"""Audited, single-writer, resumable Header extraction on private S3."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
import lief

from malweave.data.sorel_io import atomic_bytes, job_lock, json_write


def read_remote(s3, bucket: str, key: str) -> bytes:
    """Restart interrupted response bodies; SDK retries do not cover stream.read()."""
    for attempt in range(6):
        try:
            response = s3.get_object(Bucket=bucket, Key=key)["Body"]
            try:
                return response.read()
            finally:
                response.close()
        except BotoCoreError:
            if attempt == 5:
                raise
            time.sleep(min(2**attempt, 20))
    raise RuntimeError("Unreachable retry state")


def publish(s3, bucket: str, key: str, body: bytes) -> None:
    """Idempotent immutable PUT; a crash after PUT is safe to resume."""
    try:
        s3.put_object(
            Bucket=bucket, Key=key, Body=body, ServerSideEncryption="AES256", IfNoneMatch="*"
        )
    except ClientError as error:
        if error.response["Error"]["Code"] not in ("PreconditionFailed", "412"):
            raise
    if sha256(read_remote(s3, bucket, key)).digest() != sha256(body).digest():
        raise ValueError("Remote immutable artifact differs from expected bytes")


def audit_manifest(manifest: Path, inventory: Path) -> tuple[list[dict], dict]:
    """Require a completed inventory and exact pinned identities for every admission."""
    with manifest.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    with sqlite3.connect(f"file:{inventory.resolve()}?mode=ro", uri=True) as db:
        settings = dict(db.execute("SELECT name,value FROM settings"))
        if settings.get("complete") != "1":
            raise ValueError("RAW inventory is not complete")
        seen = set()
        for row in rows:
            source = row["source_sha256"]
            if (
                len(source) != 64
                or any(c not in "0123456789abcdef" for c in source)
                or source in seen
            ):
                raise ValueError("Invalid or duplicate source identity")
            seen.add(source)
            if row["split"] not in ("train", "validation", "test", "unassigned") or row[
                "label"
            ] not in (
                "benign",
                "ransomware",
            ):
                raise ValueError("Invalid split/label")
            actual = db.execute(
                "SELECT object_key,size,etag FROM objects WHERE source_sha256=?", (source,)
            ).fetchone()
            expected = (row["object_key"], int(row["object_size"]), row["object_etag"])
            if row["availability"] != "available" or actual != expected or expected[1] <= 0:
                raise ValueError("Manifest differs from completed RAW inventory")
    if not rows:
        raise ValueError("Empty admission")
    return rows, settings


def compact_result(value: dict) -> dict:
    """Keep reporting fields in RAM; complete evidence remains in SQLite and S3."""
    return {
        "source": {key: value["source"][key] for key in ("source_sha256", "split", "label")},
        **{
            key: value[key]
            for key in ("status", "header_sha256", "size_of_headers", "header_key")
            if key in value
        },
    }


def run_headers(
    *,
    manifest: Path,
    inventory: Path,
    job_dir: Path,
    output_prefix: str,
    workers: int = 4,
    retry_failures: bool = False,
    inherit_runner_sha256: str | None = None,
) -> dict:
    if not 1 <= workers <= 16:
        raise ValueError("Use 1 through 16 workers")
    output_prefix = output_prefix.strip("/")
    if not output_prefix.startswith("rands/representations/pe-header/runs/"):
        raise ValueError("Use a dedicated Header run prefix")
    rows, settings = audit_manifest(manifest, inventory)
    bucket = settings["bucket"]
    s3 = boto3.client(
        "s3",
        config=Config(
            max_pool_connections=workers * 2 + 4, retries={"mode": "standard", "max_attempts": 6}
        ),
    )
    contract = {
        "manifest_sha256": sha256(manifest.read_bytes()).hexdigest(),
        "extractor_sha256": sha256(
            Path(__file__).with_name("pe_header.py").read_bytes()
        ).hexdigest(),
        "runner_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "lief_version": lief.__version__,
        "bucket": bucket,
        "prefix": output_prefix,
        "source_hash_policy": "inherited; ETag-pinned GET plus size, no full-source rehash",
        "baseline_split_equivalence": "unverified; supplied manifest preserved",
    }
    started = time.monotonic()
    stop = False

    def request_stop(signum, frame):
        nonlocal stop
        stop = True

    with job_lock(job_dir):
        if inherit_runner_sha256:
            original = json.loads(read_remote(s3, bucket, output_prefix + "/contract.json"))
            expected = {**contract, "runner_sha256": inherit_runner_sha256}
            if original != expected:
                raise ValueError("Runner migration contract mismatch")
            revision = {
                "original_contract": original,
                "current_contract": contract,
                "reason": "Checkpoint-memory/retry/concurrency revision; extraction and source policies unchanged",
            }
            publish(
                s3,
                bucket,
                output_prefix + "/runner-revisions/" + contract["runner_sha256"] + ".json",
                json.dumps(revision, sort_keys=True).encode(),
            )
            json_write(job_dir / "runner-revision.json", revision)
            contract = original
        publish(
            s3,
            bucket,
            output_prefix + "/contract.json",
            json.dumps(contract, sort_keys=True).encode(),
        )
        json_write(job_dir / "contract.json", contract)
        json_write(job_dir / "pid.json", {"pid": os.getpid()})
        audit = {
            "status": "passed_for_manifest_header_extraction",
            "sources": len(rows),
            "raw_bytes": sum(int(r["object_size"]) for r in rows),
            "inventory_complete": True,
            "snapshot": settings.get("snapshot"),
            "inventory_protocol_note": settings.get("protocol"),
            "admission_policy": "all rows in supplied manifest; no runtime architecture/packing filter",
            "coverage": dict(Counter(r["split"] + "/" + r["label"] for r in rows)),
        }
        publish(
            s3,
            bucket,
            output_prefix + "/release-audit.json",
            json.dumps(audit, sort_keys=True).encode(),
        )
        json_write(job_dir / "release-audit.json", audit)
        db = sqlite3.connect(job_dir / "state.sqlite")
        db.execute("PRAGMA synchronous=FULL")
        db.execute(
            "CREATE TABLE IF NOT EXISTS results (source TEXT PRIMARY KEY, body BLOB NOT NULL)"
        )
        completed = {
            source: compact_result(json.loads(body))
            for source, body in db.execute("SELECT source,body FROM results")
        }
        if not set(completed).issubset({r["source_sha256"] for r in rows}):
            raise ValueError("Foreign source checkpoint")
        pending = [
            r
            for r in rows
            if r["source_sha256"] not in completed
            or (retry_failures and completed[r["source_sha256"]]["status"] != "success")
        ]
        previous = {
            sig: signal.signal(sig, request_stop) for sig in (signal.SIGINT, signal.SIGTERM)
        }

        def process(row):
            source = row["source_sha256"]
            root = output_prefix + "/sources/" + source
            if not retry_failures or source not in completed:
                try:
                    response = s3.get_object(Bucket=bucket, Key=root + "/current.json")["Body"]
                    try:
                        body = response.read()
                    finally:
                        response.close()
                    saved = json.loads(body)
                    if saved["source"] != row:
                        raise ValueError("Remote source metadata mismatch")
                    if saved["status"] == "success":
                        obj = s3.get_object(Bucket=bucket, Key=saved["header_key"])["Body"]
                        try:
                            if sha256(obj.read()).hexdigest() != saved["header_sha256"]:
                                raise ValueError("Remote Header digest mismatch")
                        finally:
                            obj.close()
                    return source, body
                except ClientError as error:
                    if error.response["Error"]["Code"] not in ("NoSuchKey", "404"):
                        raise
            item_started = time.monotonic()
            evidence = {
                "source": row,
                "source_digest_verification": contract["source_hash_policy"],
            }
            header = None
            try:
                with tempfile.TemporaryDirectory(prefix="raw-", dir=job_dir) as temporary:
                    temp = Path(temporary)
                    raw = temp / "input.pe"
                    obj = s3.get_object(
                        Bucket=bucket, Key=row["object_key"], IfMatch=row["object_etag"]
                    )
                    try:
                        with raw.open("xb") as stream:
                            raw.chmod(0o600)
                            size = 0
                            for block in obj["Body"].iter_chunks(1024 * 1024):
                                size += len(block)
                                if size > int(row["object_size"]):
                                    raise ValueError("Oversized RAW")
                                stream.write(block)
                    finally:
                        obj["Body"].close()
                    if size != int(row["object_size"]):
                        raise ValueError("RAW size mismatch")
                    result = subprocess.run(
                        [sys.executable, "-m", "malweave.data.pe_header_run", str(temp)],
                        capture_output=True,
                        check=False,
                    )
                    evidence.update(
                        worker_returncode=result.returncode,
                        worker_stdout=result.stdout.decode(errors="replace"),
                        worker_stderr=result.stderr.decode(errors="replace"),
                    )
                    if result.returncode:
                        evidence["status"] = "worker_failure"
                    else:
                        evidence.update(json.loads((temp / "evidence.json").read_text()))
                        if evidence["status"] == "success":
                            header = (temp / "header.bin").read_bytes()
            except (OSError, ValueError, RuntimeError, BotoCoreError, ClientError) as error:
                evidence.update(status="failed", error_type=type(error).__name__, error=str(error))
            if header is not None:
                evidence["header_key"] = root + "/header.bin"
                publish(s3, bucket, evidence["header_key"], header)
            evidence["runtime_seconds"] = time.monotonic() - item_started
            body = json.dumps(evidence, sort_keys=True).encode()
            publish(s3, bucket, root + "/history/" + sha256(body).hexdigest() + ".json", body)
            # History and Header are durable before replacing this recoverable pointer.
            s3.put_object(
                Bucket=bucket, Key=root + "/current.json", Body=body, ServerSideEncryption="AES256"
            )
            return source, body

        def report():
            values = list(completed.values())
            summary = {
                "sources": len(rows),
                "completed": len(values),
                "remaining": len(rows) - len(values),
                "statuses": dict(Counter(v["status"] for v in values)),
                "coverage": dict(
                    Counter(
                        v["source"]["split"] + "/" + v["source"]["label"] + "/" + v["status"]
                        for v in values
                    )
                ),
                "header_bytes": sum(
                    v.get("size_of_headers", 0) for v in values if v["status"] == "success"
                ),
                "session_elapsed_seconds": time.monotonic() - started,
                "stop_requested": stop,
                "updated_unix": time.time(),
            }
            json_write(job_dir / "progress.json", summary)
            print(json.dumps(summary), flush=True)
            return summary

        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                active = set()
                iterator = iter(pending)
                exhausted = False
                last_report = 0.0
                while active or not exhausted:
                    while not stop and not exhausted and len(active) < workers:
                        row = next(iterator, None)
                        if row is None:
                            exhausted = True
                        else:
                            active.add(pool.submit(process, row))
                    if stop:
                        exhausted = True
                    if active:
                        done, active = wait(active, timeout=5, return_when=FIRST_COMPLETED)
                        for future in done:
                            source, body = future.result()
                            db.execute(
                                "INSERT OR REPLACE INTO results VALUES (?,?)", (source, body)
                            )
                            db.commit()
                            completed[source] = compact_result(json.loads(body))
                    if time.monotonic() - last_report > 5:
                        report()
                        last_report = time.monotonic()
            summary = report()
            export = io.StringIO()
            fields = [
                "source_sha256",
                "label",
                "split",
                "status",
                "header_sha256",
                "size_of_headers",
                "header_key",
            ]
            writer = csv.DictWriter(export, fieldnames=fields)
            writer.writeheader()
            for value in completed.values():
                writer.writerow(
                    {
                        "source_sha256": value["source"]["source_sha256"],
                        "label": value["source"]["label"],
                        "split": value["source"]["split"],
                        **{k: value.get(k, "") for k in fields[3:]},
                    }
                )
            atomic_bytes(job_dir / "manifest.csv", export.getvalue().encode())
            json_write(job_dir / "summary.json", summary)
            for name, body in [
                ("manifest.csv", export.getvalue().encode()),
                ("summary.json", json.dumps(summary, sort_keys=True).encode()),
            ]:
                s3.put_object(
                    Bucket=bucket,
                    Key=output_prefix + "/" + name,
                    Body=body,
                    ServerSideEncryption="AES256",
                )
            return summary
        finally:
            db.close()
            for sig, handler in previous.items():
                signal.signal(sig, handler)


if __name__ == "__main__":
    from malweave.data.pe_header import extract_header

    directory = Path(sys.argv[1])
    extracted, evidence = extract_header((directory / "input.pe").read_bytes())
    if extracted is not None:
        atomic_bytes(directory / "header.bin", extracted)
    json_write(directory / "evidence.json", evidence)
