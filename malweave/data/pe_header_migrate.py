"""Resumable non-destructive migration of Header bytes to hash-sharded storage."""

from concurrent.futures import ThreadPoolExecutor
import csv
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import time

import boto3
from botocore.config import Config

from malweave.data.sorel_io import job_lock, json_write


def migrate_headers(manifest: Path, bucket: str, output: Path, workers: int = 64) -> dict:
    """Copy only; verify every destination's bytes before committing progress."""
    if not 1 <= workers <= 128:
        raise ValueError("Workers must be 1..128")
    with manifest.open(newline="") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames
        rows = list(reader)
    if not rows or len({r["source_sha256"] for r in rows}) != len(rows):
        raise ValueError("Empty or duplicate source manifest")
    prefix = "rands/representations/pe-header/"
    for row in rows:
        source = row["source_sha256"]
        if len(source) != 64 or any(c not in "0123456789abcdef" for c in source):
            raise ValueError("Invalid source digest")
        if row["status"] == "success" and not row["header_key"].startswith(prefix + "runs/"):
            raise ValueError("Expected historical run-scoped Header input")
    client = boto3.client(
        "s3",
        config=Config(
            max_pool_connections=workers,
            retries={"mode": "adaptive", "max_attempts": 10},
            connect_timeout=10,
            read_timeout=60,
        ),
    )
    with job_lock(output):
        identity = {
            "manifest_sha256": sha256(manifest.read_bytes()).hexdigest(),
            "bucket": bucket,
            "destination_prefix": prefix,
            "delete_sources": False,
        }
        contract = output / "contract.json"
        if contract.exists() and json.loads(contract.read_text()) != identity:
            raise ValueError("Migration identity changed")
        json_write(contract, identity)
        with sqlite3.connect(output / "state.sqlite") as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS verified (source TEXT PRIMARY KEY, new_key TEXT)"
            )
            done = dict(db.execute("SELECT source, new_key FROM verified"))
            started = time.monotonic()

            def copy(row):
                source = row["source_sha256"]
                key = prefix + source[:2] + "/" + source + ".bin"
                # Existing destinations are verified, never overwritten with different bytes.
                from botocore.exceptions import ClientError

                try:
                    response = client.get_object(Bucket=bucket, Key=key)
                except ClientError as error:
                    if error.response["Error"]["Code"] not in {"NoSuchKey", "404"}:
                        raise
                    client.copy_object(
                        Bucket=bucket,
                        Key=key,
                        CopySource={"Bucket": bucket, "Key": row["header_key"]},
                        ServerSideEncryption="AES256",
                    )
                    response = client.get_object(Bucket=bucket, Key=key)
                try:
                    payload = response["Body"].read()
                finally:
                    response["Body"].close()
                if (
                    len(payload) != int(row["size_of_headers"])
                    or sha256(payload).hexdigest() != row["header_sha256"]
                ):
                    raise ValueError("Destination Header digest/size mismatch")
                return source, key

            pending = [
                r for r in rows if r["status"] == "success" and r["source_sha256"] not in done
            ]
            with ThreadPoolExecutor(max_workers=workers) as pool:
                # Bound queued requests and retain durable per-source verification.
                for start in range(0, len(pending), workers * 4):
                    for source, key in pool.map(copy, pending[start : start + workers * 4]):
                        db.execute("INSERT INTO verified VALUES (?,?)", (source, key))
                        db.commit()
                        done[source] = key
                    json_write(
                        output / "progress.json",
                        {
                            "verified": len(done),
                            "expected": sum(r["status"] == "success" for r in rows),
                            "session_seconds": time.monotonic() - started,
                            "workers": workers,
                        },
                    )
            with (output / "manifest.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=[*fields, "historical_header_key"])
                writer.writeheader()
                for row in rows:
                    writer.writerow(
                        {
                            **row,
                            "header_key": done.get(row["source_sha256"], row["header_key"]),
                            "historical_header_key": row["header_key"],
                        }
                    )
            summary = {
                **identity,
                "complete": True,
                "verified": len(done),
                "source_rows": len(rows),
                "failures_retained": sum(r["status"] != "success" for r in rows),
                "manifest_output_sha256": sha256(
                    (output / "manifest.csv").read_bytes()
                ).hexdigest(),
            }
            json_write(output / "summary.json", summary)
            remote = prefix + "layout-migrations/hash-sharded-v1/"
            for name in ("contract.json", "manifest.csv", "summary.json"):
                client.put_object(
                    Bucket=bucket,
                    Key=remote + name,
                    Body=(output / name).read_bytes(),
                    ServerSideEncryption="AES256",
                )
            return summary
