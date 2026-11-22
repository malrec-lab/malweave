"""Resumable, digest-verified final-input audit of private S3 EXE objects."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import csv
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from malweave.data.lmlm_inputs import ReleasedExeTokenizer
from malweave.data.sorel_io import job_lock


def token_digest(ids: list[int]) -> str:
    """Match the frozen RanDS audit's uint64-length/uint32-ID encoding."""
    return sha256(struct.pack("<Q", len(ids)) + struct.pack(f"<{len(ids)}I", *ids)).hexdigest()


def audit_exe_tokens(manifest: Path, checkpoint: Path, output: Path, workers: int = 4) -> dict:
    """Audit each distinct full-EXE identity once; retain failures on ordinary resume."""
    if not 1 <= workers <= 8:
        raise ValueError("Use 1 through 8 workers")
    parent = json.loads((checkpoint / "run-manifest.json").read_text())
    if parent["status"] != "completed":
        raise ValueError("Parent must be completed")
    for name in ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json"):
        if (
            sha256((checkpoint / name).read_bytes()).hexdigest()
            != parent["artifact_files_sha256"][name]
        ):
            raise ValueError("Parent tokenizer digest mismatch")
    initialization = parent["initialization"]
    adapter = ReleasedExeTokenizer(
        checkpoint,
        initialization["source_config"],
        initialization["max_tokens"],
        initialization["max_bytes"],
    )
    with manifest.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    objects = {}
    for row in rows:
        digest = row["exe_sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid EXE identity")
        if not row["bucket"] or not row["key"] or int(row["exe_bytes"]) < 1:
            raise ValueError("Missing object identity")
        previous = objects.setdefault(digest, row)
        if previous["exe_bytes"] != row["exe_bytes"]:
            raise ValueError("Conflicting sizes for equivalent EXE")
    if not objects:
        raise ValueError("Empty audit admission")
    identity = {
        "manifest_sha256": sha256(manifest.read_bytes()).hexdigest(),
        "parent_manifest_sha256": sha256(
            (checkpoint / "run-manifest.json").read_bytes()
        ).hexdigest(),
        "adapter_sha256": sha256(
            Path(__file__).with_name("lmlm_inputs.py").read_bytes()
        ).hexdigest(),
        "auditor_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "token_digest_encoding": "SHA256(uint64_le length + uint32_le token IDs)",
    }
    s3 = boto3.client(
        "s3",
        config=Config(
            connect_timeout=10,
            read_timeout=30,
            max_pool_connections=workers,
            retries={"mode": "standard", "max_attempts": 5},
        ),
    )

    def inspect(row):
        record = {
            "exe_sha256": row["exe_sha256"],
            "status": "failed",
            "token_sha256": "",
            "token_count": 0,
            "bytes_read": 0,
            "error_type": "",
        }
        try:
            response = s3.get_object(Bucket=row["bucket"], Key=row["key"])
            body = response["Body"]
            digest = sha256()
            prefix = bytearray()
            try:
                for block in iter(lambda: body.read(1024 * 1024), b""):
                    digest.update(block)
                    record["bytes_read"] += len(block)
                    prefix.extend(block[: max(0, adapter.max_bytes - len(prefix))])
            finally:
                body.close()
            if digest.hexdigest() != row["exe_sha256"] or record["bytes_read"] != int(
                row["exe_bytes"]
            ):
                raise ValueError("EXE digest or size mismatch")
            ids = adapter.encode_bytes(bytes(prefix)).tolist()
            record.update(status="success", token_sha256=token_digest(ids), token_count=len(ids))
        except (BotoCoreError, ClientError, OSError, ValueError) as error:
            record["error_type"] = type(error).__name__
        return record

    with job_lock(output):
        output.chmod(0o700)
        contract = output / "contract.json"
        if contract.exists() and json.loads(contract.read_text()) != identity:
            raise ValueError("Audit contract changed")
        contract.write_text(json.dumps(identity, indent=2))
        db = sqlite3.connect(output / "state.sqlite")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS results (exe TEXT PRIMARY KEY, body TEXT NOT NULL)")
        done = {r[0] for r in db.execute("SELECT exe FROM results")}
        pending = iter(row for digest, row in objects.items() if digest not in done)
        try:
            # Bounded batches avoid submitting the complete corpus to the executor.
            with ThreadPoolExecutor(max_workers=workers) as pool:
                while batch := [r for _ in range(workers) if (r := next(pending, None))]:
                    for record in pool.map(inspect, batch):
                        db.execute(
                            "INSERT INTO results VALUES (?, ?)",
                            (record["exe_sha256"], json.dumps(record)),
                        )
                        db.commit()
                        done.add(record["exe_sha256"])
                    (output / "progress.json").write_text(
                        json.dumps({"completed": len(done), "unique_exe": len(objects)})
                    )
        finally:
            values = [
                json.loads(r[0]) for r in db.execute("SELECT body FROM results ORDER BY exe")
            ]
            if values:
                with (output / "tokens.csv").open("w", newline="") as stream:
                    writer = csv.DictWriter(stream, fieldnames=list(values[0]))
                    writer.writeheader()
                    writer.writerows(values)
            summary = {
                "unique_exe": len(objects),
                "completed": len(values),
                "statuses": dict(Counter(r["status"] for r in values)),
                "complete": len(values) == len(objects),
                "bytes_read": sum(r["bytes_read"] for r in values),
                "split_assigned": False,
            }
            (output / "summary.json").write_text(json.dumps(summary, indent=2))
            db.close()
    return summary
