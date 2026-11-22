"""Resumable static VERA admission evidence; never executes submitted samples."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import csv
import gzip
from hashlib import sha256
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from malweave.data.pe_assessment import architecture_from_file, assess_file, assess_packing
from malweave.data.sorel_io import atomic_bytes, job_lock, json_write


def run_admission(
    manifest: Path,
    output: Path,
    bucket: str,
    die: Path,
    workers: int = 2,
    *,
    inherit_runner_sha256: str | None = None,
) -> dict:
    """Scan eligible unique RAWs, pinning input/tool identity and retaining failures."""
    if not 1 <= workers <= 32:
        raise ValueError("Use one through thirty-two workers")
    die = die.resolve(strict=True)
    with manifest.open(newline="") as stream:
        occurrences = list(csv.DictReader(stream))
    sources = {}
    for row in occurrences:
        if row["eligibility_status"] == "excluded":
            continue
        digest = row["source_sha256"]
        if (
            len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
            or int(row["source_bytes"]) <= 0
            or not row["source_etag"]
            or not row["source_key"].startswith("vera/zenodo-17904705-v1/binaries/")
        ):
            raise ValueError("Invalid source admission")
        if digest in sources:
            previous = sources[digest]
            if any(
                previous[k] != row[k]
                for k in ("source_bytes", "csv_classification", "representation_sha256")
            ):
                raise ValueError("Conflicting duplicate source")
        else:
            sources[digest] = row
    if not sources:
        raise ValueError("Empty admission")

    def version(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        if result.returncode:
            raise ValueError("Scanner identity unavailable")
        return result.stdout.strip() or result.stderr.strip()

    rules = die.parent.parent / "Resources"
    # Include every file shipped with the portable scanner, including its rules.
    tool_root = die.parents[2]
    tool_files = {
        str(p.relative_to(tool_root)): sha256(p.read_bytes()).hexdigest()
        for p in sorted(tool_root.rglob("*"))
        if p.is_file()
    }
    if not tool_files:
        raise ValueError("Missing scanner installation")
    contract = {
        "manifest_sha256": sha256(manifest.read_bytes()).hexdigest(),
        "bucket": bucket,
        "runner_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "assessment_sha256": sha256(
            Path(__file__).with_name("pe_assessment.py").read_bytes()
        ).hexdigest(),
        "die_version": version([str(die), "--version"]),
        "file_version": version(["/usr/bin/file", "--version"]),
        "tool_files_sha256": tool_files,
        "rules_directory_present": rules.exists(),
        "mode_timeout_seconds": 60,
        "timeout_note": "Evidence collection uses pilot-tested 60s per mode; not RanDS metadata Packed provenance",
        "source_count": len(sources),
        "execute_samples": False,
    }
    s3 = boto3.client(
        "s3",
        config=Config(
            connect_timeout=10,
            read_timeout=30,
            retries={"mode": "standard", "max_attempts": 5},
            max_pool_connections=workers,
        ),
    )
    stop = False

    def request_stop(signum, frame):
        nonlocal stop
        stop = True

    with job_lock(output):
        output.chmod(0o700)
        contract_path = output / "contract.json"
        if contract_path.exists():
            original = json.loads(contract_path.read_text())
            if original != contract:
                reviewed_runner = (
                    "7cc50138b96f2d786ced3c7600ae527d272c58727e81687406340225bae9b275"
                )
                if (
                    inherit_runner_sha256 != reviewed_runner
                    or original.get("runner_sha256") != reviewed_runner
                    or {k: v for k, v in original.items() if k != "runner_sha256"}
                    != {k: v for k, v in contract.items() if k != "runner_sha256"}
                ):
                    raise ValueError("Admission contract changed")
                json_write(
                    output / "runner-migration.json",
                    {
                        "original_runner_sha256": reviewed_runner,
                        "current_runner_sha256": contract["runner_sha256"],
                        "reason": "Researcher requested up to 32 workers; concurrency-only limit change",
                        "workers": workers,
                    },
                )
                contract = original
        json_write(contract_path, contract)
        audit = {
            "passed": True,
            "sources": len(sources),
            "raw_bytes": sum(int(r["source_bytes"]) for r in sources.values()),
            "states": dict(Counter(r["csv_classification"] for r in sources.values())),
            "contract_sha256": sha256(contract_path.read_bytes()).hexdigest(),
            "source_verification": "ETag-pinned GET; full SHA256 and size before scanners",
        }
        json_write(output / "release-audit.json", audit)
        records = output / "records"
        records.mkdir(exist_ok=True, mode=0o700)
        db = sqlite3.connect(output / "state.sqlite")
        db.execute("PRAGMA synchronous=FULL")
        db.execute(
            "CREATE TABLE IF NOT EXISTS results (source TEXT PRIMARY KEY, body TEXT NOT NULL)"
        )
        done = {r[0] for r in db.execute("SELECT source FROM results")}
        if not done <= sources.keys():
            raise ValueError("Foreign source checkpoint")

        def inspect(row):
            started = time.monotonic()
            record = {"source": row, "status": "failed", "error_type": ""}
            try:
                with tempfile.TemporaryDirectory(dir=output, prefix="raw-") as tmp:
                    path = Path(tmp) / "input.pe"
                    response = s3.get_object(
                        Bucket=bucket, Key=row["source_key"], IfMatch=row["source_etag"]
                    )
                    digest, size = sha256(), 0
                    try:
                        with path.open("xb") as stream:
                            path.chmod(0o600)
                            for block in response["Body"].iter_chunks(1024 * 1024):
                                size += len(block)
                                if size > int(row["source_bytes"]):
                                    raise ValueError("Oversized RAW")
                                stream.write(block)
                                digest.update(block)
                    finally:
                        response["Body"].close()
                    if digest.hexdigest() != row["source_sha256"] or size != int(
                        row["source_bytes"]
                    ):
                        raise ValueError("RAW identity mismatch")
                    record["source_digest_verified"] = True
                    record["file"] = assess_file("/usr/bin/file", path, 30)
                    record["packing"] = assess_packing(str(die), path, 60)
                    record["arch"] = architecture_from_file(record["file"].get("stdout", ""))
                    record["status"] = (
                        "success"
                        if record["file"]["status"] == "success"
                        and record["packing"]["state"] != "unknown"
                        else "unknown"
                    )
            except (BotoCoreError, ClientError, OSError, ValueError) as error:
                record.update(error_type=type(error).__name__, error=str(error))
            record["runtime_seconds"] = time.monotonic() - started
            payload = gzip.compress(json.dumps(record, sort_keys=True).encode(), mtime=0)
            destination = records / (row["source_sha256"] + ".json.gz")
            atomic_bytes(destination, payload)
            return {
                "source_sha256": row["source_sha256"],
                "state": row["csv_classification"],
                "status": record["status"],
                "arch": record.get("arch", "unknown"),
                "packing": record.get("packing", {}).get("state", "unknown"),
                "runtime_seconds": record["runtime_seconds"],
                "evidence_bytes": len(payload),
                "evidence_sha256": sha256(payload).hexdigest(),
                "evidence_reference": str(destination),
                "error_type": record["error_type"],
            }

        previous = {
            sig: signal.signal(sig, request_stop) for sig in (signal.SIGINT, signal.SIGTERM)
        }
        pending = iter(r for digest, r in sources.items() if digest not in done)
        started = time.monotonic()
        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                while not stop:
                    batch = [r for _ in range(workers) if (r := next(pending, None))]
                    if not batch:
                        break
                    for result in pool.map(inspect, batch):
                        db.execute(
                            "INSERT INTO results VALUES (?,?)",
                            (result["source_sha256"], json.dumps(result)),
                        )
                        db.commit()
                        done.add(result["source_sha256"])
                    json_write(
                        output / "progress.json",
                        {
                            "completed": len(done),
                            "sources": len(sources),
                            "workers": workers,
                            "updated_unix": time.time(),
                        },
                    )
        finally:
            values = [
                json.loads(r[0]) for r in db.execute("SELECT body FROM results ORDER BY source")
            ]
            if values:
                with (output / "assessment.csv").open("w", newline="") as stream:
                    writer = csv.DictWriter(stream, fieldnames=list(values[0]))
                    writer.writeheader()
                    writer.writerows(values)
            summary = {
                "sources": len(sources),
                "completed": len(values),
                "complete": len(values) == len(sources),
                "stop_requested": stop,
                "statuses": dict(Counter(r["status"] for r in values)),
                "coverage": dict(
                    Counter(r["state"] + "/" + r["arch"] + "/" + r["packing"] for r in values)
                ),
                "runtime_seconds": sum(r["runtime_seconds"] for r in values),
                "evidence_bytes": sum(r["evidence_bytes"] for r in values),
                "session_seconds": time.monotonic() - started,
                "split_assigned": False,
            }
            json_write(output / "summary.json", summary)
            db.close()
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        return summary
