"""Stage audited S3 representations onto a private Runpod Network Volume.

Run only on an approved isolated worker, not a personal workstation. Sample bytes
are relayed in bounded RAM; only private metadata/state is stored on the worker.
"""

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import sqlite3
import sys
import threading
import time
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from malweave.data.s3.client import make_s3_client
from malweave.data.s3.relay import PART_BYTES, RelayError, make_runpod_client, relay_object
from malweave.training.manifest import TrainingSample, load_training_manifest
from malweave.training.sources import ByteSourceError, S3ByteSource
from malweave.training.stage import StageError, _staging_lock


def _safe_relative(value: str) -> str:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(p in {"", ".", ".."} for p in value.split("/"))
    ):
        raise StageError("Destination paths must be nonempty, relative, without dot segments.")
    return value


def _publish(client: Any, bucket: str, key: str, payload: bytes, state_root: Path) -> None:
    try:
        relay_object(
            client,
            bucket,
            key,
            (payload[i : i + 1048576] for i in range(0, len(payload), 1048576)),
            size=len(payload),
            digest=sha256(payload).hexdigest(),
            journal=state_root / "multipart" / (sha256(key.encode()).hexdigest() + ".json"),
        )
    except (BotoCoreError, ClientError, OSError) as error:
        raise RelayError("metadata_publication_io_error") from error


def stage_network(
    manifest_path: Path,
    manifest_summary_path: Path,
    state_root: Path,
    *,
    source_bucket: str,
    destination_bucket: str,
    destination_prefix: str,
    destination_endpoint: str,
    destination_region: str,
    mount_root: str = "/workspace",
    representation: str = "raw",
    workers: int = 4,
    resume: bool = False,
    progress_every: int = 100,
    source_client: Any = None,
    destination_client: Any = None,
) -> dict[str, Any]:
    """Use one local state root and one exclusively owned destination prefix per job."""
    with _staging_lock(state_root):
        return _stage_network(
            manifest_path,
            manifest_summary_path,
            state_root,
            source_bucket=source_bucket,
            destination_bucket=destination_bucket,
            destination_prefix=destination_prefix,
            destination_endpoint=destination_endpoint,
            destination_region=destination_region,
            mount_root=mount_root,
            representation=representation,
            workers=workers,
            resume=resume,
            progress_every=progress_every,
            source_client=source_client,
            destination_client=destination_client,
        )


def _stage_network(
    manifest_path,
    manifest_summary_path,
    state_root,
    *,
    source_bucket,
    destination_bucket,
    destination_prefix,
    destination_endpoint,
    destination_region,
    mount_root,
    representation,
    workers,
    resume,
    progress_every,
    source_client,
    destination_client,
):
    started = time.monotonic()
    if not 1 <= workers <= 32 or progress_every < 1 or not source_bucket or not destination_bucket:
        raise StageError(
            "Require source/destination buckets, 1..32 workers and positive progress interval."
        )
    prefix = _safe_relative(destination_prefix)
    mount = PurePosixPath(mount_root)
    if not mount.is_absolute() or ".." in mount.parts:
        raise StageError("Volume mount root must be an absolute POSIX path without traversal.")
    if source_bucket == destination_bucket:
        raise StageError("Source and destination buckets must differ.")
    try:
        payload = manifest_path.read_bytes()
        audit_payload = manifest_summary_path.read_bytes()
        audit = json.loads(audit_payload)
        digest = sha256(payload).hexdigest()
        if (
            not (
                audit.get("inventory_audit_passed") is True
                or audit.get("release_audit", {}).get("passed") is True
            )
            or audit.get("manifest", {}).get("sha256") != digest
        ):
            raise StageError("Manifest digest or source release audit does not match.")
    except (OSError, ValueError, TypeError, AttributeError) as error:
        raise StageError("Cannot verify frozen manifest and source audit.") from error
    samples = load_training_manifest(manifest_path, representation)
    reserved = {
        "stage-contract.json",
        "split-manifest.csv",
        "manifest-summary.json",
        "staging-summary.json",
    }
    keys = []
    for sample in samples:
        relative = _safe_relative(sample.relative_path or "")
        if (
            relative.split("/")[0] in reserved
            or not sample.object_key
            or sample.object_size is None
            or not 0 < sample.object_size < PART_BYTES * 9999
        ):
            raise StageError("Unsupported sample path, source object or multipart size.")
        keys.append(prefix + "/" + relative)
    if len(set(keys)) != len(keys):
        raise StageError("Two representations share a destination path.")
    contract = {
        "schema": 1,
        "manifest_sha256": digest,
        "audit_sha256": sha256(audit_payload).hexdigest(),
        "source_bucket": source_bucket,
        "destination_bucket": destination_bucket,
        "destination_prefix": prefix,
        "destination_endpoint": destination_endpoint,
        "destination_region": destination_region,
        "representation": representation,
        "output_root": str(mount / prefix),
    }
    settings = json.dumps(contract, sort_keys=True)
    state_root = state_root.expanduser().resolve()
    state_path = state_root / "network-staging.sqlite"
    if resume != state_path.exists():
        raise StageError("Use --resume only with existing network staging state.")
    if not resume and state_root.exists() and any(state_root.iterdir()):
        raise StageError("New network staging state root must be empty.")
    state_root.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(state_path)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS settings (value TEXT NOT NULL)")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS outcomes (source TEXT PRIMARY KEY,label INTEGER,status TEXT,reason TEXT,size INTEGER,reused INTEGER,seconds REAL)"
        )
        if resume:
            if connection.execute("SELECT value FROM settings").fetchall() != [(settings,)]:
                raise StageError(
                    "Network staging settings changed; choose a new state root and prefix."
                )
        else:
            with connection:
                connection.execute("INSERT INTO settings VALUES (?)", (settings,))
        target = (
            destination_client
            if destination_client is not None
            else make_runpod_client(
                workers, endpoint_url=destination_endpoint, region=destination_region
            )
        )
        source = S3ByteSource(
            source_bucket,
            source_client
            if source_client is not None
            else make_s3_client(max_pool_connections=max(10, workers)),
        )
        _publish(
            target,
            destination_bucket,
            prefix + "/stage-contract.json",
            settings.encode(),
            state_root,
        )
        stop = threading.Event()

        def work(sample: TrainingSample, key: str):
            task_started = time.monotonic()
            status, reason, reused = "success", "", False

            def chunks():
                with closing(source.iter_chunks(sample)) as stream:
                    for chunk in stream:
                        if stop.is_set():
                            raise RelayError("interrupted")
                        yield chunk

            try:
                if stop.is_set():
                    raise RelayError("interrupted")
                with closing(chunks()) as stream:
                    reused = relay_object(
                        target,
                        destination_bucket,
                        key,
                        stream,
                        size=sample.object_size,
                        digest=sample.representation_sha256,
                        journal=state_root / "multipart" / (sample.source_sha256 + ".json"),
                    )
            except ByteSourceError as error:
                status, reason = "failed", error.code
            except RelayError as error:
                status, reason = "failed", str(error)
            except (BotoCoreError, ClientError, OSError) as error:
                status, reason = "failed", type(error).__name__
            return (
                sample.source_sha256,
                sample.label,
                status,
                reason,
                sample.object_size if status == "success" else 0,
                int(reused),
                time.monotonic() - task_started,
            )

        checked, failed = 0, 0
        jobs = iter(zip(samples, keys, strict=True))
        pool = ThreadPoolExecutor(max_workers=workers)
        pending = set()
        print(f"network staging: selected={len(samples)} workers={workers}", file=sys.stderr)
        try:
            for _ in range(workers):
                job = next(jobs, None)
                if job is not None:
                    pending.add(pool.submit(work, *job))
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    result = future.result()
                    with connection:
                        connection.execute(
                            "INSERT OR REPLACE INTO outcomes VALUES (?,?,?,?,?,?,?)", result
                        )
                    checked += 1
                    failed += result[2] != "success"
                    if checked % progress_every == 0 or checked == len(samples):
                        print(
                            f"network staging: checked={checked} verified={checked - failed} failed={failed} selected={len(samples)} elapsed_seconds={time.monotonic() - started:.0f}",
                            file=sys.stderr,
                        )
                    job = next(jobs, None)
                    if job is not None:
                        pending.add(pool.submit(work, *job))
        finally:
            stop.set()
            for future in pending:
                future.cancel()
            pool.shutdown(wait=True, cancel_futures=True)
        outcomes = list(
            connection.execute("SELECT label,status,reason,size,reused,seconds FROM outcomes")
        )
    finally:
        connection.close()
    success, failures, reasons = Counter(), Counter(), Counter()
    for label, status, reason, *_ in outcomes:
        name = "benign" if label == 0 else "ransomware"
        if status == "success":
            success[name] += 1
        else:
            failures[name] += 1
            reasons[reason] += 1
    ready = {
        "passed": checked == len(samples) and not failures,
        "manifest_sha256": digest,
        "representation": representation,
        "selected": len(samples),
        "success_by_label": dict(success),
        "failure_by_label": dict(failures),
        "failure_reasons": dict(reasons),
        "output_root": contract["output_root"],
        "output_bytes": sum(row[3] for row in outcomes),
        "verification": "full_source_and_destination_sha256",
    }
    report = {
        **ready,
        "publication_complete": False,
        "workers": workers,
        "reused_files_this_run": sum(row[4] for row in outcomes),
        "uploaded_payload_bytes_this_run": sum(row[3] for row in outcomes if not row[4]),
        "transfer_accounting": "successful_outcomes_only_excludes_failed_and_readback_bytes",
        "wall_seconds_this_run": round(time.monotonic() - started, 3),
        "worker_seconds_sum": sum(row[5] for row in outcomes),
    }
    report_path = state_root / "network-staging-summary.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    if not ready["passed"]:
        raise StageError("Network staging incomplete; see local report and rerun with --resume.")
    for name, content in (
        ("split-manifest.csv", payload),
        ("manifest-summary.json", audit_payload),
        ("staging-summary.json", json.dumps(ready, sort_keys=True, indent=2).encode()),
    ):
        _publish(target, destination_bucket, prefix + "/" + name, content, state_root)
    report["publication_complete"] = True
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report
