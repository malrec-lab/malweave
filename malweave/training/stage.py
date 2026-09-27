"""Stage a frozen S3 split onto an isolated training worker before training.

RAW objects are live malware. This module must not be run on a personal workstation.
It never executes, previews, uploads, or modifies an S3 source object.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import closing, contextmanager
from dataclasses import dataclass
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
from typing import Any

from malweave.data.s3.client import make_s3_client
from malweave.data.s3.inventory import validate_private_path
from malweave.training.manifest import TrainingSample, load_training_manifest
from malweave.training.sources import ByteSourceError, S3ByteSource


class StageError(ValueError):
    """The selected representations were not completely staged and verified."""


@contextmanager
def _staging_lock(output_root: Path) -> Iterator[None]:
    """Hold a process lock through writes and report publication; never unlink it.

    A persistent sibling lock also protects an empty/new output root. The OS releases
    ownership after interruption or process death; the file itself is not a stale lock.
    """
    validate_private_path(output_root)
    root = output_root.expanduser().resolve()
    root.parent.mkdir(parents=True, exist_ok=True)
    lock_path = root.with_name(root.name + ".staging.lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EAGAIN, errno.EACCES}:
                raise StageError(
                    "Another staging process owns this output root. Do not run --resume "
                    "alongside it; wait for it to exit or stop it first."
                ) from error
            raise StageError("Cannot acquire staging lock; refusing unlocked writes.") from error
        yield
    finally:
        os.close(descriptor)


def _file_matches(path: Path, sample: TrainingSample) -> bool:
    try:
        if sample.object_size is not None and path.stat().st_size != sample.object_size:
            return False
        digest = sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest() == sample.representation_sha256
    except OSError:
        return False


def _destination(root: Path, sample: TrainingSample) -> Path:
    if not sample.relative_path:
        raise StageError("The staged representation needs a relative local path.")
    relative = Path(sample.relative_path)
    target = (root / relative).resolve()
    if relative.is_absolute() or not target.is_relative_to(root):
        raise StageError("A staged representation path escapes its output root.")
    return target


def _write_new_verified_file(path: Path, content: bytes | Iterable[bytes]) -> None:
    """Link a complete temporary file into place without overwriting existing bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".stage-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if isinstance(content, bytes):
                handle.write(content)
            else:
                for chunk in content:
                    handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


@dataclass
class _Outcome:
    sample: TrainingSample
    status: str = "success"
    reason: str = ""
    size: int = 0
    downloaded_bytes: int = 0
    reused: bool = False
    runtime_seconds: float = 0.0
    source_seconds: float = 0.0


class _Cancelled(Exception):
    """Worker cooperatively stopped before publication."""


def _verified_chunks(
    source: S3ByteSource, outcome: _Outcome, stop: threading.Event
) -> Iterator[bytes]:
    digest = sha256()
    sample = outcome.sample
    with closing(source.iter_chunks(sample)) as chunks:
        while True:
            if stop.is_set():
                raise _Cancelled()
            started = time.perf_counter()
            try:
                chunk = next(chunks, None)
                if chunk is None:
                    break
                outcome.downloaded_bytes += len(chunk)
                if (
                    sample.object_size is not None
                    and outcome.downloaded_bytes > sample.object_size
                ):
                    raise ByteSourceError("S3 size exceeds manifest.", code="size_mismatch")
                digest.update(chunk)
            finally:
                outcome.source_seconds += time.perf_counter() - started
            yield chunk
    if sample.object_size is not None and outcome.downloaded_bytes != sample.object_size:
        raise ByteSourceError("S3 size differs from manifest.", code="size_mismatch")
    if digest.hexdigest() != sample.representation_sha256:
        raise ByteSourceError("S3 digest differs from manifest.", code="digest_mismatch")
    if stop.is_set():
        raise _Cancelled()


def _stage_one(
    sample: TrainingSample,
    target: Path,
    source: S3ByteSource,
    stop: threading.Event,
    reuse_root: Path | None = None,
) -> _Outcome:
    result = _Outcome(sample)
    started = time.perf_counter()
    try:
        if stop.is_set():
            raise _Cancelled()
        if target.exists():
            if not _file_matches(target, sample):
                raise ByteSourceError(
                    "Existing bytes conflict with manifest.", code="local_conflict"
                )
            result.size = target.stat().st_size
            result.reused = True
        else:
            cached = _destination(reuse_root, sample) if reuse_root is not None else None
            if cached is not None and cached.exists():
                if not _file_matches(cached, sample):
                    raise ByteSourceError(
                        "Cached bytes conflict with manifest.", code="cache_conflict"
                    )
                if stop.is_set():
                    raise _Cancelled()
                target.parent.mkdir(parents=True, exist_ok=True)
                os.link(cached, target)
                result.size = target.stat().st_size
                result.reused = True
                return result
            with closing(_verified_chunks(source, result, stop)) as chunks:
                try:
                    _write_new_verified_file(target, chunks)
                except FileExistsError:
                    if not _file_matches(target, sample):
                        raise ByteSourceError(
                            "Destination conflict.", code="local_conflict"
                        ) from None
            result.size = target.stat().st_size
    except ByteSourceError as error:
        result.status, result.reason = "failed", error.code
    except OSError as error:
        result.status = "failed"
        result.reason = "write_error:" + errno.errorcode.get(error.errno, "UNKNOWN")
    finally:
        result.runtime_seconds = time.perf_counter() - started
    return result


def _stage_outcomes(
    samples: list[TrainingSample],
    destinations: list[Path],
    source: S3ByteSource,
    workers: int,
    reuse_root: Path | None = None,
) -> Iterator[_Outcome]:
    """At most workers outstanding jobs; only the caller commits SQLite outcomes.

    On interruption stop scheduling, cancel queued jobs, and drain running workers
    before releasing the output lock. Published but uncommitted files are reverified
    on resume, so interruption cannot silently mark the corpus complete.
    """
    stop = threading.Event()
    jobs = iter(zip(samples, destinations, strict=True))
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="staging")
    pending = set()
    try:
        for sample, target in jobs:
            pending.add(pool.submit(_stage_one, sample, target, source, stop, reuse_root))
            if len(pending) == workers:
                break
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                yield future.result()
            for _ in done:
                job = next(jobs, None)
                if job is not None:
                    pending.add(pool.submit(_stage_one, *job, source, stop, reuse_root))
    finally:
        stop.set()
        for future in pending:
            future.cancel()
        pool.shutdown(wait=True, cancel_futures=True)


def stage_manifest_from_s3(
    manifest_path: Path,
    manifest_summary_path: Path,
    output_root: Path,
    *,
    bucket: str,
    representation: str = "raw",
    resume: bool = False,
    client: Any = None,
    progress_every: int = 100,
    workers: int = 1,
    reuse_root: Path | None = None,
) -> dict[str, Any]:
    """Stage under an exclusive output lock, including resume and report writes."""
    with _staging_lock(output_root):
        return _stage_manifest_from_s3(
            manifest_path,
            manifest_summary_path,
            output_root,
            bucket=bucket,
            representation=representation,
            resume=resume,
            client=client,
            progress_every=progress_every,
            workers=workers,
            reuse_root=reuse_root,
        )


def _stage_manifest_from_s3(
    manifest_path: Path,
    manifest_summary_path: Path,
    output_root: Path,
    *,
    bucket: str,
    representation: str = "raw",
    resume: bool = False,
    client: Any = None,
    progress_every: int = 100,
    workers: int = 1,
    reuse_root: Path | None = None,
) -> dict[str, Any]:
    """Download *all selected rows*, verify bytes, and durably record each outcome."""
    validate_private_path(output_root)
    if progress_every < 1 or not bucket or not isinstance(workers, int) or not 1 <= workers <= 32:
        raise StageError("A bucket, positive progress interval, and 1..32 workers are required.")
    run_started = time.perf_counter()
    print(f"staging: phase=preflight workers={workers}", file=sys.stderr)
    if not manifest_path.is_file() or not manifest_summary_path.is_file():
        raise StageError(
            "Missing frozen manifest or audit report. For RanDS RAW, run "
            "'malweave experiment freeze-rands-raw --preset full' (or pilot) first."
        )
    manifest_digest = sha256(manifest_path.read_bytes()).hexdigest()
    try:
        audit = json.loads(manifest_summary_path.read_text(encoding="utf-8"))
        audit_passed = (
            audit.get("inventory_audit_passed") is True
            or audit.get("release_audit", {}).get("passed") is True
        )
        if not audit_passed or audit.get("manifest", {}).get("sha256") != manifest_digest:
            raise StageError("Manifest digest or source release audit does not match.")
    except (OSError, ValueError, TypeError) as error:
        raise StageError("Cannot verify the frozen manifest and audit report.") from error
    samples = load_training_manifest(manifest_path, representation)
    if any(not sample.object_key for sample in samples):
        raise StageError("Every staged sample needs a declared S3 object key.")
    root = output_root.expanduser().resolve()
    if reuse_root is not None:
        validate_private_path(reuse_root)
        reuse_root = reuse_root.expanduser().resolve()
        if (
            root == reuse_root
            or root.is_relative_to(reuse_root)
            or reuse_root.is_relative_to(root)
        ):
            raise StageError("Reuse and output roots must be separate, non-nested directories.")
    destinations = [_destination(root, sample) for sample in samples]
    if len(set(destinations)) != len(destinations):
        raise StageError("Two samples would occupy the same staged output path.")
    state_path = root / "staging.sqlite"
    report_path = root / "staging-summary.json"
    if resume != state_path.exists():
        raise StageError("Use --resume only with an existing staging state; never overwrite it.")
    if not resume and root.exists() and any(root.iterdir()):
        raise StageError("New staging output root must be empty.")
    root.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(state_path)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS outcomes (source_sha256 TEXT PRIMARY KEY, label INTEGER NOT NULL, "
            "status TEXT NOT NULL, reason TEXT NOT NULL, output_size INTEGER NOT NULL, "
            "runtime_seconds REAL NOT NULL)"
        )
        settings = {
            "manifest_sha256": manifest_digest,
            "representation": representation,
            "bucket": bucket,
            "output_root": str(root),
        }
        if reuse_root is not None:
            settings["reuse_root"] = str(reuse_root)
        if resume:
            saved = dict(connection.execute("SELECT name, value FROM settings"))
            if saved != settings:
                raise StageError("Staging settings changed; use a new output root.")
        else:
            with connection:
                connection.executemany("INSERT INTO settings VALUES (?, ?)", settings.items())
        # Construct the SDK client outside threads; each worker owns its stream.
        if client is None:
            client = make_s3_client(max_pool_connections=max(10, workers))
        source = S3ByteSource(bucket, client)
        verified_this_run = 0
        failed_this_run = 0
        downloaded_bytes = 0
        reused_this_run = 0
        source_seconds = 0.0
        worker_seconds = 0.0
        sqlite_seconds = 0.0
        transfer_started = time.perf_counter()
        prior_runtimes = dict(
            connection.execute("SELECT source_sha256, runtime_seconds FROM outcomes")
        )
        reasons_this_run: Counter[str] = Counter()
        checked_this_run = 0
        abort_reason = None
        print(
            f"staging: phase=transfer selected={len(samples)} workers={workers}", file=sys.stderr
        )
        with closing(
            _stage_outcomes(samples, destinations, source, workers, reuse_root)
        ) as results:
            for index, result in enumerate(results, start=1):
                checked_this_run = index
                sample = result.sample
                downloaded_bytes += result.downloaded_bytes
                reused_this_run += int(result.reused)
                source_seconds += result.source_seconds
                worker_seconds += result.runtime_seconds
                if result.status == "success":
                    verified_this_run += 1
                else:
                    failed_this_run += 1
                    reasons_this_run[result.reason] += 1
                    if reasons_this_run[result.reason] == 1:
                        print(f"staging failure: reason={result.reason}", file=sys.stderr)
                commit_started = time.perf_counter()
                with connection:
                    connection.execute(
                        "INSERT OR REPLACE INTO outcomes VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            sample.source_sha256,
                            sample.label,
                            result.status,
                            result.reason,
                            result.size,
                            prior_runtimes.get(sample.source_sha256, 0.0) + result.runtime_seconds,
                        ),
                    )
                sqlite_seconds += time.perf_counter() - commit_started
                if index % progress_every == 0 or index == len(samples):
                    elapsed = max(time.perf_counter() - transfer_started, 1e-9)
                    print(
                        f"staging: checked={index} verified={verified_this_run} "
                        f"failed={failed_this_run} selected={len(samples)} "
                        f"reused={reused_this_run} files_per_second={index / elapsed:.2f} "
                        f"download_mib_per_second={downloaded_bytes / 1048576 / elapsed:.2f} "
                        f"eta_seconds_approx={(len(samples) - index) * elapsed / index:.0f} "
                        f"failure_reasons={dict(reasons_this_run)}",
                        file=sys.stderr,
                    )
                if result.reason in {
                    "write_error:ENOSPC",
                    "write_error:EDQUOT",
                    "write_error:EACCES",
                    "write_error:EROFS",
                }:
                    abort_reason = result.reason
                    print(
                        f"staging: stopping early reason={abort_reason}; fix storage before resume",
                        file=sys.stderr,
                    )
                    break
        outcomes = list(
            connection.execute(
                "SELECT label, status, reason, output_size, runtime_seconds FROM outcomes"
            )
        )
    finally:
        connection.close()
    success: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    for label, status, reason, _, _ in outcomes:
        name = "benign" if label == 0 else "ransomware"
        if status == "success":
            success[name] += 1
        else:
            failures[name] += 1
            reasons[reason] += 1
    report = {
        "passed": checked_this_run == len(samples)
        and sum(success.values()) == len(samples)
        and not failures,
        "manifest_sha256": manifest_digest,
        "representation": representation,
        "selected": len(samples),
        "success_by_label": dict(success),
        "failure_by_label": dict(failures),
        "failure_reasons": dict(reasons),
        "output_root": str(root),
        "output_bytes": sum(size for _, status, _, size, _ in outcomes if status == "success"),
        "downloaded_bytes_this_run": downloaded_bytes,
        "transfer_accounting": "recorded_outcomes_only",
        "reused_files_this_run": reused_this_run,
        "reuse_root": str(reuse_root) if reuse_root is not None else None,
        "workers": workers,
        "checked_this_run": checked_this_run,
        "abort_reason": abort_reason,
        "wall_seconds_this_run": round(time.perf_counter() - run_started, 3),
        "timings_this_run": {
            "preflight_seconds": round(transfer_started - run_started, 3),
            "source_read_and_hash_seconds_sum": round(source_seconds, 3),
            "worker_seconds_sum": round(worker_seconds, 3),
            "local_io_and_other_seconds_sum": round(max(0.0, worker_seconds - source_seconds), 3),
            "sqlite_seconds": round(sqlite_seconds, 3),
        },
        "runtime_seconds": round(sum(seconds for *_, seconds in outcomes), 3),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not report["passed"]:
        raise StageError("Staging incomplete; see aggregate report and rerun with --resume.")
    return report
