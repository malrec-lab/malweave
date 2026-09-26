"""Stage a frozen S3 split onto an isolated training worker before training.

RAW objects are live malware. This module must not be run on a personal workstation.
It never executes, previews, uploads, or modifies an S3 source object.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from typing import Any

from malweave.data.s3.inventory import validate_private_path
from malweave.training.manifest import TrainingSample, load_training_manifest
from malweave.training.sources import ByteSourceError, S3ByteSource, VerifiedByteSource


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


def _write_new_verified_file(path: Path, content: bytes) -> None:
    """Link a complete temporary file into place without overwriting existing bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".stage-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


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
) -> dict[str, Any]:
    """Download *all selected rows*, verify bytes, and durably record each outcome."""
    validate_private_path(output_root)
    if progress_every < 1 or not bucket:
        raise StageError("A bucket and positive progress interval are required.")
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
        if resume:
            saved = dict(connection.execute("SELECT name, value FROM settings"))
            if saved != settings:
                raise StageError("Staging settings changed; use a new output root.")
        else:
            with connection:
                connection.executemany("INSERT INTO settings VALUES (?, ?)", settings.items())
        source = VerifiedByteSource(S3ByteSource(bucket, client))
        verified_this_run = 0
        failed_this_run = 0
        reasons_this_run: Counter[str] = Counter()
        for index, (sample, target) in enumerate(zip(samples, destinations, strict=True), start=1):
            started = time.perf_counter()
            status = "success"
            reason = ""
            size = 0
            try:
                if target.exists():
                    if not _file_matches(target, sample):
                        raise ByteSourceError(
                            "Existing staged bytes conflict with the manifest.",
                            code="local_conflict",
                        )
                    size = target.stat().st_size
                else:
                    content = source.read(sample)
                    try:
                        _write_new_verified_file(target, content)
                    except FileExistsError:
                        # Defensive against older/external writers not using our lock.
                        if not _file_matches(target, sample):
                            raise ByteSourceError(
                                "A conflicting destination appeared during staging.",
                                code="local_conflict",
                            ) from None
                    size = len(content)
            except ByteSourceError as error:
                status, reason = "failed", error.code
            except OSError as error:
                status = "failed"
                reason = "write_error:" + errno.errorcode.get(error.errno, "UNKNOWN")
            if status == "success":
                verified_this_run += 1
            else:
                failed_this_run += 1
                reasons_this_run[reason] += 1
                if reasons_this_run[reason] == 1:
                    print(
                        f"staging failure: reason={reason} (details recorded in SQLite)",
                        file=sys.stderr,
                    )
            prior = connection.execute(
                "SELECT runtime_seconds FROM outcomes WHERE source_sha256 = ?",
                (sample.source_sha256,),
            ).fetchone()
            cumulative_seconds = (
                (float(prior[0]) if prior else 0.0) + time.perf_counter() - started
            )
            with connection:
                connection.execute(
                    "INSERT OR REPLACE INTO outcomes VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        sample.source_sha256,
                        sample.label,
                        status,
                        reason,
                        size,
                        cumulative_seconds,
                    ),
                )
            if index % progress_every == 0 or index == len(samples):
                print(
                    f"staging: checked={index} verified={verified_this_run} "
                    f"failed={failed_this_run} selected={len(samples)} "
                    f"failure_reasons={dict(reasons_this_run)}",
                    file=sys.stderr,
                )
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
        "passed": sum(success.values()) == len(samples) and not failures,
        "manifest_sha256": manifest_digest,
        "representation": representation,
        "selected": len(samples),
        "success_by_label": dict(success),
        "failure_by_label": dict(failures),
        "failure_reasons": dict(reasons),
        "output_root": str(root),
        "output_bytes": sum(size for _, status, _, size, _ in outcomes if status == "success"),
        "downloaded_bytes_this_run": source.bytes_read,
        "runtime_seconds": round(sum(seconds for *_, seconds in outcomes), 3),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not report["passed"]:
        raise StageError("Staging incomplete; see aggregate report and rerun with --resume.")
    return report
