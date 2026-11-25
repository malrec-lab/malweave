"""Atomic private artifacts and single-writer locking for resumable SOREL jobs."""

from contextlib import contextmanager
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any


class SorelError(ValueError):
    """Invalid setup or inconsistent saved evidence."""


class SourceFailure(Exception):
    """An accounted per-source failure."""


def digest(path: Path) -> str:
    result = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024**2), b""):
            result.update(chunk)
    return result.hexdigest()


def durable_replace(source: Path, path: Path) -> None:
    """Rename a flushed file and sync its destination directory before state commits."""
    source.replace(path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    durable_replace(temporary, path)


def json_write(path: Path, value: Any) -> None:
    atomic_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


@contextmanager
def job_lock(job: Path):
    job.mkdir(parents=True, exist_ok=True)
    with (job / ".job.lock").open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SorelError(
                "Another process is writing this job; use one runner per job."
            ) from error
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)
