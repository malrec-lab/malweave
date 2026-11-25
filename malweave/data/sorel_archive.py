"""Bounded S3 publication of EXE/evidence and consistent, portable state checkpoints.

AWS CLI handles credentials, TLS, retries and request checksums. Raw/spool/scratch
files are never uploaded. A batch is evicted only after both uploads and its
archive-index transaction have succeeded.
"""

from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import yaml

from malweave.data import sorel_ledger as ledger
from malweave.data.sorel_io import SorelError, digest, json_write


def _aws(*args: str, missing_ok: bool = False) -> bool:
    try:
        result = subprocess.run(
            ["aws", *args, "--no-cli-pager"],
            capture_output=True,
            text=True,
            check=False,
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SorelError("S3 transfer interrupted; local state preserved.") from error
    if result.returncode:
        if missing_ok and any(value in result.stderr for value in ("404", "NoSuchKey")):
            return False
        raise SorelError(f"S3 transfer failed; local state preserved: {result.stderr[-1500:]}")
    return True


def _upload(source: Path, destination: str, *, recursive: bool = False) -> None:
    args = [
        "s3",
        "cp",
        str(source),
        destination,
        "--only-show-errors",
        "--checksum-algorithm",
        "SHA256",
    ]
    if recursive:
        args.append("--recursive")
    _aws(*args)


def _download(source: str, destination: Path, *, missing_ok: bool = False) -> bool:
    destination.parent.mkdir(parents=True, exist_ok=True)
    return _aws("s3", "cp", source, str(destination), "--only-show-errors", missing_ok=missing_ok)


def validate_prefix(prefix: str) -> str:
    parsed = urlsplit(prefix)
    if (
        parsed.scheme != "s3"
        or not parsed.netloc
        or not parsed.path.strip("/")
        or parsed.query
        or parsed.fragment
        or ".." in parsed.path.split("/")
    ):
        raise SorelError("Use a dedicated s3://bucket/prefix for this SOREL collection.")
    if not shutil.which("aws"):
        raise SorelError("S3 output requires AWS CLI v2 and configured credentials.")
    return prefix.rstrip("/")


class SorelArchive:
    def __init__(self, job: Path, prefix: str, config: Any):
        self.job = job.resolve()
        self.prefix = validate_prefix(prefix)
        self.config = config
        saved = self.job / "remote.json"
        identity = {"schema": 1, "prefix": self.prefix, "format": "batch-evidence-tar-gzip"}
        if saved.exists() and json.loads(saved.read_text()) != identity:
            raise SorelError("S3 destination changed; restore the correct part or use a new job.")
        if not saved.exists():
            with tempfile.TemporaryDirectory(dir=self.job) as tmp:
                if _download(
                    self.prefix + "/checkpoint-latest.json",
                    Path(tmp) / "pointer.json",
                    missing_ok=True,
                ):
                    raise SorelError("S3 part already exists; restore into an empty local job.")
        json_write(saved, identity)
        self.last_checkpoint = time.monotonic()

    def flush(self, db: sqlite3.Connection) -> None:
        """Archive completed outcomes not yet published, including interrupted batches."""
        from malweave.data.sorel import _export_sorel, _verify_row

        while True:
            rows = [
                json.loads(value)
                for (value,) in db.execute(
                    "SELECT o.value FROM sources s JOIN outcomes o ON o.id=s.id "
                    "WHERE s.done=1 AND s.archived=0 ORDER BY s.id LIMIT ?",
                    (self.config.batch_size,),
                )
            ]
            if not rows:
                return
            for row in rows:
                _verify_row(self.job, row)
            with tempfile.TemporaryDirectory(prefix="publish-", dir=self.job) as tmp:
                stage = Path(tmp)
                paths: set[Path] = set()
                for row in rows:
                    for name in ("file", "die", "lief"):
                        if row.get(f"{name}_report_path"):
                            paths.add(Path(row[f"{name}_report_path"]))
                    if row.get("download_receipt_report_path"):
                        directory = Path(row["download_receipt_report_path"]).parent
                        paths.update(
                            p.relative_to(self.job) for p in (self.job / directory).glob("*.json")
                        )
                    if row["status"] == "success":
                        relative = Path(row["exe_path"])
                        target = stage / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        if not target.exists():
                            os.link(self.job / relative, target)
                exports = stage / "exports"
                exports.mkdir()
                _export_sorel(self.job, rows, output_dir=exports)
                archive = stage / "evidence.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    for relative in sorted(paths):
                        tar.add(self.job / relative, arcname=str(relative), recursive=False)
                    for p in sorted(exports.iterdir()):
                        tar.add(p, arcname="exports/" + p.name, recursive=False)
                checksum = digest(archive)
                uri = f"{self.prefix}/evidence/{checksum}.tar.gz"
                if (stage / "exe").exists():
                    _upload(stage / "exe", self.prefix + "/exe/", recursive=True)
                _upload(archive, uri)
                with db:
                    db.execute(
                        "INSERT INTO archives VALUES (?, ?, ?)",
                        (checksum, uri, json.dumps([r["original_sha256"] for r in rows])),
                    )
                    for row in rows:
                        db.execute(
                            "UPDATE sources SET archived=1 WHERE id=?", (row["original_sha256"],)
                        )
                        db.execute(
                            "INSERT INTO archive_sources VALUES (?, ?)",
                            (row["original_sha256"], checksum),
                        )
                # All workers have joined at this point; identical EXE paths can be removed safely.
                for relative in paths:
                    (self.job / relative).unlink(missing_ok=True)
                for row in rows:
                    if row["status"] == "success":
                        relative = Path(row["exe_path"])
                        (self.job / relative).unlink(missing_ok=True)
                        paths.add(relative)
                for relative in paths:
                    parent = (self.job / relative).parent
                    while parent != self.job:
                        try:
                            parent.rmdir()
                        except OSError:
                            break
                        parent = parent.parent
            if time.monotonic() - self.last_checkpoint >= 900:
                self.checkpoint(db)

    def checkpoint(self, db: sqlite3.Connection) -> None:
        """Publish the pointer last so interruption cannot expose a torn checkpoint."""
        if db.execute("SELECT COUNT(*) FROM sources WHERE done=1 AND archived=0").fetchone()[0]:
            raise SorelError("Cannot checkpoint outcomes before their S3 publication.")
        with tempfile.TemporaryDirectory(prefix="checkpoint-", dir=self.job) as tmp:
            stage = Path(tmp)
            with closing(sqlite3.connect(stage / "state.sqlite")) as target:
                db.backup(target)
            for name in ("selection.json", "metadata-audit.json", "remote.json"):
                shutil.copyfile(self.job / name, stage / name)
            (stage / "config.yaml").write_text(
                yaml.safe_dump(json.loads((self.job / "selection.json").read_text())["config"])
            )
            selected = json.loads((self.job / "selection.json").read_text())["selected"]
            json_write(stage / "summary.json", ledger.summary(db, selected))
            files = {
                p.name: {"sha256": digest(p), "bytes": p.stat().st_size} for p in stage.iterdir()
            }
            location = f"{self.prefix}/checkpoints/{uuid4().hex}"
            _upload(stage, location + "/", recursive=True)
            pointer = {"schema": 1, "location": location, "files": files}
            json_write(stage / "checkpoint-latest.json", pointer)
            _upload(stage / "checkpoint-latest.json", self.prefix + "/checkpoint-latest.json")
            # Retain only the new checkpoint after its durable pointer is published.
            local = self.job / "checkpoint-latest.json"
            previous = json.loads(local.read_text()) if local.is_file() else None
            json_write(local, pointer)
            self.last_checkpoint = time.monotonic()
            if previous and previous["location"] != location:
                _aws("s3", "rm", previous["location"] + "/", "--recursive", "--only-show-errors")

    def publish_exports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tables-", dir=self.job) as tmp:
            stage = Path(tmp)
            for name in ("results.csv", "manifest.json", "export-summary.json", "summary.json"):
                os.link(self.job / name, stage / name)
            _upload(stage, self.prefix + "/exports/", recursive=True)


_CHECKPOINT_FILES = {
    "state.sqlite",
    "selection.json",
    "metadata-audit.json",
    "remote.json",
    "config.yaml",
    "summary.json",
}


def restore(job: Path, prefix: str, *, missing_ok: bool = False) -> bool:
    """Restore a consistent checkpoint into an empty local part, without raw data."""
    prefix = validate_prefix(prefix)
    marker = job / "restore-in-progress.json"
    if marker.exists() and not (job / "selection.json").exists():
        # A crash while publishing a verified restore must be retryable. Only these
        # provisional checkpoint files can exist before the selection is published.
        for name in _CHECKPOINT_FILES | {"checkpoint-latest.json"}:
            (job / name).unlink(missing_ok=True)
        marker.unlink()
    if (job / "state.sqlite").exists() or (job / "selection.json").exists():
        raise SorelError(
            "Restore requires an empty job directory; existing progress is preserved."
        )
    job.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="restore-", dir=job) as tmp:
        stage = Path(tmp)
        if not _download(
            prefix + "/checkpoint-latest.json", stage / "pointer.json", missing_ok=missing_ok
        ):
            return False
        pointer = json.loads((stage / "pointer.json").read_text())
        if not pointer["location"].startswith(prefix + "/checkpoints/"):
            raise SorelError("Invalid checkpoint location.")
        expected = _CHECKPOINT_FILES
        if set(pointer["files"]) != expected:
            raise SorelError("Invalid checkpoint file inventory.")
        for name, entry in pointer["files"].items():
            p = stage / name
            _download(pointer["location"] + "/" + name, p)
            if p.stat().st_size != entry["bytes"] or digest(p) != entry["sha256"]:
                raise SorelError("S3 checkpoint checksum mismatch.")
        if json.loads((stage / "remote.json").read_text())["prefix"] != prefix:
            raise SorelError("Checkpoint belongs to a different S3 part.")
        json_write(marker, {"schema": 1, "prefix": prefix})
        for name in expected - {"state.sqlite", "selection.json"}:
            shutil.move(stage / name, job / name)
        shutil.move(stage / "state.sqlite", job / "state.sqlite")
        shutil.copyfile(stage / "pointer.json", job / "checkpoint-latest.json")
        shutil.move(stage / "selection.json", job / "selection.json")
        marker.unlink()
    return True


_CACHE: dict[str, tuple[str, Path]] = {}


def artifact_path(job: Path, row: dict[str, Any], relative: str) -> Path:
    """Read saved remote evidence through a one-batch disk cache for verify/export."""
    path = (job / relative).resolve()
    if not path.is_relative_to(job):
        raise SorelError("Artifact path escapes the job.")
    if path.is_file() or not (job / "remote.json").exists():
        return path
    prefix = json.loads((job / "remote.json").read_text())["prefix"]
    cache = job / "archive-cache"
    cache.mkdir(exist_ok=True)
    if relative.startswith("exe/"):
        root = cache / "exe"
        if root.exists():
            shutil.rmtree(root)
        path = root / Path(relative).name
        _download(prefix + "/" + relative, path)
        return path
    with closing(sqlite3.connect((job / "state.sqlite").as_uri() + "?mode=ro", uri=True)) as db:
        record = db.execute(
            "SELECT a.digest,a.uri FROM archives a JOIN archive_sources s "
            "ON s.archive=a.digest WHERE s.id=?",
            (row["original_sha256"],),
        ).fetchone()
    if not record:
        raise SorelError("Missing archived evidence index.")
    checksum, uri = record
    previous = _CACHE.get(str(job))
    root = cache / checksum
    if previous != (checksum, root) or not root.exists():
        if previous is None:
            for old in cache.iterdir():
                if old.is_dir():
                    shutil.rmtree(old)
        if previous and previous[1].exists():
            shutil.rmtree(previous[1])
        archive = cache / "download.tar.gz"
        _download(uri, archive)
        if digest(archive) != checksum:
            raise SorelError("Archived evidence checksum mismatch.")
        if root.exists():
            shutil.rmtree(root)
        root.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                target = (root / member.name).resolve()
                if not member.isfile() or not target.is_relative_to(root):
                    raise SorelError("Unsafe archived evidence member.")
                content = tar.extractfile(member)
                if content is None:
                    raise SorelError("Unreadable archived evidence member.")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as stream:
                    shutil.copyfileobj(content, stream)
        archive.unlink()
        _CACHE[str(job)] = (checksum, root)
    return root / relative
