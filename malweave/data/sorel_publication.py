"""SOREL v3: conditional ownership, immutable evidence, atomic snapshots and replay.

Only derived EXE and static evidence enter S3. All raw inputs stay local.
"""

from __future__ import annotations

import configparser
from contextlib import closing
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tarfile
import tempfile
import threading
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from malweave.data import sorel_protocol as state
from malweave.data.sorel_io import SorelError, digest, json_write
from malweave.data.sorel_tools import Processes


class AWS:
    """AWS CLI alone retries each request (standard mode, three attempts total)."""

    def __init__(self, job: Path, processes: Processes, timeout: int = 900):
        self.job, self.processes, self.timeout = job, processes, timeout
        self.metrics = {"cli_invocations": 0, "uploaded_bytes": 0, "downloaded_bytes": 0}
        self._lock = threading.Lock()

    def call(
        self, *args: str, missing: bool = False, s3_workers: int | None = None
    ) -> dict[str, Any] | None:
        environment = dict(os.environ, AWS_RETRY_MODE="standard", AWS_MAX_ATTEMPTS="3")
        environment["AWS_PAGER"] = ""
        with tempfile.TemporaryDirectory(prefix="aws-", dir=self.job) as temporary:
            root = Path(temporary)
            if s3_workers is not None:
                config = configparser.RawConfigParser()
                config.read(os.environ.get("AWS_CONFIG_FILE", str(Path.home() / ".aws/config")))
                profile = os.environ.get("AWS_PROFILE", "default")
                section = "default" if profile == "default" else "profile " + profile
                if not config.has_section(section):
                    config.add_section(section)
                config.set(
                    section,
                    "s3",
                    "\nmax_concurrent_requests = "
                    + str(s3_workers)
                    + "\nmax_queue_size = "
                    + str(max(16, s3_workers * 4)),
                )
                config_path = root / "config"
                with config_path.open("w") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    config.write(stream)
                environment["AWS_CONFIG_FILE"] = str(config_path)
            result = self.processes.run(
                ["aws", *args, "--output", "json", "--no-cli-pager"],
                root,
                "request",
                timeout=self.timeout,
                env=environment,
            )
            with self._lock:
                self.metrics["cli_invocations"] += 1
            error = (root / result["stderr_file"]).read_text(errors="replace")
            if result["status"] != "success":
                if missing and any(code in error for code in ("(404)", "NoSuchKey", "Not Found")):
                    return None
                raise SorelError(
                    "S3 request failed; unpublished data retained: "
                    + error[-1500:]
                    + " ("
                    + result["status"]
                    + ")"
                )
            output = (root / result["stdout_file"]).read_text()
            return json.loads(output) if output.strip() else {}

    @staticmethod
    def split(uri: str) -> tuple[str, str]:
        parsed = urlsplit(uri)
        if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
            raise SorelError("Expected a dedicated s3://bucket/prefix")
        if parsed.query or parsed.fragment or ".." in parsed.path.split("/"):
            raise SorelError("Invalid S3 prefix")
        return parsed.netloc, parsed.path.lstrip("/")

    def put(self, path: Path, uri: str) -> None:
        self.call(
            "s3", "cp", str(path), uri, "--only-show-errors", "--checksum-algorithm", "SHA256"
        )
        with self._lock:
            self.metrics["uploaded_bytes"] += path.stat().st_size

    def put_tree(self, source: Path, destination: str, workers: int) -> None:
        # One CLI process reuses its S3 client/connections; every EXE remains its own PUT/object.
        self.call(
            "s3",
            "cp",
            str(source),
            destination,
            "--recursive",
            "--only-show-errors",
            "--checksum-algorithm",
            "SHA256",
            s3_workers=workers,
        )
        with self._lock:
            self.metrics["uploaded_bytes"] += sum(
                p.stat().st_size for p in source.rglob("*") if p.is_file()
            )

    def get(self, uri: str, path: Path, *, missing: bool = False) -> bool:
        path.parent.mkdir(parents=True, exist_ok=True)
        result = self.call("s3", "cp", uri, str(path), "--only-show-errors", missing=missing)
        if result is None:
            return False
        with self._lock:
            self.metrics["downloaded_bytes"] += path.stat().st_size
        return True

    def keys(self, uri: str):
        bucket, prefix = self.split(uri)
        token = None
        while True:
            args = [
                "s3api",
                "list-objects-v2",
                "--bucket",
                bucket,
                "--prefix",
                prefix,
                "--no-paginate",
                "--max-keys",
                "1000",
            ]
            if token:
                args += ["--continuation-token", token]
            page = self.call(*args)
            for item in page.get("Contents", []):
                yield "s3://" + bucket + "/" + item["Key"]
            token = page.get("NextContinuationToken")
            if not token:
                return

    def acquire(self, prefix: str, owner: dict[str, Any], takeover: str | None = None) -> str:
        bucket, key = self.split(prefix + "/main/owner.json")
        path = self.job / "ownership-request.json"
        json_write(path, owner)
        condition = ["--if-none-match", "*"]
        if takeover:
            old = self.job / "previous-owner.json"
            self.get(prefix + "/main/owner.json", old)
            if json.loads(old.read_text()).get("token") != takeover:
                raise SorelError("Takeover token does not match remote owner; nothing changed")
            head = self.call("s3api", "head-object", "--bucket", bucket, "--key", key)
            # Re-read after HEAD to avoid replacing an owner that changed between GET and HEAD.
            self.get(prefix + "/main/owner.json", old)
            if json.loads(old.read_text()).get("token") != takeover:
                raise SorelError("Remote ownership changed during takeover")
            condition = ["--if-match", head["ETag"]]
        try:
            result = self.call(
                "s3api",
                "put-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--body",
                str(path),
                *condition,
            )
        except SorelError as error:
            raise SorelError(
                "Cannot acquire part ownership. Inspect main/owner.json; explicit "
                "--takeover TOKEN is allowed only after the old job stopped. " + str(error)
            ) from error
        json_write(self.job / "ownership.json", owner)
        return result["ETag"]

    def release(self, prefix: str, etag: str) -> None:
        bucket, key = self.split(prefix + "/main/owner.json")
        self.call("s3api", "delete-object", "--bucket", bucket, "--key", key, "--if-match", etag)


def checked_work(job: Path, row: dict[str, Any]) -> Path:
    path = (job / row["local_work_dir"]).resolve()
    if not path.is_relative_to((job / "work").resolve()) or not path.is_dir():
        raise SorelError("Missing or unsafe local evidence directory")
    return path


class Store:
    def __init__(self, job: Path, prefix: str, aws: AWS, runtime: state.Runtime):
        self.job, self.prefix, self.aws, self.runtime = job, prefix.rstrip("/"), aws, runtime
        AWS.split(self.prefix)
        self.protocol = json.loads((job / "protocol.json").read_text())["sha256"]
        saved = job / "remote.json"
        identity = {"schema": 3, "prefix": self.prefix}
        if saved.exists() and json.loads(saved.read_text()) != identity:
            raise SorelError("S3 destination differs from the saved part")
        json_write(saved, identity)

    def upload_group(
        self, rows: list[dict[str, Any]], published_digests: set[str] | None = None
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        group_id = uuid4().hex
        rows = [dict(row) for row in rows]
        with tempfile.TemporaryDirectory(prefix="group-", dir=self.job) as temporary:
            root = Path(temporary)
            outputs = {}
            for row in rows:
                if row["protocol_sha256"] != self.protocol:
                    raise SorelError("Mixed scientific identities in upload group")
                work = checked_work(self.job, row)
                if row["status"] == "success":
                    output = work / "output.exe"
                    if (
                        digest(output) != row["exe_sha256"]
                        or output.stat().st_size != row["exe_bytes"]
                    ):
                        raise SorelError("Derived EXE checksum/size mismatch before publication")
                    uri = (
                        self.prefix
                        + "/exe/"
                        + row["exe_sha256"][:2]
                        + "/"
                        + row["exe_sha256"]
                        + ".exe"
                    )
                    row["exe_s3_uri"] = uri
                    if row["exe_sha256"] not in (published_digests or set()):
                        outputs.setdefault(uri, output)
            if outputs:
                staged = root / "exe"
                for uri, output in outputs.items():
                    target = staged / uri.rsplit("/", 2)[-2] / uri.rsplit("/", 1)[-1]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.link(output, target)
                self.aws.put_tree(staged, self.prefix + "/exe/", self.runtime.upload_workers)
            inventory = {}
            archive = root / "evidence.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for row in rows:
                    work = checked_work(self.job, row)
                    evidence_roots = [work, *work.parent.glob(work.name + "-interrupted-*")]
                    for path in sorted(
                        p for directory in evidence_roots for p in directory.rglob("*")
                    ):
                        # Explicit allow-list: input.pe/input.zlib/output.exe can never enter evidence.
                        if path.is_symlink() or path.suffix not in (".json", ".stdout", ".stderr"):
                            continue
                        if not path.is_file():
                            continue
                        name = (
                            "sources/"
                            + row["original_sha256"]
                            + "/"
                            + path.relative_to(work.parent).as_posix()
                        )
                        inventory[name] = {"sha256": digest(path), "bytes": path.stat().st_size}
                        tar.add(path, arcname=name, recursive=False)
                manifest = {
                    "schema": 3,
                    "id": group_id,
                    "protocol_sha256": self.protocol,
                    "rows": rows,
                    "files": inventory,
                }
                payload = state.canonical(manifest).encode()
                member = tarfile.TarInfo("manifest.json")
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))
                buffer = io.StringIO(newline="")
                writer = csv.DictWriter(buffer, state.CSV_FIELDS, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow(
                        {
                            k: state.canonical(v) if isinstance(v, (dict, list)) else v
                            for k, v in row.items()
                        }
                    )
                payload = buffer.getvalue().encode()
                member = tarfile.TarInfo("details.csv")
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))
            checksum = digest(archive)
            group = {
                "schema": 3,
                "id": group_id,
                "protocol_sha256": self.protocol,
                "archive_uri": self.prefix + "/details/" + group_id + ".tar.gz",
                "archive_sha256": checksum,
                "archive_bytes": archive.stat().st_size,
                "published_at_utc": state.now(),
                "rows": rows,
            }
            self.aws.put(archive, group["archive_uri"])
            # Manifest is the commit marker; an orphan EXE/archive is never replayed as complete.
            json_write(root / "commit.json", group)
            self.aws.put(root / "commit.json", self.prefix + "/details/" + group_id + ".json")
        return rows, group

    def cleanup(self, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            path = checked_work(self.job, row)
            shutil.rmtree(path)
            # Older interrupted directories are now in this committed evidence archive.
            for old in path.parent.glob(path.name + "-interrupted-*"):
                shutil.rmtree(old)
            try:
                path.parent.rmdir()
            except OSError:
                pass

    def checkpoint(self, snapshot: Path) -> dict[str, Any]:
        with closing(sqlite3.connect(snapshot / "state.sqlite")) as db:
            state.csv_export(db, snapshot / "results.csv")
            selected = json.loads((snapshot / "selection.json").read_text())["selected"]
            json_write(snapshot / "summary.json", state.summary(db, selected))
        files = {
            path.name: {"sha256": digest(path), "bytes": path.stat().st_size}
            for path in snapshot.iterdir()
            if path.is_file()
        }
        generation = uuid4().hex
        location = self.prefix + "/main/snapshots/" + generation
        for name in sorted(files):
            self.aws.put(snapshot / name, location + "/" + name)
        pointer = {
            "schema": 3,
            "protocol_sha256": self.protocol,
            "location": location,
            "files": files,
            "created_at_utc": state.now(),
        }
        json_write(snapshot / "latest.json", pointer)
        self.aws.put(snapshot / "latest.json", self.prefix + "/main/latest.json")
        latest = self.job / "latest.json"
        previous = json.loads(latest.read_text()) if latest.exists() else None
        json_write(latest, pointer)
        if previous and previous.get("location") != location:
            previous_location = previous.get("location", "")
            if re.fullmatch(
                re.escape(self.prefix) + r"/main/snapshots/[0-9a-f]{32}", previous_location
            ):
                # Ownership serializes restore/checkpoint. Retire the old generation only after
                # the new pointer is durable; EXE and immutable details are never deleted here.
                for name in previous.get("files", {}):
                    if name in SNAPSHOT_FILES:
                        bucket, key = AWS.split(previous_location + "/" + name)
                        self.aws.call("s3api", "delete-object", "--bucket", bucket, "--key", key)
        return pointer

    def replay(self, db: sqlite3.Connection) -> int:
        replayed = 0
        for uri in self.aws.keys(self.prefix + "/details/"):
            if not uri.endswith(".json"):
                continue
            group_id = uri.rsplit("/", 1)[-1][:-5]
            if db.execute("SELECT 1 FROM groups WHERE id=?", (group_id,)).fetchone():
                continue
            with tempfile.TemporaryDirectory(prefix="replay-", dir=self.job) as temporary:
                root = Path(temporary)
                self.aws.get(uri, root / "commit.json")
                group = json.loads((root / "commit.json").read_text())
                if (
                    group.get("schema") != 3
                    or group.get("id") != group_id
                    or group.get("protocol_sha256") != self.protocol
                    or group.get("archive_uri") != self.prefix + "/details/" + group_id + ".tar.gz"
                ):
                    raise SorelError("Invalid evidence commit identity")
                self.aws.get(group["archive_uri"], root / "evidence.tar.gz")
                archive = root / "evidence.tar.gz"
                if (
                    digest(archive) != group["archive_sha256"]
                    or archive.stat().st_size != group["archive_bytes"]
                ):
                    raise SorelError("Evidence archive checksum/size mismatch during replay")
                validate_archive(archive, group)
                for row in group["rows"]:
                    if row.get("protocol_sha256") != self.protocol:
                        raise SorelError("Evidence row protocol mismatch")
                    if not db.execute(
                        "SELECT 1 FROM sources WHERE id=?", (row["original_sha256"],)
                    ).fetchone():
                        raise SorelError("Evidence source is outside this part")
                state.publish(db, group["rows"], group)
                replayed += len(group["rows"])
        return replayed


def validate_archive(archive: Path, group: dict[str, Any]) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        entries = tar.getmembers()
        names = [m.name for m in entries]
        if len(names) != len(set(names)) or any(not m.isfile() for m in entries):
            raise SorelError("Duplicate/nonregular evidence member")
        content = tar.extractfile("manifest.json")
        if content is None:
            raise SorelError("Missing evidence manifest")
        manifest = json.load(content)
        if (
            manifest.get("schema") != 3
            or manifest.get("id") != group["id"]
            or manifest.get("protocol_sha256") != group["protocol_sha256"]
            or manifest.get("rows") != group["rows"]
        ):
            raise SorelError("Evidence manifest does not match commit")
        if set(names) != set(manifest["files"]) | {"manifest.json", "details.csv"}:
            raise SorelError("Evidence inventory mismatch")
        for name, expected in manifest["files"].items():
            if name.startswith("/") or ".." in Path(name).parts:
                raise SorelError("Unsafe evidence member")
            stream = tar.extractfile(name)
            hasher, size = sha256(), 0
            while chunk := stream.read(1024**2):
                hasher.update(chunk)
                size += len(chunk)
            if size != expected["bytes"] or hasher.hexdigest() != expected["sha256"]:
                raise SorelError("Evidence member checksum mismatch")


SNAPSHOT_FILES = {
    "state.sqlite",
    "selection.json",
    "protocol.json",
    "remote.json",
    "results.csv",
    "summary.json",
}


def snapshot(db: sqlite3.Connection, job: Path) -> Path:
    root = Path(tempfile.mkdtemp(prefix="snapshot-", dir=job))
    try:
        with closing(sqlite3.connect(root / "state.sqlite")) as target:
            db.backup(target)
        for name in ("selection.json", "protocol.json", "remote.json"):
            shutil.copyfile(job / name, root / name)
        return root
    except BaseException:
        shutil.rmtree(root)
        raise


def restore(job: Path, prefix: str, aws: AWS, *, missing: bool = False) -> bool:
    if (job / "selection.json").exists() or (job / "state.sqlite").exists():
        raise SorelError("Restore requires a fresh directory; existing progress was preserved")
    job.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="restore-", dir=job) as temporary:
        root = Path(temporary)
        if not aws.get(prefix + "/main/latest.json", root / "latest.json", missing=missing):
            return False
        pointer = json.loads((root / "latest.json").read_text())
        if (
            pointer.get("schema") != 3
            or set(pointer.get("files", {})) != SNAPSHOT_FILES
            or not re.fullmatch(
                re.escape(prefix) + r"/main/snapshots/[0-9a-f]{32}", pointer.get("location", "")
            )
        ):
            raise SorelError("Invalid snapshot pointer/inventory")
        for name, expected in pointer["files"].items():
            path = root / name
            aws.get(pointer["location"] + "/" + name, path)
            if digest(path) != expected["sha256"] or path.stat().st_size != expected["bytes"]:
                raise SorelError("Snapshot checksum/size mismatch; existing state preserved")
        if json.loads((root / "remote.json").read_text()) != {"schema": 3, "prefix": prefix}:
            raise SorelError("Snapshot destination mismatch")
        if (
            json.loads((root / "protocol.json").read_text())["sha256"]
            != pointer["protocol_sha256"]
        ):
            raise SorelError("Snapshot protocol mismatch")
        state.selection(root)
        with closing(sqlite3.connect(root / "state.sqlite")) as db:
            if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise SorelError("Invalid snapshot database")
        # A marker permits recovery from interruption between file renames.
        json_write(job / "restore-in-progress.json", {"schema": 3})
        for name in sorted(SNAPSHOT_FILES - {"selection.json"}):
            (root / name).replace(job / name)
        (root / "latest.json").replace(job / "latest.json")
        (root / "selection.json").replace(job / "selection.json")
        (job / "restore-in-progress.json").unlink()
    return True
