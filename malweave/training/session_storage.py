"""Checksum-verified private HTTPS snapshots; credentials and input payloads stay out."""

from __future__ import annotations

from hashlib import sha256
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from malweave.training.contracts import SupervisedTrainingError


def file_sha(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def request_bytes(url, *, data=None, headers=None, attempts=3, limit=256 * 1024**2):
    """Bounded private transfers; errors deliberately omit signed URLs."""
    location = urlsplit(url)
    if location.scheme != "https" or not location.netloc or location.username:
        raise SupervisedTrainingError("A private HTTPS transfer URL is required.")
    request_headers = dict(headers or {})
    if data is not None and not any(key.lower() == "content-type" for key in request_headers):
        # urllib otherwise injects application/x-www-form-urlencoded. That
        # changes the signed content type of legacy S3 presigned PUT requests.
        request_headers["Content-Type"] = ""
    for attempt in range(attempts):
        try:
            request = Request(
                url,
                data=data,
                headers=request_headers,
                method="PUT" if data is not None else "GET",
            )
            with urlopen(request, timeout=120) as response:
                result = response.read(limit + 1)
            if len(result) > limit:
                raise SupervisedTrainingError("Remote artifact exceeds its transfer limit.")
            return result
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            if attempt + 1 == attempts:
                if isinstance(error, HTTPError):
                    code = str(error.code)
                else:
                    reason = error.reason if isinstance(error, URLError) else error
                    code = f"{type(error).__name__}/{type(reason).__name__}"
                    if isinstance(reason, OSError) and isinstance(reason.errno, int):
                        code += f"; errno={reason.errno}"
                raise SupervisedTrainingError(f"Private transfer failed ({code}).") from None
            time.sleep(2**attempt)
    raise AssertionError("Unreachable transfer state")


def upload_verified(urls: dict, payload: bytes) -> str:
    """Read the object back before declaring an upload durable."""
    expected = sha256(payload).hexdigest()
    request_bytes(urls["put"], data=payload)
    actual = request_bytes(urls["get"])
    if len(actual) != len(payload) or sha256(actual).hexdigest() != expected:
        raise SupervisedTrainingError("Remote artifact read-back checksum mismatch.")
    return expected


def publish_snapshot(archive: Path, slots: list[dict], pointer_urls: dict, pointer: dict):
    """Commit the latest pointer last; failure preserves the preceding generation."""
    slot = pointer["generation"] % len(slots)
    payload = archive.read_bytes()
    digest = upload_verified(slots[slot], payload)
    result = {**pointer, "slot": slot, "bytes": len(payload), "sha256": digest}
    upload_verified(pointer_urls, json.dumps(result, sort_keys=True).encode())
    return result


def _safe_name(name):
    path = PurePosixPath(name)
    if (
        not name
        or str(path) != name
        or path.is_absolute()
        or any(part in {"..", ".env", "raw", "dataset"} for part in path.parts)
    ):
        raise SupervisedTrainingError("Snapshot contains a forbidden or unsafe member path.")
    return path


def pack_snapshot(files: dict[str, Path], output: Path, identity: dict):
    """Call only at a committed pause; enumerate source/config/artifacts explicitly."""
    if "snapshot-manifest.json" in files:
        raise SupervisedTrainingError("Reserved snapshot manifest path.")
    records = {}
    for name, path in sorted(files.items()):
        _safe_name(name)
        if path.is_symlink() or not path.is_file():
            raise SupervisedTrainingError("Snapshot source must be a regular private file.")
        records[name] = {"bytes": path.stat().st_size, "sha256": file_sha(path)}
    manifest = {"schema": 1, "identity": identity, "files": records}
    temporary = output.with_suffix(output.suffix + ".tmp")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(temporary, "w:gz", compresslevel=1) as archive:
            payload = json.dumps(manifest, sort_keys=True).encode()
            info = tarfile.TarInfo("snapshot-manifest.json")
            info.size, info.mode = len(payload), 0o600
            archive.addfile(info, io.BytesIO(payload))
            for name, path in sorted(files.items()):
                archive.add(path, arcname=name, recursive=False)
        # Verify bytes read while packing, rather than trusting earlier stat/hash.
        check = output.parent / (output.name + ".verify")
        restore_snapshot(temporary, check, identity)
        shutil.rmtree(check)
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return manifest


def restore_snapshot(archive: Path, destination: Path, identity: dict):
    """Restore trusted, digest-bound data without tar extraction or executable loading."""
    if destination.exists():
        raise SupervisedTrainingError("Restore requires a fresh destination.")
    try:
        with tarfile.open(archive, "r:gz") as source:
            members = source.getmembers()
            if len({m.name for m in members}) != len(members):
                raise SupervisedTrainingError("Duplicate snapshot members.")
            if (
                any(not m.isfile() for m in members)
                or sum(m.size for m in members) > 512 * 1024**2
            ):
                raise SupervisedTrainingError("Snapshot has unsupported members or size.")
            for member in members:
                _safe_name(member.name)
            stream = source.extractfile("snapshot-manifest.json")
            manifest = json.load(stream)
            if manifest["schema"] != 1 or manifest["identity"] != identity:
                raise SupervisedTrainingError("Snapshot identity mismatch.")
            if {m.name for m in members} != {*manifest["files"], "snapshot-manifest.json"}:
                raise SupervisedTrainingError("Snapshot membership mismatch.")
            destination.mkdir(parents=True)
            for name, record in manifest["files"].items():
                _safe_name(name)
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(name) as incoming, path.open("wb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                path.chmod(0o600)
                if path.stat().st_size != record["bytes"] or file_sha(path) != record["sha256"]:
                    raise SupervisedTrainingError("Snapshot member checksum mismatch.")
        return manifest
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
