"""Read the shared S3 release contract and store completed audit evidence."""

import base64
from contextlib import closing, contextmanager
import csv
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any

from malweave.config import PROJECT_ROOT
from malweave.data.audit_reporting import METHOD, summarize
from malweave.data.s3_layout import (
    DATASET_RECEIPT,
    EXE_MANIFEST,
    INVENTORY,
    RANDS_BENIGN,
    RANDS_RANSOMWARE,
    RAW_PREFIX,
    RAWMAL_LABELS,
    account_id,
    dataset_bucket,
    sharded_key,
)
from malweave.data.storage_io import DataError, atomic_bytes, digest, durable_replace, job_lock
from malweave.training.contracts import _private_path

CORE = (INVENTORY, EXE_MANIFEST, "audit/packing.csv", "audit/native-dotnet.csv")
ARTIFACTS = {
    "inventory": INVENTORY,
    "exe-manifest": EXE_MANIFEST,
    "packing": "audit/packing.csv",
    "native-dotnet": "audit/native-dotnet.csv",
    "rawmal-labels": RAWMAL_LABELS,
    "rands-benign": RANDS_BENIGN,
    "rands-ransomware": RANDS_RANSOMWARE,
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_JOB_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,125}[a-z0-9]|[a-z0-9]")
_JOB_STATE_KEY = re.compile(r"audit/jobs/[a-z0-9][a-z0-9-]*/state\.sqlite3")
_LEGACY_AUDIT = {
    "rands": "audit/legacy/packing-first-pass-10s.csv",
    "assemblage": "audit/legacy/packing-die-4.0.0.csv",
}


@contextmanager
def _s3_errors():
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        yield
    except ClientError as error:
        detail = error.response.get("Error", {}).get("Code", "unknown")
        raise DataError(f"S3 {error.operation_name} failed ({detail}).") from error
    except BotoCoreError as error:
        raise DataError(f"AWS request failed ({type(error).__name__}).") from error


def _client(profile: str | None):
    import boto3
    from botocore.config import Config

    return boto3.Session(profile_name=profile).client(
        "s3",
        region_name="ap-southeast-1",
        config=Config(connect_timeout=5, read_timeout=60, retries={"total_max_attempts": 3}),
    )


def _release(client, args: dict[str, str], dataset: str) -> tuple[bytes, dict]:
    reply = client.get_object(**args, Key=DATASET_RECEIPT)
    with closing(reply["Body"]) as stream:
        content = stream.read()
    try:
        receipt = json.loads(content)
        hashes = receipt["digests"]
        evidence = receipt["audit_evidence"]
        valid = (
            receipt["dataset"] == dataset
            and receipt["phase"] == "verified"
            and all(_SHA256.fullmatch(hashes.get(key, "")) for key in CORE)
            and isinstance(evidence, dict)
            and all(
                (
                    key in CORE[2:]
                    or key == _LEGACY_AUDIT.get(dataset)
                    or _JOB_STATE_KEY.fullmatch(key)
                )
                and _SHA256.fullmatch(value)
                for key, value in evidence.items()
            )
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise DataError("Expected a verified dataset receipt with canonical artifact checksums.")
    return content, receipt


def _head_checksum(head: dict) -> str:
    try:
        encoded = head["ChecksumSHA256"]
        if head.get("ChecksumType", "FULL_OBJECT") != "FULL_OBJECT":
            raise ValueError("Composite checksum")
        value = base64.b64decode(encoded, validate=True).hex()
        if not _SHA256.fullmatch(value):
            raise ValueError("Invalid digest length")
        return value
    except (KeyError, TypeError, ValueError) as error:
        raise DataError("Expected a full-object SHA-256 checksum from S3.") from error


def _destination(dataset: str) -> dict[str, str]:
    owner = account_id()
    return {"Bucket": dataset_bucket(dataset, owner), "ExpectedBucketOwner": owner}


def dataset_input_dir(dataset: str) -> Path:
    return Path("data/interim/s3") / dataset


def _private_input_dir(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if relative.parts[:2] not in {("data", "interim"), ("data", "processed")}:
        raise DataError(
            "Dataset inputs inside the repository must use data/interim or data/processed."
        )


def _download(client, args: dict[str, str], key: str, destination: Path, expected: str | None):
    if destination.is_symlink():
        raise DataError("Refusing to stage a dataset artifact through a symlink.")
    if not expected:
        expected = _head_checksum(client.head_object(**args, Key=key, ChecksumMode="ENABLED"))
    if destination.is_file() and digest(destination) == expected:
        return
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    reply = client.get_object(**args, Key=key)
    temp_path = None
    try:
        with (
            closing(reply["Body"]) as stream,
            NamedTemporaryFile(dir=destination.parent, prefix=".dataset-", delete=False) as out,
        ):
            temp_path = Path(out.name)
            checksum = sha256()
            while chunk := stream.read(1024**2):
                out.write(chunk)
                checksum.update(chunk)
            if checksum.hexdigest() != expected:
                raise DataError(f"S3 artifact checksum mismatch for {key}.")
            out.flush()
            os.fsync(out.fileno())
        durable_replace(temp_path, destination)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def fetch_dataset(
    dataset: str,
    directory: Path | None = None,
    *,
    artifacts: tuple[str, ...] = ("inventory",),
    profile: str | None = None,
) -> dict[str, Path]:
    """Stage verified release tables using the bucket-relative paths."""
    directory = (directory or dataset_input_dir(dataset)).expanduser()
    _private_input_dir(directory)
    keys = {artifact: ARTIFACTS[artifact] for artifact in artifacts}
    if "rawmal-labels" in keys and dataset != "rawmal":
        raise DataError("RawMal-TF task labels require --dataset rawmal.")
    if dataset != "rands" and keys.keys() & {"rands-benign", "rands-ransomware"}:
        raise DataError("RanDS labels require --dataset rands.")
    args = _destination(dataset)
    with job_lock(directory), _s3_errors():
        client = _client(profile)
        content, receipt = _release(client, args, dataset)
        results = {}
        for name, key in keys.items():
            path = directory / key
            _private_input_dir(path)
            _download(client, args, key, path, receipt["digests"].get(key))
            results[name] = path
        _private_input_dir(directory / DATASET_RECEIPT)
        atomic_bytes(directory / DATASET_RECEIPT, content)
    return results


def require_published_inventory(dataset: str, path: Path, *, profile: str | None = None) -> None:
    """Verify the staged inventory directly against the published release before a scan."""
    with _s3_errors():
        _, receipt = _release(_client(profile), _destination(dataset), dataset)
        if digest(path) != receipt["digests"][INVENTORY]:
            raise DataError("Audit inventory differs from the published release. Fetch it again.")


def verify_dataset(dataset: str, *, profile: str | None = None) -> dict:
    args = _destination(dataset)
    with _s3_errors():
        client = _client(profile)
        _, receipt = _release(client, args, dataset)
        checks = {**receipt["audit_evidence"], **{key: receipt["digests"][key] for key in CORE}}
        for key, expected in checks.items():
            head = client.head_object(**args, Key=key, ChecksumMode="ENABLED")
            if _head_checksum(head) != expected:
                raise DataError(f"S3 artifact checksum mismatch for {key}.")
    return {"dataset": dataset, "phase": "verified", "checked_artifacts": len(checks)}


def _snapshot(job: Path, target: Path, dataset: str, inventory: Path) -> str:
    from malweave.data.dataset_die import dataset_die_status, read_packing_evidence
    from malweave.data.pe_assessment import DIEC_MODES

    incoming = job / "state.sqlite3"
    with closing(sqlite3.connect(incoming.resolve().as_uri() + "?mode=ro", uri=True)) as source:
        fields = {row[1] for row in source.execute("PRAGMA table_info(source)")}
        if "key" in fields:
            result = summarize(job)
            method, key_column = METHOD, "key"
        elif "s3_key" in fields:
            result = dataset_die_status(job)
            method, key_column = "dataset-die", "s3_key"
        else:
            raise DataError("Unrecognized audit database.")
        if result["dataset"] != dataset or result["method"] != method:
            raise DataError("Audit database does not match the selected dataset and workflow.")
        if (
            not result["total"]
            or result["pending"]
            or (method == "dataset-die" and set(result["statuses"]) - {"success", "tool_error"})
        ):
            raise DataError(
                "Finish the audit and resolve source identity or download errors first."
            )
        if method == "dataset-die":
            contract = json.loads(
                source.execute("SELECT value FROM job WHERE key='contract'").fetchone()[0]
            )
            if not re.search(r"(?<![0-9.])3\.21(?![0-9.])", contract.get("die_version", "")):
                raise DataError("The shared packing layout uses DiE 3.21.")
            saved = source.execute("SELECT value FROM job WHERE key='release'").fetchone()
            release = json.loads(saved[0]) if saved else {}
            if (
                release.get("passed") is not True
                or release.get("inventory_sources") != result["total"]
            ):
                raise DataError("Expected the job's passing DiE release audit.")
            for sha, blob, checksum in source.execute(
                "SELECT sha256,evidence_gzip,evidence_sha256 FROM result"
            ):
                evidence = read_packing_evidence(blob, checksum)
                if (
                    evidence.get("source_sha256") != sha
                    or evidence.get("input_sha256") != sha
                    or evidence.get("source_hash_status") != "verified"
                    or set(evidence["packing"].get("modes", {})) != set(DIEC_MODES)
                    or set(evidence["packing"].get("reports", {})) != set(DIEC_MODES)
                ):
                    raise DataError("Incomplete verified packing evidence for the audit job.")
        with inventory.open(newline="", encoding="utf-8-sig") as stream:
            identities = {
                row["sha256"]: (row["s3_key"], int(row["size"]), row["etag"])
                for row in csv.DictReader(stream)
            }
        for digest_value, key, size, etag in source.execute(
            f"SELECT sha256,{key_column},size,etag FROM source"
        ):
            if key != sharded_key(RAW_PREFIX, digest_value) or identities.get(digest_value) != (
                key,
                size,
                etag,
            ):
                raise DataError("Audit job sources differ from the published RAW inventory.")
        with NamedTemporaryFile(dir=target.parent, prefix="audit-state-", delete=False) as out:
            os.fchmod(out.fileno(), 0o600)
            temporary = Path(out.name)
        with closing(sqlite3.connect(temporary)) as output:
            source.backup(output)
            output.execute("PRAGMA journal_mode=DELETE")
            if output.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise DataError("The audit snapshot failed SQLite integrity checking.")
        temporary.replace(target)
    return method


def _put_state(client, args: dict[str, str], key: str, path: Path) -> str:
    from botocore.exceptions import ClientError

    value = digest(path)
    if path.stat().st_size > 5 * 1024**3:
        raise DataError("The audit snapshot exceeds the single-object upload limit.")
    encoded = base64.b64encode(bytes.fromhex(value)).decode()
    with path.open("rb") as stream:
        try:
            client.put_object(
                **args,
                Key=key,
                Body=stream,
                ContentType="application/vnd.sqlite3",
                ChecksumSHA256=encoded,
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
            outcome = "uploaded"
        except ClientError as error:
            if error.response["Error"]["Code"] not in {"412", "PreconditionFailed"}:
                raise
            outcome = "already_published"
    existing = client.head_object(**args, Key=key, ChecksumMode="ENABLED")
    if existing["ContentLength"] != path.stat().st_size or _head_checksum(existing) != value:
        raise DataError("This job ID already holds different evidence. Use a new job ID.")
    return outcome


def publish_audit_job(dataset: str, job: Path, *, profile: str | None = None) -> dict[str, Any]:
    """Publish a consistent SQLite backup to the selected dataset's audit job path."""
    _private_path(job, "audit job")
    job = job.expanduser().resolve()
    if not _JOB_ID.fullmatch(job.name):
        raise DataError("Job IDs use lowercase letters, digits and internal hyphens.")
    if (job / "state.sqlite3").is_symlink() or not (job / "state.sqlite3").is_file():
        raise DataError("Expected state.sqlite3 under the completed audit job.")
    key = f"audit/jobs/{job.name}/state.sqlite3"
    args = _destination(dataset)
    with job_lock(job), TemporaryDirectory(prefix=".publish-", dir=job) as temp, _s3_errors():
        client = _client(profile)
        directory = Path(temp)
        _, release = _release(client, args, dataset)
        inventory = directory / INVENTORY
        _download(client, args, INVENTORY, inventory, release["digests"][INVENTORY])
        snapshot = directory / "state.sqlite3"
        try:
            method = _snapshot(job, snapshot, dataset, inventory)
        except (sqlite3.Error, KeyError, ValueError) as error:
            if isinstance(error, DataError):
                raise
            raise DataError("Invalid audit database or published inventory.") from error
        outcome = _put_state(client, args, key, snapshot)
    return {"dataset": dataset, "method": method, "key": key, "status": outcome}
