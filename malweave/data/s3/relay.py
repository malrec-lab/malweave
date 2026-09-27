"""Bounded-memory, verified S3-to-S3 transport for an isolated transfer worker.

Only the caller's explicitly selected objects are written. Use an exclusively owned
destination prefix: a local state lock is not a distributed multi-host lock.
"""

from collections.abc import Iterable
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from botocore.exceptions import ClientError

PART_BYTES = 8 * 1024 * 1024


class RelayError(ValueError):
    """Safe aggregate error code; never include object identities or credentials."""


def make_runpod_client(
    workers: int = 4, *, endpoint_url: str | None = None, region: str | None = None
) -> Any:
    import boto3
    from botocore.config import Config

    names = ("ENDPOINT_URL", "REGION", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY")
    values = {name: os.environ.get("RUNPOD_S3_" + name, "") for name in names}
    if endpoint_url is not None:
        values["ENDPOINT_URL"] = endpoint_url
    if region is not None:
        values["REGION"] = region
    if not all(values.values()):
        raise RelayError("Missing RUNPOD_S3 endpoint, region, or credentials.")
    endpoint = urlparse(values["ENDPOINT_URL"])
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or not endpoint.hostname.endswith(".runpod.io")
        or endpoint.username
        or endpoint.password
        or endpoint.query
        or endpoint.fragment
    ):
        raise RelayError("RUNPOD_S3_ENDPOINT_URL must be an HTTPS Runpod endpoint.")
    return boto3.client(
        "s3",
        endpoint_url=values["ENDPOINT_URL"],
        region_name=values["REGION"],
        aws_access_key_id=values["ACCESS_KEY_ID"],
        aws_secret_access_key=values["SECRET_ACCESS_KEY"],
        config=Config(
            max_pool_connections=max(10, workers),
            connect_timeout=10,
            read_timeout=60,
            retries={"mode": "standard", "max_attempts": 5},
        ),
    )


def head(client: Any, bucket: str, key: str) -> dict | None:
    try:
        return client.head_object(Bucket=bucket, Key=key)
    except ClientError as error:
        if str(error.response["Error"]["Code"]) in {"404", "NoSuchKey", "NotFound"}:
            return None
        raise RelayError("destination_head_error") from error


def verify_remote(client: Any, bucket: str, key: str, size: int, digest: str) -> bool:
    metadata = head(client, bucket, key)
    if metadata is None:
        return False
    if metadata["ContentLength"] != size:
        raise RelayError("destination_size_conflict")
    checksum = sha256()
    received = 0
    try:
        with closing(
            client.get_object(Bucket=bucket, Key=key, IfMatch=metadata["ETag"])["Body"]
        ) as body:
            for block in iter(lambda: body.read(1024 * 1024), b""):
                received += len(block)
                if received > size:
                    raise RelayError("destination_size_conflict")
                checksum.update(block)
    except RelayError:
        raise
    except Exception as error:
        raise RelayError("destination_read_error") from error
    if received != size or checksum.hexdigest() != digest:
        raise RelayError("destination_digest_conflict")
    return True


def _abort_saved(client: Any, bucket: str, key: str, journal: Path) -> None:
    if journal.exists():
        saved = json.loads(journal.read_text())
        if saved["bucket"] != bucket or saved["key"] != key:
            raise RelayError("multipart_journal_conflict")
        try:
            client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=saved["upload_id"])
        except ClientError as error:
            if error.response["Error"]["Code"] != "NoSuchUpload":
                raise RelayError("multipart_cleanup_failed") from error
        journal.unlink()


def relay_object(
    client: Any,
    bucket: str,
    key: str,
    chunks: Iterable[bytes],
    *,
    size: int,
    digest: str,
    journal: Path,
) -> bool:
    """Return True when reused; verify source before publication and destination after.

    Multipart upload IDs are journaled for interrupted-upload cleanup on resume.
    A process kill between CreateMultipartUpload and journal fsync can leave an orphan;
    the operator must inspect multipart uploads before deleting the private state.
    """
    _abort_saved(client, bucket, key, journal)
    if verify_remote(client, bucket, key, size, digest):
        return True
    upload_id = None
    checksum = sha256()
    received = 0
    buffer = bytearray()
    parts = []
    try:
        for chunk in chunks:
            received += len(chunk)
            if received > size:
                raise RelayError("source_size_mismatch")
            checksum.update(chunk)
            buffer.extend(chunk)
            while len(buffer) >= PART_BYTES:
                if upload_id is None:
                    upload_id = client.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
                    journal.parent.mkdir(parents=True, exist_ok=True)
                    with journal.open("w") as handle:
                        json.dump({"bucket": bucket, "key": key, "upload_id": upload_id}, handle)
                        handle.flush()
                        os.fsync(handle.fileno())
                if len(parts) >= 9999:
                    raise RelayError("multipart_part_limit")
                part = bytes(buffer[:PART_BYTES])
                del buffer[:PART_BYTES]
                response = client.upload_part(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=len(parts) + 1,
                    Body=part,
                )
                parts.append({"PartNumber": len(parts) + 1, "ETag": response["ETag"]})
        if received != size or checksum.hexdigest() != digest:
            raise RelayError("source_digest_mismatch")
        if head(client, bucket, key) is not None:
            raise RelayError("destination_appeared_during_transfer")
        if upload_id is None:
            client.put_object(Bucket=bucket, Key=key, Body=bytes(buffer))
        else:
            if buffer:
                response = client.upload_part(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=len(parts) + 1,
                    Body=bytes(buffer),
                )
                parts.append({"PartNumber": len(parts) + 1, "ETag": response["ETag"]})
            client.complete_multipart_upload(
                Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": parts}
            )
            upload_id = None
            journal.unlink()
        if not verify_remote(client, bucket, key, size, digest):
            raise RelayError("destination_missing_after_upload")
        return False
    finally:
        if upload_id is not None:
            try:
                client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
                journal.unlink(missing_ok=True)
            except Exception as error:
                raise RelayError("multipart_cleanup_failed") from error
