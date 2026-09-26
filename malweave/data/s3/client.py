"""Dataset-neutral, read-only S3 object listing primitives.

Dataset modules decide how keys map to sample identities and labels. These helpers
do not create local files. Content reads require an explicit key and size bound.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any


class S3ListingError(ValueError):
    """An S3 object-metadata request failed."""


class S3ReadError(ValueError):
    """An explicit, bounded S3 object read failed."""


def read_s3_object(
    client: Any, bucket: str, key: str, *, max_bytes: int
) -> tuple[bytes, dict[str, Any]]:
    """Read a bounded object, pinned to its HEAD identity, with content provenance."""
    if not bucket or not key or max_bytes < 1:
        raise S3ReadError("A bucket, key, and positive content limit are required.")
    try:
        head = client.head_object(Bucket=bucket, Key=key)
        size = int(head["ContentLength"])
        if not 0 < size <= max_bytes:
            raise ValueError("Object exceeds the allowed size or is empty.")
        request = {"Bucket": bucket, "Key": key, "IfMatch": head["ETag"]}
        if head.get("VersionId"):
            request["VersionId"] = head["VersionId"]
        response = client.get_object(**request)
        body = response["Body"]
        try:
            content = body.read(size + 1)
        finally:
            body.close()
        if (
            len(content) != size
            or response.get("ETag") != head["ETag"]
            or (head.get("VersionId") and response.get("VersionId") != head["VersionId"])
        ):
            raise ValueError("Downloaded object size or identity differs from HEAD.")
        return content, {
            "key": key,
            "size": size,
            "etag": head["ETag"],
            "version_id": response.get("VersionId"),
            "sha256": sha256(content).hexdigest(),
        }
    except Exception as error:
        raise S3ReadError(
            "S3 metadata download failed; check read permission, metadata prefix, "
            "object size, and source stability. No completed cache was published."
        ) from error


@dataclass(frozen=True)
class S3Object:
    key: str
    size: int
    etag: str
    last_modified: str


@dataclass(frozen=True)
class S3Page:
    objects: tuple[S3Object, ...]
    next_token: str | None


def make_s3_client() -> Any:
    """Create an AWS-SDK client only when a command actually needs S3."""
    import boto3
    from botocore.config import Config

    return boto3.client("s3", config=Config(retries={"mode": "standard", "max_attempts": 5}))


def list_s3_page(
    client: Any, bucket: str, prefix: str, *, continuation_token: str | None = None
) -> S3Page:
    """Read one page of object metadata without downloading object bytes."""
    if not bucket or not prefix:
        raise S3ListingError("A bucket and prefix are required.")
    request: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
    if continuation_token:
        request["ContinuationToken"] = continuation_token
    try:
        response = client.list_objects_v2(**request)
    except Exception as error:
        raise S3ListingError("S3 listing failed; retry from the saved page token.") from error
    next_token = response.get("NextContinuationToken")
    if response.get("IsTruncated") and not next_token:
        raise S3ListingError("S3 returned a truncated page without a continuation token.")
    objects = tuple(
        S3Object(
            key=str(item["Key"]),
            size=int(item["Size"]),
            etag=str(item.get("ETag", "")),
            last_modified=str(item.get("LastModified", "")),
        )
        for item in response.get("Contents", [])
    )
    return S3Page(objects=objects, next_token=str(next_token) if next_token else None)
