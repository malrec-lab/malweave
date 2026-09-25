"""Verified, read-only local or S3 byte sources for isolated training workers.

Do not use an S3 byte source on a personal workstation: RAW objects are live malware.
No object is fetched or local directory created merely by importing this module.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from pathlib import Path
import time
from typing import Any, Protocol

from malweave.training.manifest import TrainingSample


class ByteSourceError(ValueError):
    """An input representation could not be read and verified safely."""

    def __init__(self, message: str, *, code: str = "read_error") -> None:
        super().__init__(message)
        self.code = code


class ByteSource(Protocol):
    def read(self, sample: TrainingSample) -> bytes: ...


class LocalByteSource:
    """Read representations from a declared local root without path traversal."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    def read(self, sample: TrainingSample) -> bytes:
        if not sample.relative_path:
            raise ByteSourceError("The local representation path is missing.")
        relative = Path(sample.relative_path)
        path = (self.root / relative).resolve()
        if relative.is_absolute() or not path.is_relative_to(self.root):
            raise ByteSourceError(
                "Representation path escapes its declared root.", code="path_error"
            )
        try:
            return path.read_bytes()
        except OSError as error:
            raise ByteSourceError(
                "Could not read a local representation.", code="read_error"
            ) from error


class S3ByteSource:
    """Read only one declared object; ETag/version constraints guard mutable keys."""

    def __init__(self, bucket: str, client: Any = None) -> None:
        if not bucket:
            raise ByteSourceError("An S3 bucket is required for S3 training.")
        self.bucket = bucket
        self._client = client

    def read(self, sample: TrainingSample) -> bytes:
        if not sample.object_key:
            raise ByteSourceError("The S3 object key is missing from the split manifest.")
        if self._client is None:
            from malweave.data.s3.client import make_s3_client

            self._client = make_s3_client()
        request: dict[str, Any] = {"Bucket": self.bucket, "Key": sample.object_key}
        if sample.object_etag:
            request["IfMatch"] = sample.object_etag
        if sample.object_version:
            request["VersionId"] = sample.object_version
        try:
            response = self._client.get_object(**request)
            body = response["Body"]
            try:
                return body.read()
            finally:
                body.close()
        except Exception as error:
            raise ByteSourceError(
                "Could not read the declared S3 representation.", code="s3_error"
            ) from error


class VerifiedByteSource:
    """Verify full content on every read and retain aggregate, class-specific accounting."""

    def __init__(self, source: ByteSource) -> None:
        self.source = source
        self.attempts: Counter[str] = Counter()
        self.reads: Counter[str] = Counter()
        self.failures: Counter[str] = Counter()
        self.failure_reasons: Counter[str] = Counter()
        self.bytes_read = 0
        self.read_seconds = 0.0

    def read(self, sample: TrainingSample) -> bytes:
        label = "benign" if sample.label == 0 else "ransomware"
        self.attempts[label] += 1
        started = time.perf_counter()
        try:
            content = self.source.read(sample)
            self.bytes_read += len(content)
            if sample.object_size is not None and len(content) != sample.object_size:
                raise ByteSourceError(
                    "Representation size differs from the manifest.", code="size_mismatch"
                )
            if sha256(content).hexdigest() != sample.representation_sha256:
                raise ByteSourceError(
                    "Representation digest differs from the manifest.", code="digest_mismatch"
                )
        except ByteSourceError as error:
            self.failures[label] += 1
            self.failure_reasons[error.code] += 1
            raise
        finally:
            self.read_seconds += time.perf_counter() - started
        self.reads[label] += 1
        return content

    def summary(self) -> dict[str, Any]:
        return {
            "attempts_by_label": dict(self.attempts),
            "reads_by_label": dict(self.reads),
            "failures_by_label": dict(self.failures),
            "failure_reasons": dict(self.failure_reasons),
            "bytes_read": self.bytes_read,
            "read_seconds": round(self.read_seconds, 3),
        }
