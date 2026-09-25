"""Synthetic-only tests for normalized manifests and verified byte sources."""

from __future__ import annotations

import csv
from hashlib import sha256
import io
from pathlib import Path

import pytest

from malweave.training.manifest import TrainingManifestError, load_training_manifest
from malweave.training.sources import (
    ByteSourceError,
    LocalByteSource,
    S3ByteSource,
    VerifiedByteSource,
)


def _write_split(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)


def _row(content: bytes, *, split: str = "train", group: str | None = None) -> dict[str, str]:
    source = sha256(content).hexdigest()
    return {
        "split": split,
        "source_sha256": source,
        "label": "benign",
        "group_id": group or source,
        "availability": "available",
        "object_key": f"synthetic/{source}",
        "object_size": str(len(content)),
        "object_etag": '"synthetic"',
    }


class FakeS3:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.requests: list[dict[str, str]] = []

    def get_object(self, **request: str) -> dict[str, io.BytesIO]:
        self.requests.append(request)
        return {"Body": io.BytesIO(self.content)}


def test_raw_manifest_and_s3_source_verify_every_read(tmp_path: Path) -> None:
    content = b"synthetic-not-a-PE"
    manifest = tmp_path / "split.csv"
    _write_split(manifest, [_row(content)])
    sample = load_training_manifest(manifest, "raw")[0]
    client = FakeS3(content)
    source = VerifiedByteSource(S3ByteSource("synthetic", client))
    assert source.read(sample) == content
    assert source.read(sample) == content
    assert source.summary()["reads_by_label"] == {"benign": 2}
    assert all(request["IfMatch"] == '"synthetic"' for request in client.requests)
    client.content = b"tampered"
    with pytest.raises(ByteSourceError, match="size|digest"):
        source.read(sample)
    assert source.summary()["failures_by_label"] == {"benign": 1}


def test_split_rejects_equivalent_groups_crossing_time_splits(tmp_path: Path) -> None:
    group = sha256(b"equivalent").hexdigest()
    manifest = tmp_path / "split.csv"
    _write_split(
        manifest,
        [_row(b"first", group=group), _row(b"second", split="test", group=group)],
    )
    with pytest.raises(TrainingManifestError, match="crosses"):
        load_training_manifest(manifest, "raw")


def test_split_rejects_equivalent_representation_with_different_groups(tmp_path: Path) -> None:
    manifest = tmp_path / "split.csv"
    first = _row(b"first")
    second = _row(b"second", split="test")
    first.update(
        {"representation": "exe", "representation_sha256": sha256(b"same exe").hexdigest()}
    )
    second.update(
        {"representation": "exe", "representation_sha256": first["representation_sha256"]}
    )
    _write_split(manifest, [first, second])
    with pytest.raises(TrainingManifestError, match="equivalent representation"):
        load_training_manifest(manifest, "exe")


def test_raw_manifest_rejects_digest_that_is_not_source_identity(tmp_path: Path) -> None:
    manifest = tmp_path / "split.csv"
    row = _row(b"first")
    row["representation_sha256"] = sha256(b"other").hexdigest()
    _write_split(manifest, [row])
    with pytest.raises(TrainingManifestError, match="RAW digest"):
        load_training_manifest(manifest, "raw")


def test_exe_manifest_requires_digest_and_local_source_stays_under_root(tmp_path: Path) -> None:
    content = b"synthetic-derived-bytes"
    row = _row(b"synthetic-source")
    row.update(
        {
            "representation": "exe",
            "representation_sha256": sha256(content).hexdigest(),
            "relative_path": "exe/synthetic.bin",
            "object_size": str(len(content)),
        }
    )
    manifest = tmp_path / "exe.csv"
    _write_split(manifest, [row])
    sample = load_training_manifest(manifest, "exe")[0]
    source_root = tmp_path / "derived"
    (source_root / "exe").mkdir(parents=True)
    (source_root / "exe" / "synthetic.bin").write_bytes(content)
    assert VerifiedByteSource(LocalByteSource(source_root)).read(sample) == content
    row["relative_path"] = "../outside.bin"
    _write_split(manifest, [row])
    with pytest.raises(ByteSourceError, match="escapes"):
        LocalByteSource(source_root).read(load_training_manifest(manifest, "exe")[0])
