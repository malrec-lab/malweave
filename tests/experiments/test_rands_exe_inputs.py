"""Synthetic checks for staging a frozen EXE cohort directly from S3."""

from __future__ import annotations

import csv
from hashlib import sha256
import io
import json
from pathlib import Path

import pytest

from malweave.experiments.rands_exe_inputs import RandsExeInputError, prepare_rands_exe_inputs
from malweave.training.manifest import load_training_manifest
from malweave.training.sources import LocalByteSource, VerifiedByteSource


class FakeS3:
    def __init__(self, objects: dict[str, bytes]) -> None:
        self.objects = objects

    def head_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
        content = self.objects[Key]
        return {"ContentLength": len(content), "ETag": '"synthetic"'}

    def get_object(self, **request: str) -> dict[str, object]:
        assert request["IfMatch"] == '"synthetic"'
        return {"Body": io.BytesIO(self.objects[request["Key"]]), "ETag": '"synthetic"'}


def _row(content: bytes, split: str, label: str) -> dict[str, str | int]:
    source = sha256(b"source:" + content).hexdigest()
    return {
        "source_sha256": source,
        "label": label,
        "split": split,
        "group_id": source,
        "availability": "available",
        "object_key": f"unused-raw/{source}",
        "object_size": len(content),
        "object_etag": '"synthetic"',
    }


def test_prepare_exe_stages_s3_bytes_resumes_and_inherits_split(tmp_path: Path) -> None:
    items = [
        (b"A" * 32, "train", "benign"),
        (b"B" * 32, "validation", "ransomware"),
        (b"C" * 32, "test", "benign"),
    ]
    rows = [_row(*item) for item in items]
    source_manifest = tmp_path / "source.csv"
    with source_manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    source_summary = tmp_path / "source.json"
    source_summary.write_text(
        json.dumps(
            {
                "inventory_audit_passed": True,
                "manifest": {"sha256": sha256(source_manifest.read_bytes()).hexdigest()},
            }
        )
    )
    prefix = "rands/representations/exe/"
    objects = {
        f"{prefix}{row['source_sha256'][:2]}/{row['source_sha256']}.bin": content
        for row, (content, _, _) in zip(rows, items, strict=True)
    }
    arguments = {
        "source_manifest": source_manifest,
        "source_summary": source_summary,
        "bucket": "synthetic",
        "prefix": prefix,
        "representation_root": tmp_path / "exe",
        "state_path": tmp_path / "state.sqlite",
        "manifest_path": tmp_path / "exe.csv",
        "summary_path": tmp_path / "exe.json",
        "snapshot": "synthetic",
        "progress_every": 1,
        "client": FakeS3(objects),
    }
    with pytest.raises(RandsExeInputError, match="incomplete"):
        prepare_rands_exe_inputs(**arguments, limit=1)
    summary = prepare_rands_exe_inputs(**arguments, resume=True)
    assert summary["passed"] is True
    assert summary["selected"] == summary["published"] == 3
    samples = load_training_manifest(arguments["manifest_path"], "exe")
    assert [(sample.split, sample.label) for sample in samples] == [
        ("test", 0),
        ("train", 0),
        ("validation", 1),
    ]
    source = VerifiedByteSource(LocalByteSource(arguments["representation_root"]))
    assert {source.read(sample) for sample in samples} == {item[0] for item in items}


def _write_source_contract(tmp_path: Path, rows: list[dict[str, str | int]]) -> tuple[Path, Path]:
    manifest = tmp_path / "source.csv"
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    summary = tmp_path / "source.json"
    summary.write_text(
        json.dumps(
            {
                "inventory_audit_passed": True,
                "manifest": {"sha256": sha256(manifest.read_bytes()).hexdigest()},
            }
        )
    )
    return manifest, summary


def test_prepare_exe_resume_retries_failed_reads(tmp_path: Path) -> None:
    rows = [
        _row(b"retry-source", "train", "benign"),
        _row(b"stable-source", "test", "ransomware"),
    ]
    source_manifest, source_summary = _write_source_contract(tmp_path, rows)
    prefix = "rands/representations/exe/"
    objects = {
        f"{prefix}{row['source_sha256'][:2]}/{row['source_sha256']}.bin": content
        for row, content in zip(rows, (b"retry-exe", b"stable-exe"), strict=True)
    }

    class FailOnceS3(FakeS3):
        def __init__(self, values: dict[str, bytes]) -> None:
            super().__init__(values)
            self.failed = False

        def head_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
            if not self.failed:
                self.failed = True
                from malweave.data.s3.client import S3ReadError

                raise S3ReadError("synthetic transient read failure")
            return super().head_object(Bucket=Bucket, Key=Key)

    arguments = {
        "source_manifest": source_manifest,
        "source_summary": source_summary,
        "bucket": "synthetic",
        "prefix": prefix,
        "representation_root": tmp_path / "exe",
        "state_path": tmp_path / "state.sqlite",
        "manifest_path": tmp_path / "exe.csv",
        "summary_path": tmp_path / "exe.json",
        "snapshot": "synthetic",
        "client": FailOnceS3(objects),
    }
    with pytest.raises(RandsExeInputError, match="EXE preparation"):
        prepare_rands_exe_inputs(**arguments)

    arguments["client"] = FakeS3(objects)
    summary = prepare_rands_exe_inputs(**arguments, resume=True)
    assert summary["passed"] is True
    assert summary["statuses"] == {"success": 2}
    assert summary["published"] == 2


def test_prepare_exe_removes_entire_cross_split_duplicate_group(tmp_path: Path) -> None:
    rows = [
        _row(b"source-a", "train", "benign"),
        _row(b"source-b", "test", "benign"),
        _row(b"source-c", "train", "benign"),
        _row(b"source-d", "test", "benign"),
    ]
    source_manifest, source_summary = _write_source_contract(tmp_path, rows)
    prefix = "rands/representations/exe/"
    representations = (b"duplicate", b"duplicate", b"train-unique", b"test-unique")
    objects = {
        f"{prefix}{row['source_sha256'][:2]}/{row['source_sha256']}.bin": content
        for row, content in zip(rows, representations, strict=True)
    }
    summary = prepare_rands_exe_inputs(
        source_manifest,
        source_summary,
        "synthetic",
        prefix,
        tmp_path / "exe",
        tmp_path / "state.sqlite",
        tmp_path / "exe.csv",
        tmp_path / "exe.json",
        snapshot="synthetic",
        client=FakeS3(objects),
    )
    assert summary["passed"] is True
    assert summary["cross_split_duplicate_groups"] == 1
    assert summary["cross_split_samples_removed"] == 2
    assert summary["published"] == 2
    samples = load_training_manifest(tmp_path / "exe.csv", "exe")
    assert {sample.split for sample in samples} == {"train", "test"}
    assert len({sample.group_id for sample in samples}) == 2


def test_prepare_exe_retains_same_split_duplicate_sources(tmp_path: Path) -> None:
    rows = [
        _row(b"source-a", "train", "benign"),
        _row(b"source-b", "train", "benign"),
        _row(b"source-c", "test", "benign"),
    ]
    source_manifest, source_summary = _write_source_contract(tmp_path, rows)
    prefix = "rands/representations/exe/"
    representations = (b"same-exe", b"same-exe", b"test-exe")
    objects = {
        f"{prefix}{row['source_sha256'][:2]}/{row['source_sha256']}.bin": content
        for row, content in zip(rows, representations, strict=True)
    }
    summary = prepare_rands_exe_inputs(
        source_manifest,
        source_summary,
        "synthetic",
        prefix,
        tmp_path / "exe",
        tmp_path / "state.sqlite",
        tmp_path / "exe.csv",
        tmp_path / "exe.json",
        snapshot="synthetic",
        client=FakeS3(objects),
    )

    assert summary["passed"] is True
    assert summary["published"] == 3
    assert summary["same_split_duplicate_groups_retained"] == 1
    assert summary["same_split_duplicate_samples_retained"] == 2
    samples = load_training_manifest(tmp_path / "exe.csv", "exe")
    train_groups = [sample.group_id for sample in samples if sample.split == "train"]
    assert len(train_groups) == 2
    assert len(set(train_groups)) == 1
