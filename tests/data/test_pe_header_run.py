"""Synthetic private-store tests for Header audit and crash recovery."""

import csv
import io
import sqlite3
import struct

import boto3
from botocore.exceptions import ClientError
import pytest

from malweave.data.pe_header_run import (
    audit_manifest,
    compact_result,
    publish,
    read_remote,
    run_headers,
)
from tests.data.test_pe_sections import _synthetic_pe


def test_compact_checkpoint_drops_bulk_evidence_without_mutating_it():
    value = {
        "source": {
            "source_sha256": "synthetic",
            "split": "unassigned",
            "label": "benign",
            "object_key": "private",
        },
        "status": "success",
        "header_sha256": "digest",
        "size_of_headers": 512,
        "header_key": "header",
        "worker_stdout": "large evidence" * 1000,
    }
    compact = compact_result(value)
    assert "worker_stdout" not in compact
    assert "object_key" not in compact["source"]
    assert compact["size_of_headers"] == 512
    assert "worker_stdout" in value
    assert "object_key" in value["source"]


class Store:
    def __init__(self):
        self.objects = {}
        self.raw_downloads = 0

    def put_object(self, **kwargs):
        key = kwargs["Key"]
        if kwargs.get("IfNoneMatch") and key in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.objects[key] = kwargs["Body"]

    def get_object(self, **kwargs):
        key = kwargs["Key"]
        if key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        if key == "raw/synthetic":
            assert kwargs["IfMatch"] == '"synthetic-etag"'
            self.raw_downloads += 1

        class Body(io.BytesIO):
            def iter_chunks(self, size):
                while block := self.read(size):
                    yield block

        return {"Body": Body(self.objects[key])}


def inputs(tmp_path):
    raw = bytearray(_synthetic_pe([(b".text", 0x400, 0x20, 0x60000020)]))
    struct.pack_into("<I", raw, 0x98 + 60, 0x400)
    row = {
        "source_sha256": "a" * 64,
        "object_key": "raw/synthetic",
        "object_size": len(raw),
        "object_etag": '"synthetic-etag"',
        "availability": "available",
        "split": "train",
        "label": "benign",
    }
    manifest = tmp_path / "input.csv"
    with manifest.open("w") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    inventory = tmp_path / "inventory.sqlite"
    with sqlite3.connect(inventory) as db:
        db.execute("CREATE TABLE settings (name TEXT,value TEXT)")
        db.executemany(
            "INSERT INTO settings VALUES (?,?)",
            [("complete", "1"), ("bucket", "private-synthetic")],
        )
        db.execute(
            "CREATE TABLE objects (source_sha256 TEXT,object_key TEXT,size INTEGER,etag TEXT)"
        )
        db.execute(
            "INSERT INTO objects VALUES (?,?,?,?)",
            (row["source_sha256"], row["object_key"], len(raw), row["object_etag"]),
        )
    return manifest, inventory, bytes(raw)


def test_resume_restores_remote_after_local_checkpoint_loss(tmp_path, monkeypatch):
    manifest, inventory, raw = inputs(tmp_path)
    store = Store()
    store.objects["raw/synthetic"] = raw
    monkeypatch.setattr(boto3, "client", lambda *a, **kw: store)
    arguments = {
        "manifest": manifest,
        "inventory": inventory,
        "output_prefix": "rands/representations/pe-header/runs/synthetic",
        "workers": 1,
    }
    first = run_headers(**arguments, job_dir=tmp_path / "first")
    assert first["statuses"] == {"success": 1}
    second = run_headers(**arguments, job_dir=tmp_path / "recovered")
    assert second["statuses"] == {"success": 1}
    assert store.raw_downloads == 1
    assert any("/history/" in key for key in store.objects)


def test_audit_rejects_inventory_mismatch(tmp_path):
    manifest, inventory, _raw = inputs(tmp_path)
    with sqlite3.connect(inventory) as db:
        db.execute("UPDATE objects SET size=1")
    with pytest.raises(ValueError, match="differs"):
        audit_manifest(manifest, inventory)


def test_all_raw_manifest_can_leave_split_unassigned(tmp_path):
    manifest, inventory, _raw = inputs(tmp_path)
    manifest.write_text(manifest.read_text().replace("train", "unassigned"))
    rows, _settings = audit_manifest(manifest, inventory)
    assert rows[0]["split"] == "unassigned"


def test_immutable_upload_accepts_only_identical_bytes():
    store = Store()
    publish(store, "private", "header", b"synthetic")
    publish(store, "private", "header", b"synthetic")
    with pytest.raises(ValueError, match="differs"):
        publish(store, "private", "header", b"different")


def test_stream_failure_restarts_get(monkeypatch):
    from botocore.exceptions import ResponseStreamingError

    store = Store()
    store.objects["header"] = b"synthetic"
    original = store.get_object
    calls = []

    class Broken(io.BytesIO):
        def read(self, *args):
            raise ResponseStreamingError(error="synthetic interrupted stream")

    def get(**kwargs):
        calls.append(kwargs)
        return {"Body": Broken()} if len(calls) == 1 else original(**kwargs)

    monkeypatch.setattr(store, "get_object", get)
    monkeypatch.setattr("malweave.data.pe_header_run.time.sleep", lambda seconds: None)
    assert read_remote(store, "private", "header") == b"synthetic"
    assert len(calls) == 2
