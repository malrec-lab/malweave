"""Synthetic tests for RawMal-TF streaming EXE preparation."""

from collections import namedtuple
import csv
import hashlib
import io
import sqlite3
import threading

import boto3
from botocore.exceptions import ClientError
import pytest

from malweave.data import rawmal_exe
from malweave.data.pe_sections import IMAGE_SCN_CNT_CODE
from malweave.data.rawmal_exe import (
    RawMalSource,
    _initialize,
    _publish,
    audit_objects,
    run_batch,
    run_rawmal_exe,
)
from malweave.data.sorel_io import SorelError
from tests.data.test_pe_sections import _synthetic_pe


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.lock = threading.Lock()

    def add(self, key, content):
        self.objects[key] = (content, {"sha256": hashlib.sha256(content).hexdigest()})

    def head_object(self, **kwargs):
        if kwargs["Key"] not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        content, metadata = self.objects[kwargs["Key"]]
        return {"ContentLength": len(content), "Metadata": metadata, "ETag": '"etag"'}

    def get_object(self, **kwargs):
        class Body(io.BytesIO):
            def iter_chunks(self, chunk_size):
                while chunk := self.read(chunk_size):
                    yield chunk

        return {"Body": Body(self.objects[kwargs["Key"]][0])}

    def head_bucket(self, **kwargs):
        return {}

    def put_object(self, **kwargs):
        with self.lock:
            key = kwargs["Key"]
            if kwargs.get("IfNoneMatch") and key in self.objects:
                raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
            body = kwargs["Body"]
            content = body if isinstance(body, bytes) else body.read()
            self.objects[key] = (content, kwargs.get("Metadata", {}))

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, **kwargs):
        yield {
            "Contents": [
                {"Key": key, "Size": len(content)}
                for key, (content, _) in self.objects.items()
                if key.startswith(kwargs["Prefix"])
            ]
        }


def source_for(content, detected_format="pe"):
    digest = hashlib.sha256(content).hexdigest()
    return RawMalSource(digest, f"raw/{digest[:2]}/{digest}", len(content), detected_format)


def test_release_inventory_rejects_missing_and_unexpected_objects():
    content = b"synthetic"
    source = source_for(content)
    client = FakeS3()
    with pytest.raises(SorelError, match="incomplete"):
        audit_objects(client, "bucket", "account", [source])
    client.add(source.s3_key, content)
    audit_objects(client, "bucket", "account", [source])
    client.add("raw/unexpected", b"extra")
    with pytest.raises(SorelError, match="differs"):
        audit_objects(client, "bucket", "account", [source])


def test_batch_deduplicates_exe_and_preserves_source_appearances(tmp_path):
    first = _synthetic_pe([(b".code", 0x400, 0x20, IMAGE_SCN_CNT_CODE)])
    second = bytearray(first)
    second[0x200] = 1
    second = bytes(second)
    sources = [source_for(first), source_for(second), source_for(b"not PE", "unknown")]
    client = FakeS3()
    for source, content in zip(sources, (first, second, b"not PE")):
        client.add(source.s3_key, content)
    inventory = tmp_path / "ingestion.sqlite"
    with sqlite3.connect(inventory) as original:
        original.execute(
            "CREATE TABLE members(sha256 TEXT,source TEXT,name TEXT,label_group TEXT,"
            "kind TEXT,status TEXT)"
        )
        original.executemany(
            "INSERT INTO members VALUES(?,?,?,?,?,?)",
            [
                (s.sha256, "type", str(i), "label", "raw", "uploaded")
                for i, s in enumerate(sources)
            ],
        )
    db = sqlite3.connect(tmp_path / "state.sqlite")
    _initialize(db, inventory, sources, "input-digest", "account:bucket", "extractor")
    run_batch(client, "bucket", "account", sources, db, tmp_path, workers=2)
    rows = db.execute("SELECT status,exe_key FROM source ORDER BY status").fetchall()
    assert [row[0] for row in rows] == ["not_pe", "success", "success"]
    assert rows[1][1] == rows[2][1]
    assert len([key for key in client.objects if key.startswith("exe/")]) == 1
    _publish(client, "bucket", "account", db, tmp_path)
    exported = list(csv.DictReader(io.StringIO(client.objects["main/exe.csv"][0].decode())))
    assert len(exported) == 3
    assert all('"label": "label"' in row["source_appearances"] for row in exported)
    db.close()


def test_corrupted_raw_is_recorded_as_error_and_can_retry(tmp_path):
    content = _synthetic_pe([(b".code", 0x400, 0x20, IMAGE_SCN_CNT_CODE)])
    source = source_for(content)
    client = FakeS3()
    client.add(source.s3_key, content[:-1] + b"X")
    inventory = tmp_path / "ingestion.sqlite"
    with sqlite3.connect(inventory) as original:
        original.execute(
            "CREATE TABLE members(sha256 TEXT,source TEXT,name TEXT,label_group TEXT,"
            "kind TEXT,status TEXT)"
        )
        original.execute(
            "INSERT INTO members VALUES(?,?,?,?,?,?)",
            (source.sha256, "type", "member", "label", "raw", "uploaded"),
        )
    db = sqlite3.connect(tmp_path / "state.sqlite")
    _initialize(db, inventory, [source], "input-digest", "account:bucket", "extractor")
    run_batch(client, "bucket", "account", [source], db, tmp_path, workers=1)
    assert db.execute("SELECT status FROM source").fetchone() == ("error",)
    client.add(source.s3_key, content)
    run_batch(client, "bucket", "account", [source], db, tmp_path, workers=1)
    assert db.execute("SELECT status FROM source").fetchone() == ("success",)
    db.close()


def test_upload_failure_retains_download_for_retry(tmp_path, monkeypatch):
    content = _synthetic_pe([(b".code", 0x400, 0x20, IMAGE_SCN_CNT_CODE)])
    source = source_for(content)
    client = FakeS3()
    client.add(source.s3_key, content)
    inventory = tmp_path / "ingestion.sqlite"
    with sqlite3.connect(inventory) as original:
        original.execute(
            "CREATE TABLE members(sha256 TEXT,source TEXT,name TEXT,label_group TEXT,"
            "kind TEXT,status TEXT)"
        )
        original.execute(
            "INSERT INTO members VALUES(?,?,?,?,?,?)",
            (source.sha256, "type", "member", "label", "raw", "uploaded"),
        )
    db = sqlite3.connect(tmp_path / "state.sqlite")
    _initialize(db, inventory, [source], "input-digest", "account:bucket", "extractor")
    put = client.put_object
    monkeypatch.setattr(
        client, "put_object", lambda **kw: (_ for _ in ()).throw(OSError("offline"))
    )
    run_batch(client, "bucket", "account", [source], db, tmp_path, workers=1)
    assert db.execute("SELECT status FROM source").fetchone() == ("error",)
    assert (tmp_path / "staging" / source.sha256 / "raw").read_bytes() == content
    monkeypatch.setattr(client, "put_object", put)
    monkeypatch.setattr(client, "get_object", lambda **kw: pytest.fail("raw was downloaded twice"))
    run_batch(client, "bucket", "account", [source], db, tmp_path, workers=1)
    assert db.execute("SELECT status FROM source").fetchone() == ("success",)
    assert not (tmp_path / "staging" / source.sha256).exists()
    db.close()


def test_resume_on_new_machine_restores_snapshot_and_skips_completed(tmp_path, monkeypatch):
    first = _synthetic_pe([(b".code", 0x400, 0x20, IMAGE_SCN_CNT_CODE)])
    second = bytearray(first)
    second[0x200] = 1
    second = bytes(second)
    sources = [source_for(first), source_for(second)]
    client = FakeS3()
    for source, content in zip(sources, (first, second)):
        client.add(source.s3_key, content)
    inventory = tmp_path / "source.sqlite"
    with sqlite3.connect(inventory) as original:
        original.execute(
            "CREATE TABLE members(sha256 TEXT,source TEXT,name TEXT,label_group TEXT,"
            "kind TEXT,status TEXT)"
        )
        original.executemany(
            "INSERT INTO members VALUES(?,?,?,?,?,?)",
            [
                (s.sha256, "type", str(i), "label", "raw", "uploaded")
                for i, s in enumerate(sources)
            ],
        )
    client.add("details/state.sqlite", inventory.read_bytes())

    class Session:
        def __init__(self, **kwargs):
            pass

        def client(self, name, **kwargs):
            if name == "sts":
                return self
            assert name == "s3"
            return client

        def get_caller_identity(self):
            return {"Account": "account"}

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(boto3, "Session", Session)
    monkeypatch.setattr(rawmal_exe, "load_inventory", lambda path: (sources, {"pe": 2}))
    monkeypatch.setattr(
        rawmal_exe.shutil, "disk_usage", lambda path: usage(20 * 1024**3, 0, 20 * 1024**3)
    )
    first_run = run_rawmal_exe(tmp_path / "machine-a", "bucket", "account", "profile", limit=1)
    assert first_run["status"] == {"pending": 1, "success": 1}
    second_run = run_rawmal_exe(tmp_path / "machine-b", "bucket", "account", "profile", limit=1)
    assert second_run["status"] == {"success": 2}
    assert second_run["unique_exe"] == 1
