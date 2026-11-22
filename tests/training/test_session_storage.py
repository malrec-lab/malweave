"""Durable publication and untrusted archive integrity regression checks."""

from hashlib import sha256
import io
import json
import tarfile
from urllib.error import URLError

import pytest

from malweave.training import session_storage as storage
from malweave.training.contracts import SupervisedTrainingError


@pytest.mark.parametrize("headers, expected", [(None, ""), ({"content-type": "x/test"}, "x/test")])
def test_presigned_put_does_not_inject_unsigned_form_content_type(monkeypatch, headers, expected):
    seen = []

    def open_request(request, *, timeout):
        seen.append(request)
        return io.BytesIO(b"")

    monkeypatch.setattr(storage, "urlopen", open_request)
    assert (
        storage.request_bytes(
            "https://storage.example/private?signature=secret", data=b"synthetic", headers=headers
        )
        == b""
    )
    assert seen[0].get_method() == "PUT"
    assert seen[0].get_header("Content-type") == expected
    if headers is not None:
        assert headers == {"content-type": "x/test"}


def test_private_transfer_reports_reason_type_without_leaking_url(monkeypatch):
    private = "https://storage.example/private?signature=secret"

    def fail(*args, **kwargs):
        raise URLError(BrokenPipeError(32, private))

    monkeypatch.setattr(storage, "urlopen", fail)
    with pytest.raises(SupervisedTrainingError) as caught:
        storage.request_bytes(private, data=b"synthetic", attempts=1)
    assert "URLError/BrokenPipeError; errno=32" in str(caught.value)
    assert "secret" not in str(caught.value)
    assert "storage.example" not in str(caught.value)


def test_snapshot_roundtrip_and_identity(tmp_path):
    source = tmp_path / "last.pt"
    source.write_bytes(b"synthetic trusted checkpoint")
    archive = tmp_path / "backup.tar.gz"
    identity = {"config": "frozen", "run": "own"}
    storage.pack_snapshot({"runs/e2/last.pt": source}, archive, identity)
    destination = tmp_path / "restored"
    storage.restore_snapshot(archive, destination, identity)
    assert (destination / "runs/e2/last.pt").read_bytes() == source.read_bytes()
    with pytest.raises(SupervisedTrainingError, match="identity"):
        storage.restore_snapshot(archive, tmp_path / "wrong", {"run": "other"})
    assert not (tmp_path / "wrong").exists()


@pytest.mark.parametrize("member", ["../escaped", "/absolute", "raw/source", ".env"])
def test_restore_rejects_unsafe_paths_before_writing(tmp_path, member):
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        entry = tarfile.TarInfo(member)
        entry.size = 1
        output.addfile(entry, io.BytesIO(b"x"))
    with pytest.raises(SupervisedTrainingError, match="unsafe"):
        storage.restore_snapshot(archive, tmp_path / "restore", {})
    assert not (tmp_path / "restore").exists()
    assert not (tmp_path / "escaped").exists()


def test_restore_checks_each_member_and_cleans_partial_restore(tmp_path):
    archive = tmp_path / "corrupt.tar.gz"
    manifest = {
        "schema": 1,
        "identity": {},
        "files": {"last.pt": {"bytes": 1, "sha256": sha256(b"a").hexdigest()}},
    }
    with tarfile.open(archive, "w:gz") as output:
        for name, data in [
            ("snapshot-manifest.json", json.dumps(manifest).encode()),
            ("last.pt", b"b"),
        ]:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            output.addfile(entry, io.BytesIO(data))
    with pytest.raises(SupervisedTrainingError, match="checksum"):
        storage.restore_snapshot(archive, tmp_path / "restore", {})
    assert not (tmp_path / "restore").exists()


def test_failed_remote_verification_keeps_previous_pointer(tmp_path, monkeypatch):
    archive = tmp_path / "last.tar.gz"
    archive.write_bytes(b"new generation")
    objects = {"pointer": b"previous generation"}

    def transfer(url, *, data=None, **kwargs):
        if data is not None:
            objects[url] = data
            return b""
        return b"corrupted" if url == "slot" else objects[url]

    monkeypatch.setattr(storage, "request_bytes", transfer)
    with pytest.raises(SupervisedTrainingError, match="checksum"):
        storage.publish_snapshot(
            archive,
            [{"put": "slot", "get": "slot"}],
            {"put": "pointer", "get": "pointer"},
            {"generation": 0},
        )
    assert objects["pointer"] == b"previous generation"
