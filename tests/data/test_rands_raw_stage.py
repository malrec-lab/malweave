"""Original-byte staging integrity, resume and failure accounting on synthetic data."""

from hashlib import sha256
import io
import json
import sqlite3

import pytest

from malweave.data import rands_raw_stage as stage
from malweave.training.contracts import SupervisedTrainingError


def source(data, label="benign"):
    digest = sha256(data).hexdigest()
    return {
        "sha256": digest,
        "bytes": len(data),
        "relative_path": f"dataset/{digest[:2]}/{digest}",
        "etag": '"pinned"',
        "url": "https://private.example/own-scoped-object",
        "label": label,
    }


def test_stage_verifies_complete_original_then_reuses_it(tmp_path, monkeypatch):
    data = b"synthetic non-PE\x00" * 100
    row = source(data)
    calls = []

    def get(session, request):
        assert request["etag"] == row["etag"]
        calls.append(request)
        return io.BytesIO(data)

    monkeypatch.setattr(stage, "_open_source", get)
    manifest = {
        "identity": {"cohort": "frozen"},
        "sources": [row],
        "release_audit": {"passed": True},
    }
    first = stage.stage_raw_sources(manifest, tmp_path, workers=1)
    second = stage.stage_raw_sources(manifest, tmp_path, workers=1)
    assert first["statuses"] == {"downloaded": 1}
    assert second["statuses"] == {"reused": 1}
    assert len(calls) == 1
    assert (tmp_path / row["relative_path"]).read_bytes() == data
    with sqlite3.connect(tmp_path / "stage.sqlite3") as db:
        assert db.execute("select status,attempts from source").fetchone() == ("reused", 2)


def test_stage_digest_failure_records_source_and_removes_partial(tmp_path, monkeypatch):
    row = source(b"expected")
    monkeypatch.setattr(stage, "_open_source", lambda *args, **kwargs: io.BytesIO(b"tampered"))
    manifest = {"identity": {}, "sources": [row], "release_audit": {"passed": True}}
    with pytest.raises(SupervisedTrainingError, match="staging failed"):
        stage.stage_raw_sources(manifest, tmp_path, workers=1)
    assert not (tmp_path / row["relative_path"]).exists()
    assert not list(tmp_path.rglob("*.download"))
    report = json.loads((tmp_path / "stage-progress.json").read_text())
    assert report["statuses"] == {"failed": 1}
    with sqlite3.connect(tmp_path / "stage.sqlite3") as db:
        assert db.execute("select status from source").fetchone()[0] == "failed"


def test_invalid_staging_manifest_does_not_write_payload(tmp_path):
    row = source(b"synthetic")
    row["relative_path"] = "../escape"
    with pytest.raises(SupervisedTrainingError, match="Invalid"):
        stage.stage_raw_sources(
            {"identity": {}, "sources": [row], "release_audit": {"passed": True}}, tmp_path
        )
    assert not (tmp_path / "stage.sqlite3").exists()
