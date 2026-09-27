"""Network-volume transfers use only synthetic bytes and in-memory fake S3."""

import csv
from hashlib import sha256
import io
import json
import subprocess
import sys

from botocore.exceptions import ClientError
import pytest

from malweave import cli
from malweave.data.s3 import relay
from malweave.training.stage import StageError
from malweave.training.stage_network import stage_network


class S3:
    def __init__(self, objects=None):
        self.objects = objects or {}
        self.uploads = {}
        self.calls = 0
        self.aborts = 0
        self.puts = 0
        self.fail_part = False

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {"ContentLength": len(self.objects[Key]), "ETag": "synthetic"}

    def get_object(self, Bucket, Key, **kwargs):
        self.calls += 1
        assert kwargs.get("IfMatch") == "synthetic"
        return {"Body": io.BytesIO(self.objects[Key])}

    def put_object(self, Bucket, Key, Body):
        self.puts += 1
        self.objects[Key] = bytes(Body)

    def create_multipart_upload(self, Bucket, Key):
        self.uploads[Key] = {}
        return {"UploadId": Key}

    def upload_part(self, Bucket, Key, UploadId, PartNumber, Body):
        if self.fail_part:
            raise OSError("synthetic failure")
        self.uploads[Key][PartNumber] = bytes(Body)
        return {"ETag": str(PartNumber)}

    def complete_multipart_upload(self, Bucket, Key, UploadId, MultipartUpload):
        parts = self.uploads.pop(Key)
        self.objects[Key] = b"".join(parts[p["PartNumber"]] for p in MultipartUpload["Parts"])

    def abort_multipart_upload(self, **kwargs):
        self.uploads.pop(kwargs["Key"], None)
        self.aborts += 1


def fixture(tmp_path):
    contents = [b"harmless-fixture-one", b"harmless-fixture-two"]
    rows = [
        {
            "source_sha256": sha256(b).hexdigest(),
            "group_id": sha256(b).hexdigest(),
            "split": "train",
            "label": "benign" if i == 0 else "ransomware",
            "object_key": f"original/{i}",
            "object_size": len(b),
            "object_etag": "synthetic",
        }
        for i, b in enumerate(contents)
    ]
    manifest, audit = tmp_path / "manifest.csv", tmp_path / "audit.json"
    with manifest.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    audit.write_text(
        json.dumps(
            {
                "inventory_audit_passed": True,
                "manifest": {"sha256": sha256(manifest.read_bytes()).hexdigest()},
            }
        )
    )
    return manifest, audit, S3({f"original/{i}": b for i, b in enumerate(contents)}), contents


def run(tmp_path, source, target, **kwargs):
    return stage_network(
        tmp_path / "manifest.csv",
        tmp_path / "audit.json",
        tmp_path / "state",
        source_bucket="source",
        destination_bucket="target",
        destination_prefix="malweave/full",
        destination_endpoint="https://s3api-test.runpod.io",
        destination_region="test",
        source_client=source,
        destination_client=target,
        workers=2,
        **kwargs,
    )


def test_network_stages_exports_and_resumes_without_source_reads(tmp_path):
    manifest, audit, source, contents = fixture(tmp_path)
    target = S3()
    result = run(tmp_path, source, target)
    assert result["passed"] and result["publication_complete"]
    assert result["success_by_label"] == {"benign": 1, "ransomware": 1}
    assert result["output_bytes"] == sum(map(len, contents))
    assert result["output_root"] == "/workspace/malweave/full"
    assert target.objects["malweave/full/split-manifest.csv"] == manifest.read_bytes()
    assert target.objects["malweave/full/manifest-summary.json"] == audit.read_bytes()
    ready = json.loads(target.objects["malweave/full/staging-summary.json"])
    assert ready["manifest_sha256"] == sha256(manifest.read_bytes()).hexdigest()
    calls, puts = source.calls, target.puts
    result = run(tmp_path, source, target, resume=True)
    assert source.calls == calls and target.puts == puts
    assert result["reused_files_this_run"] == 2
    assert not list((tmp_path / "state").rglob("dataset"))


def test_wrong_source_never_published_and_retries_failed_only(tmp_path):
    _, _, source, contents = fixture(tmp_path)
    source.objects["original/0"] = b"x" * len(contents[0])
    target = S3()
    with pytest.raises(StageError, match="incomplete"):
        run(tmp_path, source, target)
    assert "malweave/full/staging-summary.json" not in target.objects
    report = json.loads((tmp_path / "state/network-staging-summary.json").read_text())
    assert report["failure_by_label"] == {"benign": 1}
    assert report["failure_reasons"] == {"source_digest_mismatch": 1}
    source.objects["original/0"] = contents[0]
    calls = source.calls
    assert run(tmp_path, source, target, resume=True)["passed"]
    assert source.calls == calls + 1


def test_changed_contract_and_bad_audit_do_not_transfer(tmp_path):
    _, audit, source, _ = fixture(tmp_path)
    target = S3()
    run(tmp_path, source, target)
    calls = source.calls
    with pytest.raises(StageError, match="settings changed"):
        run(tmp_path, source, target, resume=True, mount_root="/elsewhere")
    audit.write_text("{}")
    with pytest.raises(StageError, match="audit"):
        run(tmp_path, source, target, resume=True)
    assert source.calls == calls


@pytest.mark.parametrize("content", [b"short", b"0123456789" * 5])
def test_small_and_multipart_roundtrip(tmp_path, monkeypatch, content):
    monkeypatch.setattr(relay, "PART_BYTES", 16)
    target = S3()
    journal = tmp_path / "multipart.json"
    assert not relay.relay_object(
        target,
        "bucket",
        "key",
        iter([content]),
        size=len(content),
        digest=sha256(content).hexdigest(),
        journal=journal,
    )
    assert target.objects["key"] == content
    assert not journal.exists()


def test_multipart_source_failure_aborts_and_closes(tmp_path, monkeypatch):
    monkeypatch.setattr(relay, "PART_BYTES", 16)
    target = S3()
    with pytest.raises(relay.RelayError, match="source_digest"):
        relay.relay_object(
            target,
            "bucket",
            "key",
            [b"x" * 32],
            size=32,
            digest="0" * 64,
            journal=tmp_path / "multipart.json",
        )
    assert target.aborts == 1
    assert not target.objects and not target.uploads


def test_interrupted_upload_cleanup_and_destination_conflict(tmp_path):
    target = S3({"key": b"bad"})
    journal = tmp_path / "multipart.json"
    journal.write_text(json.dumps({"bucket": "bucket", "key": "key", "upload_id": "old"}))
    with pytest.raises(relay.RelayError, match="destination_digest"):
        relay.relay_object(
            target,
            "bucket",
            "key",
            [b"new"],
            size=3,
            digest=sha256(b"new").hexdigest(),
            journal=journal,
        )
    assert target.aborts == 1
    assert target.objects["key"] == b"bad"


def test_cli_requires_isolation_and_does_not_import_torch():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            'import sys; import malweave.cli; assert "torch" not in sys.modules; assert "tokenizers" not in sys.modules',
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert cli.main(["experiment", "stage-network"]) == 2


def test_cli_separates_source_and_runpod_settings(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(
        cli, "stage_network", lambda *args, **kwargs: captured.update(kwargs) or {}
    )
    monkeypatch.setenv("MALWEAVE_RANDS_S3_BUCKET", "original")
    for name, value in [
        ("BUCKET", "target"),
        ("ENDPOINT_URL", "https://s3api-test.runpod.io"),
        ("REGION", "test"),
    ]:
        monkeypatch.setenv("RUNPOD_S3_" + name, value)
    assert cli.main(["experiment", "stage-network", "--acknowledge-isolated-worker"]) == 0
    assert captured["source_bucket"] == "original"
    assert captured["destination_bucket"] == "target"
    assert captured["destination_prefix"].endswith("/full-train-balanced")


def test_readback_corruption_prevents_ready_report(tmp_path):
    _, _, source, _ = fixture(tmp_path)

    class CorruptDestination(S3):
        def put_object(self, Bucket, Key, Body):
            super().put_object(Bucket, Key, Body)
            if "/dataset/" in Key:
                self.objects[Key] = b"x" * len(Body)

    target = CorruptDestination()
    with pytest.raises(StageError, match="incomplete"):
        run(tmp_path, source, target)
    report = json.loads((tmp_path / "state/network-staging-summary.json").read_text())
    assert report["failure_reasons"] == {"destination_digest_conflict": 2}
    assert "malweave/full/staging-summary.json" not in target.objects


def test_multipart_upload_error_aborts_and_removes_journal(tmp_path, monkeypatch):
    monkeypatch.setattr(relay, "PART_BYTES", 16)
    target = S3()
    target.fail_part = True
    journal = tmp_path / "upload.json"
    with pytest.raises(OSError, match="synthetic"):
        relay.relay_object(
            target,
            "bucket",
            "key",
            [b"x" * 32],
            size=32,
            digest=sha256(b"x" * 32).hexdigest(),
            journal=journal,
        )
    assert target.aborts == 1
    assert not journal.exists()
    assert not target.objects


def test_same_state_lock_rejects_another_network_writer(tmp_path):
    from malweave.training.stage import _staging_lock

    _, _, source, _ = fixture(tmp_path)
    target = S3()
    with _staging_lock(tmp_path / "state"), pytest.raises(StageError, match="Another staging"):
        run(tmp_path, source, target)
    assert source.calls == target.puts == 0
