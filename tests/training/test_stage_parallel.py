"""Bounded concurrent staging against synthetic S3 streams, never real samples."""

import csv
import errno
from hashlib import sha256
import io
import json
from pathlib import Path
import threading

import pytest

from malweave.training import stage
from malweave.training.manifest import load_training_manifest
from malweave.training.sources import S3ByteSource


def fixture(root: Path, count: int = 8, repetitions: int = 100):
    objects = {
        f"synthetic/{i}": (f"synthetic-content-{i}".encode() * repetitions) for i in range(count)
    }
    rows = [
        {
            "source_sha256": sha256(content).hexdigest(),
            "group_id": sha256(content).hexdigest(),
            "label": "benign" if i % 2 else "ransomware",
            "split": "train",
            "object_key": key,
            "object_size": len(content),
            "object_etag": '"test"',
        }
        for i, (key, content) in enumerate(objects.items())
    ]
    manifest, audit = root / "split.csv", root / "audit.json"
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
    return manifest, audit, objects


class Client:
    def __init__(self, objects, barrier=None):
        self.objects = objects
        self.barrier = barrier
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.calls = 0

    def get_object(self, **request):
        assert request["IfMatch"] == '"test"'
        client = self
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.calls += 1

        class Body(io.BytesIO):
            first = True

            def read(self, size=-1):
                assert 0 < size <= 1024 * 1024
                if self.first and client.barrier is not None:
                    self.first = False
                    client.barrier.wait(timeout=10)
                return super().read(size)

            def close(self):
                if not self.closed:
                    with client.lock:
                        client.active -= 1
                super().close()

        return {"Body": Body(self.objects[request["Key"]])}


def test_parallel_streams_are_bounded_and_match_serial_results(tmp_path):
    manifest, audit, objects = fixture(tmp_path)
    serial = stage.stage_manifest_from_s3(
        manifest, audit, tmp_path / "serial", bucket="test", client=Client(objects)
    )
    client = Client(objects, threading.Barrier(4))
    parallel = stage.stage_manifest_from_s3(
        manifest, audit, tmp_path / "parallel", bucket="test", client=client, workers=4
    )
    assert client.peak == 4
    assert client.active == 0
    assert parallel["success_by_label"] == serial["success_by_label"]
    assert parallel["output_bytes"] == serial["output_bytes"] == sum(map(len, objects.values()))
    assert parallel["downloaded_bytes_this_run"] == parallel["output_bytes"]
    assert parallel["workers"] == 4
    assert parallel["wall_seconds_this_run"] > 0
    resumed = stage.stage_manifest_from_s3(
        manifest,
        audit,
        tmp_path / "parallel",
        bucket="test",
        client=client,
        workers=2,
        resume=True,
    )
    assert client.calls == 8
    assert resumed["downloaded_bytes_this_run"] == 0
    assert resumed["reused_files_this_run"] == 8


def test_large_objects_are_read_in_bounded_chunks(tmp_path):
    manifest, audit, objects = fixture(tmp_path, count=2, repetitions=200_000)
    assert all(len(content) > 2 * 1024 * 1024 for content in objects.values())
    client = Client(objects)
    result = stage.stage_manifest_from_s3(
        manifest, audit, tmp_path / "staged", bucket="test", client=client, workers=2
    )
    assert result["passed"]
    assert result["output_bytes"] == sum(map(len, objects.values()))
    assert client.active == 0


def test_interrupted_stream_is_closed_and_can_resume(tmp_path):
    manifest, audit, objects = fixture(tmp_path, count=1, repetitions=200_000)

    class BrokenClient(Client):
        def get_object(self, **request):
            response = super().get_object(**request)
            body = response["Body"]
            original_read = body.read

            def read(size):
                if body.tell():
                    raise OSError("synthetic connection lost")
                return original_read(size)

            body.read = read
            return response

    root = tmp_path / "staged"
    client = BrokenClient(objects)
    with pytest.raises(stage.StageError, match="incomplete"):
        stage.stage_manifest_from_s3(manifest, audit, root, bucket="test", client=client)
    report = json.loads((root / "staging-summary.json").read_text())
    assert report["failure_reasons"] == {"s3_error": 1}
    assert client.active == 0
    assert not list(root.rglob(".stage-*"))
    assert not (root / load_training_manifest(manifest, "raw")[0].relative_path).exists()
    result = stage.stage_manifest_from_s3(
        manifest, audit, root, bucket="test", client=Client(objects), resume=True
    )
    assert result["passed"]


@pytest.mark.parametrize(
    "mutation, reason", [(b"wrong", "size_mismatch"), (None, "digest_mismatch")]
)
def test_corrupt_stream_never_published_and_can_resume(tmp_path, mutation, reason):
    manifest, audit, objects = fixture(tmp_path)
    original = dict(objects)
    key = next(iter(objects))
    objects[key] = mutation if mutation is not None else b"x" * len(objects[key])
    client = Client(objects)
    root = tmp_path / "staged"
    with pytest.raises(stage.StageError, match="incomplete"):
        stage.stage_manifest_from_s3(
            manifest, audit, root, bucket="test", client=client, workers=4
        )
    report = json.loads((root / "staging-summary.json").read_text())
    assert report["failure_reasons"] == {reason: 1}
    sample = load_training_manifest(manifest, "raw")[0]
    assert not (root / sample.relative_path).exists()
    assert not list(root.rglob(".stage-*"))
    assert client.active == 0
    objects.update(original)
    result = stage.stage_manifest_from_s3(
        manifest, audit, root, bucket="test", client=client, workers=4, resume=True
    )
    assert result["passed"]
    assert result["reused_files_this_run"] == 7
    assert result["downloaded_bytes_this_run"] == len(original[key])


def test_disk_full_stops_scheduling_and_does_not_claim_complete(tmp_path, monkeypatch):
    manifest, audit, objects = fixture(tmp_path, count=20)
    client = Client(objects)

    def no_space(path, chunks):
        next(chunks)
        raise OSError(errno.ENOSPC, "synthetic disk full")

    monkeypatch.setattr(stage, "_write_new_verified_file", no_space)
    with pytest.raises(stage.StageError, match="incomplete"):
        stage.stage_manifest_from_s3(
            manifest, audit, tmp_path / "staged", bucket="test", client=client, workers=4
        )
    report = json.loads((tmp_path / "staged/staging-summary.json").read_text())
    assert report["abort_reason"] == "write_error:ENOSPC"
    assert report["checked_this_run"] == 1
    assert client.calls <= 4
    assert client.active == 0


def test_closing_scheduler_drains_workers_before_lock_release(tmp_path, monkeypatch):
    manifest, _, objects = fixture(tmp_path)
    samples = load_training_manifest(manifest, "raw")
    waiting = threading.Event()
    exited = threading.Event()

    def worker(sample, target, source, stop, reuse_root=None):
        if sample == samples[0]:
            assert waiting.wait(10)
            return stage._Outcome(sample)
        waiting.set()
        assert stop.wait(10)
        exited.set()
        raise stage._Cancelled()

    monkeypatch.setattr(stage, "_stage_one", worker)
    root = tmp_path / "staged"
    with stage._staging_lock(root):
        results = stage._stage_outcomes(
            samples, [root / str(i) for i in range(8)], S3ByteSource("test", Client(objects)), 2
        )
        next(results)
        results.close()
        assert exited.is_set()
    with stage._staging_lock(root):
        pass


@pytest.mark.parametrize("workers", [0, -1, 33])
def test_invalid_workers_do_not_start_downloads(tmp_path, workers):
    manifest, audit, objects = fixture(tmp_path)
    client = Client(objects)
    with pytest.raises(stage.StageError, match="workers"):
        stage.stage_manifest_from_s3(
            manifest, audit, tmp_path / "staged", bucket="test", client=client, workers=workers
        )
    assert client.calls == 0
