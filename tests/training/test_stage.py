"""Synthetic staging concurrency, error-accounting and recovery regressions."""

import csv
import errno
from hashlib import sha256
import io
import json
from pathlib import Path
import subprocess
import sys

import pytest

from malweave.training import stage


@pytest.fixture
def inputs(tmp_path: Path):
    content = b"synthetic harmless bytes"
    digest = sha256(content).hexdigest()
    manifest = tmp_path / "split.csv"
    audit = tmp_path / "audit.json"
    row = {
        "source_sha256": digest,
        "label": "benign",
        "split": "train",
        "group_id": digest,
        "object_key": "synthetic/sample",
        "object_size": len(content),
        "object_etag": '"test"',
    }
    with manifest.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=row)
        writer.writeheader()
        writer.writerow(row)
    audit.write_text(
        json.dumps(
            {
                "inventory_audit_passed": True,
                "manifest": {"sha256": sha256(manifest.read_bytes()).hexdigest()},
            }
        )
    )

    class Client:
        calls = 0

        def get_object(self, **request):
            self.calls += 1
            return {"Body": io.BytesIO(content)}

    return manifest, audit, tmp_path / "staged", Client(), content


def test_output_lock_rejects_second_process_and_releases_after_error(tmp_path: Path):
    root = tmp_path / "staged"
    with pytest.raises(RuntimeError), stage._staging_lock(root):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    "from malweave.training.stage import _staging_lock; "
                    f"\nwith _staging_lock(Path({str(root)!r})): pass"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert result.returncode != 0
        assert "Another staging process" in result.stderr
        raise RuntimeError("synthetic interruption")
    with stage._staging_lock(root):
        assert not root.exists()


def test_staging_lock_blocks_downloads(inputs):
    manifest, audit, root, client, _ = inputs
    with (
        stage._staging_lock(root),
        pytest.raises(stage.StageError, match="Another staging process"),
    ):
        stage.stage_manifest_from_s3(manifest, audit, root, bucket="test", client=client)
    assert client.calls == 0
    assert stage.stage_manifest_from_s3(manifest, audit, root, bucket="test", client=client)[
        "passed"
    ]


@pytest.mark.parametrize("number", [errno.ENOSPC, errno.EDQUOT, errno.EIO, errno.EACCES])
def test_write_errno_and_current_run_progress(inputs, monkeypatch, capsys, number):
    manifest, audit, root, client, _ = inputs
    original = stage._write_new_verified_file

    def fail(path, content):
        raise OSError(number, "synthetic failure", "private-sample-path")

    monkeypatch.setattr(stage, "_write_new_verified_file", fail)
    with pytest.raises(stage.StageError, match="incomplete"):
        stage.stage_manifest_from_s3(manifest, audit, root, bucket="test", client=client)
    report = json.loads((root / "staging-summary.json").read_text())
    assert report["failure_reasons"] == {"write_error:" + errno.errorcode[number]: 1}
    output = capsys.readouterr().err
    assert "checked=1 verified=0 failed=1" in output
    assert "private-sample-path" not in output
    monkeypatch.setattr(stage, "_write_new_verified_file", original)
    stage.stage_manifest_from_s3(manifest, audit, root, bucket="test", client=client, resume=True)
    assert "checked=1 verified=1 failed=0" in capsys.readouterr().err
    calls = client.calls
    stage.stage_manifest_from_s3(manifest, audit, root, bucket="test", client=client, resume=True)
    assert client.calls == calls


@pytest.mark.parametrize("conflict", [False, True])
def test_destination_race_verifies_content_without_overwriting(inputs, monkeypatch, conflict):
    manifest, audit, root, client, content = inputs
    original = stage._write_new_verified_file

    def race(path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"conflicting bytes" if conflict else payload)
        original(path, payload)

    monkeypatch.setattr(stage, "_write_new_verified_file", race)
    if conflict:
        with pytest.raises(stage.StageError, match="incomplete"):
            stage.stage_manifest_from_s3(manifest, audit, root, bucket="test", client=client)
        report = json.loads((root / "staging-summary.json").read_text())
        assert report["failure_reasons"] == {"local_conflict": 1}
    else:
        assert stage.stage_manifest_from_s3(manifest, audit, root, bucket="test", client=client)[
            "passed"
        ]
    digest = sha256(content).hexdigest()
    assert (root / "dataset" / digest[:2] / digest).read_bytes() == (
        b"conflicting bytes" if conflict else content
    )
