"""Verify and replay the published layout using synthetic objects and audit jobs."""

import base64
import gzip
from hashlib import sha256
import json

from botocore.exceptions import ClientError
import pytest

from malweave import cli
from malweave.data import dataset_audit, dataset_storage
from malweave.data.s3_layout import INVENTORY, RAW_PREFIX, RAWMAL_LABELS, sharded_key
from malweave.data.storage_io import DataError
from tests.data.test_dataset_audit import FakeS3, _pe_bytes


class PublishedBucket(FakeS3):
    def __init__(self, dataset, payload):
        source = sha256(payload).hexdigest()
        self.raw_key = sharded_key(RAW_PREFIX, source)
        inventory = (
            f'sha256,s3_key,size,etag\n{source},{self.raw_key},{len(payload)},"""etag-0"""\n'
        ).encode()
        objects = {self.raw_key: payload, **dict.fromkeys(dataset_storage.CORE, b"synthetic\n")}
        objects[INVENTORY] = inventory
        if dataset == "rawmal":
            objects[RAWMAL_LABELS] = b"synthetic labels"
        hashes = {key: sha256(objects[key]).hexdigest() for key in dataset_storage.CORE}
        objects["dataset.json"] = json.dumps(
            {"dataset": dataset, "phase": "verified", "digests": hashes, "audit_evidence": {}}
        ).encode()
        super().__init__(objects)
        self.writes = []

    def head_object(self, *, Key, ExpectedBucketOwner, ChecksumMode, **_):
        assert ExpectedBucketOwner == "123456789012" and ChecksumMode == "ENABLED"
        contents = self.objects[Key]
        return {
            "ContentLength": len(contents),
            "ChecksumSHA256": base64.b64encode(sha256(contents).digest()).decode(),
        }

    def put_object(self, *, Key, Body, IfNoneMatch, ChecksumSHA256, ExpectedBucketOwner, **_):
        assert IfNoneMatch == "*" and ExpectedBucketOwner == "123456789012"
        if Key in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        content = Body.read()
        assert ChecksumSHA256 == base64.b64encode(sha256(content).digest()).decode()
        self.writes.append(Key)
        self.objects[Key] = content


@pytest.fixture
def bucket(monkeypatch):
    client = PublishedBucket("vera", _pe_bytes())
    monkeypatch.setattr(dataset_storage, "_client", lambda profile: client)
    monkeypatch.setattr(dataset_audit, "_s3_client", lambda profile: client)
    return client


def test_cli_fetch_run_export_publish_and_resume_on_another_path(bucket, tmp_path, capsys):
    inputs = tmp_path / "inputs"
    assert (
        cli.main(
            ["data", "dataset-storage", "fetch", "--dataset", "vera", "--output-dir", str(inputs)]
        )
        == 0
    )
    inventory = inputs / "inventory.csv"
    assert inventory.read_bytes() == bucket.objects["inventory.csv"]
    assert (inputs / "dataset.json").is_file()

    sample = bucket.raw_key.rsplit("/", 1)[-1]
    first, second = tmp_path / "selection.txt", tmp_path / "restored-selection.txt"
    first.write_text(sample + "\n")
    second.write_text(first.read_text())
    job = tmp_path / "vera-native-review"
    run = [
        "data",
        "dataset-audit",
        "run",
        "--dataset",
        "vera",
        "--job-dir",
        str(job),
        "--workers",
        "1",
        "--inventory",
        str(inventory),
        "--sha-list",
    ]
    assert cli.main([*run, str(first)]) == 0
    assert cli.main([*run, str(second)]) == 0
    assert cli.main(["data", "dataset-audit", "export", "--job-dir", str(job)]) == 0
    assert (job / "native-dotnet.csv").is_file()

    path = "audit/jobs/vera-native-review/state.sqlite3"
    publish = [
        "data",
        "dataset-storage",
        "publish-audit",
        "--dataset",
        "vera",
        "--job-dir",
        str(job),
    ]
    capsys.readouterr()
    assert cli.main(publish) == 0
    assert json.loads(capsys.readouterr().out)["key"] == path
    assert cli.main(publish) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "already_published"
    assert bucket.writes == [path]

    bucket.objects[path] = b"someone else's evidence"
    assert cli.main(publish) == 2
    assert bucket.objects[path] == b"someone else's evidence"


def test_artifact_download_is_bound_to_receipt_and_preserves_existing_file(bucket, tmp_path):
    inventory = dataset_storage.fetch_dataset("vera", tmp_path)["inventory"]
    before = inventory.read_bytes()
    _, manifest, packing, native = dataset_storage.CORE
    paths = dataset_storage.fetch_dataset(
        "vera", tmp_path, artifacts=("exe-manifest", "packing", "native-dotnet")
    )
    assert [p.relative_to(tmp_path).as_posix() for p in paths.values()] == [
        manifest,
        packing,
        native,
    ]
    receipt = json.loads(bucket.objects["dataset.json"])
    receipt["digests"]["inventory.csv"] = sha256(b"new expected content").hexdigest()
    bucket.objects["dataset.json"] = json.dumps(receipt).encode()
    bucket.objects["inventory.csv"] = b"corrupt content"
    with pytest.raises(DataError, match="checksum mismatch"):
        dataset_storage.fetch_dataset("vera", tmp_path)
    assert inventory.read_bytes() == before
    with pytest.raises(DataError, match="differs from the published release"):
        dataset_audit.run_dataset_audit(tmp_path / "blocked", "vera", inventory=inventory)
    with pytest.raises(DataError, match="checksum mismatch"):
        dataset_storage.verify_dataset("vera")


def test_rawmal_labels_use_the_shared_key(monkeypatch, tmp_path):
    client = PublishedBucket("rawmal", _pe_bytes())
    monkeypatch.setattr(dataset_storage, "_client", lambda profile: client)
    result = dataset_storage.fetch_dataset("rawmal", tmp_path, artifacts=("rawmal-labels",))
    label_path = result["rawmal-labels"]
    assert label_path.relative_to(tmp_path).as_posix() == RAWMAL_LABELS
    assert label_path.read_bytes() == client.objects[RAWMAL_LABELS]
    with pytest.raises(DataError, match="require --dataset rawmal"):
        dataset_storage.fetch_dataset("rands", tmp_path, artifacts=("rawmal-labels",))


def test_packing_publication_requires_verified_source_and_version(bucket, tmp_path):
    import sqlite3

    from malweave.data.dataset_die import SCHEMA
    from malweave.data.pe_assessment import DIEC_MODES

    source = bucket.raw_key.rsplit("/", 1)[-1]
    job = tmp_path / "vera-die-review"
    job.mkdir()
    with sqlite3.connect(job / "state.sqlite3") as db:
        db.executescript(SCHEMA)

        def set_contract(version):
            contract = {"dataset": "vera", "method": "dataset-die", "die_version": version}
            db.execute(
                "INSERT OR REPLACE INTO job VALUES ('contract', ?)", (json.dumps(contract),)
            )

        set_contract("4.0.0")
        db.execute(
            "INSERT INTO source VALUES (?, ?, ?, ?, ?, ?)",
            (
                source,
                "active",
                bucket.raw_key,
                len(bucket.objects[bucket.raw_key]),
                '"etag-0"',
                "{}",
            ),
        )
        db.execute(
            "INSERT INTO result VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                source,
                "tool_error",
                "unknown",
                0,
                1,
                b"evidence",
                "fixture",
            ),
        )
        db.execute(
            "INSERT INTO job VALUES ('release',?)",
            (json.dumps({"passed": True, "inventory_sources": 1}),),
        )
        evidence = gzip.compress(
            json.dumps(
                {
                    "source_sha256": source,
                    "input_sha256": source,
                    "source_hash_status": "verified",
                    "packing": {
                        "modes": dict.fromkeys(DIEC_MODES, "timeout"),
                        "reports": {mode: {"status": "timeout"} for mode in DIEC_MODES},
                    },
                }
            ).encode(),
            mtime=0,
        )
        db.execute(
            "UPDATE result SET evidence_gzip=?,evidence_sha256=?",
            (evidence, sha256(evidence).hexdigest()),
        )
        db.commit()
        with pytest.raises(DataError, match="uses DiE 3.21"):
            dataset_storage.publish_audit_job("vera", job)
        set_contract("3.21")
        db.execute("UPDATE source SET etag = 'old'")
        db.commit()
        with pytest.raises(DataError, match="differ from"):
            dataset_storage.publish_audit_job("vera", job)
        db.execute("UPDATE source SET etag = ?", ('"etag-0"',))
        db.execute("UPDATE result SET status = 'download_error'")
        db.commit()
        with pytest.raises(DataError, match="resolve source identity or download"):
            dataset_storage.publish_audit_job("vera", job)
        db.execute("UPDATE result SET status = 'tool_error', evidence_sha256='bad'")
        db.commit()
        with pytest.raises(DataError, match="evidence checksum mismatch"):
            dataset_storage.publish_audit_job("vera", job)
        db.execute("UPDATE result SET evidence_sha256=?", (sha256(evidence).hexdigest(),))
        db.commit()
        assert dataset_storage.publish_audit_job("vera", job)["key"] == (
            "audit/jobs/vera-die-review/state.sqlite3"
        )
