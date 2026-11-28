"""Exercise live worker scheduling and evidence using synthetic PEs."""

import csv
import gzip
from hashlib import sha256
import json
import sqlite3
import sys
from threading import Barrier

import pytest

from malweave.data import dataset_die as die
from malweave.data.storage_io import DataError
from tests.data.test_dataset_audit import FakeS3, _pe_bytes


class InventoryS3(FakeS3):
    def __init__(self, objects):
        super().__init__(objects)
        self.release_checks = 0
        self.missing_key = None
        self.on_get = None

    def get_paginator(self, operation):
        assert operation == "list_objects_v2"
        return self

    def paginate(self, *, Bucket, Prefix, ExpectedBucketOwner):
        assert Bucket == "private" and ExpectedBucketOwner == "123456789012"
        self.release_checks += 1
        for key, payload in self.objects.items():
            if key.startswith(Prefix) and key != self.missing_key:
                yield {"Contents": [{"Key": key, "Size": len(payload), "ETag": self.etags[key]}]}

    def get_object(self, **kwargs):
        if self.on_get:
            self.on_get()
        return super().get_object(**kwargs)


@pytest.fixture
def setup(monkeypatch, tmp_path):
    scanner = tmp_path / "diec"
    scanner.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys, time\n"
        "if '--version' in sys.argv:\n"
        "    print('fixture-die 3.21')\n"
        "else:\n"
        "    assert sys.argv[2] == '--json' and len(sys.argv) == 4\n"
        "    payload = pathlib.Path(sys.argv[3]).read_bytes()\n"
        "    mode = sys.argv[1]\n"
        "    code = payload[-1]\n"
        "    if code in (100, 101) and mode == '--deepscan': time.sleep(2)\n"
        "    detected = [{'type': 'Packer', 'name': 'fixture'}] if code in (1, 101) and mode == '--heuristicscan' else []\n"
        "    print(json.dumps({'detects': [{'filetype': 'PE', 'values': detected}]}))\n"
    )
    scanner.chmod(0o700)

    def make(codes, dataset="vera", *, canonical=False):
        prefix = "representations/raw/"
        rows, objects = [], {}
        for code in codes:
            payload = _pe_bytes() + bytes([code])
            digest = sha256(payload).hexdigest()
            key = prefix + digest[:2] + "/" + digest
            objects[key] = payload
            rows.append(
                {
                    "dataset": dataset,
                    "sha256": digest,
                    "key": key,
                    "size": len(payload),
                    "bucket": "private",
                    "label": "active" if dataset == "vera" else None,
                    "extra": {},
                }
            )
        client = InventoryS3(objects)
        pinned = [{**row, "etag": client.etags[row["key"]]} for row in rows]
        monkeypatch.setitem(die.RELEASES, dataset, len(rows))
        monkeypatch.setattr(
            die, "load_sources_csv", lambda name, inventory: ([dict(r) for r in pinned], {})
        )
        monkeypatch.setattr(die, "_s3_client", lambda profile=None: client)
        monkeypatch.setattr(die, "require_published_inventory", lambda *args, **kwargs: None)
        job = tmp_path / "job"

        def run(**kwargs):
            return die.run_dataset_die(job, dataset, die_command=str(scanner), **kwargs)

        return run, job, client, pinned, scanner

    return make


def test_sixteen_workers_each_download_once_and_keep_three_reports(setup):
    run, job, client, rows, _ = setup(range(17))
    counts = []
    barrier = Barrier(16, timeout=8)

    def downloads():
        if len(counts) < 16:
            counts.append(len(list(job.glob(".packing-pe-*.pe"))))
            barrier.wait()

    client.on_get = downloads
    first = run(limit=16)
    assert len(counts) == 16 and max(counts) == 16
    assert first["success"] == 16 and first["pending"] == 1
    assert first["packing_states"] == {"not_detected": 15, "obfuscated": 1}
    assert len(client.calls) == 16
    assert not list(job.glob(".packing-pe-*.pe"))
    with pytest.raises(DataError, match="still pending"):
        die.export_dataset_die(job, job.parent / "partial.csv")

    client.on_get = None
    second = run()
    assert second["completed"] == second["success"] == 17 and second["pending"] == 0
    assert len(client.calls) == 17 and client.release_checks == 1
    assert run()["completed"] == 17 and len(client.calls) == 17
    with sqlite3.connect(job / "state.sqlite3") as db:
        for blob, checksum in db.execute("SELECT evidence_gzip, evidence_sha256 FROM result"):
            assert sha256(blob).hexdigest() == checksum
            evidence = json.loads(gzip.decompress(blob))
            assert evidence["source_hash_status"] == "verified"
            reports = evidence["packing"]["reports"]
            assert set(reports) == set(die.DIEC_MODES)
            for mode, report in reports.items():
                assert report["command"][1:3] == [f"--{mode}scan", "--json"]
                assert report["status"] == "success"
            assert len({report["command"][-1] for report in reports.values()}) == 1
    out = job.parent / "packing.csv"
    assert die.export_dataset_die(job, out)["rows"] == 17
    with out.open(newline="") as stream:
        records = list(csv.DictReader(stream))
    assert {r["sha256"] for r in records} == {r["sha256"] for r in rows}
    assert all(r["deep_status"] == "success" for r in records)
    with pytest.raises(DataError, match="new .csv"):
        die.export_dataset_die(job, out)


@pytest.mark.parametrize("dataset", ["rands", "vera", "rawmal", "assemblage"])
def test_canonical_inventory_uses_new_prefix_and_resumes(setup, dataset):
    run, job, client, rows, _ = setup([0, 1], dataset)
    assert run(limit=1)["pending"] == 1
    assert run()["completed"] == 2
    assert client.release_checks == 1
    assert {key for _, key in client.calls} == {row["key"] for row in rows}
    assert json.loads((job / "tools.json").read_text())["raw_prefix"] == "representations/raw/"


def test_older_job_contract_is_rejected(setup):
    run, job, client, _, _ = setup([0, 1])
    assert run(limit=1)["pending"] == 1
    with sqlite3.connect(job / "state.sqlite3") as db:
        contract = json.loads(
            db.execute("SELECT value FROM job WHERE key='contract'").fetchone()[0]
        )
        contract.pop("raw_prefix")
        db.execute(
            "UPDATE job SET value=? WHERE key='contract'", (json.dumps(contract, sort_keys=True),)
        )
    with pytest.raises(DataError, match="inventory or scanner identity changed"):
        run()
    assert client.release_checks == 1
    assert len(client.calls) == 1


def test_timeout_unknown_positive_and_bad_hash_keep_distinct_evidence(setup, monkeypatch):
    run, job, client, rows, _ = setup([0, 100, 101, 1])
    monkeypatch.setattr(die, "TIMEOUT_SECONDS", 1)
    key = rows[-1]["key"]
    changed = client.objects[key]
    client.objects[key] = changed[:-1] + b"\x09"
    summary = run(workers=2)
    assert summary["statuses"] == {"success": 1, "tool_error": 2, "hash_mismatch": 1}
    assert summary["packing_states"] == {"not_detected": 1, "unknown": 2, "obfuscated": 1}
    with sqlite3.connect(job / "state.sqlite3") as db:
        records = {
            sha: json.loads(gzip.decompress(blob))
            for sha, blob in db.execute("SELECT sha256, evidence_gzip FROM result")
        }
    assert records[rows[1]["sha256"]]["packing"]["reports"]["deep"]["status"] == "timeout"
    assert records[rows[2]["sha256"]]["packing"]["state"] == "obfuscated"
    assert "file" not in records[rows[-1]["sha256"]]
    assert not list(job.glob(".packing-pe-*.pe"))


@pytest.mark.parametrize("dataset", ["vera", "rands", "assemblage"])
def test_selected_scan_exports_only_requested_sources_and_records_timeout(
    setup, monkeypatch, dataset
):
    run, job, client, rows, _ = setup([0, 1, 2], dataset=dataset)
    options = []
    real_assess_packing = die.assess_packing

    def record_timeout(command, path, timeout):
        options.append(timeout)
        return real_assess_packing(command, path, timeout)

    monkeypatch.setattr(die, "assess_packing", record_timeout)
    selection = job.parent / "selection.txt"
    selection.write_text(rows[1]["sha256"] + "\n")
    result = run(sha_list=selection, timeout_per_mode=90)
    assert result["total"] == result["success"] == 1
    assert options == [90]
    assert [key for _, key in client.calls] == [rows[1]["key"]]
    assert json.loads((job / "tools.json").read_text())["timeout_per_mode_seconds"] == 90
    output = job.parent / "packing.csv"
    assert die.export_dataset_die(job, output)["rows"] == 1
    with output.open(newline="") as stream:
        assert [row["sha256"] for row in csv.DictReader(stream)] == [rows[1]["sha256"]]
    assert run(sha_list=selection, timeout_per_mode=90)["completed"] == 1
    with pytest.raises(DataError, match="identity changed"):
        run(sha_list=selection, timeout_per_mode=30)

    selection.write_text("0" * 64 + "\n")
    with pytest.raises(DataError, match="outside the packing inventory"):
        run(sha_list=selection, timeout_per_mode=90)
    assert len(client.calls) == 1


def test_release_mismatch_blocks_all_downloads_and_can_retry(setup):
    run, job, client, rows, _ = setup([0, 1], dataset="rawmal")
    client.missing_key = rows[0]["key"]
    with pytest.raises(DataError, match="release verification failed"):
        run()
    assert not client.calls
    reject = json.loads((job / "release-audit.json").read_text())
    assert reject["missing"] == 1 and not reject["passed"]

    client.missing_key = None
    labels = job.parent / "labels.csv"
    labels.write_text(
        "sha256,branch,type_labels,family_labels\n"
        + "\n".join(
            f"{row['sha256']},{branch},[],[]" for row, branch in zip(rows, ("type", "family"))
        )
        + "\n"
    )
    summary = run(labels_csv=labels, limit=1)
    assert set(summary["by_class"]) == {"type", "family"}
    assert summary["pending"] == 1 and client.release_checks == 2
    with pytest.raises(DataError, match="identity changed"):
        run()
    assert len(client.calls) == 1


def test_interrupted_job_preserves_committed_state_and_can_resume(setup, monkeypatch):
    run, job, client, rows, _ = setup([0, 1, 2])
    assert run(workers=1, limit=1)["completed"] == 1
    original = die._scan

    def stop(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(die, "_scan", stop)
    with pytest.raises(KeyboardInterrupt):
        run(workers=1)
    assert die.dataset_die_status(job)["completed"] == 1
    assert json.loads((job / "progress.json").read_text())["phase"] == "interrupted"
    monkeypatch.setattr(die, "_scan", original)
    assert run(workers=1)["completed"] == 3
    assert [key for _, key in client.calls].count(rows[0]["key"]) == 1


def test_retry_download_error_preserves_original_diagnosis(setup):
    run, job, client, _, _ = setup([0])
    client.offline = True
    assert run()["statuses"] == {"download_error": 1}
    client.offline = False
    assert run()["statuses"] == {"download_error": 1}
    assert run(retry_errors=True)["statuses"] == {"success": 1}
    with sqlite3.connect(job / "state.sqlite3") as db:
        assert db.execute("SELECT status FROM result_history").fetchall() == [("download_error",)]
        assert db.execute("SELECT status FROM result").fetchall() == [("success",)]
