"""Synthetic metadata joins, failure accounting, and read-only guarantees."""

import csv
from hashlib import sha256
import json
import sqlite3

import pytest

from malweave.data.s3.inventory import S3InventoryError
from malweave.data.s3.sorel_metadata_audit import FIELDS, audit_sorel_metadata


def fixture(tmp_path):
    pilot = tmp_path / "pilot.csv"
    fields = [
        "selection_order",
        "source_sha256",
        "bucket",
        "object_key",
        "object_size",
        "object_etag",
        "object_last_modified",
        "snapshot_id",
    ]
    with pilot.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(fields)
        for i in range(1, 5):
            w.writerow(
                [
                    i,
                    f"{i:064x}",
                    "sorel-20m",
                    f"09-DEC-2020/binaries/{i:064x}",
                    123,
                    "etag",
                    "date",
                    "snapshot",
                ]
            )
    info = tmp_path / "pilot.json"
    info.write_text(
        json.dumps(
            {
                "manifest": {"sha256": sha256(pilot.read_bytes()).hexdigest(), "rows": 4},
                "source_snapshot_id": "snapshot",
            }
        )
    )
    db = tmp_path / "meta.db"
    with sqlite3.connect(db) as c:
        c.execute(
            "CREATE TABLE meta (sha256 TEXT, " + ",".join(f'"{f}" REAL' for f in FIELDS) + ")"
        )
        c.execute("CREATE INDEX source_idx ON meta(sha256)")
        query = "INSERT INTO meta VALUES (" + ",".join("?" for _ in range(len(FIELDS) + 1)) + ")"
        c.execute(query, [f"{1:064x}", 1, 1543542570, 5, *([0] * 11)])
        c.execute(query, [f"{3:064x}", 1, 1547279640, 5, None, -1, *([2] * 9)])
        for _ in range(2):
            c.execute(query, [f"{4:064x}", 1, 1, 1, *([0] * 11)])
    return pilot, info, db


def test_join_retains_missing_invalid_duplicate_and_does_not_mutate_db(tmp_path):
    pilot, info, db = fixture(tmp_path)
    before = db.read_bytes()
    out = tmp_path / "output.csv"
    report = tmp_path / "report.json"
    result = audit_sorel_metadata(pilot, info, db, out, report, count=4)
    assert result["statuses"] == {"matched": 1, "missing": 1, "invalid": 1, "duplicate": 1}
    assert not result["passed"]
    assert db.read_bytes() == before
    with out.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 4
    assert rows[0]["temporal_split"] == "validation"
    assert rows[0]["packed_present"] == "0"
    assert rows[1]["is_malware"] == ""
    assert rows[2]["adware_present"] == ""
    assert rows[2]["flooder"] == "-1.0"
    assert rows[2]["temporal_split"] == "test"
    assert result["issues"]["adware:missing"] == 1
    assert result["sample_bytes_read"] is False
    with pytest.raises(S3InventoryError, match="overwrite"):
        audit_sorel_metadata(pilot, info, db, out, report, count=4)


def test_success_and_corrupt_db_or_pilot_produce_no_output(tmp_path):
    pilot, info, db = fixture(tmp_path)
    result = audit_sorel_metadata(
        pilot, info, db, tmp_path / "ok.csv", tmp_path / "ok.json", count=1
    )
    assert result["passed"]
    db.write_bytes(b"not a sqlite database")
    out = tmp_path / "bad.csv"
    with pytest.raises(S3InventoryError, match="SQLite"):
        audit_sorel_metadata(pilot, info, db, out, tmp_path / "bad.json", count=1)
    assert not out.exists()
    pilot.write_text("changed")
    with pytest.raises(S3InventoryError, match="digest"):
        audit_sorel_metadata(pilot, info, db, out, tmp_path / "bad.json", count=1)
