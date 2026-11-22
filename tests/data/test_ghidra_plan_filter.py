"""Plan filtering uses only synthetic retained evidence and never accesses raw samples."""

import csv
import json
from pathlib import Path
import sqlite3

import pytest

from malweave.data.ghidra_plan_filter import filter_plan
from malweave.data.sorel_io import SorelError


def inputs(root: Path):
    rows = [
        {
            "batch_id": "1",
            "priority": "1" if i < 4 else "2",
            "ordinal": str(i),
            "sha256": f"{i:064x}",
            "label": "benign" if i % 2 else "ransomware",
            "bytes": "100",
            "object_key": f"synthetic-{i}",
            "tier": "P1" if i < 4 else "P2",
        }
        for i in range(1, 6)
    ]
    plan = root / "input.csv"
    with plan.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    inventory = root / "inventory.sqlite"
    with sqlite3.connect(inventory) as db:
        db.execute("CREATE TABLE settings(name TEXT PRIMARY KEY,value TEXT)")
        db.executemany(
            "INSERT INTO settings VALUES (?,?)", [("complete", "1"), ("snapshot", "synthetic")]
        )
        db.execute(
            "CREATE TABLE objects(source_sha256 TEXT,object_key TEXT,size INTEGER,etag TEXT)"
        )
        db.executemany(
            "INSERT INTO objects VALUES (?,?,?,?)",
            [(r["sha256"], r["object_key"], 100, '"etag"') for r in rows],
        )
    evidence = root / "evidence.sqlite"
    with sqlite3.connect(evidence) as db:
        db.execute("CREATE TABLE results(source TEXT PRIMARY KEY,body BLOB)")
        for index, row in enumerate(rows[:4], 1):
            record = {
                "status": "success" if index != 3 else "failed",
                "source": {
                    "source_sha256": row["sha256"],
                    "object_key": row["object_key"],
                    "object_size": 100,
                    "object_etag": '"etag"',
                    "label": row["label"],
                },
                "source_digest_verification": "historical ETag pinned; not full source SHA verified",
                "pe": {
                    "data_directories": [
                        {
                            "type": "CLR_RUNTIME_HEADER",
                            "RVA": 8192 if index == 1 else 0,
                            "size": 72 if index == 1 else 0,
                        }
                    ]
                },
            }
            db.execute(
                "INSERT INTO results VALUES (?,?)", (row["sha256"], json.dumps(record).encode())
            )
    audit = root / "audit.json"
    audit.write_text(
        json.dumps(
            {
                "status": "passed_for_manifest_header_extraction",
                "inventory_complete": True,
                "sources": 5,
                "raw_bytes": 500,
                "snapshot": "synthetic",
            }
        )
    )
    return {
        "plan": plan,
        "evidence_db": evidence,
        "inventory_db": inventory,
        "release_audit": audit,
        "output_dir": root / "output",
        "expected_sources": 5,
        "batch_size": 1,
    }


def test_filter_excludes_before_priority_batches_and_accounts_for_every_source(tmp_path):
    args = inputs(tmp_path)
    result = filter_plan(**args)
    assert result["counts"] == {"included": 2, "excluded_dotnet": 1, "pending_review": 2}
    assert result["priorities"]["1"] == {"included": 1, "excluded_dotnet": 1, "pending_review": 1}
    with (args["output_dir"] / "batches.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert [row["priority"] for row in rows] == ["1", "2"]
    assert [row["batch_id"] for row in rows] == ["1", "2"]
    assert [row["sha256"] for row in rows] == [f"{i:064x}" for i in (2, 4)]
    assert result["batches"] == 2
    assert sum(result["counts"].values()) == 5


def test_resume_rebuilds_exports_without_reprocessing_and_rejects_policy_change(tmp_path):
    args = inputs(tmp_path)
    first = filter_plan(**args)
    second = filter_plan(**args, resume=True)
    assert first["plan_sha256"] == second["plan_sha256"]
    assert first["counts"] == second["counts"]
    with pytest.raises(SorelError, match="changed"):
        filter_plan(**{**args, "batch_size": 2}, resume=True)
    with pytest.raises(SorelError, match="fresh"):
        filter_plan(**args)


def test_failed_release_audit_does_not_create_output(tmp_path):
    args = inputs(tmp_path)
    args["release_audit"].write_text('{"status":"failed"}')
    with pytest.raises(SorelError, match="passing"):
        filter_plan(**args)
    assert not args["output_dir"].exists()


def test_mismatched_evidence_identity_is_pending_not_native_or_excluded(tmp_path):
    args = inputs(tmp_path)
    with sqlite3.connect(args["evidence_db"]) as db:
        source, payload = db.execute("SELECT source,body FROM results LIMIT 1").fetchone()
        record = json.loads(payload)
        record["source"]["object_etag"] = '"changed"'
        db.execute("UPDATE results SET body=? WHERE source=?", (json.dumps(record), source))
    result = filter_plan(**args)
    assert result["counts"]["excluded_dotnet"] == 0
    assert result["counts"]["pending_review"] == 3
