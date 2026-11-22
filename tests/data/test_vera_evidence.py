"""Redistributable synthetic restored-assessment evidence."""

import csv
import gzip
from hashlib import sha256
import json
import sqlite3

import pytest

from malweave.data.vera_evidence import audit_assemblage_evidence, export_eligibility


def evidence_fixture(root):
    (root / "records").mkdir()
    (root / "contract.json").write_text(
        json.dumps({"inventory_sha256": "inventory", "source_count": 1})
    )
    (root / "release-audit.json").write_text(
        json.dumps(
            {
                "status": "passed_for_static_die_assessment",
                "inventory_sha256": "inventory",
                "sources": 1,
            }
        )
    )
    source = "a" * 64
    record = {
        "contract_id": "contract",
        "row": {
            "source_sha256": source,
            "label": "benign",
            "architecture_file": "i386",
            "assessment_status": "success",
            "packing_state": "not_detected",
            "recursive_status": "success",
            "deep_status": "success",
            "heuristic_status": "success",
        },
        "evidence": {
            "source_sha256": source,
            "input_sha256": source,
            "source_metadata": {"source_sha256": source},
            "packing": {
                "state": "not_detected",
                "modes": {k: {} for k in ("recursive", "deep", "heuristic")},
                "reports": {k: {} for k in ("recursive", "deep", "heuristic")},
            },
        },
    }
    return root / "records" / (source + ".json.gz"), record


@pytest.mark.parametrize("fault", [None, "identity", "mode", "packing", "coverage"])
def test_restored_assessment_audit(tmp_path, fault):
    path, record = evidence_fixture(tmp_path)
    if fault == "identity":
        record["evidence"]["input_sha256"] = "b" * 64
    elif fault == "mode":
        record["evidence"]["packing"]["reports"].pop("deep")
    elif fault == "packing":
        record["evidence"]["packing"]["state"] = "unknown"
    if fault != "coverage":
        path.write_bytes(gzip.compress(json.dumps(record).encode()))
    if fault:
        with pytest.raises(ValueError):
            audit_assemblage_evidence(tmp_path, "contract")
    else:
        result = audit_assemblage_evidence(tmp_path, "contract")
        assert result["sources"] == 1
        assert result["i386_negative_packing_sources"] == 1


@pytest.mark.parametrize(
    ("architecture", "packing", "expected_arch", "expected_packed"),
    [
        ("i386", "not_detected", "I386", "false"),
        ("amd64", "not_detected", "AMD64", "false"),
        ("i386", "obfuscated", "I386", "true"),
        ("unknown", "unknown", "", ""),
    ],
)
def test_eligibility_requires_complete_verified_scan(
    tmp_path, architecture, packing, expected_arch, expected_packed
):
    benign = tmp_path / "benign"
    benign.mkdir()
    path, record = evidence_fixture(benign)
    record["row"]["architecture_file"] = architecture
    record["row"]["packing_state"] = packing
    record["evidence"]["packing"]["state"] = packing
    path.write_bytes(gzip.compress(json.dumps(record).encode()))
    vera = tmp_path / "vera"
    vera.mkdir()
    (vera / "summary.json").write_text(
        json.dumps({"complete": False, "completed": 0, "sources": 1})
    )
    with pytest.raises(ValueError, match="must complete"):
        export_eligibility(vera, benign, "contract", tmp_path / "out")
    (vera / "summary.json").write_text(
        json.dumps({"complete": True, "completed": 1, "sources": 1})
    )
    evidence = {"source": {"source_sha256": "b" * 64}, "source_digest_verified": True}
    evidence_path = vera / "evidence.json.gz"
    evidence_path.write_bytes(gzip.compress(json.dumps(evidence).encode()))
    row = {
        "source_sha256": "b" * 64,
        "evidence_reference": str(evidence_path),
        "evidence_sha256": sha256(evidence_path.read_bytes()).hexdigest(),
        "status": "success",
        "arch": architecture,
        "packing": packing,
    }
    with sqlite3.connect(vera / "state.sqlite") as db:
        db.execute("CREATE TABLE results (body TEXT)")
        db.execute("INSERT INTO results VALUES (?)", (json.dumps(row),))
    report = export_eligibility(vera, benign, "contract", tmp_path / "out")
    assert report["source_rows"] == 2
    with (tmp_path / "out/eligibility.csv").open() as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        assert row["arch"] == expected_arch
        assert row["packed"] == expected_packed
        assert row["packing_state"] == packing
        assert row["admission_evidence_valid"] == "true"
