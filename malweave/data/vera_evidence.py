"""Verify restored Assemblage assessment evidence before cohort admission."""

from collections import Counter
import csv
import gzip
from hashlib import sha256
import json
from pathlib import Path
import sqlite3


def export_eligibility(
    vera_directory: Path, benign_directory: Path, contract_id: str, output: Path
) -> dict:
    """Require complete admission scans, retaining rejected/unknown source outcomes."""
    benign_audit = audit_assemblage_evidence(benign_directory, contract_id)
    summary = json.loads((vera_directory / "summary.json").read_text())
    if not summary["complete"] or summary["completed"] != summary["sources"]:
        raise ValueError("VERA admission must complete before cohort export")
    with sqlite3.connect(f"file:{vera_directory}/state.sqlite?mode=ro", uri=True) as db:
        vera = [json.loads(body) for (body,) in db.execute("SELECT body FROM results")]
    if len(vera) != summary["sources"] or len({r["source_sha256"] for r in vera}) != len(vera):
        raise ValueError("VERA admission source coverage mismatch")
    rows = []
    for row in vera:
        reference = Path(row["evidence_reference"])
        payload = reference.read_bytes()
        if sha256(payload).hexdigest() != row["evidence_sha256"]:
            raise ValueError("VERA admission evidence digest mismatch")
        evidence = json.loads(gzip.decompress(payload))
        if evidence["source"]["source_sha256"] != row["source_sha256"]:
            raise ValueError("VERA admission evidence source mismatch")
        valid = row["status"] == "success" and evidence.get("source_digest_verified", False)
        rows.append(
            {
                "dataset": "vera",
                "source_sha256": row["source_sha256"],
                "arch": row["arch"].upper() if valid and row["arch"] != "unknown" else "",
                "packed": _packing_flag(row["packing"], valid),
                "evidence_reference": str(reference),
                "timestamp_utc": "",
                "assessment_status": row["status"],
                "packing_state": row["packing"],
                "admission_evidence_valid": str(valid).lower(),
            }
        )
    for path in sorted((benign_directory / "records").glob("*.json.gz")):
        row = json.loads(gzip.decompress(path.read_bytes()))["row"]
        valid = row["assessment_status"] == "success" and all(
            row[mode + "_status"] == "success" for mode in ("recursive", "deep", "heuristic")
        )
        rows.append(
            {
                "dataset": "assemblage",
                "source_sha256": row["source_sha256"],
                "arch": (
                    row["architecture_file"].upper()
                    if valid and row["architecture_file"] != "unknown"
                    else ""
                ),
                "packed": _packing_flag(row["packing_state"], valid),
                "evidence_reference": str(path),
                "timestamp_utc": "",
                "assessment_status": row["assessment_status"],
                "packing_state": row["packing_state"],
                "admission_evidence_valid": str(valid).lower(),
            }
        )
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    with (output / "eligibility.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output / "eligibility.csv").chmod(0o600)
    report = {
        "status": "complete_admission_evidence_not_training_release",
        "source_rows": len(rows),
        "benign_audit": benign_audit,
        "vera_summary_sha256": sha256((vera_directory / "summary.json").read_bytes()).hexdigest(),
        "eligibility_sha256": sha256((output / "eligibility.csv").read_bytes()).hexdigest(),
    }
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def _packing_flag(state: str, valid: bool) -> str:
    if not valid:
        return ""
    return {"not_detected": "false", "obfuscated": "true"}.get(state, "")


def audit_assemblage_evidence(directory: Path, contract_id: str) -> dict:
    """Read every complete report; missing, corrupt or inconsistent evidence blocks release."""
    contract = json.loads((directory / "contract.json").read_text())
    release = json.loads((directory / "release-audit.json").read_text())
    if (
        release["status"] != "passed_for_static_die_assessment"
        or release["inventory_sha256"] != contract["inventory_sha256"]
        or release["sources"] != contract["source_count"]
    ):
        raise ValueError("Assessment contract/release mismatch")
    seen = set()
    outcomes, architectures, packing = Counter(), Counter(), Counter()
    admitted = 0
    records_digest = sha256()
    for path in sorted((directory / "records").glob("*.json.gz")):
        payload = path.read_bytes()
        record = json.loads(gzip.decompress(payload))
        row, evidence = record["row"], record["evidence"]
        source = row["source_sha256"]
        if (
            record["contract_id"] != contract_id
            or path.name != source + ".json.gz"
            or source in seen
            or evidence["source_sha256"] != source
            or evidence["input_sha256"] != source
            or evidence["source_metadata"]["source_sha256"] != source
            or row["label"] != "benign"
        ):
            raise ValueError("Assessment source/contract identity mismatch")
        seen.add(source)
        reports = evidence["packing"]["reports"]
        modes = evidence["packing"]["modes"]
        for mode in ("recursive", "deep", "heuristic"):
            if mode not in reports or mode not in modes:
                raise ValueError("Missing complete DiE mode evidence")
        if evidence["packing"]["state"] != row["packing_state"]:
            raise ValueError("Packing evidence/summary mismatch")
        outcomes[row["assessment_status"]] += 1
        architectures[row["architecture_file"]] += 1
        packing[row["packing_state"]] += 1
        admitted += int(
            row["assessment_status"] == "success"
            and row["architecture_file"] == "i386"
            and row["packing_state"] == "not_detected"
            and all(row[mode + "_status"] == "success" for mode in modes)
        )
        records_digest.update(source.encode("ascii") + bytes.fromhex(sha256(payload).hexdigest()))
    if len(seen) != contract["source_count"]:
        raise ValueError("Incomplete assessment source coverage")
    return {
        "status": "passed_restored_evidence_identity_and_coverage",
        "sources": len(seen),
        "assessment_status": dict(outcomes),
        "architecture": dict(architectures),
        "packing": dict(packing),
        "i386_negative_packing_sources": admitted,
        "records_digest": records_digest.hexdigest(),
        "contract_sha256": sha256((directory / "contract.json").read_bytes()).hexdigest(),
        "release_sha256": sha256((directory / "release-audit.json").read_bytes()).hexdigest(),
    }
