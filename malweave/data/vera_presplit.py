"""Pre-split EXE/token dedup, preserving every source and state membership."""

from collections import Counter, defaultdict
import csv
from hashlib import sha256
import json
from pathlib import Path


def export_presplit(
    manifest: Path,
    eligibility: Path,
    token_results: Path,
    output: Path,
    *,
    non_temporal: bool = False,
) -> dict:
    """Require explicit admission evidence before RanDS-style ordered dedup.

    Eligibility is a reviewed per-source table, not inferred from EXE identity.
    A missing/unknown architecture or packing value blocks that source. Missing
    timestamps block representative selection, rather than inventing chronology.
    No temporal partition or undersampling is performed here.
    """

    def read(path):
        with path.open(newline="") as stream:
            return list(csv.DictReader(stream))

    rows = read(manifest)
    evidence = {}
    for row in read(eligibility):
        key = (row["dataset"], row["source_sha256"])
        if key in evidence:
            raise ValueError("Duplicate eligibility evidence")
        evidence[key] = row
    tokens = {}
    for row in read(token_results):
        if row["exe_sha256"] in tokens:
            raise ValueError("Duplicate token outcome")
        tokens[row["exe_sha256"]] = row
    sources = {}
    excluded = []
    members = defaultdict(list)
    stage_counts = Counter()
    for row in rows:
        key = (row["dataset"], row["source_sha256"])
        if key in sources:
            raise ValueError("Manifest must contain unique dataset/source membership")
        sources[key] = row
        e = evidence.get(key)
        reason = None
        if e is None or not e.get("evidence_reference"):
            reason = "missing_admission_evidence"
        elif e.get("assessment_status", "success") != "success":
            reason = "assessment_failed"
        elif e.get("admission_evidence_valid", "true") != "true":
            reason = "admission_evidence_invalid"
        elif e["arch"] != "I386":
            reason = "architecture_unknown" if not e["arch"] else "architecture_not_i386"
        elif e["packed"] != "false":
            reason = (
                "packing_obfuscated"
                if e.get("packing_state") == "obfuscated"
                else "packed"
                if e["packed"] == "true"
                else "packing_unknown"
            )
        elif not non_temporal and not e.get("timestamp_utc"):
            reason = "missing_representative_timestamp"
        if reason:
            excluded.append({"dataset": key[0], "source_sha256": key[1], "reason": reason})
        else:
            members[row["exe_sha256"]].append({**row, "timestamp_utc": e.get("timestamp_utc", "")})
    stage_counts["admitted_sources"] = sum(map(len, members.values()))

    def choose(group):
        if non_temporal:
            return min(group, key=lambda r: (r["source_sha256"], r["dataset"]))
        # UTC timestamps must be normalized by the eligibility exporter.
        return min(group, key=lambda r: (r["timestamp_utc"], r["source_sha256"], r["dataset"]))

    def reject(row, reason):
        excluded.append(
            {"dataset": row["dataset"], "source_sha256": row["source_sha256"], "reason": reason}
        )

    candidates = []
    lineage = {}
    for digest, group in sorted(members.items()):
        if len({r["label"] for r in group}) > 1:
            for row in group:
                reject(row, "conflicting_exe_labels")
            continue
        representative = choose(group)
        lineage[(representative["dataset"], representative["source_sha256"])] = group
        candidates.append(representative)
        for row in group:
            if row is not representative:
                reject(row, "same_label_exe_duplicate")
    stage_counts["exe_representatives"] = len(candidates)
    token_groups = defaultdict(list)
    for row in candidates:
        result = tokens.get(row["exe_sha256"])
        if result is None or result["status"] != "success":
            reject(row, "missing_or_failed_token_audit")
            continue
        digest = result["token_sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid audited token digest")
        token_groups[digest].append(row)
    selected, membership = [], []
    for digest, group in sorted(token_groups.items()):
        if len({r["label"] for r in group}) > 1:
            for row in group:
                reject(row, "conflicting_model_input_labels")
            continue
        representative = choose(group)
        selected.append({**representative, "model_input_sha256": digest})
        for row in group:
            if row is not representative:
                reject(row, "same_label_model_input_duplicate")
            for source in lineage[(row["dataset"], row["source_sha256"])]:
                membership.append(
                    {
                        "dataset": source["dataset"],
                        "source_sha256": source["source_sha256"],
                        "state": source["state"],
                        "model_input_sha256": digest,
                        "representative_source": representative["source_sha256"],
                    }
                )
    if len(selected) + len(excluded) != len(rows):
        raise ValueError("Source accounting mismatch")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, values, fields in (
        ("candidates.csv", selected, list(rows[0]) + ["timestamp_utc", "model_input_sha256"]),
        ("excluded.csv", excluded, ["dataset", "source_sha256", "reason"]),
        (
            "membership.csv",
            membership,
            ["dataset", "source_sha256", "state", "model_input_sha256", "representative_source"],
        ),
    ):
        with (output / name).open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(values)
        (output / name).chmod(0o600)
    summary = {
        "status": "presplit_only_not_training_release",
        "representative_policy": "source_digest" if non_temporal else "earliest_timestamp",
        "source_rows": len(rows),
        "stage_counts": dict(stage_counts),
        "selected": len(selected),
        "excluded_by_reason": dict(Counter(r["reason"] for r in excluded)),
        "split_assigned": False,
        "parent_overlap_disposition": "retain_and_report",
        "input_sha256": {
            name: sha256(path.read_bytes()).hexdigest()
            for name, path in (
                ("manifest", manifest),
                ("eligibility", eligibility),
                ("tokens", token_results),
            )
        },
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
