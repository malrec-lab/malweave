"""Rebuild a private RanDS batch plan from retained PE evidence, without rescanning."""

from __future__ import annotations

from collections import Counter
import csv
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import time

from malweave.data.pe_routing import MANAGED_POLICY, ROUTING_VERSION
from malweave.data.sorel_io import SorelError, digest, json_write


def evidence_decision(source: str, evidence: dict, original: dict, inventory: tuple) -> dict:
    """Use the retained CLR declaration, not names, class labels or summary claims."""
    result = {"decision": "pending_review", "reason": "missing_or_failed_pe_evidence"}
    if evidence.get("status") != "success":
        return result
    item = evidence.get("source", {})
    key, size, etag = inventory
    if (
        item.get("source_sha256") != source
        or item.get("object_key") != key
        or int(item.get("object_size", -1)) != size
        or item.get("object_etag") != etag
        or int(original["bytes"]) != size
        or original["object_key"] != key
        or item.get("label") != original["label"]
    ):
        return {**result, "reason": "evidence_source_identity_mismatch"}
    directories = evidence.get("pe", {}).get("data_directories", [])
    clr = [entry for entry in directories if entry.get("type") == "CLR_RUNTIME_HEADER"]
    if len(clr) != 1:
        return {**result, "reason": "missing_or_ambiguous_clr_evidence"}
    rva, size = clr[0].get("RVA"), clr[0].get("size")
    if type(rva) is not int or type(size) is not int or min(rva, size) < 0:
        return {**result, "reason": "invalid_clr_evidence"}
    result.update(
        clr_rva=rva,
        clr_size=size,
        source_digest_verification=evidence.get(
            "source_digest_verification", "historical_missing"
        ),
        header_sha256=evidence.get("header_sha256"),
    )
    if rva and size:
        result.update(decision="excluded_dotnet", reason="declared_clr_runtime_header")
    elif rva or size:
        result["reason"] = "incomplete_clr_declaration"
    else:
        result.update(decision="included", reason="no_declared_clr_in_retained_pe_evidence")
    return result


def filter_plan(
    *,
    plan: Path,
    evidence_db: Path,
    inventory_db: Path,
    release_audit: Path,
    output_dir: Path,
    batch_size: int = 100,
    byte_cap: int = 300 * 1024**2,
    expected_sources: int = 215404,
    resume: bool = False,
) -> dict:
    """Commit each source decision durably, then export all three disjoint outcomes.

    Input source identity is inherited from the retained evidence with its actual
    historical verification claim. This operation does not verify original PE SHA
    digests anew and never downloads or executes a source.
    """
    if not 1 <= batch_size <= 1000 or byte_cap <= 0:
        raise SorelError("Invalid batch limits.")
    audit = json.loads(release_audit.read_text())
    if (
        audit.get("status") != "passed_for_manifest_header_extraction"
        or not audit.get("inventory_complete")
        or audit.get("sources") != expected_sources
    ):
        raise SorelError("A passing full input release audit is required.")
    with plan.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    by_source = {row["sha256"]: row for row in rows}
    if len(rows) != expected_sources or len(by_source) != len(rows):
        raise SorelError("Plan must contain every audited source exactly once.")
    with sqlite3.connect(inventory_db.resolve().as_uri() + "?mode=ro", uri=True) as inventory:
        settings = dict(inventory.execute("SELECT name,value FROM settings"))
        if settings.get("complete") != "1" or settings.get("snapshot") != audit["snapshot"]:
            raise SorelError("Inventory is incomplete or belongs to another snapshot.")
        objects = {
            source: (key, size, etag)
            for source, key, size, etag in inventory.execute(
                "SELECT source_sha256,object_key,size,etag FROM objects"
            )
        }
    if set(objects) != set(by_source) or sum(x[1] for x in objects.values()) != audit["raw_bytes"]:
        raise SorelError("Plan/inventory/release membership or byte total mismatch.")
    contract = {
        "routing_policy": ROUTING_VERSION,
        "managed_policy": MANAGED_POLICY,
        "plan_sha256": digest(plan),
        "release_audit_sha256": digest(release_audit),
        "evidence_path": str(evidence_db.resolve()),
        "evidence_bytes": evidence_db.stat().st_size,
        "evidence_mtime_ns": evidence_db.stat().st_mtime_ns,
        "inventory_sha256": digest(inventory_db),
        "batch_size": batch_size,
        "byte_cap": byte_cap,
        "sources": expected_sources,
    }
    if output_dir.exists() and not resume:
        raise SorelError("Use a fresh output directory or explicitly resume.")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    contract_path = output_dir / "contract.private.json"
    if resume:
        if not contract_path.exists() or json.loads(contract_path.read_text()) != contract:
            raise SorelError("Filter inputs or policy changed; use a fresh output directory.")
    else:
        json_write(contract_path, contract)
    started = time.monotonic()
    with sqlite3.connect(output_dir / "state.sqlite") as state:
        state.execute(
            "CREATE TABLE IF NOT EXISTS decisions "
            "(source TEXT PRIMARY KEY, evidence_rowid INTEGER, body TEXT NOT NULL)"
        )
        last = state.execute("SELECT COALESCE(MAX(evidence_rowid),0) FROM decisions").fetchone()[0]
        processed = state.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        with sqlite3.connect(evidence_db.resolve().as_uri() + "?mode=ro", uri=True) as evidence:
            for rowid, source, body in evidence.execute(
                "SELECT rowid,source,body FROM results WHERE rowid>? ORDER BY rowid", (last,)
            ):
                if source not in by_source:
                    raise SorelError("Evidence contains a source outside the audited plan.")
                payload = body.encode() if isinstance(body, str) else bytes(body)
                record = evidence_decision(
                    source, json.loads(payload), by_source[source], objects[source]
                )
                record["evidence_sha256"] = sha256(payload).hexdigest()
                state.execute(
                    "INSERT INTO decisions VALUES (?,?,?)", (source, rowid, json.dumps(record))
                )
                processed += 1
                if processed % 100 == 0:
                    state.commit()
                    json_write(
                        output_dir / "progress.json",
                        {
                            "status": "filtering_retained_evidence",
                            "processed": processed,
                            "total": expected_sources,
                            "seconds_this_session": time.monotonic() - started,
                        },
                    )
        state.commit()
        decisions = {
            source: json.loads(body)
            for source, body in state.execute("SELECT source,body FROM decisions")
        }
        for source in set(by_source) - set(decisions):
            record = {"decision": "pending_review", "reason": "missing_pe_evidence"}
            state.execute("INSERT INTO decisions VALUES (?,NULL,?)", (source, json.dumps(record)))
            decisions[source] = record
        state.commit()
    if evidence_db.stat().st_mtime_ns != contract["evidence_mtime_ns"]:
        raise SorelError("Evidence changed during filtering; do not publish this plan.")
    counts, priorities, classes = Counter(), {}, {}
    exports = {}
    for decision in ("included", "excluded_dotnet", "pending_review"):
        selected = [row for row in rows if decisions[row["sha256"]]["decision"] == decision]
        counts[decision] = len(selected)
        path = output_dir / (decision + ".private.csv")
        fields = list(rows[0]) + ["decision", "reason", "evidence_sha256"]
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in selected:
                record = decisions[row["sha256"]]
                writer.writerow(
                    {**row, **{name: record.get(name, "") for name in fields if name not in row}}
                )
        exports[decision] = {"rows": len(selected), "sha256": digest(path)}
    for row in rows:
        decision = decisions[row["sha256"]]["decision"]
        priorities.setdefault(row["priority"], Counter())[decision] += 1
        classes.setdefault(row["label"], Counter())[decision] += 1
    included = [row for row in rows if decisions[row["sha256"]]["decision"] == "included"]
    included.sort(
        key=lambda row: (int(row["priority"]), int(row["batch_id"]), int(row["ordinal"]))
    )
    batch_id, ordinal, batch_bytes, priority = 0, 0, 0, None
    fields = list(rows[0]) + ["parent_batch_id", "parent_ordinal", "oversize_single"]
    jobs = []
    with (output_dir / "batches.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in included:
            size = int(row["bytes"])
            if (
                row["priority"] != priority
                or ordinal >= batch_size
                or batch_bytes + size > byte_cap
            ):
                batch_id += 1
                ordinal = batch_bytes = 0
                priority = row["priority"]
                jobs.append(
                    {
                        "batch_id": batch_id,
                        "priority": int(priority),
                        "tier": row["tier"],
                        "files": 0,
                        "input_bytes": 0,
                        "classes": {},
                    }
                )
            ordinal += 1
            batch_bytes += size
            writer.writerow(
                {
                    **row,
                    "batch_id": batch_id,
                    "ordinal": ordinal,
                    "parent_batch_id": row["batch_id"],
                    "parent_ordinal": row["ordinal"],
                    "oversize_single": int(size > byte_cap),
                }
            )
            job = jobs[-1]
            job["files"] += 1
            job["input_bytes"] += size
            job["classes"][row["label"]] = job["classes"].get(row["label"], 0) + 1
    summary = {
        "status": "completed",
        "managed_policy": MANAGED_POLICY,
        "sources": len(rows),
        "counts": dict(counts),
        "priorities": priorities,
        "classes": classes,
        "priority_assignment": "inherited; remove .NET before batching; no tier promotion or resampling",
        "source_digest_verification": "inherited from per-source historical evidence, not reverified",
        "exports": exports,
        "batches": len(jobs),
        "batch_size": batch_size,
        "byte_cap": byte_cap,
        "plan_sha256": digest(output_dir / "batches.csv"),
        "seconds_this_session": time.monotonic() - started,
    }
    json_write(
        output_dir / "manifest.private.json",
        {"contract": contract, "summary": summary, "batches": jobs},
    )
    json_write(output_dir / "summary.json", summary)
    json_write(output_dir / "progress.json", summary)
    for path in output_dir.iterdir():
        if path.is_file():
            path.chmod(0o600)
    return summary
