"""Metadata-only VERA label and exact-EXE audit; never assigns data splits."""

from collections import Counter, defaultdict
import csv
from hashlib import sha256
import json
from pathlib import Path


def audit_vera_timestamps(manifest: Path, output: Path, bucket: str, workers: int = 8) -> dict:
    """Resume static stored-evidence reads, retaining errors without assigning splits."""
    from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
    from datetime import datetime, timezone
    import gzip
    import sqlite3
    import time

    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError

    if workers < 1:
        raise ValueError("workers must be positive")
    with manifest.open(newline="") as stream:
        rows = {r["source_sha256"]: r for r in csv.DictReader(stream)}
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    identity = {"manifest_sha256": sha256(manifest.read_bytes()).hexdigest(), "bucket": bucket}
    contract = output / "contract.json"
    if contract.exists() and json.loads(contract.read_text()) != identity:
        raise ValueError("Timestamp audit inputs changed")
    contract.write_text(json.dumps(identity))
    db = sqlite3.connect(output / "state.sqlite")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS results (source TEXT PRIMARY KEY, body TEXT NOT NULL)")
    done = {r[0] for r in db.execute("SELECT source FROM results")}
    s3 = boto3.client(
        "s3",
        config=Config(
            connect_timeout=5,
            read_timeout=20,
            retries={"max_attempts": 3},
            max_pool_connections=workers,
        ),
    )
    now = int(time.time())

    def read(row):
        record = {
            "source_sha256": row["source_sha256"],
            "evidence_key": row["evidence_key"],
            "evidence_sha256": "",
            "timestamp_field": "lief.pe.header.time_date_stamp",
            "raw_value": "",
            "timestamp_utc": "",
            "validation_status": "missing",
            "error_type": "",
        }
        try:
            obj = s3.get_object(Bucket=bucket, Key=row["evidence_key"])["Body"]
            try:
                payload = obj.read()
            finally:
                obj.close()
            record["evidence_sha256"] = sha256(payload).hexdigest()
            if record["evidence_sha256"] != row["evidence_sha256"]:
                raise ValueError("Evidence digest mismatch")
            evidence = json.loads(gzip.decompress(payload))
            value = evidence.get("lief", {}).get("pe", {}).get("header", {}).get("time_date_stamp")
            record["raw_value"] = value if value is not None else ""
            if type(value) is int:
                record["timestamp_utc"] = datetime.fromtimestamp(value, timezone.utc).isoformat()
                record["validation_status"] = (
                    "zero" if value == 0 else "future" if value > now else "candidate_unverified"
                )
        except (
            BotoCoreError,
            ClientError,
            OSError,
            ValueError,
            TypeError,
            OverflowError,
        ) as error:
            record["validation_status"] = "failed"
            record["error_type"] = type(error).__name__
        return record

    pending = iter(row for source, row in rows.items() if source not in done)
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            active = {}
            while True:
                while len(active) < workers:
                    row = next(pending, None)
                    if row is None:
                        break
                    active[pool.submit(read, row)] = row
                if not active:
                    break
                finished, _ = wait(active, timeout=10, return_when=FIRST_COMPLETED)
                for future in finished:
                    active.pop(future)
                    record = future.result()
                    db.execute(
                        "INSERT INTO results VALUES (?, ?)",
                        (record["source_sha256"], json.dumps(record)),
                    )
                    db.commit()
                    done.add(record["source_sha256"])
                (output / "progress.json").write_text(
                    json.dumps(
                        {"completed": len(done), "sources": len(rows), "updated_unix": time.time()}
                    )
                )
    finally:
        values = [json.loads(r[0]) for r in db.execute("SELECT body FROM results ORDER BY source")]
        if values:
            with (output / "timestamps.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(values[0]))
                writer.writeheader()
                writer.writerows(values)
        summary = {
            "sources": len(rows),
            "completed": len(values),
            "statuses": dict(Counter(r["validation_status"] for r in values)),
            "complete": len(values) == len(rows),
            "split_assigned": False,
        }
        (output / "summary.json").write_text(json.dumps(summary, indent=2))
        db.close()
    return summary


def export_vera_audit(manifest: Path, labels: Path, output: Path) -> dict:
    """Account for every released occurrence and quarantine disagreeing sources."""
    with manifest.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    with labels.open(encoding="utf-8-sig", newline="") as stream:
        label_rows = list(csv.DictReader(stream))
    mapping = {}
    for row in label_rows:
        source = row["File Hash"].strip().lower()
        if source in mapping:
            raise ValueError("Duplicate label identity; resolve before audit export")
        mapping[source] = row["Classification"].strip()
    disagreements = {
        row["source_sha256"]
        for row in rows
        if mapping.get(row["source_sha256"], "").lower() != row["partition"].lower()
        and mapping.get(row["source_sha256"]) in {"Active", "Latent"}
    }
    inventory, excluded = [], []
    groups = defaultdict(list)
    for row in rows:
        source = row["source_sha256"]
        state = mapping.get(source, "MISSING")
        reasons = []
        if source in disagreements:
            reasons.append("folder_csv_disagreement")
        if state not in {"Active", "Latent"}:
            reasons.append("failed_analysis" if state == "Failed Analysis" else "missing_label")
        if row["status"] != "success":
            reasons.append("extraction_" + row["status"])
        inventory.append(
            {
                **row,
                "csv_classification": state,
                "label": "ransomware",
                "eligibility_status": "excluded"
                if reasons
                else "pending_timestamp_arch_packing_overlap_audit",
            }
        )
        excluded.extend({"source_sha256": source, "reason_code": reason} for reason in reasons)
        if not reasons:
            groups[row["representation_sha256"]].append((source, state))
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)

    def write(name, values, fields):
        with (output / name).open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(values)
        (output / name).chmod(0o600)

    write("inventory.csv", inventory, list(inventory[0]) if inventory else [])
    write("excluded.csv", excluded, ["source_sha256", "reason_code"])
    members = [
        {
            "source_sha256": source,
            "exe_representation_sha256": digest,
            "state": state,
            "state_conflict": len({s for _, s in group}) > 1,
        }
        for digest, group in groups.items()
        for source, state in sorted(set(group))
    ]
    write(
        "groups.csv",
        members,
        ["source_sha256", "exe_representation_sha256", "state", "state_conflict"],
    )
    summary = {
        "status": "partial_metadata_audit_not_training_release",
        "source_occurrences": len(rows),
        "unique_sources": len({row["source_sha256"] for row in rows}),
        "extraction_status_occurrences": dict(Counter(row["status"] for row in rows)),
        "unique_excluded_sources": len({row["source_sha256"] for row in excluded}),
        "unique_exclusions_by_reason": {
            reason: len({r["source_sha256"] for r in excluded if r["reason_code"] == reason})
            for reason in sorted({r["reason_code"] for r in excluded})
        },
        "candidate_unique_sources": len({m["source_sha256"] for m in members}),
        "candidate_unique_exe": len(groups),
        "candidate_shared_active_latent_exe_groups": sum(
            len({state for _, state in group}) > 1 for group in groups.values()
        ),
        "input_sha256": {
            "manifest": sha256(manifest.read_bytes()).hexdigest(),
            "labels": sha256(labels.read_bytes()).hexdigest(),
        },
        "output_sha256": {
            p.name: sha256(p.read_bytes()).hexdigest() for p in sorted(output.glob("*.csv"))
        },
        "pending": [
            "timestamp coverage",
            "architecture/packing",
            "Assemblage join",
            "parent exposure overlap",
            "final model-input dedup",
            "temporal policy",
        ],
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
