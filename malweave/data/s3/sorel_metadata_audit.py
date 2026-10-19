"""Read-only, bounded SOREL metadata joins; never read malware bytes."""

from collections import Counter
import csv
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from pathlib import Path
import sqlite3
import time

from malweave.data.s3.inventory import S3InventoryError, validate_private_path
from malweave.data.s3.sorel import SOREL_BINARIES_PREFIX, SOREL_BUCKET, SOREL_SHA256_PATTERN

TAGS = (
    "adware",
    "flooder",
    "ransomware",
    "dropper",
    "spyware",
    "packed",
    "crypto_miner",
    "file_infector",
    "installer",
    "worm",
    "downloader",
)
FIELDS = ("is_malware", "rl_fs_t", "rl_ls_const_positives", *TAGS)


def digest(path: Path) -> str:
    """Hash an artifact without loading it into memory."""
    h = sha256()
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def audit_sorel_metadata(
    pilot: Path,
    pilot_summary: Path,
    metadata: Path,
    output: Path,
    summary: Path,
    *,
    count: int = 1000,
) -> dict:
    """Audit the first count ranked pilot sources, retaining missing/invalid joins."""
    started = time.monotonic()
    validate_private_path(output)
    validate_private_path(summary, summary=True)
    paths = (pilot, pilot_summary, metadata, output, summary)
    if len({p.resolve() for p in paths}) != len(paths):
        raise S3InventoryError("Inputs and outputs must have distinct paths.")
    if count < 1 or count > 10000:
        raise S3InventoryError("Count must be between 1 and 10000 for this bounded audit.")
    if output.exists() or summary.exists():
        raise S3InventoryError("Outputs exist; refusing to overwrite.")
    info = json.loads(pilot_summary.read_text())
    if digest(pilot) != info["manifest"]["sha256"]:
        raise S3InventoryError("Pilot digest differs from summary.")
    rows = []
    seen = set()
    with pilot.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        source_fields = list(reader.fieldnames or ())
        required = {
            "selection_order",
            "source_sha256",
            "bucket",
            "object_key",
            "object_size",
            "object_etag",
            "object_last_modified",
            "snapshot_id",
        }
        if set(source_fields) != required:
            raise S3InventoryError("Unexpected pilot schema.")
        total = 0
        for total, r in enumerate(reader, 1):
            sid = r["source_sha256"]
            if (
                None in r
                or any(v is None for v in r.values())
                or not SOREL_SHA256_PATTERN.fullmatch(sid)
                or sid in seen
                or int(r["selection_order"]) != total
                or r["bucket"] != SOREL_BUCKET
                or r["object_key"] != SOREL_BINARIES_PREFIX + sid
                or r["snapshot_id"] != info["source_snapshot_id"]
                or int(r["object_size"]) < 0
            ):
                raise S3InventoryError("Invalid pilot provenance or ordering.")
            seen.add(sid)
            if total <= count:
                rows.append(r)
    if total != info["manifest"]["rows"] or len(rows) != count:
        raise S3InventoryError("Pilot row count mismatch or insufficient selections.")
    statuses = Counter()
    issues = Counter()
    labels = Counter()
    splits = Counter()
    missing = Counter()
    nonzero = Counter()
    exported = []
    metadata_digest = digest(metadata)
    try:
        with sqlite3.connect(metadata.resolve().as_uri() + "?mode=ro", uri=True) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise S3InventoryError("SQLite quick_check failed; database may be incomplete.")
            columns = {r[1] for r in db.execute("PRAGMA table_info(meta)")}
            if not {"sha256", *FIELDS} <= columns:
                raise S3InventoryError("meta schema lacks required documented columns.")
            index_columns = []
            for index in db.execute("PRAGMA index_list(meta)"):
                name = index[1].replace('"', '""')
                index_columns.append([r[2] for r in db.execute(f'PRAGMA index_info("{name}")')])
            if not any(c and c[0] == "sha256" for c in index_columns):
                raise S3InventoryError("meta.sha256 needs an existing index for bounded joins.")
            query = "SELECT " + ",".join(f'"{f}"' for f in FIELDS)
            query += " FROM meta WHERE sha256 = ? LIMIT 2"
            for r in rows:
                hits = db.execute(query, (r["source_sha256"],)).fetchall()
                values = dict.fromkeys(FIELDS)
                errors = []
                utc = split = ""
                status = "missing" if not hits else "duplicate" if len(hits) > 1 else "matched"
                if len(hits) == 1:
                    values = dict(zip(FIELDS, hits[0]))
                    for field, value in values.items():
                        if value is None:
                            missing[field] += 1
                            errors.append(field + ":missing")
                        elif (
                            not isinstance(value, (int, float))
                            or not math.isfinite(value)
                            or value < 0
                            or (field == "is_malware" and value not in (0, 1))
                        ):
                            errors.append(field + ":invalid")
                    if not any(e.startswith("rl_fs_t:") for e in errors):
                        ts = values["rl_fs_t"]
                        try:
                            utc = datetime.fromtimestamp(ts, timezone.utc).isoformat()
                            split = (
                                "train"
                                if ts < 1543542570
                                else ("validation" if ts < 1547279640 else "test")
                            )
                        except (ValueError, OverflowError, OSError):
                            errors.append("rl_fs_t:invalid")
                    if not any(e.startswith("is_malware:") for e in errors):
                        labels[str(int(values["is_malware"]))] += 1
                        if values["is_malware"] == 0:
                            errors.append("unexpected_benign_binary")
                    for tag in TAGS:
                        if not any(e.startswith(tag + ":") for e in errors):
                            nonzero[tag] += int(values[tag] != 0)
                    if errors:
                        status = "invalid"
                statuses[status] += 1
                issues.update(errors)
                if split:
                    splits[split] += 1
                exported.append(
                    {
                        **r,
                        **values,
                        "metadata_join_status": status,
                        "audit_issues": ";".join(errors),
                        "first_seen_utc": utc,
                        "temporal_split": split,
                        **{
                            tag + "_present": (
                                ""
                                if len(hits) != 1 or any(e.startswith(tag + ":") for e in errors)
                                else int(values[tag] != 0)
                            )
                            for tag in TAGS
                        },
                    }
                )
    except sqlite3.Error as error:
        raise S3InventoryError(
            "Cannot audit SQLite: incomplete or invalid metadata database."
        ) from error
    if digest(metadata) != metadata_digest:
        raise S3InventoryError("Metadata database changed during audit.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(exported[0]))
        writer.writeheader()
        writer.writerows(exported)
    result = {
        "audit_scope": "Local listing plus authoritative metadata join; no PE-content audit",
        "schema_version": 1,
        "selected_rows": count,
        "statuses": dict(statuses),
        "passed": statuses["matched"] == count,
        "issues": dict(issues),
        "missing_fields_in_matched_rows": dict(missing),
        "label_counts": dict(labels),
        "temporal_split_counts": dict(splits),
        "tag_nonzero_counts": dict(nonzero),
        "tag_count_denominator": "Only uniquely joined rows with valid values for that tag",
        "pilot_sha256": info["manifest"]["sha256"],
        "source_snapshot_id": info["source_snapshot_id"],
        "metadata_sha256": metadata_digest,
        "metadata_schema": sorted(columns),
        "output_sha256": digest(output),
        "selected_compressed_bytes": sum(int(r["object_size"]) for r in rows),
        "sample_bytes_read": False,
        "live_s3_verified": False,
        "full_corpus_extraction_ready": False,
        "runtime_seconds": round(time.monotonic() - started, 3),
        "split_policy": "SOREL timestamp boundaries; no fitting or training performed",
    }
    summary.parent.mkdir(parents=True, exist_ok=True)
    with summary.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    return result
