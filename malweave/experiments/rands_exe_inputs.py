"""Stage leakage-checked EXE inputs from S3 for a frozen source split."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from typing import Any

from malweave.data.s3.client import S3ReadError, make_s3_client, read_s3_object
from malweave.data.s3.inventory import validate_private_path
from malweave.training.manifest import TrainingSample, load_training_manifest

EXE_SPLIT_FIELDS = (
    "split",
    "source_sha256",
    "label",
    "group_id",
    "representation",
    "representation_sha256",
    "relative_path",
    "object_size",
    "snapshot",
)


class RandsExeInputError(ValueError):
    """A frozen RAW split cannot safely be converted into EXE inputs."""


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _validate_source_contract(source_manifest: Path, source_summary: Path) -> str:
    manifest_digest = _digest(source_manifest)
    try:
        summary = json.loads(source_summary.read_text(encoding="utf-8"))
        passed = (
            summary.get("inventory_audit_passed") is True
            or summary.get("release_audit", {}).get("passed") is True
        )
        valid = passed and summary["manifest"]["sha256"] == manifest_digest
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise RandsExeInputError("Cannot validate the frozen source manifest.") from error
    if not valid:
        raise RandsExeInputError("Source inventory audit or manifest digest does not match.")
    return manifest_digest


def _write_representation(path: Path, content: bytes, digest: str) -> bool:
    if path.exists():
        if _digest(path) != digest:
            raise RandsExeInputError(
                "An existing EXE representation conflicts with extracted bytes."
            )
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".exe-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)
    return False


def _open_state(
    path: Path, settings: dict[str, str], samples: list[TrainingSample], *, resume: bool
) -> sqlite3.Connection:
    existed = path.exists()
    if existed != resume:
        raise RandsExeInputError(
            "Use --resume only with an existing EXE state DB; never overwrite extraction state."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS outcomes ("
        "source_sha256 TEXT PRIMARY KEY, split TEXT NOT NULL, label INTEGER NOT NULL, "
        "status TEXT NOT NULL, warnings TEXT NOT NULL, representation_sha256 TEXT NOT NULL, "
        "relative_path TEXT NOT NULL, output_size INTEGER NOT NULL, runtime_ms REAL NOT NULL)"
    )
    if resume:
        saved = dict(connection.execute("SELECT name, value FROM settings"))
        if saved != settings:
            connection.close()
            raise RandsExeInputError("EXE preparation settings changed; use a new state DB.")
    else:
        connection.executemany("INSERT INTO settings VALUES (?, ?)", settings.items())
        connection.commit()
    completed = {row[0] for row in connection.execute("SELECT source_sha256 FROM outcomes")}
    if not completed.issubset({sample.source_sha256 for sample in samples}):
        connection.close()
        raise RandsExeInputError("EXE state contains a source outside the frozen RAW manifest.")
    return connection


def _label_name(label: int) -> str:
    return "benign" if label == 0 else "ransomware"


def prepare_rands_exe_inputs(
    source_manifest: Path,
    source_summary: Path,
    bucket: str,
    prefix: str,
    representation_root: Path,
    state_path: Path,
    manifest_path: Path,
    summary_path: Path,
    *,
    snapshot: str,
    max_object_bytes: int = 2_147_483_648,
    resume: bool = False,
    limit: int | None = None,
    progress_every: int = 100,
    client: Any = None,
) -> dict[str, Any]:
    """Stage a frozen EXE cohort from S3 and publish its verified training manifest."""
    if limit is not None and limit < 1:
        raise RandsExeInputError("--limit must be positive.")
    if progress_every < 1:
        raise RandsExeInputError("--progress-every must be positive.")
    for path in (state_path, manifest_path, representation_root):
        validate_private_path(path)
    validate_private_path(summary_path, summary=True)
    if manifest_path.exists() or (summary_path.exists() and not resume):
        raise RandsExeInputError("EXE manifest or summary already exists; use new output paths.")
    if not bucket or not prefix.endswith("/") or max_object_bytes < 1:
        raise RandsExeInputError(
            "Bucket, slash-terminated EXE prefix, and size limit are required."
        )
    manifest_digest = _validate_source_contract(source_manifest, source_summary)
    samples = load_training_manifest(source_manifest, "raw")
    settings = {
        "source_manifest_sha256": manifest_digest,
        "bucket": bucket,
        "prefix": prefix,
        "representation_root": str(representation_root.expanduser().resolve()),
        "snapshot": snapshot,
        "source": "staged_s3_exe_bytes_v1",
    }
    connection = _open_state(state_path, settings, samples, resume=resume)
    client = make_s3_client() if client is None else client
    try:
        if resume:
            # Failed reads are retryable. Successful rows remain durable so resuming
            # never downloads the completed cohort again.
            with connection:
                connection.execute("DELETE FROM outcomes WHERE status != 'success'")
        completed = {row[0] for row in connection.execute("SELECT source_sha256 FROM outcomes")}
        pending = [sample for sample in samples if sample.source_sha256 not in completed]
        if limit is not None:
            pending = pending[:limit]
        for index, sample in enumerate(pending, start=1):
            started = time.perf_counter()
            key = f"{prefix}{sample.source_sha256[:2]}/{sample.source_sha256}.bin"
            digest = ""
            relative = ""
            size = 0
            warnings = ""
            status = "success"
            try:
                content, provenance = read_s3_object(
                    client, bucket, key, max_bytes=max_object_bytes
                )
                digest = provenance["sha256"]
                relative = f"exe/{sample.source_sha256[:2]}/{sample.source_sha256}.bin"
                _write_representation(representation_root / relative, content, digest)
                size = len(content)
            except S3ReadError:
                status = "s3_read_error"
            with connection:
                connection.execute(
                    "INSERT INTO outcomes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sample.source_sha256,
                        sample.split,
                        sample.label,
                        status,
                        warnings,
                        digest,
                        relative,
                        size,
                        (time.perf_counter() - started) * 1000,
                    ),
                )
            if index % progress_every == 0 or index == len(pending):
                total_done = connection.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0]
                print(
                    f"prepare-exe: completed={total_done} selected={len(samples)}",
                    file=sys.stderr,
                )
        rows = list(connection.execute("SELECT * FROM outcomes ORDER BY source_sha256"))
    finally:
        connection.close()

    statuses = Counter(row["status"] for row in rows)
    outcomes_by_split_label_status = Counter(
        (row["split"], _label_name(row["label"]), row["status"]) for row in rows
    )
    by_split_label: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        by_split_label[row["split"]][_label_name(row["label"])] += 1
    complete = len(rows) == len(samples)
    successful = [row for row in rows if row["status"] == "success"]
    groups: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in successful:
        groups[row["representation_sha256"]].append(row)
    conflicts = [group for group in groups.values() if len({row["label"] for row in group}) > 1]
    crossing = [group for group in groups.values() if len({row["split"] for row in group}) > 1]
    safe_groups = [group for group in groups.values() if len({row["split"] for row in group}) == 1]
    published_rows = [row for group in safe_groups for row in group]
    published_rows.sort(key=lambda row: (row["split"], row["label"], row["source_sha256"]))
    published_coverage = Counter((row["split"], row["label"]) for row in published_rows)
    required_coverage = {(sample.split, sample.label) for sample in samples}
    coverage_complete = all(published_coverage[key] > 0 for key in required_coverage)
    passed = complete and not conflicts and bool(published_rows) and coverage_complete
    summary: dict[str, Any] = {
        "operation": "prepare_rands_exe_inputs",
        "passed": passed,
        "source_manifest_sha256": manifest_digest,
        "bucket": bucket,
        "prefix": prefix,
        "selected": len(samples),
        "completed": len(rows),
        "successful": len(successful),
        "published": len(published_rows) if passed else 0,
        "statuses": dict(sorted(statuses.items())),
        "failed_samples_excluded": len(rows) - len(successful),
        "completed_by_split_and_label": {
            split: dict(sorted(counts.items())) for split, counts in sorted(by_split_label.items())
        },
        "outcomes_by_split_label_status": {
            split: {
                label: {
                    status: count
                    for (item_split, item_label, status), count in sorted(
                        outcomes_by_split_label_status.items()
                    )
                    if item_split == split and item_label == label
                }
                for label in ("benign", "ransomware")
            }
            for split in ("train", "validation", "test")
        },
        "exact_exe_groups": len(groups),
        "same_split_duplicate_groups_retained": sum(len(group) > 1 for group in safe_groups),
        "same_split_duplicate_samples_retained": sum(
            len(group) for group in safe_groups if len(group) > 1
        ),
        "cross_label_duplicate_groups": len(conflicts),
        "cross_split_duplicate_groups": len(crossing),
        "cross_split_samples_removed": sum(len(group) for group in crossing),
        "published_split_label_coverage_complete": coverage_complete,
        "representation_bytes": sum(row["output_size"] for row in successful),
        "runtime_seconds": round(sum(row["runtime_ms"] for row in rows) / 1000, 3),
    }
    if passed:
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=EXE_SPLIT_FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in published_rows:
            writer.writerow(
                {
                    "split": row["split"],
                    "source_sha256": row["source_sha256"],
                    "label": _label_name(row["label"]),
                    "group_id": row["representation_sha256"],
                    "representation": "exe",
                    "representation_sha256": row["representation_sha256"],
                    "relative_path": row["relative_path"],
                    "object_size": row["output_size"],
                    "snapshot": snapshot,
                }
            )
        payload = output.getvalue().encode("utf-8")
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(payload)
        summary["manifest"] = {
            "rows": len(published_rows),
            "bytes": len(payload),
            "sha256": sha256(payload).hexdigest(),
        }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not passed:
        reason = (
            "incomplete" if not complete else "duplicate leakage or split/label coverage conflict"
        )
        raise RandsExeInputError(f"EXE preparation {reason}; see the aggregate summary.")
    return summary
