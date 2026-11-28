"""Read audit job state and export per-dataset results without accessing S3."""

from collections import Counter
from contextlib import contextmanager
import csv
import json
import os
from pathlib import Path
import sqlite3
from tempfile import NamedTemporaryFile

from ..training.contracts import _private_path
from .storage_io import DataError

METHOD = "native-dotnet"


def canonical_job_identity(identity: dict) -> dict:
    """Recognize prior metadata for the same classifier without editing its evidence."""
    if (
        identity.get("method") == "pe-full-file-dnfile-v2"
        and identity.get("pipeline_version") == "dataset-audit-v2"
        and identity.get("download_mode") == "full_file"
    ):
        identity = {
            **{
                k: v for k, v in identity.items() if k not in {"pipeline_version", "download_mode"}
            },
            "method": METHOD,
        }
    config = identity.get("config", {})
    if "sha_list_sha256" in config and "sha_list" in config:
        return {**identity, "config": {k: v for k, v in config.items() if k != "sha_list"}}
    return identity


_CSV_FIELDS = (
    "dataset",
    "sha256",
    "source_label",
    "size_bytes",
    "machine",
    "optional_header_magic",
    "pe32_plus",
    "clr_present",
    "status",
    "label",
    "reason",
    "bytes_downloaded",
)


@contextmanager
def read_audit_state(job_dir: Path):
    """Use one read-only snapshot for all queries in a report or export."""
    path = (job_dir / "state.sqlite3").resolve()
    if not path.is_file():
        raise DataError(f"no audit database under {job_dir}")
    db = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        yield db
    finally:
        db.close()


def _summary(db: sqlite3.Connection) -> dict:
    job = dict(db.execute("SELECT key, value FROM job"))
    if "identity" not in job:
        raise DataError("audit database has no job identity")
    identity = canonical_job_identity(json.loads(job["identity"]))
    labels: Counter = Counter()
    reasons: Counter = Counter()
    statuses: Counter = Counter()
    counts = {
        "awaiting": 0,
        "finalized": 0,
        "retryable_errors": 0,
        "version_mismatches": 0,
        "clr_present": 0,
        "bytes_downloaded": 0,
    }
    total = 0
    for status, label, reason, clr, count, transferred in db.execute(
        """
        SELECT r.status, r.label, r.reason, r.clr_present, COUNT(*),
               COALESCE(SUM(r.bytes_downloaded), 0)
        FROM source s LEFT JOIN result r ON r.sha256 = s.sha256
        GROUP BY 1, 2, 3, 4
        """
    ):
        total += count
        counts["bytes_downloaded"] += transferred
        if status:
            statuses[status] += count
        if label:
            labels[label] += count
        if reason:
            reasons[reason] += count
        if clr == 1:
            counts["clr_present"] += count
        if status == "version_mismatch":
            counts["version_mismatches"] += count
        elif status == "transport_error":
            counts["retryable_errors"] += count
        elif status == "success" and label:
            counts["finalized"] += count
        else:
            counts["awaiting"] += count
    return {
        "dataset": identity["dataset"],
        "method": METHOD if identity["method"] == METHOD else "historical-audit",
        "total": total,
        "pending": total - counts["finalized"],
        **counts,
        "by_label": dict(labels),
        "by_reason": dict(reasons),
        "by_status": dict(statuses),
        "excluded": identity.get("excluded", {}),
        "versions": {
            "pefile": identity.get("pefile_version"),
            "dnfile": identity.get("dnfile_version"),
            "python": identity.get("python_version"),
        },
    }


def summarize(job_dir: Path) -> dict:
    with read_audit_state(job_dir) as db:
        return _summary(db)


def audit_status(job_dir: Path) -> str:
    summary = summarize(job_dir)
    progress = job_dir / "progress" / "progress.json"
    if progress.is_file():
        current_run = json.loads(progress.read_text())
        current_run.pop("stage", None)
        summary["current_run"] = current_run
    return json.dumps(summary, indent=2, sort_keys=True)


def export_dataset_audit(job_dir: Path, output: Path) -> dict:
    """Publish a complete CSV without replacing an existing file or changing the job."""
    output = output.expanduser()
    _private_path(output, "dataset audit CSV")
    if output.suffix.lower() != ".csv":
        raise DataError("dataset audit export requires a .csv output")
    if output.exists():
        raise DataError(f"audit CSV already exists: {output}")

    with read_audit_state(job_dir) as db:
        summary = _summary(db)
        if summary["pending"]:
            raise DataError(f"audit job is incomplete: {summary['pending']} unresolved sources")
        output.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            prefix=".audit-",
            dir=output.parent,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            try:
                writer = csv.writer(stream, lineterminator="\n")
                writer.writerow(_CSV_FIELDS)
                for (
                    sha,
                    source_label,
                    size,
                    status,
                    label,
                    reason,
                    clr,
                    stage_a,
                    nbytes,
                ) in db.execute(
                    """
                    SELECT s.sha256, s.label, s.size, r.status, r.label, r.reason,
                           r.clr_present, r.stage_a, r.bytes_downloaded
                    FROM source s JOIN result r ON r.sha256 = s.sha256
                    ORDER BY s.sha256
                    """
                ):
                    evidence = json.loads(stage_a) if stage_a else {}
                    writer.writerow(
                        (
                            summary["dataset"],
                            sha,
                            source_label,
                            size,
                            evidence.get("machine"),
                            evidence.get("optional_header_magic"),
                            evidence.get("pe32_plus"),
                            clr,
                            status,
                            label,
                            reason,
                            nbytes,
                        )
                    )
                stream.flush()
                os.fsync(stream.fileno())
                try:
                    os.link(temporary, output)
                except FileExistsError as exc:
                    raise DataError(f"audit CSV already exists: {output}") from exc
            finally:
                temporary.unlink(missing_ok=True)

    return {"dataset": summary["dataset"], "rows": summary["total"], "output": str(output)}
