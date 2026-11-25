"""Packing audits on full releases or explicit selections using the RanDS DiE checks."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import closing
import csv
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
from tempfile import NamedTemporaryFile
import time

from malweave.data.audit_reporting import read_audit_state
from malweave.data.dataset_audit import (
    OWNER,
    ObjectVersionMismatch,
    SourceDigestMismatch,
    _digest_rows,
    _s3_client,
    _sha_pattern_ok,
    _stream_full_file,
    load_sources_csv,
)
from malweave.data.pe_assessment import DIEC_MODES, assess_file, assess_packing
from malweave.data.rands_die import DiskProgress, _counts, _stop_signals
from malweave.data.rands_pe_assessment import _resolve_executable
from malweave.data.sorel_io import SorelError, digest, job_lock, json_write
from malweave.data.sorel_tools import rule_digest
from malweave.training.contracts import _private_path

RELEASES = {
    "rands": ("RanDS_PE_Dataset/dataset/", 215404),
    "vera": ("vera/zenodo-17904705-v1/binaries/", 38282),
    "rawmal": ("raw/", 78934),
    "assemblage": ("raw/", 86585),
}
TIMEOUT_SECONDS = 10
SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS job (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS source (
    sha256 TEXT PRIMARY KEY, label TEXT NOT NULL, s3_key TEXT NOT NULL,
    size INTEGER NOT NULL, etag TEXT NOT NULL, metadata TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS result (
    sha256 TEXT PRIMARY KEY REFERENCES source(sha256), status TEXT NOT NULL,
    packing TEXT NOT NULL, seconds REAL NOT NULL, bytes INTEGER NOT NULL,
    evidence_gzip BLOB NOT NULL, evidence_sha256 TEXT NOT NULL);
"""


def _load_inventory(dataset: str, labels_csv: Path | None) -> tuple[list[dict], str]:
    prefix, expected = RELEASES[dataset]
    rows, _ = load_sources_csv(dataset)
    keys = set()
    for row in rows:
        key = row["key"]
        if (
            key in keys
            or not key.startswith(prefix)
            or key.rsplit("/", 1)[-1] != row["sha256"]
            or not row["etag"]
            or row["size"] <= 0
        ):
            raise SorelError("Packing inventory has a duplicate key or invalid pinned source.")
        keys.add(key)
    if len(rows) != expected:
        raise SorelError(f"Expected {expected} sources in {dataset}; found {len(rows)}.")
    if labels_csv is not None:
        if dataset != "rawmal":
            raise SorelError("Task label CSV is supported for RawMal-TF.")
        with labels_csv.open(newline="", encoding="utf-8-sig") as file:
            labels = {}
            for row in csv.DictReader(file):
                sha = row["sha256"]
                if sha in labels:
                    raise SorelError("Duplicate SHA-256 in RawMal-TF task labels.")
                labels[sha] = row
        if labels.keys() != {row["sha256"] for row in rows}:
            raise SorelError("RawMal-TF task labels must cover the same inventory.")
        for row in rows:
            labels_row = labels[row["sha256"]]
            branch = labels_row["branch"]
            if branch not in {"type", "family"}:
                raise SorelError("RawMal-TF task label branch must be type or family.")
            row["label"] = branch
            row["extra"] = {
                **row["extra"],
                "type_labels": labels_row["type_labels"],
                "family_labels": labels_row["family_labels"],
            }
    return rows, prefix


def _check_release(client, rows: list[dict], prefix: str) -> dict:
    required = {row["key"]: (row["size"], row["etag"]) for row in rows}
    mismatches = 0
    for page in client.get_paginator("list_objects_v2").paginate(
        Bucket=rows[0]["bucket"], Prefix=prefix, ExpectedBucketOwner=OWNER
    ):
        for item in page.get("Contents", []):
            expected = required.pop(item["Key"], None)
            if expected is not None and expected != (item["Size"], item["ETag"]):
                mismatches += 1
    return {
        "passed": not required and not mismatches,
        "inventory_sources": len(rows),
        "missing": len(required),
        "identity_mismatches": mismatches,
        "by_source_label": dict(Counter(row["label"] or "unlabelled" for row in rows)),
    }


def _scan(client, row: dict, job: Path, die: str, file: str, timeout_per_mode: int) -> tuple:
    start = time.monotonic()
    evidence = {
        "source_sha256": row["sha256"],
        "source_label": row["label"],
        "s3_key": row["key"],
        "s3_etag": row["etag"],
        "source_hash_status": "not_checked",
        "packing": {"state": "unknown"},
    }
    status = "download_error"
    size = 0
    with NamedTemporaryFile(dir=job, prefix=".packing-pe-", suffix=".pe") as temporary:
        try:
            evidence["input_sha256"] = _stream_full_file(client, row, temporary)
        except SourceDigestMismatch as error:
            status = "hash_mismatch"
            evidence.update(error=str(error), source_hash_status="mismatch")
        except ObjectVersionMismatch as error:
            status = "version_mismatch"
            evidence["error"] = str(error)
        except OSError as error:
            evidence["error"] = str(error)
        else:
            temporary.flush()
            path = Path(temporary.name)
            evidence["source_hash_status"] = "verified"
            evidence["file"] = assess_file(file, path, TIMEOUT_SECONDS)
            packing = assess_packing(die, path, timeout_per_mode)
            evidence["packing"] = packing
            status = (
                "success"
                if evidence["file"]["status"] == "success"
                and all(outcome == "success" for outcome in packing["modes"].values())
                else "tool_error"
            )
        finally:
            size = temporary.tell()
    elapsed = time.monotonic() - start
    evidence.update(status=status, runtime_seconds=elapsed, downloaded_bytes=size)
    blob = gzip.compress(json.dumps(evidence, sort_keys=True).encode(), mtime=0)
    return (
        row["sha256"],
        status,
        evidence["packing"]["state"],
        elapsed,
        size,
        blob,
        sha256(blob).hexdigest(),
    )


def run_dataset_die(
    job: Path,
    dataset: str,
    *,
    workers: int = 16,
    limit: int | None = None,
    profile: str | None = None,
    die_command: str = "diec",
    labels_csv: Path | None = None,
    sha_list: Path | None = None,
    timeout_per_mode: int | None = None,
) -> dict:
    """Scan originals with a bounded queue and commit each completed attempt."""
    if dataset not in RELEASES:
        raise SorelError(f"Unsupported packing dataset: {dataset!r}.")
    if workers < 1 or (limit is not None and limit < 1):
        raise SorelError("Workers and limit must be positive.")
    _private_path(job, "dataset DiE job directory")
    timeout_per_mode = TIMEOUT_SECONDS if timeout_per_mode is None else timeout_per_mode
    if timeout_per_mode < 1:
        raise SorelError("DiE timeout per mode must be at least one second.")
    rows, prefix = _load_inventory(dataset, labels_csv)
    if sha_list is not None:
        requested = [line.strip() for line in sha_list.read_text().splitlines() if line.strip()]
        wanted = set(requested)
        if not wanted or len(wanted) != len(requested) or not all(map(_sha_pattern_ok, wanted)):
            raise SorelError("Pass a nonempty SHA list with unique lowercase SHA-256 values.")
        rows = [row for row in rows if row["sha256"] in wanted]
        if len(rows) != len(wanted):
            raise SorelError("The SHA list contains sources outside the packing inventory.")
    by_sha = {row["sha256"]: row for row in rows}
    die = _resolve_executable(die_command, "DiE")
    file = _resolve_executable("file", "file")
    tool = Path(die)
    version = subprocess.run(
        [die, "--version"], capture_output=True, text=True, check=True, timeout=10
    ).stdout.strip()
    contract = {
        "schema": 1,
        "method": "dataset-die",
        "dataset": dataset,
        "inventory_sha256": _digest_rows(rows),
        "die_version": version,
        "die_sha256": digest(tool),
        "rules_sha256": rule_digest(tool.parent / "db"),
        "file_sha256": digest(Path(file)),
        "protocol_sha256": digest(Path(__file__).with_name("pe_assessment.py")),
        "runner_sha256": digest(Path(__file__)),
        "modes": list(DIEC_MODES),
        "timeout_per_mode_seconds": timeout_per_mode,
    }
    encoded = json.dumps(contract, sort_keys=True)
    job = job.resolve()
    with job_lock(job), _stop_signals(), closing(sqlite3.connect(job / "state.sqlite3")) as db:
        job.chmod(0o700)
        db.executescript(SCHEMA)
        saved = db.execute("SELECT value FROM job WHERE key='contract'").fetchone()
        if saved and saved[0] != encoded:
            raise SorelError(
                "Packing inventory or scanner identity changed; choose a new job directory."
            )
        if saved is None:
            client = _s3_client(profile)
            release = _check_release(client, rows, prefix)
            json_write(job / "release-audit.json", release)
            if not release["passed"]:
                raise SorelError("S3 packing release verification failed; see release-audit.json.")
            with db:
                db.execute("INSERT INTO job VALUES ('contract', ?)", (encoded,))
                db.execute("INSERT INTO job VALUES ('release', ?)", (json.dumps(release),))
                db.executemany(
                    "INSERT INTO source VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (
                            r["sha256"],
                            r["label"] or "unlabelled",
                            r["key"],
                            r["size"],
                            r["etag"],
                            json.dumps(r["extra"], sort_keys=True),
                        )
                        for r in rows
                    ],
                )
        else:
            client = None
            release = json.loads(
                db.execute("SELECT value FROM job WHERE key='release'").fetchone()[0]
            )
            json_write(job / "release-audit.json", release)
        json_write(job / "tools.json", contract)
        for temporary in job.glob(".packing-pe-*.pe"):
            temporary.unlink()
        pending = db.execute(
            "SELECT s.sha256 FROM source s LEFT JOIN result r USING (sha256) "
            "WHERE r.sha256 IS NULL ORDER BY s.rowid LIMIT ?",
            (limit if limit is not None else -1,),
        ).fetchall()
        candidates = [by_sha[sha] for (sha,) in pending]
        disk_reserve = 1024**3 + sum(
            sorted((r["size"] for r in candidates), reverse=True)[:workers]
        )
        if candidates and shutil.disk_usage(job).free < disk_reserve:
            raise SorelError("Insufficient space for the active PE downloads and SQLite evidence.")

        progress = DiskProgress(job)
        counts = _counts(db)
        progress.emit(phase="scanning", workers=workers, **counts)
        last_update = time.monotonic()
        phase = "failed"
        try:
            if candidates and client is None:
                client = _s3_client(profile)
            with progress, ThreadPoolExecutor(max_workers=workers) as pool:
                sources = iter(candidates)
                active = set()

                def submit() -> None:
                    row = next(sources, None)
                    if row is not None:
                        active.add(
                            pool.submit(_scan, client, row, job, die, file, timeout_per_mode)
                        )

                for _ in range(min(workers, len(candidates))):
                    submit()
                while active:
                    ready, active = wait(active, timeout=5, return_when=FIRST_COMPLETED)
                    for future in ready:
                        with db:
                            db.execute(
                                "INSERT INTO result VALUES (?, ?, ?, ?, ?, ?, ?)", future.result()
                            )
                        submit()
                    if time.monotonic() - last_update >= 5:
                        progress.emit(phase="scanning", workers=workers, **_counts(db))
                        last_update = time.monotonic()
            phase = "complete" if _counts(db)["pending"] == 0 else "limited"
        except KeyboardInterrupt:
            phase = "interrupted"
            raise
        finally:
            summary = {"dataset": dataset, "method": "dataset-die", **_counts(db)}
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            progress.emit(phase=phase, workers=workers, **summary)
            json_write(job / "summary.json", summary)
        return summary


def dataset_die_status(job: Path) -> dict:
    with read_audit_state(job) as db:
        saved = db.execute("SELECT value FROM job WHERE key='contract'").fetchone()
        if saved is None or json.loads(saved[0]).get("method") != "dataset-die":
            raise SorelError("This directory has no verified dataset DiE job.")
        return {"dataset": json.loads(saved[0])["dataset"], "method": "dataset-die", **_counts(db)}


def export_dataset_die(job: Path, output: Path) -> dict:
    _private_path(output, "DiE export")
    if output.suffix != ".csv" or output.exists():
        raise SorelError("Pass a new .csv output path for the packing export.")
    status = dataset_die_status(job)
    if status["pending"]:
        raise SorelError(
            f"Packing export is incomplete: {status['pending']} sources still pending."
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with NamedTemporaryFile(
        dir=output.parent, mode="w", newline="", encoding="utf-8", suffix=".csv"
    ) as file:
        writer = csv.writer(file)
        writer.writerow(
            (
                "dataset",
                "sha256",
                "source_label",
                "status",
                "packing",
                *(f"{mode}_status" for mode in DIEC_MODES),
                "bytes_downloaded",
                "runtime_seconds",
                "evidence_sha256",
            )
        )
        with read_audit_state(job) as db:
            records = db.execute(
                "SELECT s.sha256,s.label,r.status,r.packing,r.bytes,r.seconds,"
                "r.evidence_gzip,r.evidence_sha256 FROM source s JOIN result r USING (sha256) "
                "ORDER BY s.rowid"
            )
            for sha, label, outcome, packing, size, seconds, blob, checksum in records:
                if sha256(blob).hexdigest() != checksum:
                    raise SorelError("Packing evidence checksum mismatch.")
                modes = json.loads(gzip.decompress(blob))["packing"].get("modes", {})
                writer.writerow(
                    (
                        status["dataset"],
                        sha,
                        label,
                        outcome,
                        packing,
                        *(modes.get(mode, "") for mode in DIEC_MODES),
                        size,
                        seconds,
                        checksum,
                    )
                )
                count += 1
        file.flush()
        os.fsync(file.fileno())
        try:
            os.link(file.name, output)
        except FileExistsError as error:
            raise SorelError("Packing export already exists.") from error
    return {"dataset": status["dataset"], "rows": count, "output": str(output)}
