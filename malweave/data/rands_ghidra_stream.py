"""Audited RanDS DIS/DEC extraction with two bounded PE batches and durable results.

The DiE database is read only. Sixteen source workers each run DIS then DEC;
one downloader batch overlaps the active batch. Only this job's scratch is deleted.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from contextlib import closing
import csv
from dataclasses import asdict
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
from queue import Empty, Queue
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from malweave.data.dataset_config import RandsDatasetConfig
from malweave.data.pe_assessment import DIEC_MODES, _types
from malweave.data.rands import SHA256_PATTERN, load_rands_metadata
from malweave.data.rands_die import _download, _stop_signals
from malweave.data.rands_ghidra import (
    SCRIPT_ROOT,
    _extension,
    _ghidra_command,
    _normalizer,
    _script_digest,
    _terminate_process,
)
from malweave.data.s3_layout import RAW_PREFIX
from malweave.data.storage_io import DataError, atomic_bytes, digest, job_lock, json_write
from malweave.training.contracts import _private_path

VIEWS = ("dis", "dec")
SELECTION = "RanDS Arch=I386 and Packed=false; all three DiE modes valid, no obfuscation"


def _readonly(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")
    return db


def _decode_evidence(row: sqlite3.Row) -> dict[str, Any]:
    blob = row["evidence_gzip"]
    if not blob or sha256(blob).hexdigest() != row["evidence_sha256"]:
        raise DataError("DiE evidence checksum mismatch; repair the evidence before extraction.")
    try:
        evidence = json.loads(gzip.decompress(blob))
    except (OSError, ValueError, EOFError) as error:
        raise DataError("Invalid compressed DiE evidence.") from error
    if not isinstance(evidence, dict):
        raise DataError("Invalid DiE evidence object.")
    return evidence


def _admission(row: sqlite3.Row, metadata: dict[str, Any]) -> str:
    if metadata["arch"] != "I386":
        return "metadata_architecture"
    if metadata["packed"] is not False:
        return "metadata_packed"
    if row["packing"] is None:
        return "die_missing"
    evidence = _decode_evidence(row)
    if (
        evidence.get("source_sha256") != row["sha256"]
        or evidence.get("metadata") != metadata
        or evidence.get("s3_key") != row["s3_key"]
        or evidence.get("s3_etag") != row["etag"]
    ):
        raise DataError("DiE evidence does not match its audited source.")
    packing = evidence.get("packing", {})
    if packing.get("state") != row["packing"]:
        raise DataError("DiE packing summary conflicts with its evidence.")
    if row["packing"] == "obfuscated":
        return "die_obfuscated"
    if (
        row["packing"] != "not_detected"
        or evidence.get("source_hash_status") != "verified"
        or evidence.get("input_sha256") != row["sha256"]
        or packing.get("types")
        or packing.get("modes") != dict.fromkeys(DIEC_MODES, "success")
    ):
        return "die_unknown_or_failed"
    for mode in DIEC_MODES:
        record = packing.get("reports", {}).get(mode, {})
        report = record.get("report", {})
        detects = report.get("detects") if isinstance(report, dict) else None
        if (
            record.get("status") != "success"
            or record.get("returncode") != 0
            or not isinstance(detects, list)
            or not detects
            or not all(isinstance(d, dict) and isinstance(d.get("values"), list) for d in detects)
            or not any(d.get("filetype") in {"PE", "PE32", "PE32+", "PE64"} for d in detects)
            or _types(detects)
        ):
            return "die_invalid_negative"
    return "eligible"


def _select(db: sqlite3.Connection, die_job: Path, config: RandsDatasetConfig) -> dict[str, Any]:
    """Revalidate release, metadata, source inventory and complete admission evidence."""
    with closing(_readonly(die_job / "state.sqlite3")) as source:
        values = dict(source.execute("SELECT key,value FROM job"))
        contract = json.loads(values["contract"])
        audit = json.loads(values["release_audit"])
        if (
            not audit.get("passed")
            or audit.get("files") != config.expected.files
            or audit.get("labels") != config.expected.labels
            or audit.get("shards") != config.expected.shards
            or contract.get("dataset") != json.loads(json.dumps(asdict(config)))
            or contract.get("modes") != list(DIEC_MODES)
        ):
            raise DataError("DiE release audit/configuration does not match this RanDS release.")
        for name in (config.benign_csv, config.ransomware_csv):
            if digest(die_job / "metadata" / name) != audit["metadata_sha256"][name]:
                raise DataError("RanDS metadata changed since the DiE release audit.")
        metadata = load_rands_metadata(config, die_job / "metadata")
        inventory_digest = sha256(b"[")
        selection_digest = sha256()
        labels, shards, reasons = Counter(), set(), Counter()
        raw_prefix = contract.get("raw_prefix", "")
        if urlsplit(raw_prefix).path.strip("/") != RAW_PREFIX:
            raise DataError(
                "Use a RanDS DiE job from the canonical S3 layout for new Ghidra runs."
            )
        root_key = urlsplit(raw_prefix).path.lstrip("/")
        rows = source.execute(
            "SELECT s.*,r.packing,r.evidence_gzip,r.evidence_sha256 FROM source s "
            "LEFT JOIN result r ON s.sha256=r.sha256 ORDER BY s.rowid"
        )
        count = 0
        for row in rows:
            sha = row["sha256"]
            record = metadata.records.get(sha)
            if (
                not SHA256_PATTERN.fullmatch(sha)
                or record is None
                or json.loads(row["metadata"]) != record.__dict__
                or row["label"] != record.label
                or row["size"] != record.size_bytes
                or row["s3_key"] != f"{root_key}/{sha[:2]}/{sha}"
                or not row["etag"]
            ):
                raise DataError("Invalid source in the audited DiE inventory.")
            inventory_row = [
                row[k] for k in ("sha256", "label", "s3_key", "size", "etag", "metadata")
            ]
            inventory_digest.update((", " if count else "").encode())
            inventory_digest.update(json.dumps(inventory_row, sort_keys=True).encode())
            reason = _admission(row, record.__dict__)
            source_values = (
                sha,
                row["label"],
                row["s3_key"],
                row["size"],
                row["etag"],
                row["metadata"],
                row["evidence_sha256"],
                reason,
            )
            db.execute("INSERT INTO source VALUES (?,?,?,?,?,?,?,?)", source_values)
            selection_digest.update(json.dumps(source_values).encode())
            labels[record.label] += 1
            shards.add(sha[:2])
            reasons[reason] += 1
            count += 1
        inventory_digest.update(b"]")
        if (
            count != audit["files"]
            or dict(labels) != audit["labels"]
            or len(shards) != audit["shards"]
            or inventory_digest.hexdigest() != audit["source_list_sha256"]
        ):
            raise DataError("DiE source inventory no longer matches its release audit.")
        return {
            "selection": SELECTION,
            "source_count": count,
            "reasons": dict(reasons),
            "selection_sha256": selection_digest.hexdigest(),
            "die_contract_sha256": sha256(values["contract"].encode()).hexdigest(),
            "release_audit": audit,
            "prefix": raw_prefix,
        }


def _tools(headless: Path, script_root: Path) -> dict[str, Any]:
    if not headless.is_file() or not os.access(headless, os.X_OK):
        raise DataError("Pass an executable Ghidra support/analyzeHeadless launcher.")
    properties = headless.parent.parent / "Ghidra/application.properties"
    if not properties.is_file():
        raise DataError("Ghidra application.properties is missing; cannot identify the tool.")
    java_home = os.environ.get("JAVA_HOME")
    java = Path(java_home) / "bin/java" if java_home else Path(shutil.which("java") or "")
    if not java.is_file():
        raise DataError("Java is unavailable; configure JAVA_HOME for this Ghidra installation.")
    if not (java.parent / "javac").is_file():
        raise DataError(
            "Ghidra requires a full JDK; javac is missing from the configured Java home."
        )
    try:
        version = subprocess.run(
            [str(java), "-version"], capture_output=True, text=True, timeout=15, check=True
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DataError("Could not identify the configured Java runtime.") from error
    return {
        "headless": str(headless.resolve()),
        "launcher_sha256": digest(headless),
        "application_properties": properties.read_text(),
        "java": str(java.resolve()),
        "java_sha256": digest(java.resolve()),
        "java_version": version.stdout + version.stderr,
        "scripts": {view: _script_digest(script_root, view) for view in VIEWS},
        "distribution_sha256": _distribution_digest(headless.parent.parent),
    }


def _distribution_digest(root: Path) -> str:
    checksum = sha256()
    paths = sorted(set(root.glob("Ghidra/**/*.jar")) | set(root.glob("support/*.sh")))
    for path in paths:
        checksum.update(str(path.relative_to(root)).encode() + b"\0")
        checksum.update(digest(path).encode() + b"\0")
    return checksum.hexdigest()


def _connect(job: Path) -> sqlite3.Connection:
    db = sqlite3.connect(job / "state.sqlite3")
    db.row_factory = sqlite3.Row
    db.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS job (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS source (
            sha256 TEXT PRIMARY KEY, label TEXT NOT NULL, s3_key TEXT NOT NULL,
            size INTEGER NOT NULL, etag TEXT NOT NULL, metadata TEXT NOT NULL,
            die_evidence_sha256 TEXT, admission TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS result (
            sha256 TEXT NOT NULL REFERENCES source(sha256), view TEXT NOT NULL,
            status TEXT NOT NULL, seconds REAL NOT NULL, output_size INTEGER NOT NULL,
            output_sha256 TEXT, output_path TEXT, evidence_gzip BLOB NOT NULL,
            evidence_sha256 TEXT NOT NULL, PRIMARY KEY (sha256, view));
        CREATE TABLE IF NOT EXISTS transfer (
            id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL, status TEXT NOT NULL,
            bytes INTEGER NOT NULL, seconds REAL NOT NULL, evidence_gzip BLOB NOT NULL);
    """)
    return db


def _verify_outputs(db: sqlite3.Connection, job: Path) -> None:
    for row in db.execute("SELECT output_path,output_size,output_sha256 FROM result"):
        if row["output_path"] is None:
            continue
        path = job / row["output_path"]
        if (
            not path.resolve().is_relative_to(job)
            or not path.is_file()
            or path.stat().st_size != row["output_size"]
            or digest(path) != row["output_sha256"]
        ):
            raise DataError(
                "A committed representation is missing or changed; restore it before resume."
            )


def _summary(db: sqlite3.Connection) -> dict[str, Any]:
    selection = json.loads(db.execute("SELECT value FROM job WHERE key='selection'").fetchone()[0])
    contract = json.loads(db.execute("SELECT value FROM job WHERE key='contract'").fetchone()[0])
    eligible = db.execute("SELECT COUNT(*) FROM source WHERE admission='eligible'").fetchone()[0]
    complete = db.execute(
        "SELECT COUNT(*) FROM (SELECT sha256 FROM result GROUP BY sha256 HAVING COUNT(*)=2)"
    ).fetchone()[0]
    views = {}
    for view in VIEWS:
        statuses = dict(
            db.execute("SELECT status,COUNT(*) FROM result WHERE view=? GROUP BY status", (view,))
        )
        size, seconds = db.execute(
            "SELECT COALESCE(SUM(output_size),0),COALESCE(SUM(seconds),0) FROM result WHERE view=?",
            (view,),
        ).fetchone()
        views[view] = {
            "statuses": statuses,
            "completed": sum(statuses.values()),
            "success": statuses.get("success", 0),
            "failed": sum(n for s, n in statuses.items() if s != "success"),
            "output_bytes": size,
            "summed_seconds": round(seconds, 3),
            "by_class": {
                label: dict(
                    db.execute(
                        "SELECT r.status,COUNT(*) FROM result r JOIN source s USING(sha256) "
                        "WHERE r.view=? AND s.label=? GROUP BY r.status",
                        (view, label),
                    )
                )
                for label in ("benign", "ransomware")
            },
        }
    return {
        "selection": selection,
        "execution_mode": contract.get("execution_mode", "separate"),
        "eligible": eligible,
        "completed": complete,
        "pending": eligible - complete,
        "complete": eligible == complete,
        "representations": views,
        "downloaded_bytes": db.execute("SELECT COALESCE(SUM(bytes),0) FROM transfer").fetchone()[
            0
        ],
    }


def _emit(
    db: sqlite3.Connection, job: Path, started: float, phase: str, **extra: Any
) -> dict[str, Any]:
    result = {
        **_summary(db),
        "phase": phase,
        "workers": 16,
        "batch_size": 16,
        "prefetch_batches": 1,
        "updated_at_unix": time.time(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        **extra,
    }
    json_write(job / "progress.json", result)
    print(
        f"[rands-ghidra] {phase}: {result['completed']}/{result['eligible']} sources; "
        f"DIS {result['representations']['dis']['success']} successful, "
        f"DEC {result['representations']['dec']['success']} successful",
        file=sys.stderr,
        flush=True,
    )
    return result


class _Processes:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active: set[subprocess.Popen] = set()
        self.stopping = threading.Event()

    def run(self, command: list[str], root: Path, timeout: int, heap_mb: int) -> dict[str, Any]:
        env = dict(os.environ)
        home = root / "home"
        home.mkdir(mode=0o700)
        temporary = root / "tmp"
        temporary.mkdir(mode=0o700)
        properties = {
            "user.home": home,
            "java.io.tmpdir": temporary,
            "application.tempdir": temporary,
        }
        options = " ".join(
            f"-D{key}={json.dumps(str(path), ensure_ascii=False)}"
            for key, path in properties.items()
        )
        env["_JAVA_OPTIONS"] = env.get("_JAVA_OPTIONS", "") + f" -Xmx{heap_mb}m {options}"
        env["XDG_CONFIG_HOME"] = str(home / "config")
        env["XDG_CACHE_HOME"] = str(home / "cache")
        for key in ("TMPDIR", "TMP", "TEMP"):
            env[key] = str(temporary)
        if env.get("JAVA_HOME"):
            env["PATH"] = str(Path(env["JAVA_HOME"]) / "bin") + os.pathsep + env.get("PATH", "")
        record: dict[str, Any] = {"command": command, "heap_mb": heap_mb, "status": "launch_error"}
        with (root / "stdout").open("wb") as out, (root / "stderr").open("wb") as err:
            try:
                with self.lock:
                    if self.stopping.is_set():
                        raise InterruptedError("Runner is stopping.")
                    process = subprocess.Popen(
                        command, stdout=out, stderr=err, env=env, start_new_session=True
                    )
                    self.active.add(process)
                try:
                    process.wait(timeout=timeout)
                    record["status"] = "success" if process.returncode == 0 else "failed"
                except subprocess.TimeoutExpired:
                    _terminate_process(process)
                    record["status"] = "timeout"
                finally:
                    with self.lock:
                        self.active.discard(process)
                record["returncode"] = process.returncode
            except OSError as error:
                record["error"] = str(error)
        record["stdout"] = (root / "stdout").read_text(errors="replace")
        record["stderr"] = (root / "stderr").read_text(errors="replace")
        return record

    def stop(self) -> None:
        with self.lock:
            self.stopping.set()
            processes = tuple(self.active)
        for process in processes:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 10
        for process in processes:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()


def _stage(source: dict[str, Any], root: Path, bucket: str) -> dict[str, Any]:
    started = time.monotonic()
    path = root / source["sha256"]
    evidence: dict[str, Any] = {
        "source_sha256": source["sha256"],
        "s3_key": source["s3_key"],
        "s3_etag": source["etag"],
        "status": "download_error",
        "bytes": 0,
    }
    try:
        _download(f"s3://{bucket}/{source['s3_key']}", path, source["etag"])
        evidence["bytes"] = path.stat().st_size
        evidence["status"] = "size_mismatch"
        if path.stat().st_size != source["size"]:
            raise DataError("Staged PE size differs from the audited inventory.")
        evidence["input_sha256"] = digest(path)
        evidence["status"] = "hash_mismatch"
        if evidence["input_sha256"] != source["sha256"]:
            raise DataError("Staged PE hash differs from its source identity.")
        evidence["status"] = "verified"
    except (OSError, DataError) as error:
        evidence["error"] = str(error)
    evidence["seconds"] = time.monotonic() - started
    return evidence


def _download_batch(
    batch: list[dict[str, Any]], root: Path, bucket: str, events: Queue
) -> list[dict[str, Any]]:
    root.mkdir(mode=0o700)
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_stage, source, root, bucket): source for source in batch}
        for future in as_completed(futures):
            evidence = future.result()
            futures[future]["transfer"] = evidence
            events.put(("transfer", evidence))
    return batch


def _extract_view(
    source: dict[str, Any],
    view: str,
    batch_root: Path,
    job: Path,
    headless: Path,
    scripts: Path,
    processes: _Processes,
    heap_mb: int,
) -> dict[str, Any]:
    started = time.monotonic()
    sha = source["sha256"]
    root = batch_root / f"{sha}-{view}"
    root.mkdir(mode=0o700)
    project, output = root / "project", root / "output"
    project.mkdir()
    output.mkdir()
    file_timeout, function_timeout = (60, 30) if view == "dis" else (300, 60)
    command = _ghidra_command(
        analyze_headless=headless,
        representation=view,
        script_root=scripts,
        source_path=batch_root / sha,
        project_root=project,
        output_root=output,
        timeout_per_file_seconds=file_timeout,
        timeout_per_function_seconds=function_timeout,
        analysis_timeout_per_file_seconds=300,
        max_cpu=1,
    )
    execution = processes.run(command, root, 300 + file_timeout + 120, heap_mb)
    logs = execution["stdout"] + "\n" + execution["stderr"]
    status = "ghidra_" + execution["status"]
    if execution["status"] == "success":
        if "analysisTimeoutOccurred()=true" in logs or "run: finished (timeout)" in logs:
            status = "partial_timeout"
        elif "run: finished (crash)" in logs or "decompileFunction:" in logs:
            status = "partial_error"
        elif (
            f"run: finished (success) <{sha}>" not in logs
            or "analysisTimeoutOccurred()=false" not in logs
        ):
            status = "unconfirmed_completion"
        else:
            status = "success"
    result: dict[str, Any] = {
        "source_sha256": sha,
        "view": view,
        "status": status,
        "transfer": source["transfer"],
        "execution": execution,
        "die_evidence_sha256": source["die_evidence_sha256"],
        "output_size": 0,
        "output_sha256": None,
        "output_path": None,
    }
    _save_view_output(result, output / (sha + _extension(view)), job)
    result["seconds"] = time.monotonic() - started
    return result


def _save_view_output(result: dict[str, Any], raw: Path, job: Path) -> None:
    sha, view, status = result["source_sha256"], result["view"], result["status"]
    if raw.is_file():
        result["raw_output_sha256"] = digest(raw)
        try:
            normalized = _normalizer(view)(raw.read_bytes())
            if normalized:
                prefix = "representations" if status == "success" else "partial"
                relative = Path(prefix) / view / sha[:2] / (sha + _extension(view))
                destination = job / relative
                checksum = sha256(normalized).hexdigest()
                if destination.exists() and digest(destination) != checksum:
                    raise DataError("Existing representation conflicts with new output.")
                atomic_bytes(destination, normalized)
                result.update(
                    output_size=len(normalized), output_sha256=checksum, output_path=str(relative)
                )
            elif status == "success":
                result["status"] = "empty_representation"
        except UnicodeError as error:
            result.update(status="normalization_error", error=str(error))
    elif status == "success":
        result["status"] = "missing_output"


def _extract_shared_views(
    source: dict[str, Any],
    batch_root: Path,
    job: Path,
    headless: Path,
    scripts: Path,
    processes: _Processes,
    heap_mb: int,
) -> list[dict[str, Any]]:
    """Experimental full analysis once, then independent DIS/DEC script outcomes."""
    started = time.monotonic()
    sha = source["sha256"]
    root = batch_root / f"{sha}-shared"
    root.mkdir(mode=0o700)
    project, output = root / "project", root / "output"
    project.mkdir()
    output.mkdir()
    # DEC's default full analysis is intentional; no DIS preScript is applied.
    command = _ghidra_command(
        analyze_headless=headless,
        representation="dec",
        script_root=scripts,
        source_path=batch_root / sha,
        project_root=project,
        output_root=output,
        timeout_per_file_seconds=300,
        timeout_per_function_seconds=60,
        analysis_timeout_per_file_seconds=300,
        max_cpu=1,
    )
    command = command[: command.index("-postScript")]
    file_limits = {"dis": 60, "dec": 300}
    names = {"dis": "Disassembler", "dec": "Decompiler"}
    for view in source["pending"]:
        command.extend(
            (
                "-postScript",
                f"{names[view]}.java",
                str(output),
                str(file_limits[view]),
                "30" if view == "dis" else "60",
            )
        )
    command.extend(("-deleteProject", "-okToDelete"))
    timeout = 300 + sum(file_limits[v] for v in source["pending"]) + 120
    execution = processes.run(command, root, timeout, heap_mb)
    logs = execution["stdout"] + "\n" + execution["stderr"]
    records = []
    for view in source["pending"]:
        # Ghidra prefixes each script's output. Never share completion/error markers.
        pattern = re.compile(rf"\b{names[view]}\.java>\s?(.*)")
        view_logs = "\n".join(
            match.group(1) for line in logs.splitlines() if (match := pattern.search(line))
        )
        raw = output / (sha + _extension(view))
        confirmed = f"run: finished (success) <{sha}>" in view_logs
        finished = confirmed or any(
            marker in view_logs for marker in ("run: finished (timeout)", "run: finished (crash)")
        )
        status = "ghidra_" + execution["status"]
        if finished:
            if (
                "analysisTimeoutOccurred()=true" in view_logs
                or "run: finished (timeout)" in view_logs
            ):
                status = "partial_timeout"
            elif "run: finished (crash)" in view_logs or "decompileFunction:" in view_logs:
                status = "partial_error"
            elif confirmed and "analysisTimeoutOccurred()=false" in view_logs:
                status = "success"
            else:
                status = "unconfirmed_completion"
        elif not view_logs and not raw.exists():
            status = "not_started"
        elif execution["status"] == "success":
            status = "unconfirmed_completion"
        record = {
            "source_sha256": sha,
            "view": view,
            "status": status,
            "execution_mode": "shared-full",
            "runtime_scope": "shared_process_wall_inclusive",
            "transfer": source["transfer"],
            "execution": execution,
            "script_logs": view_logs,
            "die_evidence_sha256": source["die_evidence_sha256"],
            "output_size": 0,
            "output_sha256": None,
            "output_path": None,
        }
        _save_view_output(record, raw, job)
        record["seconds"] = time.monotonic() - started
        records.append(record)
    return records


def _process_source(
    source: dict[str, Any],
    batch_root: Path,
    job: Path,
    headless: Path,
    scripts: Path,
    processes: _Processes,
    heap_mb: int,
    events: Queue,
    execution_mode: str = "separate",
) -> None:
    if execution_mode == "shared-full" and source["transfer"]["status"] == "verified":
        if processes.stopping.is_set():
            return
        records = _extract_shared_views(
            source, batch_root, job, headless, scripts, processes, heap_mb
        )
        for record in records:
            if not processes.stopping.is_set() or record["status"] == "success":
                events.put(("result", record))
        return
    for view in source["pending"]:
        if processes.stopping.is_set():
            return
        if source["transfer"]["status"] != "verified":
            result = {
                "source_sha256": source["sha256"],
                "view": view,
                "status": source["transfer"]["status"],
                "transfer": source["transfer"],
                "seconds": 0,
                "output_size": 0,
                "output_sha256": None,
                "output_path": None,
            }
        else:
            result = _extract_view(
                source, view, batch_root, job, headless, scripts, processes, heap_mb
            )
        if processes.stopping.is_set() and result["status"] != "success":
            # A coordinator stop is not a terminal failure of this source/view.
            return
        events.put(("result", result))


def _drain(db: sqlite3.Connection, events: Queue) -> None:
    while True:
        try:
            kind, record = events.get_nowait()
        except Empty:
            return
        blob = gzip.compress(json.dumps(record, sort_keys=True).encode(), mtime=0)
        with db:
            if kind == "transfer":
                db.execute(
                    "INSERT INTO transfer (sha256,status,bytes,seconds,evidence_gzip) VALUES (?,?,?,?,?)",
                    (
                        record["source_sha256"],
                        record["status"],
                        record["bytes"],
                        record["seconds"],
                        blob,
                    ),
                )
            else:
                db.execute(
                    "INSERT INTO result VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        record["source_sha256"],
                        record["view"],
                        record["status"],
                        record["seconds"],
                        record["output_size"],
                        record["output_sha256"],
                        record["output_path"],
                        blob,
                        sha256(blob).hexdigest(),
                    ),
                )


def _export(db: sqlite3.Connection, job: Path) -> None:
    for view in VIEWS:
        rows = db.execute(
            "SELECT s.sha256,s.label,r.status,r.seconds,r.output_size,r.output_sha256,r.output_path "
            "FROM source s JOIN result r USING(sha256) WHERE r.view=? ORDER BY s.sha256",
            (view,),
        )
        path = job / f"{view}-manifest.csv"
        temporary = path.with_suffix(".tmp")
        with temporary.open("w", newline="") as stream:
            os.fchmod(stream.fileno(), 0o600)
            writer = csv.writer(stream)
            writer.writerow(
                (
                    "source_sha256",
                    "label",
                    "status",
                    "seconds",
                    "output_size",
                    "output_sha256",
                    "output_path",
                )
            )
            writer.writerows(tuple(row) for row in rows)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    path = job / "selection.csv"
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", newline="") as stream:
        os.fchmod(stream.fileno(), 0o600)
        writer = csv.writer(stream)
        writer.writerow(("source_sha256", "label", "admission", "die_evidence_sha256"))
        writer.writerows(
            tuple(row)
            for row in db.execute(
                "SELECT sha256,label,admission,die_evidence_sha256 FROM source ORDER BY sha256"
            )
        )
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def run_rands_ghidra(
    job: Path,
    die_job: Path,
    config: RandsDatasetConfig,
    headless: Path,
    *,
    script_root: Path = SCRIPT_ROOT,
    limit: int | None = None,
    heap_mb: int = 1024,
    min_free_bytes: int = 5 * 1024**3,
    execution_mode: str = "separate",
) -> dict[str, Any]:
    """Run 16-source batches, prefetch one batch, commit each view before cleanup."""
    _private_path(job, "RanDS Ghidra job")
    job, die_job = job.expanduser().resolve(), die_job.expanduser().resolve()
    headless, script_root = headless.expanduser().resolve(), script_root.expanduser().resolve()
    if job == die_job or job in die_job.parents or die_job in job.parents:
        raise DataError("Ghidra and DiE jobs must use separate, non-nested directories.")
    if (limit is not None and limit < 1) or heap_mb < 128 or min_free_bytes < 0:
        raise DataError("Require positive limit, heap >=128 MiB and nonnegative disk reserve.")
    if execution_mode not in ("separate", "shared-full"):
        raise DataError("Require separate or shared-full Ghidra execution mode.")
    tools = _tools(headless, script_root)
    contract = {
        "schema": 1,
        "die_job": str(die_job),
        "dataset": asdict(config),
        "tools": tools,
        "selection": SELECTION,
        "batch_size": 16,
        "workers": 16,
        "prefetch_batches": 1,
        "heap_mb": heap_mb,
        "max_cpu": 1,
        "execution_mode": execution_mode,
        "runner_sha256": digest(Path(__file__)),
        "normalizer_sha256": digest(Path(__file__).with_name("rands_ghidra.py")),
    }
    encoded = json.dumps(contract, sort_keys=True)
    started = time.monotonic()
    with job_lock(job), _stop_signals(), closing(_connect(job)) as db:
        job.chmod(0o700)
        saved = db.execute("SELECT value FROM job WHERE key='contract'").fetchone()
        if saved and saved[0] != encoded:
            raise DataError("Ghidra job tools/config changed; use a new job directory.")
        json_write(
            job / "progress.json",
            {
                "phase": "validating_selection",
                "pid": os.getpid(),
                "updated_at_unix": time.time(),
            },
        )
        # Rebuild the selection transactionally to detect modified admission evidence on resume.
        previous = db.execute("SELECT value FROM job WHERE key='selection'").fetchone()
        with db:
            db.execute("DELETE FROM source")
            selection = _select(db, die_job, config)
            selected = json.dumps(selection, sort_keys=True)
            if previous and previous[0] != selected:
                raise DataError("DiE inventory/admission evidence changed; use a new Ghidra job.")
            db.execute("INSERT OR IGNORE INTO job VALUES ('contract',?)", (encoded,))
            db.execute("INSERT OR IGNORE INTO job VALUES ('selection',?)", (selected,))
        json_write(job / "tools.json", tools)
        json_write(job / "selection.json", selection)
        json_write(job / "pid.json", {"pid": os.getpid()})
        _verify_outputs(db, job)
        # Only scratch owned by this locked, contract-validated job is disposable.
        work = job / "work"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(mode=0o700)
        pending = [
            dict(row)
            for row in db.execute(
                "SELECT s.*,GROUP_CONCAT(v.view) AS pending_views FROM source s "
                "CROSS JOIN (SELECT 'dis' AS view UNION ALL SELECT 'dec') v "
                "LEFT JOIN result r ON r.sha256=s.sha256 AND r.view=v.view "
                "WHERE s.admission='eligible' AND r.sha256 IS NULL GROUP BY s.sha256 ORDER BY s.sha256"
            )
        ]
        if limit is not None:
            pending = pending[:limit]
        for source in pending:
            pending_views = source.pop("pending_views").split(",")
            source["pending"] = [view for view in VIEWS if view in pending_views]
        batches = [pending[i : i + 16] for i in range(0, len(pending), 16)]
        processes, events = _Processes(), Queue()
        feeder = ThreadPoolExecutor(max_workers=1)
        workers = ThreadPoolExecutor(max_workers=16)
        phase, error = "complete", None
        bucket = urlsplit(selection["prefix"]).netloc
        future = None
        last_emit = 0.0

        def start_batch(index: int):
            # Reserve scratch for both this batch and its successor before scheduling either.
            needed = sum(s["size"] for b in batches[index : index + 2] for s in b)
            if shutil.disk_usage(job).free < min_free_bytes + needed:
                raise DataError("Insufficient disk reserve for the active and prefetched batches.")
            return feeder.submit(
                _download_batch, batches[index], work / f"batch-{index}", bucket, events
            )

        try:
            if batches:
                future = start_batch(0)
            for index in range(len(batches)):
                while not future.done():
                    wait([future], timeout=1)
                    _drain(db, events)
                    if time.monotonic() - last_emit >= 5:
                        _emit(db, job, started, "downloading", batch=index + 1)
                        last_emit = time.monotonic()
                batch = future.result()
                _drain(db, events)
                batch_root = work / f"batch-{index}"
                active = {
                    workers.submit(
                        _process_source,
                        source,
                        batch_root,
                        job,
                        headless,
                        script_root,
                        processes,
                        heap_mb,
                        events,
                        execution_mode,
                    )
                    for source in batch
                }
                future = start_batch(index + 1) if index + 1 < len(batches) else None
                while active:
                    done, active = wait(active, timeout=1, return_when=FIRST_COMPLETED)
                    _drain(db, events)
                    for finished in done:
                        finished.result()
                    if time.monotonic() - last_emit >= 5:
                        _emit(db, job, started, "extracting", batch=index + 1)
                        last_emit = time.monotonic()
                    if shutil.disk_usage(job).free < min_free_bytes:
                        raise DataError("Disk reserve reached; committed results are resumable.")
                _drain(db, events)
                # Every terminal representation is committed before its PE/project is removed.
                shutil.rmtree(batch_root)
                _emit(db, job, started, "batch_complete", batch=index + 1)
            if not _summary(db)["complete"]:
                phase = "limit_reached"
        except KeyboardInterrupt:
            phase = "interrupted"
            raise
        except BaseException as failure:
            phase, error = "failed", str(failure)
            raise
        finally:
            processes.stop()
            workers.shutdown(wait=True, cancel_futures=True)
            # Finish bounded in-flight S3 calls before deleting their destination files.
            feeder.shutdown(wait=True, cancel_futures=True)
            _drain(db, events)
            shutil.rmtree(work)
            _export(db, job)
            report = _emit(db, job, started, phase, **({"error": error} if error else {}))
            json_write(job / "summary.json", report)
        return report
