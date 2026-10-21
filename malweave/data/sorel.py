"""Bounded SOREL acquisition, pre-extraction screening and durable processing state.

Only EXE outputs and provenance survive processing. Original IDs refer to the
pre-disarming bytes and must never be compared with released-PE digests.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any
import zlib

import lief
import yaml

from malweave.config import PROJECT_ROOT
from malweave.data import sorel_ledger as ledger
from malweave.data.pe_assessment import architecture_from_file, assess_file, assess_packing
from malweave.data.pe_sections import ExeExtractionResult
from malweave.data.sorel_io import (
    SorelError,
    SourceFailure,
    atomic_bytes,
    durable_replace,
    job_lock,
)
from malweave.data.sorel_io import digest as _digest
from malweave.data.sorel_io import json_write as _json_write
from malweave.data.sorel_transfer import BASE_URL, download_source

ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class SorelConfig:
    release: str = "09-DEC-2020"
    seed: int = 42
    samples: int = 100
    batch_size: int = 8
    workers: int = 2
    architecture_policy: str = "annotate"
    packing_policy: str = "exclude_detected_and_unknown"
    max_compressed_bytes: int = 32 * 1024**2
    max_pe_bytes: int = 128 * 1024**2
    min_free_bytes: int = 5 * 1024**3
    file_timeout_seconds: int = 10
    die_timeout_seconds: int = 15
    request_timeout_seconds: int = 120
    request_attempts: int = 3
    lief_timeout_seconds: int = 60
    download_backend: str = "curl"


def load_sorel_config(path: Path) -> SorelConfig:
    try:
        config = SorelConfig(**yaml.safe_load(path.read_text()))
        for key, default in asdict(SorelConfig()).items():
            value = getattr(config, key)
            if type(value) is not type(default):
                raise ValueError(f"{key} has an invalid type")
            if isinstance(value, int) and (value < 0 or (key != "seed" and value == 0)):
                raise ValueError(f"{key} must be positive")
        if config.release != "09-DEC-2020":
            raise ValueError("unsupported release")
        if config.architecture_policy not in ("annotate", "i386"):
            raise ValueError("architecture_policy must be annotate or i386")
        if config.packing_policy != "exclude_detected_and_unknown":
            raise ValueError("unsupported packing_policy")
        if config.download_backend not in ("curl", "urllib"):
            raise ValueError("download_backend must be curl or urllib")
        if config.workers > config.batch_size:
            raise ValueError("workers must not exceed batch_size")
        return config
    except (TypeError, ValueError, yaml.YAMLError) as error:
        raise SorelError(f"Invalid SOREL configuration: {error}") from error


def _private(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path.is_relative_to(PROJECT_ROOT):
        relative = path.relative_to(PROJECT_ROOT)
        if tuple(relative.parts[:2]) not in (("data", "processed"), ("data", "raw")):
            raise SorelError("Private SOREL artifacts must be under data/processed or data/raw.")
    return path


def prepare_sorel(metadata: Path, job: Path, config: SorelConfig) -> dict[str, Any]:
    """Audit metadata and reservoir-sample into SQLite with bounded Python memory."""
    job = _private(job)
    with job_lock(job):
        return _prepare_sorel(metadata, job, config)


def _prepare_sorel(metadata: Path, job: Path, config: SorelConfig) -> dict[str, Any]:
    if (job / "selection.json").exists() or (job / "state.sqlite").exists():
        raise SorelError("Selection/state exists; choose a new job directory.")
    if not metadata.is_file():
        raise SorelError("Metadata database does not exist.")
    started = time.monotonic()
    rng = random.Random(config.seed)
    labels: Counter[str] = Counter()
    invalid_ids = eligible = 0
    with closing(ledger.connect(job / "state.sqlite")) as target:
        with sqlite3.connect(metadata.resolve().as_uri() + "?mode=ro", uri=True) as source:
            if source.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise SorelError("Metadata SQLite quick_check failed.")
            columns = [row[1] for row in source.execute("PRAGMA table_info(meta)")]
            if not {"sha256", "is_malware", "rl_fs_t"}.issubset(columns):
                raise SorelError("Metadata lacks required ID, label or first-seen columns.")
            duplicates = source.execute(
                "SELECT COUNT(*) FROM (SELECT sha256 FROM meta GROUP BY sha256 HAVING COUNT(*) > 1)"
            ).fetchone()[0]
            if duplicates:
                raise SorelError("Metadata contains duplicate IDs.")
            for identifier, label, first_seen in source.execute(
                "SELECT sha256,is_malware,rl_fs_t FROM meta"
            ):
                labels[str(label)] += 1
                if not isinstance(identifier, str) or not ID_PATTERN.fullmatch(identifier):
                    invalid_ids += 1
                    continue
                if label != 1:
                    continue
                eligible += 1
                slot = eligible - 1 if eligible <= config.samples else rng.randrange(eligible)
                if slot < config.samples:
                    value = json.dumps(
                        {"original_sha256": identifier, "is_malware": 1, "rl_fs_t": first_seen},
                        sort_keys=True,
                    )
                    target.execute(
                        "INSERT INTO sources(slot,id,value) VALUES(?,?,?) ON CONFLICT(slot) "
                        "DO UPDATE SET id=excluded.id,value=excluded.value",
                        (slot, identifier, value),
                    )
            selected = target.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        passed = (
            not invalid_ids and set(labels).issubset({"0", "1"}) and selected == config.samples
        )
        audit = {
            "passed": passed,
            "sqlite_quick_check": "ok",
            "columns": columns,
            "label_counts": dict(labels),
            "invalid_ids": invalid_ids,
            "duplicate_ids": duplicates,
            "eligible_malware": eligible,
            "selected": selected,
            "metadata_bytes": metadata.stat().st_size,
            "metadata_sha256": _digest(metadata),
            "selection_seed": config.seed,
            "runtime_seconds": round(time.monotonic() - started, 3),
        }
        _json_write(job / "metadata-audit.json", audit)
        if not passed:
            raise SorelError(
                "Metadata audit failed or too few malware records; see metadata-audit.json."
            )
        target.commit()
        selection = {
            "schema": 2,
            "release": config.release,
            "audit": audit,
            "config": asdict(config),
            "selected": selected,
            "sources_sha256": ledger.selection_digest(target),
            "sources_table": "state.sqlite:sources",
        }
        _json_write(job / "selection.json", selection)
    return {key: value for key, value in audit.items() if key != "metadata_sha256"}


def _selection(job: Path, config: SorelConfig) -> dict[str, Any]:
    selection = json.loads((job / "selection.json").read_text())
    if selection.get("schema") != 2:
        raise SorelError("Legacy selection is export-only; prepare a new job for this code.")
    if selection.get("config") != asdict(config) or not selection["audit"]["passed"]:
        raise SorelError("Selection config/audit differs; create a new job for changed inputs.")
    return selection


def _tool(command: str) -> dict[str, str]:
    executable = shutil.which(command)
    if not executable:
        raise SorelError(f"Missing static-analysis tool: {command}")
    result = subprocess.run(
        [executable, "--version"], capture_output=True, text=True, timeout=15, check=False
    )
    if result.returncode:
        raise SorelError(f"Cannot obtain tool version: {command}")
    identity = {
        "path": executable,
        "version": result.stdout.strip(),
        "sha256": _digest(Path(executable)),
    }
    if command == "curl":
        version = re.search(r"curl (\d+)\.(\d+)\.(\d+)", result.stdout)
        if not version or tuple(map(int, version.groups())) < (7, 70, 0):
            raise SorelError("Audited curl transfers require curl >= 7.70; use urllib otherwise.")
    if command == "diec":
        binary = Path(executable).resolve()
        roots = (binary.parent.parent / "Resources", binary.parent)
        rules = next((root for root in roots if (root / "db").is_dir()), None)
        if rules:
            digest = sha256()
            count = 0
            for name in ("db", "db_custom"):
                for path in sorted((rules / name).rglob("*")):
                    if path.is_file():
                        digest.update(path.relative_to(rules).as_posix().encode())
                        digest.update(bytes.fromhex(_digest(path)))
                        count += 1
            identity.update(rules_sha256=digest.hexdigest(), rules_files=str(count))
        else:
            identity["rules_sha256"] = "unknown"
    return identity


def _connect(job: Path, config: SorelConfig, *, tools: dict[str, Any]) -> sqlite3.Connection:
    selection = _selection(job, config)
    contract = json.dumps(
        {
            "schema": 2,
            "selection_sha256": _digest(job / "selection.json"),
            "extractor_sha256": _digest(Path(__file__).with_name("pe_sections.py")),
            "screening_sha256": _digest(Path(__file__).with_name("pe_assessment.py")),
            "adapter_sha256": _digest(Path(__file__)),
            "support_sha256": {
                name: _digest(Path(__file__).with_name(name + ".py"))
                for name in ("sorel_io", "sorel_ledger", "sorel_transfer", "pe_worker")
            },
            "lief": lief.__version__,
            "config": asdict(config),
            "tools": tools,
        },
        sort_keys=True,
    )
    connection = ledger.connect(job / "state.sqlite")
    if ledger.selection_digest(connection) != selection["sources_sha256"]:
        connection.close()
        raise SorelError("Source selection changed; resume rejected.")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("CREATE TABLE IF NOT EXISTS contract (value TEXT NOT NULL)")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS outcomes (id TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    row = connection.execute("SELECT value FROM contract").fetchone()
    if row and row[0] != contract:
        connection.close()
        raise SorelError("Job inputs/tools/extractor changed; resume rejected. Use a new job.")
    if not row:
        connection.execute("INSERT INTO contract VALUES (?)", (contract,))
    connection.commit()
    if selection["release"] != config.release:
        connection.close()
        raise SorelError("Release differs from selection.")
    return connection


def plan_sorel_download(job: Path, config: SorelConfig) -> dict[str, int]:
    """Legacy external staging plan. Prefer sorel-run for complete transfer receipts."""
    job = _private(job)
    with job_lock(job):
        _selection(job, config)
        with closing(ledger.connect(job / "state.sqlite")) as connection:
            batch = ledger.pending(connection, config.batch_size)
            summary = ledger.summary(connection, config.samples)
        spool = job / "spool"
        spool.mkdir(exist_ok=True)
        if any(spool.iterdir()):
            raise SorelError(
                "Spool is not empty; finish the current batch before planning another."
            )
        lines = [
            "fail",
            "silent",
            "show-error",
            "parallel",
            f"parallel-max = {config.workers}",
            f"max-time = {config.request_timeout_seconds}",
            "connect-timeout = 20",
            f"max-filesize = {config.max_compressed_bytes}",
        ]
        for row in batch:
            identifier = row["original_sha256"]
            lines.extend(
                [
                    f'url = "{BASE_URL}{identifier}"',
                    "output = " + json.dumps(str(spool / f"{identifier}.zlib")),
                ]
            )
        _json_write(job / "batch.json", batch)
        atomic_bytes(job / "download.curl", ("\n".join(lines) + "\n").encode())
        return {"batch_sources": len(batch), "pending_before_batch": summary["pending"]}


def decompress_sorel(content: bytes, maximum: int) -> bytes:
    decoder = zlib.decompressobj()
    try:
        pe = decoder.decompress(content, maximum + 1)
    except zlib.error as error:
        raise SourceFailure("decompression_error") from error
    if len(pe) > maximum or decoder.unconsumed_tail:
        raise SourceFailure("pe_size_limit")
    if not decoder.eof or decoder.unused_data:
        raise SourceFailure("invalid_zlib_stream")
    return pe


def _process(
    source: dict[str, Any], job: Path, config: SorelConfig, tools: dict[str, Any], staged: bool
) -> dict[str, Any]:
    started = time.monotonic()
    row: dict[str, Any] = {
        **source,
        "dataset": "sorel",
        "release": config.release,
        "status": "pending",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "compressed_bytes": 0,
        "pe_bytes": 0,
        "exe_bytes": 0,
        "architecture": "unknown",
        "packing": "unknown",
        "download_seconds": 0,
        "decompress_seconds": 0,
        "screen_seconds": 0,
        "extract_seconds": 0,
    }
    try:
        clock = time.monotonic()
        if staged:
            path = job / "spool" / f"{source['original_sha256']}.zlib"
            if not path.is_file():
                raise SourceFailure("download_missing")
            if path.stat().st_size > config.max_compressed_bytes:
                raise SourceFailure("compressed_size_limit")
            compressed = path.read_bytes()
        else:
            path, receipt = download_source(
                job, source["original_sha256"], config, tools.get("curl", {}).get("path", "curl")
            )
            compressed = path.read_bytes()
            row["download_receipt_report_path"] = receipt.relative_to(job).as_posix()
            row["download_receipt_report_sha256"] = _digest(receipt)
        row["download_seconds"] = round(time.monotonic() - clock, 6)
        row["compressed_bytes"] = len(compressed)
        clock = time.monotonic()
        pe = decompress_sorel(compressed, config.max_pe_bytes)
        del compressed
        row["decompress_seconds"] = round(time.monotonic() - clock, 6)
        row["pe_bytes"] = len(pe)
        row["released_pe_sha256"] = sha256(pe).hexdigest()
        clock = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="pe-", dir=job / "scratch") as directory:
            path = Path(directory) / "sample.pe"
            path.write_bytes(pe)
            path.chmod(0o600)
            file_report = assess_file(tools["file"]["path"], path, config.file_timeout_seconds)
            _save_tool_report(job, row, "file", tools["file"], file_report)
            row["file_status"] = file_report["status"]
            row["file_description"] = file_report.get("stdout", "").strip()
            row["architecture"] = architecture_from_file(row["file_description"])
            packing = assess_packing(tools["diec"]["path"], path, config.die_timeout_seconds)
            row.update(
                packing=packing["state"], die_modes=packing["modes"], die_types=packing["types"]
            )
            _save_tool_report(job, row, "die", tools["diec"], packing)
        row["screen_seconds"] = round(time.monotonic() - clock, 6)
        if row["packing"] != "not_detected":
            raise SourceFailure(
                "filtered_obfuscated"
                if row["packing"] == "obfuscated"
                else "filtered_packing_unknown"
            )
        if config.architecture_policy == "i386" and row["architecture"] != "i386":
            raise SourceFailure("filtered_architecture")
        clock = time.monotonic()
        result = _run_lief_worker(pe, job, config)
        _save_tool_report(job, row, "lief", {"version": lief.__version__}, result.audit)
        row["warnings"] = list(result.warnings)
        row["section_count"] = result.section_count
        row["executable_section_count"] = result.executable_section_count
        row["lief_status"] = result.status
        row["extract_seconds"] = round(time.monotonic() - clock, 6)
        if result.status != "success":
            raise SourceFailure(result.status)
        digest = result.representation_sha256
        relative = Path("exe") / digest[:2] / f"{digest}.exe"
        output = job / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        # Named after source ID to avoid shared temporary paths for identical EXE outputs.
        temporary = output.parent / f"{source['original_sha256']}.part"
        if output.exists():
            if _digest(output) != digest:
                raise SorelError("Conflicting or corrupt existing EXE output.")
        else:
            atomic_bytes(temporary, result.extracted_bytes)
            durable_replace(temporary, output)
        if _digest(output) != digest:
            raise SorelError("Output verification failed.")
        row.update(
            status="success",
            exe_sha256=digest,
            exe_path=relative.as_posix(),
            exe_bytes=result.extracted_size,
        )
    except SourceFailure as error:
        row["status"] = str(error)
    receipt = (
        job
        / "downloads"
        / source["original_sha256"][:2]
        / source["original_sha256"]
        / "receipt.json"
    )
    if receipt.is_file():
        row["download_receipt_report_path"] = receipt.relative_to(job).as_posix()
        row["download_receipt_report_sha256"] = _digest(receipt)
        transfer = json.loads(receipt.read_text())
        row["download_http_status"] = transfer.get("http_status")
        row["download_attempts"] = transfer.get("attempt", 0)
        row["download_seconds"] = transfer.get("total_wall_seconds", 0)
        row["network_received_bytes"] = transfer.get("total_received_bytes", 0)
        row["download_history_complete"] = transfer.get("history_complete", True)
        row["download_timing_scope"] = (
            "sum of timed network attempts; excludes local spool read and interrupted duration"
        )
    elif staged:
        row["download_evidence"] = "external_staging_receipt_not_saved"
        row["download_timing_scope"] = "local spool read only, not S3 transfer time"
    row["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    row["runtime_seconds"] = round(time.monotonic() - started, 6)
    return row


def _save_tool_report(
    job: Path, row: dict[str, Any], name: str, tool: dict[str, Any], result: Any
) -> None:
    path = (
        Path("tool-reports") / name / row["original_sha256"][:2] / f"{row['original_sha256']}.json"
    )
    _json_write(
        job / path,
        {
            "schema": 1,
            "dataset": row["dataset"],
            "release": row["release"],
            "original_sha256": row["original_sha256"],
            "released_pe_sha256": row["released_pe_sha256"],
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "result": result,
        },
    )
    row[f"{name}_report_path"] = path.as_posix()
    row[f"{name}_report_sha256"] = _digest(job / path)


def _run_lief_worker(pe: bytes, job: Path, config: SorelConfig) -> ExeExtractionResult:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="lief-", dir=job / "scratch") as directory:
        root = Path(directory)
        source, output, report_path = root / "input.pe", root / "output.exe", root / "report.json"
        source.write_bytes(pe)
        source.chmod(0o600)
        command = [
            sys.executable,
            "-m",
            "malweave.data.pe_worker",
            "--input",
            str(source),
            "--output",
            str(output),
            "--report",
            str(report_path),
        ]
        audit: dict[str, Any] = {
            "command": command,
            "lief_version": lief.__version__,
            "input_sha256": sha256(pe).hexdigest(),
            "input_bytes": len(pe),
            "sections": [],
            "warnings": [],
            "native_diagnostics": "captured",
        }
        status = "lief_worker_error"
        with (root / "stdout").open("wb") as stdout, (root / "stderr").open("wb") as stderr:
            try:
                result = subprocess.run(
                    command,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=config.lief_timeout_seconds,
                    check=False,
                )
                audit["returncode"] = result.returncode
                if result.returncode:
                    status = "lief_worker_crash"
                elif report_path.is_file():
                    audit.update(json.loads(report_path.read_text()))
                    status = audit["status"]
            except subprocess.TimeoutExpired as error:
                status = "lief_timeout"
                audit["error"] = str(error)
            except (OSError, ValueError, KeyError) as error:
                audit["error"] = str(error)
        audit.update(
            stdout=(root / "stdout").read_text(errors="replace"),
            stderr=(root / "stderr").read_text(errors="replace"),
            runtime_seconds=round(time.monotonic() - started, 6),
            status=status,
        )
        content = output.read_bytes() if status == "success" and output.is_file() else None
        digest = sha256(content).hexdigest() if content is not None else None
        if status == "success" and (
            content is None
            or digest != audit.get("representation_sha256")
            or len(content) != audit.get("extracted_bytes")
        ):
            status = "lief_worker_invalid_output"
            audit["status"] = status
            content = None
            digest = None
        return ExeExtractionResult(
            status,
            tuple(audit.get("warnings", [])),
            audit.get("section_count", 0),
            audit.get("executable_section_count", 0),
            content,
            digest,
            audit,
        )


def _check_disk(job: Path, config: SorelConfig) -> None:
    reserve = config.batch_size * (config.max_pe_bytes + config.max_compressed_bytes)
    if shutil.disk_usage(job).free < config.min_free_bytes + reserve:
        raise SorelError("Insufficient free space; pending state preserved.")


def _verify_row(job: Path, row: dict[str, Any]) -> None:
    for name in ("file", "die", "lief"):
        if row.get(f"{name}_report_path"):
            _read_tool_report(job, row, name)
    if row.get("download_receipt_report_path"):
        _verify_transfer(job, row)
    if row["status"] == "success":
        output = (job / row["exe_path"]).resolve()
        if (
            not output.is_relative_to(job)
            or not output.is_file()
            or output.stat().st_size != row["exe_bytes"]
            or _digest(output) != row["exe_sha256"]
        ):
            raise SorelError("Completed output is absent or corrupt; verification rejected.")


def verify_sorel(job: Path) -> dict[str, Any]:
    """Explicit full audit; never repeated automatically for every batch."""
    job = _private(job)
    checked = 0
    with closing(
        sqlite3.connect((job / "state.sqlite").as_uri() + "?mode=ro", uri=True)
    ) as connection:
        connection.execute("BEGIN")
        selection = json.loads((job / "selection.json").read_text())
        if (
            selection.get("schema") == 2
            and ledger.selection_digest(connection) != selection["sources_sha256"]
        ):
            raise SorelError("Source selection is corrupt.")
        counts: Counter[str] = Counter()
        for row in ledger.SavedRows(connection):
            _verify_row(job, row)
            checked += 1
            counts[row["status"]] += 1
        if selection.get("schema") == 2:
            done = connection.execute("SELECT COUNT(*) FROM sources WHERE done=1").fetchone()[0]
            mismatch = connection.execute(
                "SELECT COUNT(*) FROM outcomes o LEFT JOIN sources s "
                "ON o.id=s.id WHERE s.id IS NULL OR s.done!=1"
            ).fetchone()[0]
            if (
                done != checked
                or mismatch
                or dict(counts)
                != ledger.summary(connection, selection["selected"])["status_counts"]
            ):
                raise SorelError("Saved progress/aggregate counts are inconsistent.")
    return {"verified_sources": checked, "passed": True}


def run_sorel(
    job: Path, config: SorelConfig, *, staged: bool = False, limit: int | None = None
) -> dict[str, Any]:
    """Process indexed pending rows; no full-history reads or exports inside the batch loop."""
    job = _private(job)
    with job_lock(job):
        return _run_sorel(job, config, staged=staged, limit=limit)


def _run_sorel(
    job: Path, config: SorelConfig, *, staged: bool, limit: int | None
) -> dict[str, Any]:
    _selection(job, config)
    if limit is not None and limit <= 0:
        raise SorelError("limit must be positive")
    names = ["file", "diec"] + (
        ["curl"] if not staged and config.download_backend == "curl" else []
    )
    tools = {name: _tool(name) for name in names}
    connection = _connect(job, config, tools=tools)
    try:
        started = time.monotonic()
        processed = 0
        (job / "scratch").mkdir(exist_ok=True)
        # A terminated runner can leave bounded temporary files after its last commit.
        for path in (job / "scratch").iterdir():
            if path.is_dir() and path.name.startswith(("pe-", "lief-")):
                shutil.rmtree(path)
        for path in (job / "spool").glob("*.zlib"):
            saved = connection.execute(
                "SELECT done FROM sources WHERE id=?", (path.stem,)
            ).fetchone()
            if saved and saved[0]:
                path.unlink()
        staged_batch = json.loads((job / "batch.json").read_text()) if staged else None
        with ThreadPoolExecutor(max_workers=config.workers) as executor:
            while True:
                if staged_batch is None:
                    batch = ledger.pending(
                        connection,
                        min(config.batch_size, limit - processed) if limit else config.batch_size,
                    )
                else:
                    batch = []
                    for source in staged_batch:
                        saved = connection.execute(
                            "SELECT value,done FROM sources WHERE id=?",
                            (source["original_sha256"],),
                        ).fetchone()
                        if saved is None or json.loads(saved[0]) != source:
                            raise SorelError("Staged batch is outside the frozen selection.")
                        if not saved[1]:
                            batch.append(source)
                        else:
                            (job / "spool" / f"{source['original_sha256']}.zlib").unlink(
                                missing_ok=True
                            )
                    batch = batch[:limit] if limit else batch
                if not batch:
                    break
                _check_disk(job, config)
                results = executor.map(
                    lambda source: _process(source, job, config, tools, staged), batch
                )
                for row in results:
                    # The evidence and EXE are durable before committing a completed outcome.
                    _verify_row(job, row)
                    ledger.record(connection, row)
                    (job / "spool" / f"{row['original_sha256']}.zlib").unlink(missing_ok=True)
                    processed += 1
                summary = ledger.summary(connection, config.samples)
                summary.update(
                    architecture_policy=config.architecture_policy,
                    staged_download_time_excluded=staged,
                    this_invocation_seconds=round(time.monotonic() - started, 3),
                    note="Completed means accounted, not all accepted for training.",
                )
                _json_write(job / "summary.json", summary)
                print(
                    json.dumps({"completed": summary["completed"], "selected": config.samples}),
                    flush=True,
                )
                if staged or (limit and processed >= limit):
                    break
        summary = ledger.summary(connection, config.samples)
        summary.update(
            architecture_policy=config.architecture_policy,
            staged_download_time_excluded=staged,
            this_invocation_seconds=round(time.monotonic() - started, 3),
        )
        _json_write(job / "summary.json", summary)
        if summary["pending"] == 0:
            export_sorel(job, _locked=True)
        return summary
    finally:
        connection.close()


def _csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    # Keep scanner-provided strings as text when opened in a spreadsheet.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _read_tool_report(job: Path, row: dict[str, Any], name: str) -> dict[str, Any]:
    path = (job / row[f"{name}_report_path"]).resolve()
    if (
        not path.is_relative_to(job)
        or not path.is_file()
        or _digest(path) != row[f"{name}_report_sha256"]
    ):
        raise SorelError(f"Saved {name} report is absent or corrupt; verification rejected.")
    report = json.loads(path.read_text())
    if report.get("original_sha256") != row["original_sha256"]:
        raise SorelError("Saved report belongs to a different source.")
    if (
        name in ("file", "die", "lief")
        and report.get("released_pe_sha256") != row["released_pe_sha256"]
    ):
        raise SorelError("Saved tool report refers to different PE bytes.")
    return report


def _die_findings(value: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if "type" in value:
            findings.append(value)
        for child in value.values():
            findings.extend(_die_findings(child))
    elif isinstance(value, list):
        for child in value:
            findings.extend(_die_findings(child))
    return findings


def export_sorel(job: Path, *, _locked: bool = False) -> dict[str, Any]:
    job = _private(job)
    if not _locked:
        with job_lock(job):
            return export_sorel(job, _locked=True)
    database = job / "state.sqlite"
    if not database.is_file():
        raise SorelError("No saved SOREL state to export.")
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("BEGIN")
        return _export_sorel(job, ledger.SavedRows(connection))


def _export_sorel(job: Path, rows: ledger.SavedRows) -> dict[str, Any]:
    """Export saved results without network access, PE reads or scanner calls."""
    job = _private(job)
    manifest = job / "manifest.json"
    temporary = manifest.with_suffix(".json.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write("[\n")
        for index, row in enumerate(rows):
            if index:
                stream.write(",\n")
            json.dump(row, stream, sort_keys=True)
        stream.write("\n]\n")
    temporary.replace(manifest)
    fields = ["original_sha256", "status", "packing", "architecture"]
    fields += sorted({key for row in rows for key in row} - set(fields))
    path = job / "results.csv"
    temporary = path.with_suffix(".csv.tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(value) for key, value in row.items()})
    temporary.replace(path)

    path = job / "die-detections.csv"
    temporary = path.with_suffix(".csv.tmp")
    fields = [
        "original_sha256",
        "source_status",
        "packing",
        "mode",
        "scan_status",
        "type",
        "name",
        "version",
        "info",
        "detection_json",
        "die_report_path",
    ]
    reports_saved: Counter[str] = Counter()
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            base = {
                "original_sha256": row["original_sha256"],
                "source_status": row["status"],
                "packing": row["packing"],
                "die_report_path": row.get("die_report_path", ""),
            }
            if not row.get("die_report_path"):
                writer.writerow(
                    {
                        **base,
                        "scan_status": "full_report_not_saved"
                        if "die_modes" in row
                        else "not_run",
                    }
                )
                continue
            report = _read_tool_report(job, row, "die")["result"]
            reports_saved["die"] += 1
            for mode, result in report["reports"].items():
                mode_row = {**base, "mode": mode, "scan_status": result["status"]}
                findings = _die_findings(result.get("report", {}))
                if not findings:
                    writer.writerow(mode_row)
                for finding in findings:
                    writer.writerow(
                        {
                            **mode_row,
                            **{
                                key: _csv_value(finding.get(key, ""))
                                for key in ("type", "name", "version", "info")
                            },
                            "detection_json": _csv_value(finding),
                        }
                    )
    temporary.replace(path)

    path = job / "tool-runs.csv"
    temporary = path.with_suffix(".csv.tmp")
    fields = [
        "original_sha256",
        "tool",
        "mode",
        "status",
        "version",
        "command",
        "returncode",
        "runtime_seconds",
        "stdout",
        "stderr",
        "error",
        "report_path",
        "report_sha256",
    ]
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            for name in ("file", "die", "lief"):
                base = {"original_sha256": row["original_sha256"], "tool": name}
                if not row.get(f"{name}_report_path"):
                    attempted = (
                        "file_status" in row
                        if name == "file"
                        else "die_modes" in row
                        if name == "die"
                        else "warnings" in row
                    )
                    writer.writerow(
                        {**base, "status": "full_report_not_saved" if attempted else "not_run"}
                    )
                    continue
                saved = _read_tool_report(job, row, name)
                if name != "die":
                    reports_saved[name] += 1
                result = saved["result"]
                runs = result["reports"].items() if name == "die" else [("", result)]
                for mode, run in runs:
                    writer.writerow(
                        {
                            **base,
                            "mode": mode,
                            "version": saved["tool"].get("version", ""),
                            "report_path": row[f"{name}_report_path"],
                            "report_sha256": row[f"{name}_report_sha256"],
                            **{
                                key: _csv_value(run.get(key, ""))
                                for key in (
                                    "status",
                                    "command",
                                    "returncode",
                                    "runtime_seconds",
                                    "stdout",
                                    "stderr",
                                    "error",
                                )
                            },
                        }
                    )
    temporary.replace(path)

    path = job / "lief-sections.csv"
    temporary = path.with_suffix(".csv.tmp")
    fields = [
        "original_sha256",
        "index",
        "name",
        "raw_offset",
        "raw_size",
        "virtual_address",
        "virtual_size",
        "characteristics",
        "selected",
        "effective_start",
        "effective_end",
        "output_offset",
        "copied_bytes",
        "warnings",
        "lief_report_path",
    ]
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            if row.get("lief_report_path"):
                report = _read_tool_report(job, row, "lief")["result"]
                for section in report["sections"]:
                    writer.writerow(
                        {
                            "original_sha256": row["original_sha256"],
                            "lief_report_path": row["lief_report_path"],
                            **{key: _csv_value(value) for key, value in section.items()},
                        }
                    )
    temporary.replace(path)
    transfer_counts = _export_downloads(job, rows)
    summary = {
        "exported_sources": len(rows),
        "status_counts": dict(Counter(row["status"] for row in rows)),
        "saved_tool_reports": {name: reports_saved[name] for name in ("file", "die", "lief")},
        "files": [
            "results.csv",
            "die-detections.csv",
            "tool-runs.csv",
            "lief-sections.csv",
            "downloads.csv",
        ],
        "download_status_counts": transfer_counts,
        "note": "Exports use saved evidence only. Missing historical reports are not reconstructed.",
    }
    _json_write(job / "export-summary.json", summary)
    return summary


def _export_downloads(job: Path, rows: ledger.SavedRows) -> dict[str, int]:
    path = job / "downloads.csv"
    temporary = path.with_suffix(".csv.tmp")
    fields = [
        "original_sha256",
        "attempt",
        "status",
        "http_status",
        "backend",
        "received_bytes",
        "received_bytes_complete",
        "wall_seconds",
        "timing_complete",
        "history_complete",
        "note",
        "started_at_utc",
        "finished_at_utc",
        "returncode",
        "error",
        "stderr",
        "stdout",
        "command",
        "metrics",
        "report_path",
        "report_sha256",
    ]
    counts: Counter[str] = Counter()
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            if not row.get("download_receipt_report_path"):
                writer.writerow(
                    {"original_sha256": row["original_sha256"], "status": "receipt_not_saved"}
                )
                counts["receipt_not_saved"] += 1
                continue
            _verify_transfer(job, row)
            directory = (job / row["download_receipt_report_path"]).parent
            for attempt in sorted(directory.glob("attempt-*.json")):
                record = json.loads(attempt.read_text())
                writer.writerow(
                    {
                        **{key: _csv_value(record.get(key, "")) for key in fields},
                        "report_path": attempt.relative_to(job).as_posix(),
                        "report_sha256": _digest(attempt),
                    }
                )
                counts[record["status"]] += 1
    temporary.replace(path)
    return dict(counts)


def _verify_transfer(job: Path, row: dict[str, Any]) -> None:
    receipt = _read_tool_report(job, row, "download_receipt")
    directory = (job / row["download_receipt_report_path"]).parent
    previous = None
    seconds = 0.0
    size = 0
    for path in sorted(directory.glob("attempt-*.json")):
        attempt = json.loads(path.read_text())
        if (
            attempt.get("previous_attempt_sha256") != previous
            or attempt["original_sha256"] != row["original_sha256"]
        ):
            raise SorelError("Download attempt history is corrupt.")
        previous = _digest(path)
        seconds += attempt["wall_seconds"]
        size += attempt["received_bytes"]
    if (
        previous != row["download_receipt_report_sha256"]
        or abs(seconds - receipt["total_wall_seconds"]) > 0.00001
        or size != receipt["total_received_bytes"]
    ):
        raise SorelError("Download receipt does not match saved attempts.")
