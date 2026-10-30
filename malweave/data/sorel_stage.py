"""SOREL v3 per-source acquisition, static screening and isolated extraction."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any
from uuid import uuid4
import zlib

from malweave.data.pe_assessment import DIEC_MODES, OBFUSCATION_TYPES
from malweave.data.pe_identity import verify_sorel_architecture
from malweave.data.sorel_io import SorelError, SourceFailure, digest, json_write
from malweave.data.sorel_protocol import CSV_FIELDS, Rules, Runtime, now
from malweave.data.sorel_tools import Processes, read_json_output
from malweave.data.sorel_transfer import BASE_URL


class StopJob(SorelError):
    """A source/global access failure leaves the source pending and stops scheduling."""


def _findings(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if "type" in value:
            found.append(value)
        for child in value.values():
            found.extend(_findings(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_findings(child))
    return found


def _canonical_type(value: Any) -> str | None:
    if isinstance(value, str):
        return next(
            (name for name in OBFUSCATION_TYPES if name.casefold() == value.casefold()), None
        )
    return None


def screen_die(
    tool: str,
    pe: Path,
    root: Path,
    rules: Rules,
    runtime: Runtime,
    processes: Processes,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    modes: dict[str, Any] = {}
    for mode in DIEC_MODES:
        old = (previous or {}).get("modes", {}).get(mode)
        if old and old.get("status") == "success":
            modes[mode] = {
                **old,
                "reused": True,
                "reused_evidence": old,
                "attempts": [],
                "total_seconds": 0,
            }
            continue
        attempts = []
        for attempt in range(1, rules.die_attempts + 1):
            name = f"die-{mode}-{attempt:02d}"
            result = processes.run(
                [tool, f"--{mode}scan", "--json", str(pe)],
                root,
                name,
                timeout=rules.die_timeout_seconds,
                memory_bytes=runtime.memory_per_task_bytes,
                output_budget=max(
                    1,
                    runtime.disk_budget_bytes // (runtime.workers + runtime.upload_queue_sources),
                )
                if runtime.disk_budget_bytes
                else 0,
            )
            if result["status"] == "interrupted":
                raise InterruptedError("DiE interrupted")
            if result["status"].startswith("resource_"):
                raise SourceFailure("deferred_resource")
            if result["status"] == "success":
                try:
                    report = read_json_output(root, result, runtime.memory_per_task_bytes)
                    detects = report.get("detects")
                    if (
                        not isinstance(detects, list)
                        or not detects
                        or not any(
                            isinstance(d, dict)
                            and d.get("filetype") in ("PE", "PE32", "PE32+", "PE64")
                            for d in detects
                        )
                        or not all(
                            isinstance(d, dict) and isinstance(d.get("values"), list)
                            for d in detects
                        )
                    ):
                        raise ValueError("Invalid DiE PE report")
                    result["report"] = report
                except MemoryError:
                    raise SourceFailure("deferred_resource") from None
                except (ValueError, AttributeError, TypeError) as error:
                    result.update(status="invalid_report", error=str(error))
            attempts.append(result)
            json_write(root / (name + ".json"), result)
            if result["status"] == "success":
                break
        modes[mode] = {
            **attempts[-1],
            "attempts": attempts,
            "total_seconds": sum(a["runtime_seconds"] for a in attempts),
        }
    findings = [item for mode in modes.values() for item in _findings(mode.get("report", {}))]
    types = sorted({name for item in findings if (name := _canonical_type(item.get("type")))})
    result = {
        "modes": modes,
        "types": types,
        "names": sorted(
            {str(item.get("name", "")) for item in findings if _canonical_type(item.get("type"))}
        ),
        "state": "obfuscated"
        if types
        else "not_detected"
        if all(m["status"] == "success" for m in modes.values())
        else "scan_failed",
    }
    json_write(root / "die.json", result)
    return result


def download(
    identifier: str,
    root: Path,
    rules: Rules,
    runtime: Runtime,
    tools: dict[str, Any],
    processes: Processes,
) -> tuple[Path, dict[str, Any]]:
    output = root / "input.zlib"
    attempts = []
    # A per-task work allowance is a resource budget, NOT a corpus-size filter.
    allowance = max(
        1, runtime.disk_budget_bytes // (runtime.workers + runtime.upload_queue_sources)
    )
    for attempt in range(1, rules.request_attempts + 1):
        output.unlink(missing_ok=True)
        command = [
            tools["curl"]["path"],
            "-sS",
            "--fail",
            "--location",
            "--connect-timeout",
            str(rules.connect_timeout_seconds),
            "--max-time",
            str(rules.request_timeout_seconds),
            "--max-filesize",
            str(allowance),
            "--output",
            str(output),
            "--write-out",
            "%{json}",
            "--url",
            BASE_URL + identifier,
        ]
        result = processes.run(
            command,
            root,
            f"download-{attempt:02d}",
            timeout=rules.request_timeout_seconds + 5,
            observed_file=output,
            file_budget=allowance,
        )
        try:
            metrics = json.loads((root / result["stdout_file"]).read_text())
        except (OSError, ValueError):
            metrics = {}
        result["metrics"] = metrics
        result["http_status"] = (
            int(metrics.get("http_code", metrics.get("response_code", 0))) or None
        )
        result["received_bytes"] = output.stat().st_size if output.exists() else 0
        attempts.append(result)
        json_write(root / f"download-{attempt:02d}.json", result)
        if result["status"] == "interrupted":
            raise InterruptedError("Download interrupted")
        if result["http_status"] == 403:
            raise StopJob("SOREL source returned HTTP 403; access must be fixed before resume")
        if result["http_status"] == 404:
            break
        if result.get("returncode") == 23:
            raise StopJob("Cannot write source download; local state retained")
        if result.get("returncode") == 63 or result["status"].startswith("resource_"):
            result["status"] = "deferred_resource"
            break
        if result["status"] == "success" and result["http_status"] == 200 and output.is_file():
            break
        if (
            result["http_status"]
            and 400 <= result["http_status"] < 500
            and result["http_status"] not in (408, 429)
        ):
            break
        if attempt < rules.request_attempts and processes.abort.wait(2 ** (attempt - 1)):
            raise InterruptedError("Download retry interrupted")
    receipt = {
        "attempts": attempts,
        "attempt_count": len(attempts),
        "status": result["status"],
        "http_status": result["http_status"],
        "network_received_bytes": sum(a["received_bytes"] for a in attempts),
        "total_seconds": sum(a["runtime_seconds"] for a in attempts),
        "download_budget_bytes": allowance,
    }
    success = result["status"] == "success" and result["http_status"] == 200 and output.is_file()
    if success:
        receipt["compressed_sha256"] = digest(output)
        receipt["compressed_bytes"] = output.stat().st_size
    json_write(root / "download.json", receipt)
    if not success:
        raise SourceFailure(
            "http_404"
            if result["http_status"] == 404
            else "deferred_resource"
            if result["status"] == "deferred_resource"
            else "download_failed"
        )
    return output, receipt


def decompress(
    source: Path, target: Path, allowance: int, reserve: int, processes: Processes
) -> dict[str, Any]:
    decoder = zlib.decompressobj()
    hasher = sha256()
    size = 0
    try:
        with source.open("rb") as stream, target.open("wb") as output:
            os.fchmod(output.fileno(), 0o600)
            while chunk := stream.read(1024**2):
                if processes.abort.is_set():
                    raise InterruptedError("Decompression interrupted")
                while chunk:
                    value = decoder.decompress(chunk, 1024**2)
                    chunk = decoder.unconsumed_tail
                    size += len(value)
                    if size > allowance or shutil.disk_usage(target.parent).free < reserve + len(
                        value
                    ):
                        raise SourceFailure("deferred_resource")
                    output.write(value)
                    hasher.update(value)
                    if decoder.unused_data:
                        raise SourceFailure("invalid_zlib_stream")
            if not decoder.eof:
                raise SourceFailure("invalid_zlib_stream")
            output.flush()
            os.fsync(output.fileno())
    except zlib.error as error:
        raise SourceFailure("decompression_error") from error
    return {"pe_bytes": size, "released_pe_sha256": hasher.hexdigest()}


def extract(
    pe: Path,
    root: Path,
    rules: Rules,
    runtime: Runtime,
    processes: Processes,
) -> dict[str, Any]:
    attempts = []
    for attempt in range(1, rules.lief_attempts + 1):
        output, report = root / "output.exe", root / f"lief-result-{attempt:02d}.json"
        result = processes.run(
            [
                sys.executable,
                "-m",
                "malweave.data.pe_worker",
                "--input",
                str(pe),
                "--output",
                str(output),
                "--report",
                str(report),
                "--memory-limit",
                str(runtime.memory_per_task_bytes),
            ],
            root,
            f"lief-{attempt:02d}",
            timeout=rules.lief_timeout_seconds,
            memory_bytes=runtime.memory_per_task_bytes,
            output_budget=max(
                1, runtime.disk_budget_bytes // (runtime.workers + runtime.upload_queue_sources)
            )
            if runtime.disk_budget_bytes
            else 0,
        )
        attempts.append(result)
        if result["status"] == "interrupted":
            raise InterruptedError("LIEF interrupted")
        if result["status"].startswith("resource_"):
            return {
                "status": "deferred_resource",
                "attempts": attempts,
                "resource_reason": "lief_memory_budget",
            }
        if result["status"] == "success" and report.is_file():
            try:
                audit = json.loads(report.read_text())
            except ValueError:
                audit = {"status": "lief_invalid_report"}
            # A normal parse rejection is deterministic and is not retried.
            if audit.get("status") != "success":
                return {**audit, "attempts": attempts}
            if (
                output.is_file()
                and output.stat().st_size == audit.get("extracted_bytes")
                and digest(output) == audit.get("representation_sha256")
            ):
                return {**audit, "attempts": attempts}
            result["status"] = "lief_invalid_output"
        # Retry crashes/timeouts only. Invalid output is retained as an integrity error,
        # not silently accepted as a parse success.
        if result["status"] == "lief_invalid_output":
            return {"status": "lief_invalid_output", "attempts": attempts}
    return {
        "status": "lief_timeout" if result["status"] == "timeout" else "lief_crash",
        "attempts": attempts,
    }


def process(
    item: dict[str, Any],
    job: Path,
    rules: Rules,
    runtime: Runtime,
    tools: dict[str, Any],
    processes: Processes,
    run_id: str,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    identifier, attempt = item["original_sha256"], item["attempt"]
    root = job / "work" / identifier / f"attempt-{attempt:06d}"
    if root.exists():
        root.rename(root.with_name(root.name + "-interrupted-" + uuid4().hex))
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    row: dict[str, Any] = dict.fromkeys(CSV_FIELDS, "")
    metadata = item["source_metadata"]
    row.update(
        {("sorel_packed" if k == "packed" else k): v for k, v in metadata.items() if k != "sha256"}
    )
    row.update(
        original_sha256=identifier,
        dataset="sorel",
        release=rules.release,
        partition_index=rules.partition_index,
        partition_count=rules.partition_count,
        attempt=attempt,
        run_id=run_id,
        status="pending",
        storage_status="pending",
        architecture="unknown",
        architecture_status="not_run",
        packing="not_run",
        file_status="not_run",
        lief_status="not_run",
        warnings=[],
        compressed_bytes="",
        pe_bytes="",
        exe_bytes="",
        network_received_bytes=0,
        download_seconds=0,
        decompress_seconds=0,
        identity_seconds=0,
        screen_seconds=0,
        extract_seconds=0,
        local_work_dir=root.relative_to(job).as_posix(),
        details_member_root=f"sources/{identifier}/attempt-{attempt:06d}",
        started_at_utc=now(),
        error_stage="download",
        local_evidence_status="complete",
    )
    for mode in DIEC_MODES:
        row[f"die_{mode}_status"] = "not_run"
        row[f"die_{mode}_attempts"] = 0
    pe = root / "input.pe"
    completed = False
    try:
        compressed, receipt = download(identifier, root, rules, runtime, tools, processes)
        row.update(
            {
                key: receipt[key]
                for key in ("compressed_sha256", "compressed_bytes", "network_received_bytes")
            }
        )
        row.update(
            download_seconds=receipt["total_seconds"],
            download_attempts=receipt["attempt_count"],
            download_http_status=receipt["http_status"],
            error_stage="decompress",
        )
        clock = time.monotonic()
        allowance = max(
            1, runtime.disk_budget_bytes // (runtime.workers + runtime.upload_queue_sources)
        )
        row.update(decompress(compressed, pe, allowance, runtime.min_free_bytes, processes))
        row["decompress_seconds"] = time.monotonic() - clock
        compressed.unlink()
        row["error_stage"] = "architecture"
        identity = verify_sorel_architecture(pe, identifier, cancelled=processes.abort.is_set)
        json_write(root / "identity.json", identity)
        if identity.get("released_pe_sha256") not in (None, row["released_pe_sha256"]):
            raise StopJob("Released PE changed during architecture verification")
        row.update(
            architecture=identity["architecture"],
            architecture_status=identity["status"],
            architecture_method=identity["method"],
            identity_seconds=identity["runtime_seconds"],
        )
        for key in ("original_machine", "original_subsystem", "pe_format"):
            row[key] = identity.get(key, "")
        if identity["status"] == "invalid_pe":
            raise SourceFailure(identity["reason"])
        row["error_stage"] = "file"
        clock = time.monotonic()
        description = processes.run(
            [tools["file"]["path"], "-b", str(pe)],
            root,
            "file",
            timeout=rules.file_timeout_seconds,
            memory_bytes=runtime.memory_per_task_bytes,
            output_budget=max(
                1, runtime.disk_budget_bytes // (runtime.workers + runtime.upload_queue_sources)
            )
            if runtime.disk_budget_bytes
            else 0,
        )
        row["file_status"] = description["status"]
        row["file_seconds"] = description["runtime_seconds"]
        if (root / description["stdout_file"]).stat().st_size <= 1024**2:
            row["file_description"] = (
                (root / description["stdout_file"]).read_text(errors="replace").strip()
            )
        if description["status"] == "interrupted":
            raise InterruptedError("file interrupted")
        if rules.architecture_policy == "x86_verified":
            if identity["status"] != "verified" or identity["architecture"] == "unknown":
                raise SourceFailure("deferred_architecture")
            if identity["architecture"] not in ("i386", "amd64"):
                raise SourceFailure("filtered_architecture")
        row["error_stage"] = "die"
        clock = time.monotonic()
        prior_die = None
        if previous and previous.get("released_pe_sha256") == row["released_pe_sha256"]:
            prior_path = Path(previous.get("reusable_die_path", ""))
            if prior_path.is_file():
                prior_die = json.loads(prior_path.read_text())
        packing = screen_die(tools["diec"]["path"], pe, root, rules, runtime, processes, prior_die)
        row.update(
            packing=packing["state"], die_types=packing["types"], die_names=packing["names"]
        )
        for mode, value in packing["modes"].items():
            row.update(
                {
                    f"die_{mode}_status": value["status"],
                    f"die_{mode}_attempts": len(value.get("attempts", [])),
                    f"die_{mode}_seconds": value.get("total_seconds", 0),
                }
            )
        row["screen_seconds"] = time.monotonic() - clock
        if packing["state"] == "obfuscated":
            raise SourceFailure("filtered_obfuscated")
        if packing["state"] != "not_detected":
            raise SourceFailure("die_scan_failed")
        row["error_stage"] = "lief"
        clock = time.monotonic()
        audit = extract(pe, root, rules, runtime, processes)
        row.update(
            lief_status=audit["status"],
            lief_attempts=len(audit["attempts"]),
            extract_seconds=time.monotonic() - clock,
            warnings=audit.get("warnings", []),
            section_count=audit.get("section_count", 0),
            executable_section_count=audit.get("executable_section_count", 0),
        )
        json_write(root / "lief.json", audit)
        if audit["status"] != "success":
            raise SourceFailure(audit["status"])
        row.update(
            status="success",
            error_stage="",
            exe_sha256=audit["representation_sha256"],
            exe_bytes=audit["extracted_bytes"],
        )
        completed = True
    except SourceFailure as error:
        row.update(status=str(error), error=str(error))
        if str(error).startswith("deferred_"):
            row["resource_reason"] = (
                row["error_stage"] if str(error) == "deferred_resource" else ""
            )
        receipt_path = root / "download.json"
        if receipt_path.is_file():
            receipt = json.loads(receipt_path.read_text())
            row.update(
                download_seconds=receipt["total_seconds"],
                download_attempts=receipt["attempt_count"],
                download_http_status=receipt["http_status"],
                network_received_bytes=receipt["network_received_bytes"],
            )
        completed = True
    finally:
        if completed:
            row.update(finished_at_utc=now(), runtime_seconds=round(time.monotonic() - started, 6))
            # Commit the complete outcome before deleting temporary source inputs.
            json_write(root / "outcome.json", row)
            pe.unlink(missing_ok=True)
            (root / "input.zlib").unlink(missing_ok=True)
    return row
