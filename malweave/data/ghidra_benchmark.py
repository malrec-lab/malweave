"""Authorized CPU pilot benchmarks; signed transfers stay in the coordinator."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from hashlib import sha256
import io
import json
import math
import os
from pathlib import Path
import signal
import statistics
import subprocess
import sys
import tarfile
import threading
import time
from urllib.request import Request, urlopen

from malweave.config import PROJECT_ROOT
from malweave.data.ghidra_tools import setup_ghidra
from malweave.data.pe_routing import MANAGED_POLICY, ROUTING_VERSION, classify_pe
from malweave.data.rands_ghidra import SCRIPT_ROOT, _extension, _ghidra_command
from malweave.data.rands_ghidra_stream import _extract_view, _Processes, _save_view_output
from malweave.data.sorel_io import SorelError, digest, json_write
from malweave.training.session_storage import upload_verified


def process_tree_rss(text: str, root: int) -> int:
    rows = [tuple(map(int, line.split())) for line in text.splitlines() if line.strip()]
    descendants = {root}
    while True:
        expanded = descendants | {pid for pid, parent, _ in rows if parent in descendants}
        if expanded == descendants:
            break
        descendants = expanded
    return sum(rss * 1024 for pid, _, rss in rows if pid in descendants)


def cgroup_snapshot(root: Path = Path("/sys/fs/cgroup")) -> dict:
    """Best-effort container counters; unavailable is not zero usage or zero OOMs."""
    result = {}
    for name in ("memory.current", "memory.peak", "memory.max"):
        try:
            text = (root / name).read_text().strip()
            result[name.replace(".", "_")] = None if text == "max" else int(text)
        except (OSError, ValueError):
            pass
    for name in ("memory.events", "cpu.stat"):
        try:
            result[name.replace(".", "_")] = {
                key: int(value)
                for key, value in (line.split() for line in (root / name).read_text().splitlines())
            }
        except (OSError, ValueError):
            pass
    try:
        quota, period = (root / "cpu.max").read_text().split()
        result["cpu_quota_cores"] = None if quota == "max" else int(quota) / int(period)
    except (OSError, ValueError, ZeroDivisionError):
        pass
    return {"available": bool(result), **result}


class _Meter:
    """Sample this coordinator's process-tree RSS, not all jobs on a shared host."""

    def __init__(self):
        self.active = set()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.metrics = {
            "max_active_parser_processes": 0,
            "sampled_process_tree_peak_rss_bytes": 0,
            "rss_samples": 0,
            "rss_sampling_errors": 0,
            "rss_sampling_interval_seconds": 2,
        }
        self.thread = threading.Thread(target=self.sample, daemon=True)

    def sample(self):
        previous_cpu = None
        while not self.stop_event.is_set():
            try:
                output = subprocess.run(
                    ["ps", "-axo", "pid=,ppid=,rss="],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=True,
                    env={"PATH": os.defpath},
                ).stdout
                value = process_tree_rss(output, os.getpid())
                self.metrics["sampled_process_tree_peak_rss_bytes"] = max(
                    value, self.metrics["sampled_process_tree_peak_rss_bytes"]
                )
                self.metrics["rss_samples"] += 1
                snapshot = cgroup_snapshot()
                cpu = snapshot.get("cpu_stat", {}).get("usage_usec")
                current = time.monotonic()
                if cpu is not None and previous_cpu is not None:
                    old_cpu, old_time = previous_cpu
                    if current > old_time and cpu >= old_cpu:
                        snapshot["cpu_used_cores_interval"] = (cpu - old_cpu) / (
                            (current - old_time) * 1_000_000
                        )
                if cpu is not None:
                    previous_cpu = (cpu, current)
                self.metrics["cgroup"] = snapshot
            except (OSError, ValueError, subprocess.SubprocessError):
                self.metrics["rss_sampling_errors"] += 1
            self.stop_event.wait(2)

    def add(self, pid):
        with self.lock:
            self.active.add(pid)
            self.metrics["max_active_parser_processes"] = max(
                len(self.active), self.metrics["max_active_parser_processes"]
            )

    def remove(self, pid):
        with self.lock:
            self.active.discard(pid)


def benchmark_summary(results: list[dict], seconds: float, workers: int) -> dict:
    times = [row["seconds"] for row in results]
    successful = sum(
        all(item["status"] == "success" for item in row.get("views", []))
        and len(row.get("views", [])) == 2
        and not row.get("pending")
        and not row.get("excluded")
        for row in results
    )
    input_bytes = sum(row.get("input_bytes", 0) for row in results)
    successful_bytes = sum(
        row.get("input_bytes", 0)
        for row in results
        if len(row.get("views", [])) == 2
        and all(view["status"] == "success" for view in row["views"])
        and not row.get("pending")
        and not row.get("excluded")
    )
    buckets = {}
    for name, low, high in (
        ("below_0.1_MiB", 0, 0.1),
        ("0.1_to_1_MiB", 0.1, 1),
        ("1_to_10_MiB", 1, 10),
        ("at_least_10_MiB", 10, math.inf),
    ):
        rows = [row for row in results if low <= row.get("input_bytes", 0) / 1024**2 < high]
        buckets[name] = {
            "sources": len(rows),
            "input_bytes": sum(row.get("input_bytes", 0) for row in rows),
            "mean_seconds": statistics.mean(row["seconds"] for row in rows) if rows else None,
            "max_seconds": max((row["seconds"] for row in rows), default=None),
        }
    return {
        "sources": len(results),
        "both_views_successful": successful,
        "incomplete_or_failed": len(results)
        - successful
        - sum(bool(row.get("excluded")) for row in results),
        "excluded_dotnet": sum(bool(row.get("excluded")) for row in results),
        "excluded_input_bytes": sum(
            row.get("input_bytes", 0) for row in results if row.get("excluded")
        ),
        "pending_backend_or_review": sum(bool(row.get("pending")) for row in results),
        "workers": workers,
        "work_seconds": seconds,
        "input_bytes": input_bytes,
        "successful_input_bytes": successful_bytes,
        "sum_source_seconds": sum(times),
        "verified_source_backup_bytes": sum(row.get("backup_bytes", 0) for row in results),
        "output_bytes_including_partial": {
            name: sum(
                view.get("output_size", 0)
                for row in results
                for view in row.get("views", [])
                if view.get("view") == name
            )
            for name in ("dis", "dec")
        },
        "input_MiB_per_hour_including_failures": input_bytes / 1024**2 * 3600 / seconds
        if seconds > 0
        else None,
        "successful_input_MiB_per_hour": successful_bytes / 1024**2 * 3600 / seconds
        if seconds > 0
        else None,
        "size_buckets": buckets,
        "parser_cpu_seconds": sum(row.get("child_cpu_seconds", 0) for row in results),
        "peak_single_child_rss_bytes": max(
            (row.get("peak_child_rss_bytes", 0) for row in results), default=0
        ),
        "sources_per_hour_including_failures": len(results) * 3600 / seconds
        if seconds > 0
        else None,
        "successful_sources_per_hour": successful * 3600 / seconds if seconds > 0 else None,
        "per_source_seconds": {
            "mean": statistics.mean(times) if times else None,
            "median": statistics.median(times) if times else None,
            "max": max(times) if times else None,
        },
        "classes": {
            label: {
                "sources": sum(row["label"] == label for row in results),
                "both_views_successful": sum(
                    row["label"] == label
                    and len(row.get("views", [])) == 2
                    and all(view["status"] == "success" for view in row["views"])
                    and not row.get("pending")
                    and not row.get("excluded")
                    for row in results
                ),
                "pending_backend_or_review": sum(
                    row["label"] == label and bool(row.get("pending")) for row in results
                ),
                "excluded_dotnet": sum(
                    row["label"] == label and bool(row.get("excluded")) for row in results
                ),
            }
            for label in ("benign", "ransomware")
        },
        # A small pilot cannot establish a corpus tail or a hard batch limit.
        "conservative_12h_batch_proposal": (
            math.floor(10 * 3600 * workers / max(times))
            if times and max(times) > 0 and successful == len(results)
            else None
        ),
        "batch_basis": "10h usable, 2h reserve, observed slowest source; pilot-only proposal",
        "twelve_hour_input_MiB_proposal": (
            successful_bytes / 1024**2 * 3600 / seconds * 10 * 0.75
            if seconds > 0 and successful == len(results) and results
            else None
        ),
        "byte_batch_basis": "10h throughput with additional 25% margin; same size mix only",
        "size_alone_determines_runtime": False,
        "corpus_throughput_established": False,
    }


def unlimited_command(headless, view, source, project, output) -> list[str]:
    command = _ghidra_command(
        analyze_headless=headless,
        representation=view,
        script_root=SCRIPT_ROOT,
        source_path=source,
        project_root=project,
        output_root=output,
        timeout_per_file_seconds=0,
        timeout_per_function_seconds=0,
        analysis_timeout_per_file_seconds=0,
        max_cpu=1,
    )
    offset = command.index("-analysisTimeoutPerFile")
    del command[offset : offset + 2]
    command[command.index("-postScript") + 1] = (
        "DisassemblerUnlimited.java" if view == "dis" else "DecompilerUnlimited.java"
    )
    return command


def _unlimited_view(source, view, raw_root, job, headless, processes, heap_mb):
    begin = time.monotonic()
    sha = source["sha256"]
    root = raw_root / f"{sha}-{view}"
    root.mkdir()
    for name in ("project", "output"):
        (root / name).mkdir()
    command = unlimited_command(headless, view, raw_root / sha, root / "project", root / "output")
    json_write(job / "parser-phase.json", {"view": view, "started_at": time.time()})
    execution = processes.run(command, root, None, heap_mb)
    logs = execution["stdout"] + "\n" + execution["stderr"]
    status = "ghidra_" + execution["status"]
    if execution["status"] == "success":
        if "decompileFunction:" in logs or "run: finished (crash)" in logs:
            status = "partial_error"
        elif (
            f"run: finished (success) <{sha}>" in logs
            and "analysisTimeoutOccurred()=false" in logs
        ):
            status = "success"
        else:
            status = "unconfirmed_completion"
    result = {
        "source_sha256": sha,
        "view": view,
        "status": status,
        "execution": execution,
        "transfer": source["transfer"],
        "timeout_policy": "unlimited",
        "output_size": 0,
        "output_sha256": None,
        "output_path": None,
        "script_sha256": {
            name: digest(SCRIPT_ROOT / name)
            for name in (
                "Lifter.java",
                "Disassembler.java",
                "DisassemblerUnlimited.java",
                "DecompilerUnlimited.java",
                "SetAnalysisOptionsForDisassembly.java",
            )
        },
    }
    _save_view_output(result, root / "output" / (sha + _extension(view)), job)
    result["seconds"] = time.monotonic() - begin
    return result


def _pack_evidence(job):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
        for name in ("source-report.json", "parser-result.json", "parser.log", "routing.json"):
            if (job / name).exists():
                bundle.add(job / name, arcname=name)
        for name in ("representations", "partial"):
            if (job / name).exists():
                bundle.add(job / name, arcname=name)
    payload = archive.getvalue()
    if len(payload) > 256 * 1024**2:
        raise SorelError("Pilot evidence exceeds its bounded publication capacity.")
    return payload


def parser_source(config_path: Path) -> None:
    """Internal subprocess: no cloud URLs/keys in its configuration or environment."""
    import resource

    config = json.loads(config_path.read_text())
    source = config["source"]
    raw_root, job = Path(config["raw_root"]), Path(config["job"])
    headless = Path(config["headless"])
    processes = _Processes()

    def stop(*args):
        processes.stop()
        raise InterruptedError("Parser stopped; retain coordinator evidence.")

    signal.signal(signal.SIGTERM, stop)
    started = time.monotonic()
    views = []
    routing = None

    def checkpoint():
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        json_write(
            job / "parser-result.json",
            {
                "views": views,
                "routing": routing,
                "pending": routing is not None and routing["route"] == "pending_review",
                "excluded": routing is not None and routing["route"] == "excluded_dotnet",
                "seconds": time.monotonic() - started,
                "peak_child_rss_bytes": int(
                    usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
                ),
                "child_cpu_seconds": usage.ru_utime + usage.ru_stime,
            },
        )

    try:
        if config.get("mode") == "batch":
            routing = classify_pe((raw_root / source["sha256"]).read_bytes())
            if routing["input_sha256"] != source["sha256"]:
                raise SorelError("Routing input differs from the verified source.")
            json_write(job / "routing.json", routing)
            if routing["route"] != "ghidra_x86":
                status = (
                    "excluded_dotnet"
                    if routing["route"] == "excluded_dotnet"
                    else "deferred_pe_review"
                )
                views.extend({"view": view, "status": status} for view in ("dis", "dec"))
                return
        for view in ("dis", "dec"):
            if config.get("timeout_policy") == "unlimited":
                result = _unlimited_view(
                    source, view, raw_root, job, headless, processes, config["heap_mb"]
                )
            else:
                result = _extract_view(
                    source,
                    view,
                    raw_root,
                    job,
                    headless,
                    SCRIPT_ROOT,
                    processes,
                    config.get("heap_mb", 2048),
                )
            views.append(result)
            checkpoint()
    finally:
        processes.stop()
        checkpoint()


BATCH_MAX_SOURCES = 1000


def validate_batch_sources(sources: list[dict], *, heap_mb: int, unlimited: bool) -> None:
    """Validate a fixed-size batch manifest that is not a 10/32/64 comparison."""

    count = len(sources)
    if not 0 < count <= BATCH_MAX_SOURCES:
        raise SorelError(f"Batch manifest must hold 1..{BATCH_MAX_SOURCES} sources.")
    if len({row["sha256"] for row in sources}) != count:
        raise SorelError("Batch manifest repeats a source identity.")
    if sorted(row["index"] for row in sources) != list(range(1, count + 1)):
        raise SorelError("Batch manifest indices must run 1..count without gaps.")
    if any(row.get("metadata_arch") != "I386" for row in sources):
        raise SorelError("Batch manifest accepts metadata-I386 sources only.")
    if any(row.get("label") not in ("benign", "ransomware") for row in sources):
        raise SorelError("Batch manifest labels must be benign or ransomware.")
    if heap_mb != 1024:
        raise SorelError("Batch runs require the fixed 1 GiB heap.")
    if not unlimited:
        raise SorelError("Batch runs require unlimited analysis; no per-file deadline.")
    for row in sources:
        identity = row["sha256"]
        if len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
            raise SorelError("Invalid batch source identity.")
        if not 0 < row["bytes"] <= 256 * 1024**2:
            raise SorelError("Batch source exceeds bounded transfer capacity.")


def publish_representations(row: dict, job: Path, result: dict) -> None:
    """Publish successful views to the canonical sharded representation store."""

    routing = result.get("routing")
    if (
        result.get("pending")
        or result.get("excluded")
        or (routing and routing["route"] != "ghidra_x86")
    ):
        return
    publications = row.get("representations") or {}
    for view in result.get("views", []):
        urls = publications.get(view["view"])
        if not urls or view.get("status") != "success" or not view.get("output_path"):
            continue
        payload = (job / view["output_path"]).read_bytes()
        view["representation_sha256"] = upload_verified(urls, payload)
        view["representation_bytes"] = len(payload)
        view["representation_key"] = urls.get("key")


def run_benchmark(
    manifest_path: Path, cache_dir: Path, output_dir: Path, *, workers: int, isolated_worker: bool
) -> dict:
    overall_started = time.monotonic()
    if not isolated_worker:
        raise SorelError("Real-PE benchmark requires an authorized isolated worker.")
    if workers not in (1, 2, 3, 4, 5, 8, 12, 13, 16, 21):
        raise SorelError("Unsupported pilot worker count.")
    manifest = json.loads(manifest_path.read_text())
    sources = manifest["sources"]
    count = len(sources)
    heap_mb = manifest.get("heap_mb", 2048)
    unlimited = manifest.get("timeout_policy") == "unlimited"
    benchmark_mode = manifest.get("mode", "pilot")
    if benchmark_mode == "batch":
        validate_batch_sources(sources, heap_mb=heap_mb, unlimited=unlimited)
    elif benchmark_mode != "pilot":
        raise SorelError("Unknown benchmark manifest mode.")
    elif workers == 12:
        raise SorelError("12 workers require batch mode; legacy pilot settings are unchanged.")
    elif count == 64 and (
        workers not in (1, 2, 3, 5, 8, 13, 21) or heap_mb != 1024 or not unlimited
    ):
        raise SorelError(
            "64-source Fibonacci comparison requires fixed 1 GiB heaps and no deadlines."
        )
    if benchmark_mode == "pilot" and (
        heap_mb not in (1024, 2048)
        or (count != 64 and workers >= 4 and (count != 32 or heap_mb != 1024))
    ):
        raise SorelError("4/8/16-worker comparison requires 32 sources and fixed 1 GiB heaps.")
    if benchmark_mode == "pilot" and (
        count not in (10, 32, 64)
        or len({row["sha256"] for row in sources}) != count
        or sorted(row["index"] for row in sources) != list(range(1, count + 1))
        or any(row["metadata_arch"] != "I386" for row in sources)
        or {
            label: sum(row["label"] == label for row in sources)
            for label in ("benign", "ransomware")
        }
        != {"benign": count // 2, "ransomware": count // 2}
    ):
        raise SorelError("Expected 10, 32 or 64 unique, balanced I386 pilot sources.")
    if benchmark_mode == "pilot":
        for row in sources:
            if len(row["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in row["sha256"]):
                raise SorelError("Invalid pilot source identity.")
            if not 0 < row["bytes"] <= 256 * 1024**2:
                raise SorelError("Pilot source exceeds bounded transfer capacity.")
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise SorelError("Benchmark output exists; use a new attempt and preserve receipts.")
    tools = setup_ghidra(cache_dir)
    startup_seconds = time.monotonic() - overall_started
    scratch = cache_dir.resolve().parent / (
        f"ghidra-benchmark-w{workers}-" + sha256(manifest["contract"].encode()).hexdigest()[:12]
    )
    scratch.mkdir(parents=True, mode=0o700, exist_ok=False)
    output_dir.mkdir(parents=True, mode=0o700)
    environment = {
        "PATH": str(Path(tools["java_home"]) / "bin") + os.pathsep + os.defpath,
        "JAVA_HOME": tools["java_home"],
        "LANG": "C.UTF-8",
        "JAVA_TOOL_OPTIONS": "-Djava.awt.headless=true",
    }
    results = []
    inflight = {}
    started = time.monotonic()
    report = {
        "status": "running",
        "mode": benchmark_mode,
        "batch_id": manifest.get("batch_id"),
        "tier": manifest.get("tier"),
        "contract": manifest["contract"],
        "workers": workers,
        "heap_mb": heap_mb,
        "timeout_policy": "unlimited" if unlimited else "legacy_bounded",
        "routing_policy": ROUTING_VERSION if benchmark_mode == "batch" else "legacy_pilot",
        "managed_policy": MANAGED_POLICY if benchmark_mode == "batch" else "legacy_pilot",
        "tools": tools,
        "host_cpu_count": os.cpu_count(),
        "gpu_requested": False,
        "source_count": count,
        "planned_input_bytes": sum(row["bytes"] for row in sources),
        "startup_seconds": startup_seconds,
        "bootstrap_seconds": manifest.get("bootstrap_seconds"),
        "results": results,
        "sampling": manifest["sampling"],
        "source_plan_sha256": manifest["source_plan_sha256"],
        "isolation_note": "Dedicated authorized Kaggle worker; environment scrubbing is not a sandbox.",
    }
    meter = _Meter()
    meter.thread.start()

    def save():
        report["resources"] = dict(meter.metrics)
        report["inflight"] = dict(inflight)
        report["seconds"] = time.monotonic() - started
        deferred = sum(bool(row.get("pending")) for row in results)
        report["recorded_attempts"] = len(results)
        report["terminal_sources"] = len(results) - deferred
        report["unfinished_sources"] = count - report["terminal_sources"]
        report["pending_sources"] = [
            {
                "index": row["index"],
                "source_sha256": row["source_sha256"],
                "label": row["label"],
                "route": row["routing"]["route"],
                "reason": row["routing"]["reason"],
            }
            for row in results
            if row.get("pending")
        ]
        report["excluded_sources"] = [
            {
                "index": row["index"],
                "source_sha256": row["source_sha256"],
                "label": row["label"],
                "reason": row["routing"]["reason"],
            }
            for row in results
            if row.get("excluded")
        ]
        report["summary"] = benchmark_summary(results, report["seconds"], workers)
        report["remaining_representation_sources"] = (
            count
            - report["summary"]["both_views_successful"]
            - report["summary"]["excluded_dotnet"]
        )
        report["total_seconds_including_startup"] = report["seconds"] + startup_seconds
        if report["bootstrap_seconds"] is not None:
            report["total_seconds_including_bootstrap"] = (
                report["total_seconds_including_startup"] + report["bootstrap_seconds"]
            )
        json_write(output_dir / "benchmark-report.json", report)
        upload_verified(manifest["progress"], (output_dir / "benchmark-report.json").read_bytes())
        print(
            json.dumps(
                {
                    "completed": report["summary"]["both_views_successful"],
                    "recorded_attempts": len(results),
                    "pending_backend_or_review": deferred,
                    "excluded_dotnet": report["summary"]["excluded_dotnet"],
                    "workers": workers,
                    "seconds": report["seconds"],
                    "status": report["status"],
                }
            ),
            flush=True,
        )

    def one(row: dict) -> dict:
        begin = time.monotonic()
        sha = row["sha256"]
        job = output_dir / f"source-{row['index']:02d}"
        job.mkdir(mode=0o700)
        raw = scratch / f"raw-{row['index']:02d}"
        raw.mkdir(mode=0o700)
        path = raw / sha
        result = {
            "index": row["index"],
            "source_sha256": sha,
            "label": row["label"],
            "input_bytes": row["bytes"],
            "metadata_packed": row["metadata_packed"],
            "s3_key": row["key"],
            "s3_etag": row["etag"],
            "views": [],
            "status": "started",
        }
        try:
            transfer_start = time.monotonic()
            request = Request(row["download"], headers={"If-Match": row["etag"]})
            with urlopen(request, timeout=180) as response, path.open("wb") as stream:
                actual = 0
                while block := response.read(1024 * 1024):
                    actual += len(block)
                    if actual > row["bytes"]:
                        raise SorelError("Source download exceeds its audited size.")
                    stream.write(block)
            if path.stat().st_size != row["bytes"] or digest(path) != sha:
                raise SorelError("Downloaded source differs from its frozen identity.")
            source = {
                "sha256": sha,
                "transfer": {
                    "status": "verified",
                    "input_sha256": sha,
                    "bytes": row["bytes"],
                    "seconds": time.monotonic() - transfer_start,
                },
                # This Ghidra-only pilot does not invent or require a DiE admission claim.
                "die_evidence_sha256": None,
            }
            config = {
                "mode": benchmark_mode,
                "source": source,
                "raw_root": str(raw),
                "job": str(job),
                "headless": tools["analyze_headless"],
                "heap_mb": heap_mb,
                "timeout_policy": "unlimited" if unlimited else "legacy_bounded",
            }
            config_path = job / "parser-config.json"
            json_write(config_path, config)
            command = [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path;from malweave.data.ghidra_benchmark import parser_source;"
                    f"parser_source(Path({str(config_path)!r}))"
                ),
            ]
            with (job / "parser.log").open("wb") as log:
                process = subprocess.Popen(
                    command,
                    cwd=PROJECT_ROOT,
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                meter.add(process.pid)
                inflight[str(row["index"])] = {
                    "phase": "parser_start",
                    "parser_pid": process.pid,
                    "published_views": [],
                }
                try:
                    if unlimited:
                        published = set()
                        while True:
                            try:
                                process.wait(timeout=5)
                                done = True
                            except subprocess.TimeoutExpired:
                                done = False
                            phase_path = job / "parser-phase.json"
                            if phase_path.exists():
                                phase = json.loads(phase_path.read_text())
                                view_name = phase["view"]
                                progress = inflight[str(row["index"])]
                                progress.update(
                                    phase=view_name,
                                    phase_seconds=max(0, time.time() - phase["started_at"]),
                                )
                                stdout = raw / f"{sha}-{view_name}" / "stdout"
                                if stdout.exists():
                                    with stdout.open("rb") as stream:
                                        stream.seek(max(0, stdout.stat().st_size - 4096))
                                        progress["log_tail"] = stream.read().decode(
                                            "utf-8", errors="replace"
                                        )[-1500:]
                            if (job / "parser-result.json").exists():
                                checkpoint = json.loads((job / "parser-result.json").read_text())
                                for view in checkpoint["views"]:
                                    name = view["view"]
                                    if name not in published and name in row.get(
                                        "view_backups", {}
                                    ):
                                        checksum = upload_verified(
                                            row["view_backups"][name], _pack_evidence(job)
                                        )
                                        published.add(name)
                                        inflight[str(row["index"])].update(
                                            published_views=sorted(published),
                                            latest_view_sha256=checksum,
                                        )
                            if done:
                                break
                    else:
                        process.wait(timeout=1320)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    raise SorelError("Bounded source parser timeout.") from None
                finally:
                    meter.remove(process.pid)
            if (job / "parser-result.json").exists():
                result.update(json.loads((job / "parser-result.json").read_text()))
            result["parser_returncode"] = process.returncode
            result["status"] = (
                "excluded_dotnet"
                if result.get("excluded")
                else "deferred_pending_backend_or_review"
                if result.get("pending")
                else "success"
                if process.returncode == 0
                and len(result["views"]) == 2
                and all(view["status"] == "success" for view in result["views"])
                else "failed_or_partial"
            )
            publish_representations(row, job, result)
        except (OSError, SorelError, ValueError, subprocess.SubprocessError) as error:
            result.update(status="failed", error_type=type(error).__name__)
        result["analysis_and_download_seconds"] = time.monotonic() - begin
        json_write(job / "source-report.json", result)
        payload = _pack_evidence(job)
        result["backup_sha256"] = upload_verified(row["backup"], payload)
        result["backup_bytes"] = len(payload)
        result["seconds"] = time.monotonic() - begin
        json_write(job / "receipt.json", result)
        # Delete only the exact immutable input copy after remote output verification.
        path.unlink(missing_ok=True)
        inflight.pop(str(row["index"]), None)
        return result

    save()
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending = {pool.submit(one, row) for row in sources}
            while pending:
                done, pending = wait(pending, timeout=60, return_when=FIRST_COMPLETED)
                for future in done:
                    results.append(future.result())
                save()
        report["summary"] = benchmark_summary(results, time.monotonic() - started, workers)
        report["status"] = (
            "partial"
            if report["summary"]["incomplete_or_failed"]
            else "completed_with_exclusions"
            if report["summary"]["excluded_dotnet"]
            else "completed"
        )
    except Exception as error:
        report.update(status="failed", coordinator_error_type=type(error).__name__)
        raise
    finally:
        meter.stop_event.set()
        meter.thread.join(timeout=5)
        save()
    return report
