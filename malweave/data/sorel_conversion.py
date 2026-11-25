"""Continuous, bounded SOREL v3 coordinator; no training dependencies or PE execution."""

from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import closing
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import sqlite3
import sys
import threading
import time
from typing import Any
from uuid import uuid4

import lief

from malweave.data import sorel_protocol as state
from malweave.data import sorel_stage as stages
from malweave.data.sorel_io import SorelError, digest, job_lock, json_write
from malweave.data.sorel_publication import AWS, Store, restore, snapshot
from malweave.data.sorel_tools import Processes, rule_digest

ROOT = Path(__file__).resolve().parents[2]


def log(event: str, **values: Any) -> None:
    print(state.canonical({"event": event, **values}), file=sys.stderr, flush=True)


def tool_identity(job: Path, processes: Processes) -> dict[str, Any]:
    tools = {}
    root = job / "tool-checks" / uuid4().hex
    for name in ("curl", "file", "diec"):
        executable = shutil.which(name)
        if not executable:
            raise SorelError("Missing conversion prerequisite: " + name)
        path = Path(executable).resolve()
        result = processes.run([str(path), "--version"], root, name, timeout=10)
        if result["status"] != "success":
            raise SorelError("Tool version probe failed: " + name)
        tools[name] = {
            "path": str(path),
            "sha256": digest(path),
            "version": (root / result["stdout_file"]).read_text().strip(),
            "probe": result,
        }
    base = Path(tools["diec"]["path"]).parent
    if not (base / "db").is_dir():
        raise SorelError("DiE signature directory missing beside diec")
    tools["diec"]["signature_sha256"] = rule_digest(base / "db")
    tools["diec"]["custom_signature_sha256"] = rule_digest(base / "db_custom")
    tools["diec"]["libraries"] = {
        p.name: digest(p) for p in sorted(base.glob("*.so*")) if p.is_file()
    }
    tools["file"]["magic"] = {}
    for path in (Path("/usr/share/misc/magic.mgc"), Path("/usr/lib/file/magic.mgc")):
        if path.is_file():
            tools["file"]["magic"][path.name] = digest(path)
    tools["lief"] = {"version": lief.__version__, "sha256": digest(Path(lief.__file__))}
    tools["python"] = {
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
    }
    return tools


def freeze(job: Path, selection: dict[str, Any], tools: dict[str, Any]) -> dict[str, Any]:
    identities = {
        name: {key: value for key, value in identity.items() if key not in ("path", "probe")}
        for name, identity in tools.items()
    }
    code = {
        name: digest(Path(__file__).parent / name)
        for name in (
            "sorel_stage.py",
            "pe_identity.py",
            "pe_worker.py",
            "pe_sections.py",
            "pe_assessment.py",
        )
    }
    value = {
        "schema": 3,
        "rules": selection["rules"],
        "sources_sha256": selection["sources_sha256"],
        "metadata_sha256": selection["metadata_sha256"],
        "tools": identities,
        "code": code,
    }
    cohort = {
        **value,
        "rules": {k: v for k, v in value["rules"].items() if k != "partition_index"},
    }
    cohort.pop("sources_sha256")
    identity = {
        "sha256": sha256(state.canonical(value).encode()).hexdigest(),
        "value": value,
        "cohort_sha256": sha256(state.canonical(cohort).encode()).hexdigest(),
    }
    path = job / "protocol.json"
    if path.exists() and json.loads(path.read_text()) != identity:
        raise SorelError(
            "Scientific rules, source selection, code or tool identities changed; resume rejected"
        )
    json_write(path, identity)
    return identity


def status(job: Path) -> dict[str, Any]:
    selected = state.selection(job)
    with closing(
        sqlite3.connect((job / "state.sqlite").resolve().as_uri() + "?mode=ro", uri=True)
    ) as db:
        return state.summary(db, selected["selected"])


def request_retry(db: sqlite3.Connection, statuses: list[str]) -> int:
    if not statuses or any(s == "success" or s.startswith("filtered_") for s in statuses):
        raise SorelError(
            "Explicit retry accepts failed/deferred statuses, not success or filtered outcomes"
        )
    with db:
        placeholders = ",".join("?" for _ in statuses)
        result = db.execute(
            "UPDATE sources SET done=0,retry_requested=1 WHERE id IN (SELECT id FROM current "
            "WHERE json_extract(value,'$.status') IN (" + placeholders + "))",
            statuses,
        )
    return result.rowcount


class Progress:
    def __init__(self, job: Path, selected: int, start: dict[str, Any]):
        self.job, self.selected, self.start = job, selected, start
        self.started = time.monotonic()
        self.window = deque([(self.started, 0)])
        self.last_published = 0
        self.initial_cpu = time.process_time()
        self.initial_children_cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
        self.net = self.network()

    @staticmethod
    def network() -> dict[str, int]:
        values = {"rx": 0, "tx": 0}
        try:
            for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
                name, stats = line.split(":", 1)
                if name.strip() == "lo":
                    continue
                numbers = stats.split()
                values["rx"] += int(numbers[0])
                values["tx"] += int(numbers[8])
        except (OSError, ValueError, IndexError):
            pass
        return values

    def emit(
        self,
        db: sqlite3.Connection,
        *,
        active: int,
        queued: int,
        phase: str,
        aws: AWS | None = None,
    ) -> dict[str, Any]:
        value = state.summary(db, self.selected)
        current = time.monotonic()
        elapsed = max(0.000001, current - self.started)
        published = value["published_sources"] - self.start["published_sources"]
        processed = value["processing_attempts"] - self.start["processing_attempts"]
        self.window.append((current, published))
        while len(self.window) > 2 and self.window[1][0] < current - 300:
            self.window.popleft()
        period = current - self.window[0][0]
        recent_rate = (published - self.window[0][1]) / period if period >= 300 else 0
        usage = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        child_cpu = (
            children.ru_utime
            + children.ru_stime
            - self.initial_children_cpu.ru_utime
            - self.initial_children_cpu.ru_stime
        )
        cpu_seconds = time.process_time() - self.initial_cpu + child_cpu
        network = self.network()
        value.update(
            elapsed_seconds=round(elapsed, 3),
            phase=phase,
            active_workers=active,
            queued_publication_sources=queued,
            run_processing_attempts=processed,
            run_published_sources=published,
            processed_sources_per_second=round(processed / elapsed, 4),
            published_sources_per_second=round(max(0, published) / elapsed, 4),
            recent_publication_rate=round(recent_rate, 4) if recent_rate else None,
            eta_seconds=round(value["pending_sources"] / recent_rate) if recent_rate else None,
            cpu_seconds_completed_processes=round(cpu_seconds, 3),
            cpu_cores_average_completed_processes=round(cpu_seconds / elapsed, 3),
            coordinator_peak_rss_bytes=usage.ru_maxrss * 1024,
            children_peak_rss_bytes=children.ru_maxrss * 1024,
            disk_free_bytes=shutil.disk_usage(self.job).free,
            host_network_rx_bytes=network["rx"] - self.net["rx"],
            host_network_tx_bytes=network["tx"] - self.net["tx"],
            s3_traffic=dict(aws.metrics) if aws else {},
        )
        log("progress", **value)
        return value


def _local_pending(db: sqlite3.Connection, job: Path, count: int) -> list[dict[str, Any]]:
    rows = []
    for (value,) in db.execute(
        "SELECT value FROM history WHERE published=0 AND json_extract(value,'$.storage_status')!='missing_local_evidence' ORDER BY id,attempt LIMIT ?",
        (count,),
    ):
        row = json.loads(value)
        if row.get("storage_status") == "missing_local_evidence":
            continue
        path = (job / row.get("local_work_dir", "missing")).resolve()
        if path.is_relative_to((job / "work").resolve()) and (path / "outcome.json").is_file():
            rows.append(row)
        else:
            row.update(
                storage_status="missing_local_evidence",
                local_evidence_status="missing_after_restore",
            )
            with db:
                db.execute(
                    "UPDATE history SET value=? WHERE id=? AND attempt=?",
                    (state.canonical(row), row["original_sha256"], row["attempt"]),
                )
                db.execute(
                    "UPDATE current SET value=? WHERE id=? AND attempt=?",
                    (state.canonical(row), row["original_sha256"], row["attempt"]),
                )
                db.execute("UPDATE sources SET done=0 WHERE id=?", (row["original_sha256"],))
    return rows


def run(
    job: Path,
    metadata: Path,
    rules: state.Rules,
    runtime: state.Runtime,
    *,
    prefix: str | None = None,
    limit: int | None = None,
    takeover: str | None = None,
    retry: list[str] | None = None,
    benchmark: bool = False,
) -> dict[str, Any]:
    if limit is not None and limit < 1:
        raise SorelError("--limit must be positive")
    if benchmark and (rules.partition_index != 1 or limit != 1000):
        raise SorelError("The acceptance benchmark is the first 1000 sources of part 1")
    job = job.resolve()
    with job_lock(job):
        processes = Processes()
        aws = AWS(job, processes, runtime.upload_timeout_seconds) if prefix else None
        if prefix:
            AWS.split(prefix)
        stop = threading.Event()
        interrupted = 0
        old_handler = signal.getsignal(signal.SIGINT)

        def interrupt(signum, frame):
            nonlocal interrupted
            interrupted += 1
            stop.set()
            log(
                "stopping" if interrupted == 1 else "aborting",
                message="draining" if interrupted == 1 else "local state retained",
            )
            if interrupted >= 2:
                processes.terminate()

        signal.signal(signal.SIGINT, interrupt)
        setup_started = time.monotonic()
        setup_done = threading.Event()

        def setup_heartbeat():
            while not setup_done.wait(5):
                log("setup", elapsed_seconds=round(time.monotonic() - setup_started, 2))

        heartbeat = threading.Thread(target=setup_heartbeat, daemon=True)
        heartbeat.start()
        owner_etag = None
        store = None
        db = None
        active = {}
        waiting = deque()
        upload_future = None
        upload_count = 0
        checkpoint_future = None
        checkpoint_path = None
        saved = None
        fatal = None
        try:
            if limit is None or limit > 1000:
                report = job / "release-audit.json"
                sibling = job.parent / "part-01/release-audit.json"
                if not report.exists() and sibling.exists():
                    report = sibling
                if not report.exists() and prefix:
                    aws.get(
                        prefix.rsplit("/part-", 1)[0] + "/main/release-audit.json",
                        report,
                        missing=True,
                    )
                early = json.loads(report.read_text()) if report.exists() else {}
                if not early.get("full_launch_ready"):
                    raise SorelError(
                        "Full launch requires the completed benchmark and reviewed release audit"
                    )
            if prefix:
                owner = {
                    "schema": 3,
                    "token": uuid4().hex,
                    "host": platform.node(),
                    "pid": os.getpid(),
                    "started_at_utc": state.now(),
                }
                owner_etag = aws.acquire(prefix, owner, takeover)
                log("ownership_acquired", token=owner["token"], prefix=prefix)
            marker = job / "restore-in-progress.json"
            if marker.exists():
                # Only provisional snapshot files may be replaced; no work has started yet.
                from malweave.data.sorel_publication import SNAPSHOT_FILES

                for name in SNAPSHOT_FILES | {
                    "state.sqlite-wal",
                    "state.sqlite-shm",
                    "latest.json",
                }:
                    (job / name).unlink(missing_ok=True)
                marker.unlink()
            if not (job / "selection.json").exists():
                if (job / "state.sqlite").exists():
                    raise SorelError(
                        "Incomplete preparation; preserve this directory and use a fresh job"
                    )
                if not prefix or not restore(job, prefix, aws, missing=True):
                    state.prepare(metadata, job, rules)
            selected = state.selection(job, rules)
            if benchmark:
                from malweave.data.sorel_setup import METADATA_SHA256

                if (
                    selected["total_malware"] != 9962820
                    or selected["metadata_sha256"] != METADATA_SHA256
                ):
                    raise SorelError(
                        "Acceptance benchmark requires the pinned official SOREL metadata"
                    )
                with closing(sqlite3.connect(job / "state.sqlite")) as check:
                    count = check.execute("SELECT COUNT(*) FROM current").fetchone()[0]
                    beyond = check.execute(
                        "SELECT COUNT(*) FROM current c JOIN sources s ON c.id=s.id WHERE s.ordinal>=1000"
                    ).fetchone()[0]
                    if count > 1000 or beyond:
                        raise SorelError(
                            "Benchmark must be confined to the first 1000 sources of part 1"
                        )
                    limit = 1000 - count
            tools = tool_identity(job, processes)
            identity = freeze(job, selected, tools)
            if limit is None or limit > 1000:
                report = job / "release-audit.json"
                sibling = job.parent / "part-01/release-audit.json"
                if not report.exists() and sibling.exists():
                    report = sibling
                if not report.exists() and prefix:
                    remote_report = prefix.rsplit("/part-", 1)[0] + "/main/release-audit.json"
                    aws.get(remote_report, report, missing=True)
                reviewed = json.loads(report.read_text()) if report.exists() else {}
                if (
                    not reviewed.get("full_launch_ready")
                    or reviewed.get("cohort_sha256") != identity["cohort_sha256"]
                    or reviewed.get("source_tree_sha256") != source_tree_digest()
                ):
                    raise SorelError(
                        "Full launch requires a passing release audit for this exact protocol/code"
                    )
            runtime = state.resolve_runtime(runtime, job)
            if runtime.upload_queue_sources < runtime.workers:
                raise SorelError("Upload queue capacity must be at least the worker count")
            if runtime.memory_per_task_bytes * runtime.workers > runtime.memory_budget_bytes:
                raise SorelError("Worker memory allowances exceed the total memory budget")
            db = state.connect(job)
            if prefix:
                store = Store(job, prefix, aws, runtime)
                log("replay", recovered_sources=store.replay(db))
            # Recover local outcomes committed to disk just before an interrupted SQLite commit.
            for path in (job / "work").glob("*/attempt-*/outcome.json"):
                row = json.loads(path.read_text())
                if row.get("protocol_sha256") == identity["sha256"]:
                    state.record(db, row)
            run_id = uuid4().hex
            environment = {
                "id": run_id,
                "benchmark": benchmark,
                "started_at_utc": state.now(),
                "rules": asdict(rules),
                "runtime": asdict(runtime),
                "tools": tools,
                "protocol_sha256": identity["sha256"],
                "platform": platform.platform(),
                "python": sys.version,
                "setup_seconds": round(time.monotonic() - setup_started, 3),
                "container_image": os.environ.get("MALWEAVE_WORKER_IMAGE_DIGEST", "not_recorded"),
            }
            json_write(job / "runs" / (run_id + ".json"), environment)
            with db:
                db.execute("INSERT INTO runs VALUES(?,?)", (run_id, state.canonical(environment)))
            if retry:
                if not store and (job / "remote.json").exists():
                    raise SorelError("An S3-backed part must resume with its saved S3 destination")
                log("retry_requested", sources=request_retry(db, retry), statuses=retry)
            if not prefix and (job / "remote.json").exists():
                raise SorelError(
                    "An S3-backed part requires --s3-prefix for publication and ownership"
                )
            if store:
                # Reset lost unpublished inputs before selecting pending sources. Preserve history.
                for (value,) in db.execute("SELECT value FROM history WHERE published=0"):
                    row = json.loads(value)
                    path = job / row.get("local_work_dir", "missing") / "outcome.json"
                    if not path.is_file():
                        row.update(
                            storage_status="missing_local_evidence",
                            local_evidence_status="missing_after_restore",
                        )
                        with db:
                            db.execute(
                                "UPDATE history SET value=? WHERE id=? AND attempt=?",
                                (state.canonical(row), row["original_sha256"], row["attempt"]),
                            )
                            db.execute(
                                "UPDATE current SET value=? WHERE id=? AND attempt=?",
                                (state.canonical(row), row["original_sha256"], row["attempt"]),
                            )
                            db.execute(
                                "UPDATE sources SET done=0 WHERE id=?", (row["original_sha256"],)
                            )
                waiting.extend(_local_pending(db, job, runtime.upload_queue_sources))
            progress = Progress(job, selected["selected"], state.summary(db, selected["selected"]))
            setup_done.set()
            heartbeat.join()
            log(
                "ready",
                **{
                    k: v
                    for k, v in environment.items()
                    if k in ("runtime", "setup_seconds", "protocol_sha256")
                },
            )
            submitted, after = 0, -1
            buffered = deque()
            last_log = last_group = last_checkpoint = time.monotonic()
            last_disk_check = 0.0
            disk_used = 0
            with (
                ThreadPoolExecutor(max_workers=runtime.workers) as workers,
                ThreadPoolExecutor(max_workers=2) as background,
            ):
                if store:
                    checkpoint_path = snapshot(db, job)
                    checkpoint_future = background.submit(store.checkpoint, checkpoint_path)
                while True:
                    if checkpoint_future and checkpoint_future.done():
                        try:
                            checkpoint_future.result()
                        except Exception as error:  # noqa: BLE001 -- stop scheduling and retain every active result
                            fatal = fatal or error
                            stop.set()
                            log("fatal", stage="snapshot", error=str(error))
                        shutil.rmtree(checkpoint_path)
                        checkpoint_future = checkpoint_path = None
                        last_checkpoint = time.monotonic()
                    if upload_future and upload_future.done():
                        try:
                            rows, group = upload_future.result()
                            state.publish(db, rows, group)
                            store.cleanup(rows)
                            queued = {(row["original_sha256"], row["attempt"]) for row in waiting}
                            extra = _local_pending(
                                db, job, max(0, runtime.upload_queue_sources - len(active))
                            )
                            waiting.extend(
                                row
                                for row in extra
                                if (row["original_sha256"], row["attempt"]) not in queued
                            )
                        except Exception as error:  # noqa: BLE001 -- stop scheduling and retain every active result
                            fatal = fatal or error
                            stop.set()
                            log("fatal", stage="upload", error=str(error))
                        upload_future = None
                        upload_count = 0
                        last_group = time.monotonic()
                    for future in [f for f in active if f.done()]:
                        item = active.pop(future)
                        try:
                            row = future.result()
                            row["protocol_sha256"] = identity["sha256"]
                            work = job / row["local_work_dir"]
                            row["local_publication_bytes"] = sum(
                                p.stat().st_size for p in work.iterdir() if p.is_file()
                            )
                            json_write(work / "outcome.json", row)
                            state.record(db, row)
                            if store:
                                waiting.append(row)
                        except InterruptedError:
                            stop.set()
                        except Exception as error:  # noqa: BLE001 -- stop scheduling and retain every active result
                            fatal = fatal or error
                            stop.set()
                            log("fatal", stage="source", error=str(error))
                    current = time.monotonic()
                    if (
                        store
                        and waiting
                        and not upload_future
                        and not fatal
                        and not processes.abort.is_set()
                    ):
                        group_bytes = sum(
                            row.get("local_publication_bytes") or row.get("exe_bytes") or 0
                            for row in waiting
                        )
                        if (
                            len(waiting) >= runtime.upload_sources
                            or group_bytes >= runtime.upload_bytes
                            or current - last_group >= runtime.upload_interval_seconds
                            or stop.is_set()
                            or not active
                        ):
                            group_rows = []
                            group_size = 0
                            while waiting and len(group_rows) < runtime.upload_sources:
                                size = (
                                    waiting[0].get("local_publication_bytes")
                                    or waiting[0].get("exe_bytes")
                                    or 0
                                )
                                if group_rows and group_size + size > runtime.upload_bytes:
                                    break
                                group_rows.append(waiting.popleft())
                                group_size += size
                            upload_count = len(group_rows)
                            published_digests = {
                                row["exe_sha256"]
                                for row in group_rows
                                if row.get("exe_sha256")
                                and db.execute(
                                    "SELECT 1 FROM outputs WHERE digest=? AND published=1",
                                    (row["exe_sha256"],),
                                ).fetchone()
                            }
                            upload_future = background.submit(
                                store.upload_group, group_rows, published_digests
                            )
                    if current - last_disk_check >= 5:
                        disk_used = sum(
                            p.stat().st_size for p in (job / "work").rglob("*") if p.is_file()
                        )
                        last_disk_check = current
                    free = shutil.disk_usage(job).free
                    allowance = runtime.disk_budget_bytes // (
                        runtime.workers + runtime.upload_queue_sources
                    )
                    disk_ready = (
                        free > runtime.min_free_bytes + max(1024**2, allowance)
                        and disk_used + max(1024**2, allowance) <= runtime.disk_budget_bytes
                    )
                    capacity = len(active) + len(waiting) + upload_count
                    while (
                        not stop.is_set()
                        and len(active) < runtime.workers
                        and (limit is None or submitted < limit)
                        and disk_ready
                        and (not store or capacity < runtime.upload_queue_sources)
                    ):
                        if not buffered:
                            buffered.extend(state.pending(db, runtime.fetch_batch, after))
                        if not buffered:
                            break
                        item = buffered.popleft()
                        after = item["ordinal"]
                        previous = db.execute(
                            "SELECT value FROM current WHERE id=?", (item["original_sha256"],)
                        ).fetchone()
                        previous_row = json.loads(previous[0]) if previous else None
                        if previous_row:
                            old = job / previous_row.get("local_work_dir", "missing") / "die.json"
                            previous_row["reusable_die_path"] = str(old) if old.is_file() else ""
                        future = workers.submit(
                            stages.process,
                            item,
                            job,
                            rules,
                            runtime,
                            tools,
                            processes,
                            run_id,
                            previous_row,
                        )
                        active[future] = item
                        submitted += 1
                        capacity += 1
                    no_more = not buffered and not state.pending(db, 1, after)
                    finished_processing = (
                        stop.is_set() or (limit is not None and submitted >= limit) or no_more
                    )
                    if (
                        not disk_ready
                        and not active
                        and not upload_future
                        and not waiting
                        and not finished_processing
                    ):
                        fatal = fatal or SorelError(
                            "Insufficient disk budget/free space; local progress retained"
                        )
                        stop.set()
                        log("fatal", stage="disk", error=str(fatal))
                    if current - last_log >= runtime.progress_seconds:
                        saved = progress.emit(
                            db,
                            active=len(active),
                            queued=len(waiting) + upload_count,
                            phase="draining"
                            if stop.is_set()
                            else "processing"
                            if active
                            else "publishing",
                            aws=aws,
                        )
                        last_log = current
                    if (
                        store
                        and not checkpoint_future
                        and not fatal
                        and not processes.abort.is_set()
                        and current - last_checkpoint >= runtime.checkpoint_seconds
                    ):
                        checkpoint_path = snapshot(db, job)
                        checkpoint_future = background.submit(store.checkpoint, checkpoint_path)
                    if finished_processing and not active:
                        if fatal or processes.abort.is_set():
                            if not upload_future and not checkpoint_future:
                                break
                        elif not waiting and not upload_future and not checkpoint_future:
                            break
                    futures = list(active)
                    if upload_future:
                        futures.append(upload_future)
                    if checkpoint_future:
                        futures.append(checkpoint_future)
                    if futures:
                        wait(futures, timeout=0.1, return_when=FIRST_COMPLETED)
                    else:
                        processes.abort.wait(0.1)
                if not fatal and not processes.abort.is_set():
                    if store:
                        checkpoint_path = snapshot(db, job)
                        checkpoint_future = background.submit(store.checkpoint, checkpoint_path)
                        while not checkpoint_future.done():
                            if time.monotonic() - last_log >= runtime.progress_seconds:
                                progress.emit(
                                    db, active=0, queued=0, phase="final_snapshot", aws=aws
                                )
                                last_log = time.monotonic()
                            wait([checkpoint_future], timeout=0.1)
                        checkpoint_future.result()
                        shutil.rmtree(checkpoint_path)
                    else:
                        state.csv_export(db, job / "results.csv")
            saved = progress.emit(
                db,
                active=0,
                queued=len(waiting) + upload_count,
                phase="failed"
                if fatal
                else "aborted"
                if processes.abort.is_set()
                else "stopped"
                if stop.is_set()
                else "complete",
                aws=aws,
            )
            saved["run_id"] = run_id
            saved["setup_seconds"] = environment["setup_seconds"]
            saved["protocol_sha256"] = identity["sha256"]
            json_write(job / "summary.json", saved)
            json_write(job / "runs" / (run_id + "-summary.json"), saved)
            if benchmark:
                saved["benchmark_sources_completed"] = db.execute(
                    "SELECT COUNT(*) FROM current c JOIN sources s ON s.id=c.id WHERE s.ordinal<1000"
                ).fetchone()[0]
                json_write(job / "benchmark-1000.json", saved)
            with db:
                db.execute(
                    "UPDATE runs SET value=? WHERE id=?",
                    (state.canonical({**environment, "summary": saved}), run_id),
                )
            if store and not fatal and not processes.abort.is_set():
                aws.put(job / "summary.json", prefix + "/main/run-summary.json")
                if benchmark:
                    aws.put(job / "benchmark-1000.json", prefix + "/main/benchmark-1000.json")
            if owner_etag and not fatal and not processes.abort.is_set():
                aws.release(prefix, owner_etag)
                owner_etag = None
            if fatal:
                raise SorelError(str(fatal)) from fatal
            if processes.abort.is_set():
                raise SorelError(
                    "Aborted; local progress preserved. Remote ownership is retained for explicit takeover"
                )
            return saved
        except BaseException as error:
            log("fatal", error=str(error), remote_ownership_retained=bool(owner_etag))
            raise
        finally:
            setup_done.set()
            heartbeat.join(timeout=1)
            signal.signal(signal.SIGINT, old_handler)
            if db is not None:
                db.close()


def source_tree_digest() -> str:
    paths = [ROOT / "pyproject.toml", ROOT / "uv.lock", ROOT / "Dockerfile.sorel"]
    for folder, pattern in (("malweave", "*.py"), ("tests", "*.py"), ("configs", "*.yaml")):
        paths.extend((ROOT / folder).rglob(pattern))
    result = sha256()
    for path in sorted(paths):
        if path.is_file():
            result.update(path.relative_to(ROOT).as_posix().encode())
            result.update(bytes.fromhex(digest(path)))
    return result.hexdigest()


def audit(job: Path) -> dict[str, Any]:
    selected = state.selection(job)
    benchmark = (
        json.loads((job / "benchmark-1000.json").read_text())
        if (job / "benchmark-1000.json").exists()
        else {}
    )
    value = status(job)
    with closing(sqlite3.connect(job / "state.sqlite")) as db:
        rows = db.execute(
            "SELECT s.ordinal,c.value,c.published FROM sources s JOIN current c ON c.id=s.id ORDER BY s.ordinal LIMIT 1000"
        ).fetchall()
        schema_ok = all(set(state.CSV_FIELDS).issubset(json.loads(row[1])) for row in rows)
        integrity = db.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        unknown = db.execute(
            "SELECT COUNT(*) FROM current WHERE json_extract(value,'$.status')='deferred_architecture'"
        ).fetchone()[0]
    tree = source_tree_digest()
    validation_file = ROOT / "reports/sorel-v3/repository-checks.json"
    image_file = ROOT / "reports/sorel-v3/image.json"
    validation = json.loads(validation_file.read_text()) if validation_file.exists() else {}
    image = json.loads(image_file.read_text()) if image_file.exists() else {}
    with closing(sqlite3.connect(job / "state.sqlite")) as db:
        runtime_images = {
            json.loads(value).get("container_image")
            for (value,) in db.execute("SELECT value FROM runs")
        }
    protocol = json.loads((job / "protocol.json").read_text())
    checks = {
        "database_integrity": integrity,
        "fixed_schema": schema_ok,
        "consecutive_selection": selected["selection_method"] == "sha256_sorted_consecutive",
        "first_1000_completed": len(rows) == 1000
        and benchmark.get("benchmark_sources_completed") == 1000,
        "benchmark_fully_published": len(rows) == 1000 and all(r[2] for r in rows),
        "no_upload_pending": value["upload_pending_sources"] == 0,
        "unknown_architecture_observed": unknown == 0,
        "unknown_architecture_policy_reviewed": False,
        "container_digest_recorded": image.get("image_id", "missing") in runtime_images
        and image.get("source_tree_sha256") == tree,
        "synthetic_checks_passed": validation.get("command") == "make check"
        and validation.get("exit_code") == 0
        and validation.get("source_tree_sha256") == tree,
        "benchmark_protocol_matches": benchmark.get("protocol_sha256") == protocol["sha256"],
    }
    review_file = job / "cohort-review.json"
    if review_file.exists():
        review = json.loads(review_file.read_text())
        checks["unknown_architecture_policy_reviewed"] = (
            review.get("cohort_sha256") == protocol["cohort_sha256"]
            and review.get("unknown_policy") == "defer"
            and review.get("researcher_approved") is True
        )
        if checks["unknown_architecture_policy_reviewed"]:
            checks["unknown_architecture_observed"] = True
    # Container/repository validation is attached by the release procedure, never inferred from a smoke run.
    report = {
        "schema": 3,
        "protocol_sha256": protocol["sha256"],
        "cohort_sha256": protocol["cohort_sha256"],
        "source_tree_sha256": tree,
        "checks": checks,
        "full_launch_ready": all(checks.values()),
        "summary": value,
        "created_at_utc": state.now(),
    }
    json_write(job / "release-audit.json", report)
    return report
