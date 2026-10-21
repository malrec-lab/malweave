"""Operational pipeline regressions: bounded scheduling, isolated failures and resume."""

import csv
from dataclasses import asdict
import itertools
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tracemalloc
import zlib

import pytest
from tests.data.test_pe_sections import _synthetic_pe
from tests.data.test_sorel import _job, _scanners, _stage
import yaml

from malweave.cli import main
from malweave.data import sorel
from malweave.data.pe_sections import IMAGE_SCN_CNT_CODE


def _curl_fixture(monkeypatch):
    original = subprocess.run
    calls = []
    pe = _synthetic_pe([(b".text", 0x400, 0x20, IMAGE_SCN_CNT_CODE)])

    def run(command, **kwargs):
        if command[0] != "curl":
            return original(command, **kwargs)
        identifier = command[-1].split("/")[-1]
        calls.append(identifier)
        Path(command[command.index("--output") + 1]).write_bytes(zlib.compress(pe))
        return subprocess.CompletedProcess(command, 0, '{"http_code":200}', "")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_automatic_run_resumes_without_history_reads_or_per_batch_exports(tmp_path, monkeypatch):
    job, config, _ = _job(tmp_path, count=5)
    _scanners(monkeypatch)
    calls = _curl_fixture(monkeypatch)
    queries = []
    connect = sorel._connect

    def traced(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connection.set_trace_callback(queries.append)
        return connection

    monkeypatch.setattr(sorel, "_connect", traced)
    export = sorel.export_sorel
    exports = []
    monkeypatch.setattr(sorel, "export_sorel", lambda *args, **kwargs: exports.append(True))
    first = sorel.run_sorel(job, config, limit=1)
    assert first["pending"] == 4 and not exports
    assert not (job / "manifest.json").exists()
    final = sorel.run_sorel(job, config)
    assert final["completed"] == 5 and final["pending"] == 0
    assert len(calls) == len(set(calls)) == 5
    assert len(exports) == 1
    assert not any(query.startswith("SELECT") and "FROM outcomes" in query for query in queries)
    assert final["distinct_exe"] == 1
    assert not list((job / "spool").iterdir())
    monkeypatch.setattr(sorel, "export_sorel", export)
    export(job)
    assert sorel.verify_sorel(job) == {"verified_sources": 5, "passed": True}
    with (job / "downloads.csv").open(encoding="utf-8-sig", newline="") as stream:
        downloads = list(csv.DictReader(stream))
    assert len(downloads) == 5 and {row["http_status"] for row in downloads} == {"200"}
    assert final["network_received_bytes"] == sum(int(row["received_bytes"]) for row in downloads)


def test_interruption_after_commit_keeps_progress_and_reuses_completed_downloads(
    tmp_path, monkeypatch
):
    job, config, _ = _job(tmp_path)
    _scanners(monkeypatch)
    calls = _curl_fixture(monkeypatch)
    record = sorel.ledger.record
    committed = []

    def interrupt(connection, row):
        record(connection, row)
        committed.append(row["original_sha256"])
        raise KeyboardInterrupt

    monkeypatch.setattr(sorel.ledger, "record", interrupt)
    with pytest.raises(KeyboardInterrupt):
        sorel.run_sorel(job, config)
    with sqlite3.connect(job / "state.sqlite") as connection:
        assert connection.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM sources WHERE done=1").fetchone()[0] == 1
    monkeypatch.setattr(sorel.ledger, "record", record)
    process = sorel._process
    resumed = []

    def track(source, *args, **kwargs):
        resumed.append(source["original_sha256"])
        return process(source, *args, **kwargs)

    monkeypatch.setattr(sorel, "_process", track)
    final = sorel.run_sorel(job, config)
    assert final["completed"] == config.samples
    assert not set(committed) & set(resumed)
    assert len(calls) == config.samples  # Already-downloaded pending input reused its receipt.
    assert not list((job / "spool").iterdir())


@pytest.mark.parametrize(
    "failure, expected", [("crash", "lief_worker_crash"), ("timeout", "lief_timeout")]
)
def test_bad_lief_worker_is_accounted_and_other_sources_continue(
    tmp_path, monkeypatch, failure, expected
):
    job, config, _ = _job(tmp_path, count=2)
    _scanners(monkeypatch)
    _stage(
        job, config, zlib.compress(_synthetic_pe([(b".text", 0x400, 0x20, IMAGE_SCN_CNT_CODE)]))
    )
    original = subprocess.run
    sequence = itertools.count()

    def run(command, **kwargs):
        if "malweave.data.pe_worker" in command and next(sequence) == 0:
            script = (
                "import sys; print('synthetic crash',file=sys.stderr); sys.exit(17)"
                if failure == "crash"
                else "import time; print('before hang',flush=True); time.sleep(10)"
            )
            if failure == "timeout":
                kwargs["timeout"] = 0.15
            return original([sys.executable, "-c", script], **kwargs)
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    final = sorel.run_sorel(job, config, staged=True)
    assert final["status_counts"] == {expected: 1, "success": 1}
    rows = json.loads((job / "manifest.json").read_text())
    failed = next(row for row in rows if row["status"] == expected)
    report = sorel._read_tool_report(job, failed, "lief")["result"]
    if failure == "crash":
        assert report["returncode"] == 17 and "synthetic crash" in report["stderr"]
    else:
        assert "before hang" in report["stdout"] and "error" in report
    assert not list((job / "scratch").iterdir())


def test_writer_lock_and_changed_selection_are_rejected(tmp_path, monkeypatch):
    job, config, _ = _job(tmp_path, count=1)
    _scanners(monkeypatch)
    with sorel.job_lock(job), pytest.raises(sorel.SorelError, match="Another process"):
        sorel.run_sorel(job, config)
    with sqlite3.connect(job / "state.sqlite") as connection:
        connection.execute("UPDATE sources SET value='{}'")
    with pytest.raises(sorel.SorelError, match="selection changed"):
        sorel.run_sorel(job, config)


def test_cli_run_prepares_and_processes_with_one_command(tmp_path, monkeypatch):
    prepared, config, metadata = _job(tmp_path, count=2)
    _scanners(monkeypatch)
    _curl_fixture(monkeypatch)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(asdict(config)))
    job = tmp_path / "automatic"
    command = ["data", "sorel-run", "--job-dir", str(job), "--config", str(path)]
    assert main([*command, "--metadata", str(metadata)]) == 0
    assert main(command) == 0
    assert main(["data", "sorel-verify", "--job-dir", str(job)]) == 0
    assert json.loads((job / "summary.json").read_text())["pending"] == 0
    assert json.loads((prepared / "selection.json").read_text())["schema"] == 2


def test_download_attempt_tampering_is_detected_without_scanning(tmp_path, monkeypatch):
    job, config, _ = _job(tmp_path, count=1)
    _scanners(monkeypatch)
    _curl_fixture(monkeypatch)
    sorel.run_sorel(job, config)
    attempt = next((job / "downloads").rglob("attempt-*.json"))
    saved = json.loads(attempt.read_text())
    saved["received_bytes"] += 1
    sorel._json_write(attempt, saved)
    with pytest.raises(sorel.SorelError, match="receipt"):
        sorel.verify_sorel(job)


def test_export_streams_large_legacy_records_with_bounded_memory(tmp_path):
    job = tmp_path / "large-export"
    job.mkdir()
    count = 6000
    with sqlite3.connect(job / "state.sqlite") as connection:
        connection.execute("CREATE TABLE outcomes (id TEXT PRIMARY KEY, value TEXT)")
        connection.executemany(
            "INSERT INTO outcomes VALUES (?, ?)",
            (
                (
                    f"{index:064x}",
                    json.dumps(
                        {
                            "original_sha256": f"{index:064x}",
                            "status": "filtered_obfuscated",
                            "packing": "obfuscated",
                            "architecture": "unknown",
                            "file_description": "x" * 4096,
                        }
                    ),
                )
                for index in range(count)
            ),
        )
    tracemalloc.start()
    try:
        summary = sorel.export_sorel(job)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert summary["exported_sources"] == count
    assert peak < 8 * 1024**2  # Source text alone exceeds 23 MiB if all rows are retained.
    with (job / "results.csv").open(encoding="utf-8-sig", newline="") as stream:
        assert sum(1 for _ in csv.DictReader(stream)) == count


def test_sqlite_progress_and_aggregates_rollback_with_outcome(tmp_path, monkeypatch):
    job, config, _ = _job(tmp_path, count=1)
    _scanners(monkeypatch)
    _curl_fixture(monkeypatch)
    add = sorel.ledger._add

    def fail(*args, **kwargs):
        add(*args, **kwargs)
        raise RuntimeError("synthetic interrupted transaction")

    monkeypatch.setattr(sorel.ledger, "_add", fail)
    with pytest.raises(RuntimeError, match="interrupted transaction"):
        sorel.run_sorel(job, config)
    with sqlite3.connect(job / "state.sqlite") as connection:
        assert connection.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0] == 0
        assert connection.execute("SELECT SUM(done) FROM sources").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM totals").fetchone()[0] == 0
