"""Synthetic evidence, bounded batch overlap, partial results and recovery tests."""

from collections import Counter
import csv
from dataclasses import asdict
import gzip
from hashlib import sha256
import json
from queue import Queue
import sqlite3
import sys
import threading

import pytest

from malweave.cli import _parser, main
from malweave.data import rands_ghidra_stream as stream
from malweave.data.dataset_config import RandsDatasetConfig, RandsExpectedCounts
from malweave.data.pe_assessment import DIEC_MODES
from malweave.data.rands import BENIGN_HEADER, RANSOMWARE_ACTUAL_HEADER, RandsRecord
from malweave.data.storage_io import DataError, digest


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    def build(count=4, variants=None):
        die = tmp_path / "die"
        (die / "metadata").mkdir(parents=True)
        payloads, sources, evidence_rows = {}, [], []
        records = []
        variants = variants or {}
        raw_prefix = "representations/raw"
        for index in range(count):
            content = f"synthetic redistributable source {index}".encode()
            sha = sha256(content).hexdigest()
            payloads[sha] = content
            label = "benign" if index % 2 == 0 else "ransomware"
            variant = variants.get(index)
            record = RandsRecord(
                sha,
                "1" * 40,
                "2" * 32,
                len(content),
                "exe",
                "AMD64" if variant == "arch" else "I386",
                variant == "packed",
                1.5,
                "Synthetic" if label == "ransomware" else None,
                2020,
                label,
            )
            records.append(record)
            key, etag = f"{raw_prefix}/{sha[:2]}/{sha}", '"synthetic-etag"'
            sources.append(
                (sha, label, key, len(content), etag, json.dumps(record.__dict__, sort_keys=True))
            )
            packing = {
                "state": "not_detected",
                "types": [],
                "modes": dict.fromkeys(DIEC_MODES, "success"),
                "reports": {
                    mode: {
                        "status": "success",
                        "returncode": 0,
                        "report": {"detects": [{"filetype": "PE32", "values": []}]},
                    }
                    for mode in DIEC_MODES
                },
            }
            if variant == "obfuscated":
                packing.update(state="obfuscated", types=["Packer"])
            if variant == "timeout":
                packing["modes"]["deep"] = "timeout"
                packing["state"] = "unknown"
            if variant == "false_negative":
                packing["reports"]["deep"]["report"]["detects"][0]["values"] = [{"type": "packer"}]
            evidence = {
                "source_sha256": sha,
                "input_sha256": sha,
                "source_hash_status": "verified",
                "metadata": record.__dict__,
                "s3_key": key,
                "s3_etag": etag,
                "packing": packing,
            }
            blob = gzip.compress(json.dumps(evidence).encode(), mtime=0)
            if variant != "missing":
                evidence_rows.append(
                    (sha, "success", packing["state"], 0, 0, blob, sha256(blob).hexdigest())
                )
        for label, name, header in (
            ("benign", "Benign.csv", BENIGN_HEADER),
            ("ransomware", "Ransomware.csv", RANSOMWARE_ACTUAL_HEADER),
        ):
            with (die / "metadata" / name).open("w", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(header)
                for r in records:
                    if r.label != label:
                        continue
                    row = [
                        r.sha256,
                        r.sha1,
                        r.md5,
                        r.size_bytes,
                        r.extension,
                        r.arch,
                        int(r.packed),
                        r.entropy,
                    ]
                    if label == "ransomware":
                        row.append(r.family)
                    writer.writerow(row + [r.year, f"{r.sha256[:2]}/{r.sha256}"])
        labels = dict(Counter(r.label for r in records))
        config = RandsDatasetConfig(
            "rands",
            "synthetic-stream",
            "SYNTHETIC_ROOT",
            "Benign.csv",
            "Ransomware.csv",
            "dataset",
            RandsExpectedCounts(len({r.sha256[:2] for r in records}), count, labels),
            {},
        )
        audit = {
            "passed": True,
            "files": count,
            "labels": labels,
            "shards": config.expected.shards,
            "source_list_sha256": sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
            "metadata_sha256": {
                name: digest(die / "metadata" / name) for name in ("Benign.csv", "Ransomware.csv")
            },
        }
        contract = {
            "dataset": asdict(config),
            "prefix": "s3://synthetic/metadata",
            "raw_prefix": f"s3://synthetic/{raw_prefix}",
            "modes": list(DIEC_MODES),
        }
        with sqlite3.connect(die / "state.sqlite3") as db:
            db.executescript("""
                CREATE TABLE job (key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE source (sha256 TEXT PRIMARY KEY,label TEXT,s3_key TEXT,size INTEGER,etag TEXT,metadata TEXT);
                CREATE TABLE result (sha256 TEXT PRIMARY KEY,status TEXT,packing TEXT,seconds REAL,bytes INTEGER,evidence_gzip BLOB,evidence_sha256 TEXT);
            """)
            db.executemany(
                "INSERT INTO job VALUES (?,?)",
                [("contract", json.dumps(contract)), ("release_audit", json.dumps(audit))],
            )
            db.executemany("INSERT INTO source VALUES (?,?,?,?,?,?)", sources)
            db.executemany("INSERT INTO result VALUES (?,?,?,?,?,?,?)", evidence_rows)
        ghidra = tmp_path / "ghidra"
        (ghidra / "support").mkdir(parents=True)
        (ghidra / "Ghidra").mkdir()
        (ghidra / "Ghidra/application.properties").write_text("application.version=synthetic\n")
        analyzer = ghidra / "support/analyzeHeadless"
        analyzer.write_text(
            f"#!{sys.executable}\n"
            "import pathlib,sys\n"
            "args=sys.argv\n"
            "source=pathlib.Path(args[args.index('-import')+1])\n"
            "post=args.index('-postScript')\n"
            "view='dis' if args[post+1]=='Disassembler.java' else 'dec'\n"
            "out=pathlib.Path(args[post+2])\n"
            "text='ram\\t0\\t0\\t90\\tnop\\n' if view=='dis' else 'int main(){return 0;}\\n'\n"
            "(out/(source.name+('.asm' if view=='dis' else '.c'))).write_text(text)\n"
            "print('run: analysisTimeoutOccurred()=false')\n"
            "print('run: finished (success) <'+source.name+'>')\n"
        )
        analyzer.chmod(0o700)
        monkeypatch.setattr(
            stream, "_tools", lambda headless, scripts: {"launcher_sha256": digest(headless)}
        )
        downloads = []

        def download(uri, destination, etag=None):
            assert etag == '"synthetic-etag"'
            sha = uri.rsplit("/", 1)[-1]
            downloads.append(sha)
            destination.write_bytes(payloads[sha])
            destination.chmod(0o600)

        monkeypatch.setattr(stream, "_download", download)
        job = tmp_path / "ghidra-job"

        def run(**kwargs):
            return stream.run_rands_ghidra(job, die, config, analyzer, min_free_bytes=0, **kwargs)

        return run, job, die, downloads, analyzer

    return build


def test_metadata_and_all_die_modes_are_required(fixture):
    run, job, _, downloads, _ = fixture(
        8,
        {
            1: "packed",
            2: "arch",
            3: "obfuscated",
            4: "timeout",
            5: "missing",
            6: "false_negative",
        },
    )
    result = run()
    assert result["eligible"] == result["completed"] == 2
    assert len(downloads) == 2
    assert result["selection"]["reasons"] == {
        "eligible": 2,
        "metadata_packed": 1,
        "metadata_architecture": 1,
        "die_obfuscated": 1,
        "die_unknown_or_failed": 1,
        "die_missing": 1,
        "die_invalid_negative": 1,
    }
    assert not (job / "work").exists()
    assert (job / "selection.csv").is_file()
    for view in stream.VIEWS:
        assert result["representations"][view]["success"] == 2
        assert set(result["representations"][view]["by_class"]) == {"benign", "ransomware"}


def test_prefetch_overlaps_16_workers_and_never_stages_a_third_batch(fixture, monkeypatch):
    run, job, _, downloads, _ = fixture(35)
    first_active = threading.Barrier(16)
    prefetched = threading.Event()
    lock = threading.Lock()
    active, peak, checked = 0, 0, []
    original_download, original_view = stream._download, stream._extract_view

    def download(uri, destination, etag=None):
        original_download(uri, destination, etag)
        with lock:
            if len(downloads) == 32:
                prefetched.set()
            if len(downloads) > 32:
                assert not (job / "work/batch-0").exists()

    def view(source, representation, batch_root, *args):
        nonlocal active, peak
        if batch_root.name == "batch-0" and representation == "dis":
            with lock:
                active += 1
                peak = max(peak, active)
            first_active.wait(timeout=10)
            assert prefetched.wait(timeout=10), "next batch was not downloaded during extraction"
            with lock:
                # Raw PE names are hashes; projects and outputs have other names.
                pe_count = sum(1 for p in (job / "work").glob("*/*") if len(p.name) == 64)
                checked.append(pe_count)
        result = original_view(source, representation, batch_root, *args)
        if batch_root.name == "batch-0" and representation == "dis":
            with lock:
                active -= 1
        return result

    monkeypatch.setattr(stream, "_download", download)
    monkeypatch.setattr(stream, "_extract_view", view)
    result = run()
    assert peak == 16
    assert checked and max(checked) <= 32
    assert len(downloads) == result["completed"] == 35
    assert not (job / "work").exists()
    assert all(v["success"] == 35 for v in result["representations"].values())


def test_limit_resume_and_per_view_commit_survive_interruption(fixture, monkeypatch):
    run, job, _, downloads, _ = fixture(2)
    original = stream._extract_view

    def interrupt(source, view, *args):
        if view == "dec":
            raise KeyboardInterrupt()
        return original(source, view, *args)

    monkeypatch.setattr(stream, "_extract_view", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run(limit=1)
    with sqlite3.connect(job / "state.sqlite3") as db:
        assert db.execute("SELECT view FROM result").fetchall() == [("dis",)]
    assert json.loads((job / "progress.json").read_text())["phase"] == "interrupted"
    assert not (job / "work").exists()
    monkeypatch.setattr(stream, "_extract_view", original)
    seen = []

    def record(source, view, *args):
        seen.append(view)
        return original(source, view, *args)

    monkeypatch.setattr(stream, "_extract_view", record)
    result = run(limit=1)
    assert seen == ["dec"]
    assert result["phase"] == "limit_reached"
    assert len(downloads) == 2
    assert run()["complete"]
    before = len(downloads)
    assert run()["complete"]
    assert len(downloads) == before


def test_hash_failure_is_recorded_for_both_views_and_cleaned(fixture, monkeypatch):
    run, job, _, downloads, _ = fixture(2)

    def corrupt(uri, destination, etag=None):
        sha = uri.rsplit("/", 1)[-1]
        downloads.append(sha)
        destination.write_bytes(b"X" * len(b"synthetic redistributable source 0"))

    monkeypatch.setattr(stream, "_download", corrupt)
    monkeypatch.setattr(
        stream, "_extract_view", lambda *args: pytest.fail("Ghidra read a corrupt PE")
    )
    result = run()
    assert all(v["statuses"] == {"hash_mismatch": 2} for v in result["representations"].values())
    assert not (job / "work").exists()
    assert run()["complete"]
    assert len(downloads) == 2


@pytest.mark.parametrize(
    "marker,status",
    [
        ("run: finished (timeout)", "partial_timeout"),
        ("run: finished (crash)", "partial_error"),
        ("decompileFunction: results.isTimedOut()=true", "partial_error"),
        ("no completion", "unconfirmed_completion"),
    ],
)
def test_nonempty_output_is_not_proof_of_success(fixture, marker, status):
    run, job, _, _, analyzer = fixture(2)
    analyzer.write_text(
        analyzer.read_text().replace(
            "print('run: finished (success) <'+source.name+'>')", f"print({marker!r})"
        )
    )
    result = run()
    assert all(v["statuses"] == {status: 2} for v in result["representations"].values())
    assert len(list((job / "partial/dis").glob("*/*"))) == 2
    with sqlite3.connect(job / "state.sqlite3") as db:
        for blob, checksum in db.execute("SELECT evidence_gzip,evidence_sha256 FROM result"):
            assert sha256(blob).hexdigest() == checksum
            evidence = json.loads(gzip.decompress(blob))
            assert marker in evidence["execution"]["stdout"]
            assert evidence["execution"]["command"]


@pytest.mark.parametrize("change", ["audit", "metadata", "evidence"])
def test_invalid_audit_or_evidence_blocks_downloads(fixture, change):
    run, _, die, downloads, _ = fixture()
    if change == "metadata":
        with (die / "metadata/Benign.csv").open("a") as handle:
            handle.write("\n")
    else:
        with sqlite3.connect(die / "state.sqlite3") as db:
            if change == "audit":
                value = json.loads(
                    db.execute("SELECT value FROM job WHERE key='release_audit'").fetchone()[0]
                )
                value["passed"] = False
                db.execute(
                    "UPDATE job SET value=? WHERE key='release_audit'", (json.dumps(value),)
                )
            else:
                db.execute("UPDATE result SET evidence_gzip=?", (b"corrupt",))
    with pytest.raises(DataError):
        run()
    assert downloads == []


def test_changed_tools_or_selection_cannot_resume(fixture):
    run, _, die, downloads, analyzer = fixture()
    run(limit=1)
    before = len(downloads)
    original = analyzer.read_text()
    analyzer.write_text(original + "\n# new tool revision\n")
    with pytest.raises(DataError, match="tools/config changed"):
        run()
    analyzer.write_text(original)
    with sqlite3.connect(die / "state.sqlite3") as db:
        db.execute("UPDATE result SET evidence_sha256='changed'")
    with pytest.raises(DataError, match="checksum"):
        run()
    assert len(downloads) == before


def test_disk_reserve_stops_before_download_and_keeps_pending(fixture, monkeypatch):
    run, job, _, downloads, _ = fixture()
    monkeypatch.setattr(stream.shutil, "disk_usage", lambda path: type("Usage", (), {"free": 0})())
    with pytest.raises(DataError, match="disk reserve"):
        run()
    assert not downloads
    assert not (job / "work").exists()
    report = json.loads((job / "progress.json").read_text())
    assert report["phase"] == "failed"
    assert report["pending"] == 4


def test_status_cli_and_required_paths(tmp_path, capsys):
    args = _parser().parse_args(["data", "rands-ghidra", "run", "--job-dir", str(tmp_path)])
    assert args.heap_mb == 1024
    assert main(["data", "rands-ghidra", "run", "--job-dir", str(tmp_path)]) == 2
    (tmp_path / "progress.json").write_text('{"phase":"synthetic"}')
    assert main(["data", "rands-ghidra", "status", "--job-dir", str(tmp_path)]) == 0
    assert "synthetic" in capsys.readouterr().out


def test_shutdown_does_not_record_killed_views_as_terminal_failures(tmp_path, monkeypatch):
    processes = stream._Processes()
    events = Queue()

    def stopped(*args):
        processes.stopping.set()
        return {"status": "ghidra_failed"}

    monkeypatch.setattr(stream, "_extract_view", stopped)
    stream._process_source(
        {"pending": ["dis", "dec"], "transfer": {"status": "verified"}},
        tmp_path,
        tmp_path,
        tmp_path,
        tmp_path,
        processes,
        1024,
        events,
    )
    assert events.empty()


def test_resume_checks_committed_output_before_cleanup_or_download(fixture):
    run, job, _, downloads, _ = fixture()
    run(limit=1)
    before = len(downloads)
    output = next((job / "representations/dis").glob("*/*"))
    output.write_text("changed")
    stale = job / "work/stale"
    stale.mkdir(parents=True)
    with pytest.raises(DataError, match="representation is missing or changed"):
        run()
    assert stale.is_dir()
    assert len(downloads) == before


def test_tool_preflight_requires_a_full_jdk(tmp_path, monkeypatch):
    install = tmp_path / "ghidra"
    (install / "support").mkdir(parents=True)
    (install / "Ghidra").mkdir()
    headless = install / "support/analyzeHeadless"
    headless.write_text("#!/bin/sh\nexit 0\n")
    headless.chmod(0o700)
    (install / "Ghidra/application.properties").write_text("application.version=synthetic\n")
    java_home = tmp_path / "jre"
    (java_home / "bin").mkdir(parents=True)
    (java_home / "bin/java").write_text("synthetic JRE only")
    monkeypatch.setenv("JAVA_HOME", str(java_home))
    with pytest.raises(DataError, match="full JDK"):
        stream._tools(headless, stream.SCRIPT_ROOT)


@pytest.mark.parametrize("timeout", [False, True])
def test_java_and_native_temporary_files_are_cleaned_with_batch(
    fixture, tmp_path, monkeypatch, timeout
):
    outside = tmp_path / "external-temp"
    outside.mkdir()
    monkeypatch.setenv("TMPDIR", str(outside))
    monkeypatch.setenv(
        "_JAVA_OPTIONS", f"-Djava.io.tmpdir={outside} -Dapplication.tempdir={outside}"
    )
    run, job, _, _, analyzer = fixture(2)
    analyzer.write_text(
        analyzer.read_text().replace(
            "post=args.index('-postScript')\n",
            "post=args.index('-postScript')\n"
            "import os,shlex,time\n"
            "props=dict(o[2:].split('=',1) for o in shlex.split(os.environ['_JAVA_OPTIONS']) if o.startswith('-D'))\n"
            "temp=pathlib.Path(props['java.io.tmpdir'])\n"
            "assert temp==pathlib.Path(props['application.tempdir'])\n"
            "assert temp==pathlib.Path(os.environ['TMPDIR'])\n"
            "assert temp.is_relative_to(source.parent)\n"
            "(temp/'synthetic-ghidra.cache').write_bytes(b'harmless cache')\n"
            f"time.sleep({60 if timeout else 0})\n",
        )
    )
    if timeout:
        original = stream._Processes.run

        def bounded(self, command, root, seconds, heap_mb):
            return original(self, command, root, 1, heap_mb)

        monkeypatch.setattr(stream._Processes, "run", bounded)
    result = run()
    expected = {"ghidra_timeout" if timeout else "success": 2}
    assert all(v["statuses"] == expected for v in result["representations"].values())
    assert not list(outside.iterdir())
    assert not (job / "work").exists()


def _shared_analyzer(analyzer, dec_outcome="success"):
    analyzer.write_text(
        f"#!{sys.executable}\n"
        "import pathlib,sys,time\n"
        "args=sys.argv\n"
        "assert args.count('-import')==1 and '-preScript' not in args\n"
        "source=pathlib.Path(args[args.index('-import')+1])\n"
        "with pathlib.Path(__file__).with_name('launches').open('a') as f: f.write('launch\\n')\n"
        "for i,arg in enumerate(args):\n"
        " if arg!='-postScript': continue\n"
        " name=args[i+1]\n"
        " dec=name=='Decompiler.java'\n"
        f" outcome={dec_outcome!r} if dec else 'success'\n"
        " if outcome=='omit': sys.exit(1)\n"
        " out=pathlib.Path(args[i+2])\n"
        " text='int main(){return 0;}\\n' if dec else 'ram\\t0\\t0\\t90\\tnop\\n'\n"
        " (out/(source.name+('.c' if dec else '.asm'))).write_text(text)\n"
        " def emit(s): print('INFO  '+name+'> '+s,flush=True)\n"
        " emit('run: analysisTimeoutOccurred()=false')\n"
        " if outcome=='hang': time.sleep(60)\n"
        " if outcome=='error': emit('decompileFunction: results.getErrorMessage()=synthetic error')\n"
        " if outcome=='none': continue\n"
        " marker='timeout' if outcome=='timeout' else 'success'\n"
        " emit('run: finished ('+marker+') <'+source.name+'>')\n"
    )


def test_shared_full_uses_one_import_and_process_for_both_views(fixture):
    run, job, _, _, analyzer = fixture(2)
    _shared_analyzer(analyzer)
    result = run(execution_mode="shared-full")
    assert result["execution_mode"] == "shared-full"
    assert all(v["statuses"] == {"success": 2} for v in result["representations"].values())
    assert analyzer.with_name("launches").read_text().splitlines() == ["launch"] * 2
    assert not (job / "work").exists()
    with sqlite3.connect(job / "state.sqlite3") as db:
        for (blob,) in db.execute("SELECT evidence_gzip FROM result"):
            record = json.loads(gzip.decompress(blob))
            command = record["execution"]["command"]
            assert command.count("-postScript") == 2
            assert command.count("-import") == 1
            assert "-preScript" not in command
            assert record["runtime_scope"] == "shared_process_wall_inclusive"


@pytest.mark.parametrize(
    "outcome,status",
    [
        ("timeout", "partial_timeout"),
        ("error", "partial_error"),
        ("none", "unconfirmed_completion"),
        ("omit", "not_started"),
        ("hang", "ghidra_timeout"),
    ],
)
def test_shared_full_keeps_view_markers_and_failures_independent(
    fixture, monkeypatch, outcome, status
):
    run, job, _, _, analyzer = fixture(2)
    _shared_analyzer(analyzer, outcome)
    if outcome == "hang":
        original = stream._Processes.run

        def bounded(self, command, root, seconds, heap_mb):
            return original(self, command, root, 1, heap_mb)

        monkeypatch.setattr(stream._Processes, "run", bounded)
    result = run(execution_mode="shared-full")
    assert result["representations"]["dis"]["statuses"] == {"success": 2}
    assert result["representations"]["dec"]["statuses"] == {status: 2}
    assert not (job / "work").exists()


def test_shared_full_resume_runs_only_uncommitted_view_and_rejects_mode_drift(fixture):
    run, job, _, downloads, analyzer = fixture(2)
    _shared_analyzer(analyzer)
    run(execution_mode="shared-full", limit=1)
    with sqlite3.connect(job / "state.sqlite3") as db:
        output = db.execute("SELECT output_path FROM result WHERE view='dec'").fetchone()[0]
        db.execute("DELETE FROM result WHERE view='dec'")
    (job / output).unlink()
    result = run(execution_mode="shared-full", limit=1)
    assert result["completed"] == 1
    with sqlite3.connect(job / "state.sqlite3") as db:
        blob = db.execute("SELECT evidence_gzip FROM result WHERE view='dec'").fetchone()[0]
    command = json.loads(gzip.decompress(blob))["execution"]["command"]
    assert command.count("-postScript") == 1
    assert "Decompiler.java" in command and "Disassembler.java" not in command
    before = len(downloads)
    with pytest.raises(DataError, match="tools/config changed"):
        run(execution_mode="separate")
    assert len(downloads) == before
