"""v3 acceptance uses generated inert PE bytes, fake transport and fake scanners only."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tarfile
import threading
import time
import zlib

import pytest

from malweave.data import sorel_conversion as conversion
from malweave.data import sorel_protocol as state
from malweave.data import sorel_stage as stage
from malweave.data.sorel_io import SorelError, digest, json_write
from malweave.data.sorel_publication import AWS, Store, restore, snapshot, validate_archive
from malweave.data.sorel_tools import Processes
from tests.data.test_pe_sections import _synthetic_pe


def metadata(path: Path, count: int = 15):
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE meta ("
            + ",".join(
                name + (" TEXT PRIMARY KEY" if name == "sha256" else " REAL")
                for name in state.METADATA_FIELDS
            )
            + ")"
        )
        for i in reversed(range(count)):
            row = [f"{i:064x}", 1, float(i), 2] + [int(i % 2 == 0)] * 11
            db.execute("INSERT INTO meta VALUES(" + ",".join("?" * 15) + ")", row)
    return path


def job(tmp_path, count=15):
    path = tmp_path / "job"
    rules = state.Rules()
    selected = state.prepare(metadata(tmp_path / "meta.db", count), path, rules)
    json_write(path / "protocol.json", {"sha256": "a" * 64})
    return path, rules, selected


def outcome(path, item, *, status="success", output=b"inert extracted representation"):
    identifier, attempt = item["original_sha256"], item["attempt"]
    root = path / "work" / identifier / f"attempt-{attempt:06d}"
    root.mkdir(parents=True, exist_ok=True)
    row = dict.fromkeys(state.CSV_FIELDS, "")
    row.update(
        original_sha256=identifier,
        attempt=attempt,
        status=status,
        architecture="i386",
        packing="not_detected",
        storage_status="pending",
        runtime_seconds=0.1,
        download_seconds=0.01,
        network_received_bytes=12,
        local_work_dir=root.relative_to(path).as_posix(),
        exe_bytes=len(output),
        exe_sha256=sha256(output).hexdigest(),
        released_pe_sha256="b" * 64,
        details_member_root=f"sources/{identifier}/attempt-{attempt:06d}",
        protocol_sha256="a" * 64,
    )
    (root / "output.exe").write_bytes(output)
    (root / "input.pe").write_bytes(b"raw synthetic fixture excluded")
    (root / "input.zlib").write_bytes(b"raw synthetic fixture excluded")
    json_write(root / "die.json", {"modes": {}, "state": "not_detected"})
    json_write(root / "outcome.json", row)
    return row


class FakeAWS:
    def __init__(self, root):
        self.root = root
        self.metrics = {"requests": 0, "uploaded_bytes": 0, "downloaded_bytes": 0}
        self.fail = None
        self.calls = []

    def path(self, uri):
        return self.root / uri.removeprefix("s3://")

    def put(self, source, uri):
        self.calls.append(uri)
        if self.fail and self.fail in uri:
            raise SorelError("Injected upload failure")
        target = self.path(uri)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())

    def put_tree(self, source, prefix, workers):
        for path in source.rglob("*"):
            if path.is_file():
                self.put(path, prefix + path.relative_to(source).as_posix())

    def get(self, uri, target, *, missing=False):
        path = self.path(uri)
        if not path.exists():
            if missing:
                return False
            raise SorelError("Missing fake object")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        return True

    def keys(self, prefix):
        root = self.path(prefix)
        if root.exists():
            yield from (
                "s3://" + p.relative_to(self.root).as_posix()
                for p in sorted(root.rglob("*"))
                if p.is_file()
            )

    def call(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ("s3api", "delete-object"):
            bucket = args[args.index("--bucket") + 1]
            key = args[args.index("--key") + 1]
            self.path("s3://" + bucket + "/" + key).unlink(missing_ok=True)
        return {}


def test_consecutive_balanced_partition_preserves_every_original_field(tmp_path):
    source = metadata(tmp_path / "meta.db", 17)
    groups = []
    for index in range(1, 6):
        path = tmp_path / str(index)
        result = state.prepare(source, path, replace(state.Rules(), partition_index=index))
        with closing(state.connect(path)) as db:
            rows = list(db.execute("SELECT id,metadata FROM sources ORDER BY ordinal"))
            assert all(set(json.loads(value)) == set(state.METADATA_FIELDS) for _, value in rows)
        groups.append([identifier for identifier, _ in rows])
        assert result["selection_method"] == "sha256_sorted_consecutive"
    assert list(map(len, groups)) == [4, 4, 3, 3, 3]
    assert [item for group in groups for item in group] == [f"{i:064x}" for i in range(17)]
    assert state.partition_bounds(9962820, 5, 1) == (0, 1992564)
    assert state.partition_bounds(9962820, 5, 5) == (7970256, 9962820)


def test_resume_rejects_legacy_or_changed_scientific_rules(tmp_path):
    path, rules, _ = job(tmp_path)
    with pytest.raises(SorelError, match="Scientific"):
        state.selection(path, replace(rules, die_attempts=4))
    json_write(path / "selection.json", {"schema": 2})
    with pytest.raises(SorelError, match="Legacy"):
        state.selection(path)


def test_publication_dedup_manifest_replay_and_resume_without_raw(tmp_path):
    path, _, _ = job(tmp_path)
    aws = FakeAWS(tmp_path / "remote")
    store = Store(path, "s3://bucket/v3/part-01", aws, state.Runtime())
    with closing(state.connect(path)) as db:
        rows = [outcome(path, item) for item in state.pending(db, 2)]
        for row in rows:
            state.record(db, row)
        checkpoint = snapshot(db, path)
        store.checkpoint(checkpoint)
        uploaded, group = store.upload_group(rows)
        assert not db.execute("SELECT published FROM current WHERE published=1").fetchall()
        assert len([uri for uri in aws.calls if isinstance(uri, str) and "/exe/" in uri]) == 1
        archive = aws.path(group["archive_uri"])
        validate_archive(archive, group)
        with tarfile.open(archive) as tar:
            assert not any(
                name.endswith(("input.pe", "input.zlib", "output.exe")) for name in tar.getnames()
            )
            assert "details.csv" in tar.getnames()
        state.publish(db, uploaded, group)
        state.publish(db, uploaded, group)
        assert state.summary(db, 3)["published_sources"] == 2
        assert state.summary(db, 3)["unique_exe_s3"] == 1
        store.cleanup(uploaded)
    target = tmp_path / "restored"
    assert restore(target, store.prefix, aws)
    restored = Store(target, store.prefix, aws, state.Runtime())
    with closing(state.connect(target)) as db:
        assert restored.replay(db) == 2
        assert restored.replay(db) == 0
        assert state.summary(db, 3)["published_sources"] == 2
        assert len(state.pending(db, 100)) == 1
        state.csv_export(db, target / "results.csv")
        assert group["archive_uri"] in (target / "results.csv").read_text(encoding="utf-8-sig")


def test_upload_failure_retains_local_data_and_previous_snapshot(tmp_path):
    path, _, _ = job(tmp_path)
    aws = FakeAWS(tmp_path / "remote")
    store = Store(path, "s3://bucket/v3/part-01", aws, state.Runtime())
    with closing(state.connect(path)) as db:
        row = outcome(path, state.pending(db, 1)[0])
        state.record(db, row)
        first = snapshot(db, path)
        store.checkpoint(first)
        previous = aws.path(store.prefix + "/main/latest.json").read_bytes()
        aws.fail = "/details/"
        with pytest.raises(SorelError):
            store.upload_group([row])
        assert (path / row["local_work_dir"] / "output.exe").exists()
        assert not list(aws.keys(store.prefix + "/details/"))
        assert state.summary(db, 3)["upload_pending_sources"] == 1
        aws.fail = "/main/snapshots/"
        with pytest.raises(SorelError):
            store.checkpoint(snapshot(db, path))
        assert aws.path(store.prefix + "/main/latest.json").read_bytes() == previous


def test_replay_rejects_corruption_and_foreign_sources_before_commit(tmp_path):
    path, _, _ = job(tmp_path)
    aws = FakeAWS(tmp_path / "remote")
    store = Store(path, "s3://bucket/v3/part-01", aws, state.Runtime())
    with closing(state.connect(path)) as db:
        row = outcome(path, state.pending(db, 1)[0])
        _, group = store.upload_group([row])
        aws.path(group["archive_uri"]).write_bytes(b"corrupted archive")
        with pytest.raises(SorelError, match="checksum"):
            store.replay(db)
        assert not db.execute("SELECT 1 FROM current").fetchall()


def test_explicit_retry_preserves_history_without_retrying_filtered(tmp_path):
    path, _, _ = job(tmp_path)
    with closing(state.connect(path)) as db:
        row = outcome(path, state.pending(db, 1)[0], status="die_scan_failed")
        state.record(db, row)
        assert state.pending(db, 1)[0]["original_sha256"] != row["original_sha256"]
        assert conversion.request_retry(db, ["die_scan_failed"]) == 1
        item = state.pending(db, 1)[0]
        assert item["attempt"] == 2
        next_row = outcome(path, item)
        state.record(db, next_row)
        assert db.execute("SELECT COUNT(*) FROM history").fetchone()[0] == 2
        assert state.summary(db, 3)["successful_sources"] == 1
        with pytest.raises(SorelError):
            conversion.request_retry(db, ["filtered_obfuscated"])


def test_failed_die_mode_retries_independently_and_preserves_positive(tmp_path):
    class Scanner:
        def __init__(self):
            self.calls = []

        def run(self, command, root, name, **kwargs):
            self.calls.append(name)
            valid = "deep" not in name or name.endswith("03")
            report = {
                "detects": [
                    {
                        "filetype": "PE",
                        "values": [{"type": "Packer", "name": "test"}]
                        if "recursive" in name
                        else [],
                    }
                ]
            }
            (root / (name + ".stdout")).write_text(json.dumps(report) if valid else "bad-json")
            return {"status": "success", "stdout_file": name + ".stdout", "runtime_seconds": 0.1}

    scanner = Scanner()
    result = stage.screen_die(
        "diec",
        tmp_path / "inert.pe",
        tmp_path,
        state.Rules(),
        state.Runtime(memory_per_task_bytes=2**28),
        scanner,
    )
    assert result["state"] == "obfuscated"
    assert scanner.calls == [
        "die-recursive-01",
        "die-deep-01",
        "die-deep-02",
        "die-deep-03",
        "die-heuristic-01",
    ]
    scanner.calls.clear()
    stage.screen_die(
        "diec", tmp_path / "inert.pe", tmp_path, state.Rules(), state.Runtime(), scanner, result
    )
    assert not scanner.calls


def test_streaming_decompress_detects_corruption_and_defers_resource(tmp_path):
    source, target = tmp_path / "input.zlib", tmp_path / "input.pe"
    source.write_bytes(zlib.compress(b"a" * 20000))
    processes = Processes()
    report = stage.decompress(source, target, 100000, 0, processes)
    assert report["released_pe_sha256"] == digest(target)
    with pytest.raises(stage.SourceFailure, match="deferred_resource"):
        stage.decompress(source, target, 1000, 0, processes)
    source.write_bytes(zlib.compress(b"fixture")[:-2])
    with pytest.raises(stage.SourceFailure, match="invalid_zlib"):
        stage.decompress(source, target, 100000, 0, processes)


def test_lief_isolated_real_static_extraction_and_parse_rejection(tmp_path):
    pe = tmp_path / "input.pe"
    pe.write_bytes(_synthetic_pe([(b".text", 0x400, 32, 0x20)]))
    result = stage.extract(
        pe, tmp_path, state.Rules(), state.Runtime(memory_per_task_bytes=1024**3), Processes()
    )
    assert result["status"] == "success"
    assert result["extracted_bytes"] == 32
    pe.write_bytes(b"bad input")
    result = stage.extract(
        pe, tmp_path, state.Rules(), state.Runtime(memory_per_task_bytes=1024**3), Processes()
    )
    assert result["status"] != "success"
    assert len(result["attempts"]) == 1


def test_lief_retries_timeout_but_not_parse_error(tmp_path):
    class Crashing:
        def __init__(self):
            self.calls = 0

        def run(self, *args, **kwargs):
            self.calls += 1
            return {"status": "timeout", "runtime_seconds": 0.1}

    tool = Crashing()
    result = stage.extract(tmp_path / "inert.pe", tmp_path, state.Rules(), state.Runtime(), tool)
    assert tool.calls == 3 and result["status"] == "lief_timeout"


def test_aws_lock_is_conditional_and_rejects_unconfirmed_takeover(tmp_path):
    class Conditional(AWS):
        def __init__(self):
            super().__init__(tmp_path, Processes())
            self.remote = None
            self.args = []

        def call(self, *args, **kwargs):
            self.args.append(args)
            if args[:2] == ("s3api", "head-object"):
                return {"ETag": "etag"}
            if args[:2] == ("s3api", "put-object"):
                if "--if-none-match" in args and self.remote is not None:
                    raise SorelError("PreconditionFailed")
                self.remote = json.loads(Path(args[args.index("--body") + 1]).read_text())
            return {"ETag": "etag"}

        def get(self, uri, path, **kwargs):
            json_write(path, self.remote)
            return True

    aws = Conditional()
    assert aws.acquire("s3://bucket/part-01", {"token": "old"}) == "etag"
    with pytest.raises(SorelError, match="ownership"):
        aws.acquire("s3://bucket/part-01", {"token": "other"})
    with pytest.raises(SorelError, match="token"):
        aws.acquire("s3://bucket/part-01", {"token": "new"}, "wrong")
    assert aws.acquire("s3://bucket/part-01", {"token": "new"}, "old") == "etag"
    assert "--if-match" in aws.args[-1]


def test_continuous_dispatch_commits_fast_source_and_bounds_active_work(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "job"
    source = metadata(tmp_path / "meta.db", 25)
    fast_done, third_started = threading.Event(), threading.Event()
    lock = threading.Lock()
    active, peak = 0, 0

    def process(item, job, *args):
        nonlocal active, peak
        number = int(item["original_sha256"], 16)
        with lock:
            active += 1
            peak = max(peak, active)
        if number == 0:
            assert fast_done.wait(4)
            assert third_started.wait(4), "Scheduling waited for an entire batch"
        if number == 2:
            third_started.set()
        row = outcome(job, item)
        with lock:
            active -= 1
        return row

    record = state.record

    def tracked(db, row):
        record(db, row)
        if int(row["original_sha256"], 16) == 1:
            fast_done.set()

    monkeypatch.setattr(stage, "process", process)
    monkeypatch.setattr(state, "record", tracked)
    monkeypatch.setattr(conversion, "tool_identity", lambda *args: {"test": {"sha256": "test"}})
    result = conversion.run(
        path,
        source,
        state.Rules(),
        state.Runtime(workers=2, progress_seconds=1, min_free_bytes=1),
        limit=5,
    )
    assert result["processed_sources"] == 5
    assert peak <= 2
    result = conversion.run(
        path, source, state.Rules(), state.Runtime(workers=1, min_free_bytes=1), limit=5
    )
    assert result["processed_sources"] == 5
    assert result["run_processing_attempts"] == 0
    assert '"phase":"complete"' in capsys.readouterr().err


def test_background_publication_heartbeat_dedup_and_queue_bounds(tmp_path, monkeypatch, capsys):
    source = metadata(tmp_path / "meta.db", 100)

    class Transport(FakeAWS):
        def __init__(self, job, processes, timeout):
            super().__init__(tmp_path / "remote")
            self.released = False

        def acquire(self, *args):
            return "etag"

        def release(self, *args):
            self.released = True

        def put(self, source, uri):
            if "/details/" in uri and uri.endswith(".tar.gz"):
                time.sleep(1.05)
            return super().put(source, uri)

    transport = Transport(None, None, None)

    def factory(*args):
        return transport

    factory.split = AWS.split
    monkeypatch.setattr(conversion, "AWS", factory)
    monkeypatch.setattr(conversion, "tool_identity", lambda *args: {"test": {"sha256": "test"}})
    monkeypatch.setattr(stage, "process", lambda item, job, *args: outcome(job, item))
    result = conversion.run(
        tmp_path / "job",
        source,
        state.Rules(),
        state.Runtime(
            workers=2,
            upload_sources=2,
            upload_queue_sources=4,
            progress_seconds=1,
            min_free_bytes=1,
        ),
        prefix="s3://bucket/v3/part-01",
        limit=6,
    )
    assert result["published_sources"] == 6
    assert result["upload_pending_sources"] == 0
    assert result["unique_exe_s3"] == 1
    assert transport.released
    assert len([uri for uri in transport.calls if isinstance(uri, str) and "/exe/" in uri]) == 1
    logs = [
        json.loads(line) for line in capsys.readouterr().err.splitlines() if line.startswith("{")
    ]
    assert sum(line.get("event") == "progress" for line in logs) >= 2
    assert (
        max(
            line.get("active_workers", 0) + line.get("queued_publication_sources", 0)
            for line in logs
        )
        <= 4
    )


def test_first_interrupt_drains_active_work_and_saves_local_state(tmp_path, monkeypatch):
    import os
    import signal

    source = metadata(tmp_path / "meta.db", 100)

    def process(item, job, *args):
        if int(item["original_sha256"], 16) == 0:
            os.kill(os.getpid(), signal.SIGINT)
            time.sleep(0.03)
        return outcome(job, item)

    monkeypatch.setattr(stage, "process", process)
    monkeypatch.setattr(conversion, "tool_identity", lambda *args: {"test": {"sha256": "test"}})
    result = conversion.run(
        tmp_path / "job",
        source,
        state.Rules(),
        state.Runtime(workers=2, min_free_bytes=1),
        limit=10,
    )
    assert result["phase"] == "stopped"
    assert 1 <= result["processed_sources"] <= 2
    assert (tmp_path / "job/results.csv").is_file()


def test_second_interrupt_aborts_created_subprocesses_only(tmp_path):
    import sys

    processes = Processes()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            processes.run,
            [sys.executable, "-c", "import time; time.sleep(30)"],
            tmp_path,
            "sleep",
            timeout=30,
        )
        deadline = time.monotonic() + 2
        while not processes._children and time.monotonic() < deadline:
            time.sleep(0.01)
        processes.terminate()
        result = future.result(timeout=3)
    assert result["status"] == "interrupted" or result.get("returncode", 0) < 0
    assert not processes._children


def test_missing_unpublished_evidence_stays_in_history_and_is_rescheduled(tmp_path):
    path, _, _ = job(tmp_path)
    with closing(state.connect(path)) as db:
        row = outcome(path, state.pending(db, 1)[0])
        state.record(db, row)
        (path / row["local_work_dir"] / "outcome.json").unlink()
        assert conversion._local_pending(db, path, 10) == []
        assert state.pending(db, 1)[0]["attempt"] == 2
        assert state.summary(db, 3)["upload_pending_sources"] == 0
        historical = json.loads(db.execute("SELECT value FROM history").fetchone()[0])
        assert historical["local_evidence_status"] == "missing_after_restore"


def test_non_utf8_section_name_keeps_raw_identity_and_serializes(tmp_path):
    from malweave.data.pe_sections import extract_executable_sections

    name = b"\xff\xfe\x80ABC"
    pe = _synthetic_pe([(name, 0x400, 32, 0x20)])
    result = extract_executable_sections(pe, collect_audit=True)
    encoded = json.dumps(result.audit)
    assert encoded
    assert result.audit["sections"][0]["name_raw_hex"] == name.ljust(8, b"\x00").hex()
    source = tmp_path / "input.pe"
    source.write_bytes(pe)
    report = stage.extract(
        source, tmp_path, state.Rules(), state.Runtime(memory_per_task_bytes=1024**3), Processes()
    )
    assert report["status"] == "success"
    assert len(report["attempts"]) == 1
    assert digest(tmp_path / "output.exe") == sha256(b"A" * 32).hexdigest()


def test_aws_group_upload_uses_one_cli_and_bounded_s3_threads(tmp_path):
    calls = []

    class Tool:
        def run(self, command, root, name, **kwargs):
            calls.append(
                (command, kwargs["env"], Path(kwargs["env"]["AWS_CONFIG_FILE"]).read_text())
            )
            (root / "request.stdout").write_text("")
            (root / "request.stderr").write_text("")
            return {
                "status": "success",
                "stdout_file": "request.stdout",
                "stderr_file": "request.stderr",
            }

    source = tmp_path / "exe"
    source.mkdir()
    for i in range(4):
        (source / f"{i}.exe").write_bytes(b"inert")
    aws = AWS(tmp_path, Tool())
    aws.put_tree(source, "s3://bucket/v3/part-01/exe/", 3)
    assert len(calls) == 1 and "--recursive" in calls[0][0]
    assert "max_concurrent_requests = 3" in calls[0][2]
    assert calls[0][1]["AWS_MAX_ATTEMPTS"] == "3"
    assert aws.metrics["uploaded_bytes"] == 20


def test_missing_release_audit_rejects_before_remote_ownership(tmp_path, monkeypatch):
    calls = []

    class Transport(FakeAWS):
        split = AWS.split

        def __init__(self, *args):
            super().__init__(tmp_path / "remote")

        def acquire(self, *args):
            calls.append("acquired")

    monkeypatch.setattr(conversion, "AWS", Transport)
    with pytest.raises(SorelError, match="release audit"):
        conversion.run(
            tmp_path / "job",
            tmp_path / "absent.db",
            state.Rules(),
            state.Runtime(),
            prefix="s3://bucket/v3.1/part-01",
        )
    assert not calls
