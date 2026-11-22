"""No live inputs: aggregate timing proposals must disclose failures and tail limits."""

from hashlib import sha256
import json
from pathlib import Path

import pytest

from malweave.data import ghidra_benchmark as benchmark
from malweave.data.ghidra_benchmark import (
    benchmark_summary,
    process_tree_rss,
    run_benchmark,
    unlimited_command,
)
from malweave.data.sorel_io import SorelError
from tests.data.test_pe_routing import synthetic_pe


def test_batch_cli_accepts_twelve_workers():
    from malweave.cli import _parser

    args = _parser().parse_args(
        [
            "data",
            "benchmark-ghidra",
            "--manifest",
            "synthetic.private.json",
            "--output-dir",
            "synthetic-output",
            "--workers",
            "12",
            "--isolated-worker",
        ]
    )
    assert args.workers == 12


def test_cgroup_telemetry_is_not_summed_rss_and_retains_oom_evidence(tmp_path):
    (tmp_path / "memory.current").write_text("1234\n")
    (tmp_path / "memory.peak").write_text("5678\n")
    (tmp_path / "memory.max").write_text("max\n")
    (tmp_path / "memory.events").write_text("oom 2\noom_kill 1\n")
    (tmp_path / "cpu.stat").write_text("usage_usec 123456\nnr_throttled 9\n")
    (tmp_path / "cpu.max").write_text("400000 100000\n")
    snapshot = benchmark.cgroup_snapshot(tmp_path)
    assert snapshot["available"] is True
    assert snapshot["memory_current"] == 1234
    assert snapshot["memory_max"] is None
    assert snapshot["memory_events"]["oom_kill"] == 1
    assert snapshot["cpu_quota_cores"] == 4
    assert snapshot["cpu_stat"]["nr_throttled"] == 9


def test_missing_cgroup_counters_are_not_reported_as_zero(tmp_path):
    assert benchmark.cgroup_snapshot(tmp_path) == {"available": False}


def row(label, seconds, status="success"):
    return {
        "label": label,
        "seconds": seconds,
        "views": [{"status": status}, {"status": "success"}],
    }


def test_timing_budget_reserves_two_hours_and_uses_slowest_source():
    result = benchmark_summary([row("benign", 10), row("ransomware", 20)], 30, 1)
    assert result["both_views_successful"] == 2
    assert result["conservative_12h_batch_proposal"] == 1800
    assert result["per_source_seconds"]["mean"] == 15
    assert result["classes"]["ransomware"]["sources"] == 1
    assert result["corpus_throughput_established"] is False


def test_failure_is_counted_and_prevents_unqualified_batch_recommendation():
    result = benchmark_summary([row("benign", 10, "partial_timeout")], 10, 1)
    assert result["incomplete_or_failed"] == 1
    assert result["successful_sources_per_hour"] == 0
    assert result["conservative_12h_batch_proposal"] is None


def test_empty_pilot_cannot_establish_throughput():
    result = benchmark_summary([], 0, 2)
    assert result["sources_per_hour_including_failures"] is None
    assert result["conservative_12h_batch_proposal"] is None


def test_byte_throughput_is_separate_from_file_throughput():
    first, second = row("benign", 10), row("ransomware", 20)
    first["input_bytes"], second["input_bytes"] = 1024**2, 9 * 1024**2
    result = benchmark_summary([first, second], 30, 2)
    assert result["input_MiB_per_hour_including_failures"] == 1200
    assert result["successful_input_bytes"] == 10 * 1024**2
    assert result["twelve_hour_input_MiB_proposal"] == 9000
    assert result["size_buckets"]["1_to_10_MiB"]["sources"] == 2
    assert result["size_alone_determines_runtime"] is False


def test_rss_measurement_excludes_unrelated_sessions():
    assert process_tree_rss("10 1 20\n11 10 30\n12 11 40\n50 1 999\n", 10) == 90 * 1024


@pytest.mark.parametrize("view", ["dis", "dec"])
def test_unlimited_commands_have_no_analysis_deadline(view):
    command = unlimited_command(
        Path("/headless"), view, Path("/source"), Path("/project"), Path("/output")
    )
    assert "-analysisTimeoutPerFile" not in command
    assert command[command.index("-postScript") + 1].endswith("Unlimited.java")
    assert command[command.index("-max-cpu") + 1] == "1"


@pytest.mark.parametrize(
    "log,expected",
    [
        ("ERROR SCRIPT ERROR: ClassNotFound", "unconfirmed_completion"),
        ("analysisTimeoutOccurred()=false\nrun: finished (success) <synthetic>", "success"),
        ("decompileFunction: incomplete=real parser error", "partial_error"),
    ],
)
def test_unlimited_parser_never_hides_script_or_function_errors(
    tmp_path, monkeypatch, log, expected
):
    class Processes:
        def run(self, command, root, timeout, heap):
            assert timeout is None and heap == 1024
            return {"status": "success", "returncode": 0, "stdout": log, "stderr": ""}

    monkeypatch.setattr(benchmark, "_save_view_output", lambda *args: None)
    result = benchmark._unlimited_view(
        {"sha256": "synthetic", "transfer": {}},
        "dec",
        tmp_path,
        tmp_path,
        Path("/headless"),
        Processes(),
        1024,
    )
    assert result["status"] == expected


def test_isolated_worker_acknowledgement_required_before_reading_manifest(tmp_path):
    with pytest.raises(SorelError, match="isolated"):
        run_benchmark(
            tmp_path / "missing.json",
            tmp_path / "cache",
            tmp_path / "output",
            workers=1,
            isolated_worker=False,
        )
    assert not (tmp_path / "output").exists()


def batch_source(index, label="benign", arch="I386", size=1024, identity=None):
    return {
        "index": index,
        "sha256": identity or f"{index:064x}",
        "label": label,
        "metadata_arch": arch,
        "bytes": size,
    }


def test_twelve_worker_batch_reaches_tool_setup_not_just_cli(tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "mode": "batch",
                "heap_mb": 1024,
                "timeout_policy": "unlimited",
                "sources": [batch_source(i) for i in range(1, 101)],
            }
        )
    )

    def stop_at_tools(cache):
        raise RuntimeError("synthetic tool setup reached")

    monkeypatch.setattr(benchmark, "setup_ghidra", stop_at_tools)
    with pytest.raises(RuntimeError, match="synthetic tool setup reached"):
        run_benchmark(
            path, tmp_path / "cache", tmp_path / "output", workers=12, isolated_worker=True
        )


def test_twelve_workers_do_not_expand_legacy_pilot_protocol(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"mode": "pilot", "sources": []}))
    with pytest.raises(SorelError, match="12 workers require batch mode"):
        run_benchmark(
            path, tmp_path / "cache", tmp_path / "output", workers=12, isolated_worker=True
        )


def test_batch_manifest_accepts_unbalanced_fixed_size_runs():
    sources = [
        batch_source(1, "benign"),
        batch_source(2, "ransomware"),
        batch_source(3, "ransomware"),
    ]
    benchmark.validate_batch_sources(sources, heap_mb=1024, unlimited=True)


@pytest.mark.parametrize(
    "sources,heap,unlimited,match",
    [
        ([batch_source(1, arch="AMD64")], 1024, True, "metadata-I386"),
        (
            [batch_source(1), batch_source(2, identity=batch_source(1)["sha256"])],
            1024,
            True,
            "repeats",
        ),
        ([batch_source(2)], 1024, True, "indices"),
        ([], 1024, True, "1.."),
        ([batch_source(1, size=0)], 1024, True, "capacity"),
        ([batch_source(1)], 2048, True, "1 GiB heap"),
        ([batch_source(1)], 1024, False, "unlimited"),
    ],
)
def test_batch_manifest_rejects_unqualified_runs(sources, heap, unlimited, match):
    with pytest.raises(SorelError, match=match):
        benchmark.validate_batch_sources(sources, heap_mb=heap, unlimited=unlimited)


def test_unknown_manifest_mode_is_rejected_before_setup(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"mode": "sweep", "sources": []}')
    with pytest.raises(SorelError, match="mode"):
        run_benchmark(
            manifest,
            tmp_path / "cache",
            tmp_path / "output",
            workers=1,
            isolated_worker=True,
        )
    assert not (tmp_path / "cache").exists()


def test_successful_views_publish_to_the_canonical_representation_store(tmp_path, monkeypatch):
    seen = []

    def fake_upload(urls, payload):
        seen.append((urls["key"], payload))
        return "synthetic-digest"

    monkeypatch.setattr(benchmark, "upload_verified", fake_upload)
    job = tmp_path / "job"
    (job / "representations/dis/ab").mkdir(parents=True)
    (job / "representations/dec/ab").mkdir(parents=True)
    (job / "representations/dis/ab/ab12.asm").write_text("dis")
    (job / "representations/dec/ab/ab12.c").write_text("dec")
    row = {
        "representations": {
            "dis": {"key": "rands/representations/dis/ab/ab12.asm"},
            "dec": {"key": "rands/representations/dec/ab/ab12.c"},
        }
    }
    result = {
        "views": [
            {
                "view": "dis",
                "status": "success",
                "output_path": "representations/dis/ab/ab12.asm",
            },
            {
                "view": "dec",
                "status": "partial_error",
                "output_path": "representations/dec/ab/ab12.c",
            },
        ]
    }
    benchmark.publish_representations(row, job, result)
    assert [key for key, _ in seen] == ["rands/representations/dis/ab/ab12.asm"]
    assert result["views"][0]["representation_sha256"] == "synthetic-digest"
    assert result["views"][0]["representation_bytes"] == 3
    assert "representation_sha256" not in result["views"][1]


@pytest.mark.parametrize("managed,pe64", [(True, False), (True, True), (False, True)])
def test_batch_parser_defers_non_native_sources_before_any_ghidra_call(
    tmp_path, monkeypatch, managed, pe64
):
    monkeypatch.setattr(benchmark.signal, "signal", lambda *args: None)
    content = synthetic_pe(managed=managed, pe64=pe64)
    identity = sha256(content).hexdigest()
    (tmp_path / identity).write_bytes(content)
    config = tmp_path / "parser-config.json"
    config.write_text(
        json.dumps(
            {
                "source": {"sha256": identity},
                "raw_root": str(tmp_path),
                "job": str(tmp_path),
                "headless": "/must-not-run",
                "mode": "batch",
                "timeout_policy": "unlimited",
                "heap_mb": 1024,
            }
        )
    )

    def forbidden(*args, **kwargs):
        pytest.fail("A deferred input must not enter Ghidra")

    monkeypatch.setattr(benchmark, "_unlimited_view", forbidden)
    monkeypatch.setattr(benchmark, "_extract_view", forbidden)
    benchmark.parser_source(config)
    result = json.loads((tmp_path / "parser-result.json").read_text())
    assert result["pending"] is not managed
    assert result["excluded"] is managed
    assert result["routing"]["input_sha256"] == identity
    assert len(result["views"]) == 2
    assert all(
        view["status"] == ("excluded_dotnet" if managed else "deferred_pe_review")
        for view in result["views"]
    )
    evidence = benchmark._pack_evidence(tmp_path)
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(evidence)) as archive:
        assert {"routing.json", "parser-result.json"} <= set(archive.getnames())
    assert not (tmp_path / "representations").exists()


@pytest.mark.parametrize("mode", ["batch", "pilot"])
def test_native_batch_and_legacy_pilot_keep_both_unlimited_views_and_settings(
    tmp_path, monkeypatch, mode
):
    monkeypatch.setattr(benchmark.signal, "signal", lambda *args: None)
    content = synthetic_pe(managed=mode == "pilot")
    identity = sha256(content).hexdigest()
    (tmp_path / identity).write_bytes(content)
    config = tmp_path / "parser-config.json"
    config.write_text(
        json.dumps(
            {
                "source": {"sha256": identity},
                "raw_root": str(tmp_path),
                "job": str(tmp_path),
                "headless": "/headless",
                "mode": mode,
                "timeout_policy": "unlimited",
                "heap_mb": 1024,
            }
        )
    )
    calls = []

    def extract(source, view, raw, job, headless, processes, heap):
        calls.append((view, heap))
        return {"view": view, "status": "success"}

    monkeypatch.setattr(benchmark, "_unlimited_view", extract)
    benchmark.parser_source(config)
    result = json.loads((tmp_path / "parser-result.json").read_text())
    assert result["pending"] is False
    if mode == "batch":
        assert result["routing"]["route"] == "ghidra_x86"
    else:
        assert result["routing"] is None
    assert calls == [("dis", 1024), ("dec", 1024)]


def test_pending_or_mismatched_routing_cannot_publish_even_with_success_views(
    tmp_path, monkeypatch
):
    def forbidden(*args):
        pytest.fail("Deferred or incompatible views must not be published")

    monkeypatch.setattr(benchmark, "upload_verified", forbidden)
    for result in (
        {"pending": True},
        {"excluded": True},
        {"routing": {"route": "excluded_dotnet"}},
        {"routing": {"route": "managed_pending"}},
        {"routing": {"route": "pending_review"}},
    ):
        result["views"] = [{"view": "dis", "status": "success", "output_path": "not-read"}]
        benchmark.publish_representations(
            {"representations": {"dis": {"put": "never"}}}, tmp_path, result
        )


def test_deferred_sources_are_not_success_and_remain_in_class_accounting():
    pending = {
        "label": "benign",
        "seconds": 1,
        "input_bytes": 100,
        "pending": True,
        "views": [{"view": view, "status": "deferred_managed_backend"} for view in ("dis", "dec")],
    }
    result = benchmark_summary([pending], 1, 12)
    assert result["both_views_successful"] == 0
    assert result["pending_backend_or_review"] == 1
    assert result["classes"]["benign"]["pending_backend_or_review"] == 1
    assert result["successful_input_bytes"] == 0
    assert result["conservative_12h_batch_proposal"] is None


def test_real_batch_parser_boundary_preserves_dotnet_exclusion_and_verified_evidence(
    tmp_path, monkeypatch
):
    import io
    import tarfile

    content = synthetic_pe(managed=True)
    identity = sha256(content).hexdigest()
    source = {
        **batch_source(1, size=len(content), identity=identity),
        "metadata_packed": "0",
        "key": "synthetic-input",
        "etag": '"synthetic"',
        "download": "https://synthetic.invalid/input",
        "backup": {"key": "synthetic-evidence"},
        "representations": {"dis": {"key": "must-not-publish"}},
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "mode": "batch",
                "contract": "synthetic-routing-contract",
                "heap_mb": 1024,
                "timeout_policy": "unlimited",
                "sources": [source],
                "sampling": "synthetic",
                "source_plan_sha256": "synthetic",
                "progress": {"key": "synthetic-progress"},
            }
        )
    )
    monkeypatch.setattr(
        benchmark,
        "setup_ghidra",
        lambda cache: {
            "java_home": "/synthetic",
            "analyze_headless": "/must-not-launch-ghidra",
        },
    )
    monkeypatch.setattr(benchmark, "urlopen", lambda *args, **kwargs: io.BytesIO(content))
    uploaded = {}

    def upload(urls, payload):
        uploaded[urls["key"]] = payload
        return sha256(payload).hexdigest()

    monkeypatch.setattr(benchmark, "upload_verified", upload)
    result = run_benchmark(
        manifest, tmp_path / "cache", tmp_path / "output", workers=12, isolated_worker=True
    )
    assert result["status"] == "completed_with_exclusions"
    assert result["summary"]["both_views_successful"] == 0
    assert result["summary"]["pending_backend_or_review"] == 0
    assert result["summary"]["excluded_dotnet"] == 1
    assert result["summary"]["incomplete_or_failed"] == 0
    assert result["summary"]["classes"]["benign"]["excluded_dotnet"] == 1
    assert result["remaining_representation_sources"] == 0
    assert result["terminal_sources"] == 1
    assert result["unfinished_sources"] == 0
    assert result["recorded_attempts"] == 1
    assert result["pending_sources"] == []
    assert result["excluded_sources"][0]["source_sha256"] == identity
    assert result["results"][0]["status"] == "excluded_dotnet"
    assert (
        result["results"][0]["backup_sha256"] == sha256(uploaded["synthetic-evidence"]).hexdigest()
    )
    with tarfile.open(fileobj=io.BytesIO(uploaded["synthetic-evidence"])) as archive:
        routing = json.load(archive.extractfile("routing.json"))
        assert routing["input_sha256"] == identity
        assert "source-report.json" in archive.getnames()
        assert not any(name.startswith("representations") for name in archive.getnames())
    assert set(uploaded) == {"synthetic-evidence", "synthetic-progress"}
