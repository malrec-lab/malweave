"""SOREL protocol tests use only synthetic PEs, SQLite metadata and fake scanners."""

from __future__ import annotations

import csv
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import subprocess
import zlib

import pytest
from tests.data.test_pe_sections import _synthetic_pe

from malweave.cli import main
from malweave.data import pe_assessment, sorel
from malweave.data.pe_sections import IMAGE_SCN_CNT_CODE


def _job(tmp_path: Path, *, count: int = 4, architecture: str = "annotate"):
    metadata = tmp_path / "meta.db"
    with sqlite3.connect(metadata) as connection:
        connection.execute(
            "CREATE TABLE meta (sha256 TEXT PRIMARY KEY, is_malware INT, rl_fs_t REAL)"
        )
        connection.executemany(
            "INSERT INTO meta VALUES (?, ?, ?)", [(f"{i:064x}", 1, i) for i in range(count)]
        )
        connection.execute("INSERT INTO meta VALUES (?, ?, ?)", ("f" * 64, 0, 99))
    config = replace(
        sorel.SorelConfig(),
        samples=count,
        batch_size=2,
        workers=2,
        architecture_policy=architecture,
    )
    job = tmp_path / "job"
    summary = sorel.prepare_sorel(metadata, job, config)
    assert summary["label_counts"] == {"0": 1, "1": count}
    assert summary["passed"]
    return job, config, metadata


def _scanners(monkeypatch, *, packing: str = "not_detected", architecture="unknown"):
    monkeypatch.setattr(
        sorel, "_tool", lambda name: {"path": name, "version": "test", "sha256": "test"}
    )
    monkeypatch.setattr(
        sorel,
        "assess_file",
        lambda *args: {
            "status": "success",
            "stdout": "PE32 executable\n",
            "stderr": "diagnostic",
            "returncode": 0,
            "command": ["file", "-b", "synthetic.pe"],
        },
    )
    monkeypatch.setattr(sorel, "architecture_from_file", lambda *args: architecture)
    monkeypatch.setattr(
        sorel,
        "assess_packing",
        lambda *args: {
            "state": packing,
            "modes": {name: "success" for name in pe_assessment.DIEC_MODES},
            "types": ["Packer"] if packing == "obfuscated" else [],
            "reports": {
                name: {
                    "status": "success",
                    "stdout": "original output",
                    "stderr": "diagnostic",
                    "returncode": 0,
                    "command": ["diec", f"--{name}scan", "synthetic.pe"],
                    "report": {
                        "detects": [
                            {
                                "filetype": "PE32",
                                "values": [
                                    {
                                        "type": "packer"
                                        if packing == "obfuscated"
                                        else "compiler",
                                        "name": "=synthetic",
                                        "version": "1.0",
                                        "extra": {"kept": True},
                                    },
                                ],
                            }
                        ]
                    },
                }
                for name in pe_assessment.DIEC_MODES
            },
        },
    )


def _stage(job, config, content):
    summary = sorel.plan_sorel_download(job, config)
    assert summary["batch_sources"] <= config.batch_size
    for source in json.loads((job / "batch.json").read_text()):
        (job / "spool" / f"{source['original_sha256']}.zlib").write_bytes(content)


def test_streaming_selection_is_reproducible_and_private(tmp_path):
    job, config, metadata = _job(tmp_path, count=8)
    smaller = replace(config, samples=3)
    other = tmp_path / "other"
    sorel.prepare_sorel(metadata, other, smaller)
    repeat = tmp_path / "repeat"
    sorel.prepare_sorel(metadata, repeat, smaller)
    a = json.loads((other / "selection.json").read_text())
    b = json.loads((repeat / "selection.json").read_text())
    assert a["sources_sha256"] == b["sources_sha256"]
    with sqlite3.connect(other / "state.sqlite") as connection:
        rows = [json.loads(value) for (value,) in connection.execute("SELECT value FROM sources")]
    assert len(rows) == 3
    assert all(row["is_malware"] == 1 for row in rows)
    with pytest.raises(sorel.SorelError, match="exists"):
        sorel.prepare_sorel(metadata, job, config)
    with pytest.raises(sorel.SorelError, match="config"):
        sorel.plan_sorel_download(job, replace(config, seed=5))


def test_batch_cleanup_exact_dedup_resume_and_corruption(tmp_path, monkeypatch):
    job, config, _ = _job(tmp_path)
    _scanners(monkeypatch)
    pe = _synthetic_pe([(b".text", 0x400, 0x20, IMAGE_SCN_CNT_CODE)])
    compressed = zlib.compress(pe)
    _stage(job, config, compressed)
    report = sorel.run_sorel(job, config, staged=True, limit=1)
    assert report["completed"] == 1
    assert len(list((job / "spool").iterdir())) == 1
    with pytest.raises(sorel.SorelError, match="Spool"):
        sorel.plan_sorel_download(job, config)
    report = sorel.run_sorel(job, config, staged=True)
    assert report["completed"] == 2
    assert not list((job / "spool").iterdir())
    # Same planned batch is a no-op on resume, including already recorded failures.
    assert sorel.run_sorel(job, config, staged=True)["completed"] == 2
    _stage(job, config, compressed)
    report = sorel.run_sorel(job, config, staged=True)
    assert report["pending"] == 0
    assert report["status_counts"] == {"success": 4}
    assert report["distinct_exe"] == 1
    assert report["architecture_counts"] == {"unknown": 4}
    assert not list((job / "scratch").iterdir())
    rows = json.loads((job / "manifest.json").read_text())
    assert rows[0]["released_pe_sha256"] == sha256(pe).hexdigest()
    assert rows[0]["released_pe_sha256"] != rows[0]["original_sha256"]
    assert report["staged_download_time_excluded"]
    output = job / rows[0]["exe_path"]
    output.write_bytes(b"corrupted")
    with pytest.raises(sorel.SorelError, match="corrupt"):
        sorel.verify_sorel(job)


@pytest.mark.parametrize(
    ("packing", "architecture", "policy", "expected"),
    [
        ("obfuscated", "i386", "annotate", "filtered_obfuscated"),
        ("unknown", "i386", "annotate", "filtered_packing_unknown"),
        ("not_detected", "unknown", "i386", "filtered_architecture"),
    ],
)
def test_screen_before_extraction(tmp_path, monkeypatch, packing, architecture, policy, expected):
    job, config, _ = _job(tmp_path, count=1, architecture=policy)
    _scanners(monkeypatch, packing=packing, architecture=architecture)
    monkeypatch.setattr(sorel, "_run_lief_worker", lambda *args: pytest.fail("must filter first"))
    _stage(job, config, zlib.compress(b"synthetic bytes"))
    report = sorel.run_sorel(job, config, staged=True)
    assert report["status_counts"] == {expected: 1}
    row = json.loads((job / "manifest.json").read_text())[0]
    assert (job / row["file_report_path"]).is_file()
    assert (job / row["die_report_path"]).is_file()
    assert "lief_report_path" not in row  # Filtering precedes extraction.
    assert not list((job / "spool").iterdir())


@pytest.mark.parametrize(
    ("content", "maximum", "expected"),
    [
        (b"not zlib", 1000, "decompression_error"),
        (zlib.compress(b"abc")[:-1], 1000, "invalid_zlib_stream"),
        (zlib.compress(b"abc") + b"trailer", 1000, "invalid_zlib_stream"),
        (zlib.compress(b"a" * 1000), 99, "pe_size_limit"),
    ],
)
def test_decompression_is_bounded_and_complete(content, maximum, expected):
    with pytest.raises(sorel.SourceFailure, match=expected):
        sorel.decompress_sorel(content, maximum)


def test_missing_download_and_bad_zlib_accounted_and_not_replaced(tmp_path, monkeypatch):
    job, config, _ = _job(tmp_path, count=2)
    _scanners(monkeypatch)
    sorel.plan_sorel_download(job, config)
    batch = json.loads((job / "batch.json").read_text())
    (job / "spool" / f"{batch[0]['original_sha256']}.zlib").write_bytes(b"bad zlib")
    report = sorel.run_sorel(job, config, staged=True)
    assert report["status_counts"] == {"download_missing": 1, "decompression_error": 1}
    assert report["pending"] == 0
    assert sorel.plan_sorel_download(job, config)["batch_sources"] == 0


def test_unknown_diec_is_not_negative_and_pe32_is_not_i386(monkeypatch, tmp_path):
    assert pe_assessment.architecture_from_file("PE32 executable (GUI)") == "unknown"
    assert pe_assessment.architecture_from_file("PE32 executable Intel 80386") == "i386"
    responses = iter(
        [
            '{"detects":[{"filetype":"PE32","values":[{"type":"packer","name":"test"}]}]}',
            "{}",
            "{}",
        ]
    )
    monkeypatch.setattr(
        pe_assessment.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, next(responses), ""),
    )
    result = pe_assessment.assess_packing("diec", tmp_path / "fake", 1)
    assert result["state"] == "obfuscated"  # A positive survives failures in other modes.
    assert result["types"] == ["Packer"]
    assert result["reports"]["recursive"]["report"]["detects"][0]["values"][0]["name"] == "test"
    monkeypatch.setattr(
        pe_assessment.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "{}", ""),
    )
    assert pe_assessment.assess_packing("diec", tmp_path / "fake", 1)["state"] == "unknown"
    monkeypatch.setattr(
        pe_assessment.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, '{"detects":[{"filetype":"Binary","values":[]}]}', ""
        ),
    )
    assert pe_assessment.assess_packing("diec", tmp_path / "fake", 1)["state"] == "unknown"


def test_scanner_reports_preserve_invalid_output_errors_and_timeout(monkeypatch, tmp_path):
    arguments = ["diec", "--deep scan", "synthetic.pe"]
    results = iter(
        [
            subprocess.CompletedProcess(arguments, 1, "invalid JSON", "scanner failed"),
            subprocess.TimeoutExpired(
                arguments, 1, output=b"partial stdout", stderr=b"partial stderr"
            ),
            subprocess.CompletedProcess(arguments, 0, "{}", "warning"),
        ]
    )

    def scan(*args, **kwargs):
        value = next(results)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(pe_assessment.subprocess, "run", scan)
    result = pe_assessment.assess_packing("diec", tmp_path / "fake", 1)
    assert result["state"] == "unknown"
    assert result["reports"]["recursive"]["stdout"] == "invalid JSON"
    assert result["reports"]["recursive"]["stderr"] == "scanner failed"
    assert result["reports"]["recursive"]["returncode"] == 1
    assert result["reports"]["deep"]["stdout"] == "partial stdout"
    assert result["reports"]["deep"]["status"] == "timeout"
    assert result["reports"]["heuristic"]["report"] == {}
    monkeypatch.setattr(
        pe_assessment.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 2, "partial description", "file failed"
        ),
    )
    report = pe_assessment.assess_file("file", tmp_path / "fake", 1)
    assert report["status"] == "error"
    assert report["stdout"] == "partial description"
    assert report["stderr"] == "file failed"
    assert report["returncode"] == 2


def test_saved_tool_evidence_exports_without_scanning_and_detects_corruption(
    tmp_path, monkeypatch
):
    job, config, _ = _job(tmp_path, count=1)
    _scanners(monkeypatch)
    pe = _synthetic_pe([(b".code", 0x400, 0x20, IMAGE_SCN_CNT_CODE)])
    _stage(job, config, zlib.compress(pe))
    sorel.run_sorel(job, config, staged=True)
    row = json.loads((job / "manifest.json").read_text())[0]
    for tool in ("file", "die", "lief"):
        saved = sorel._read_tool_report(job, row, tool)
        assert saved["released_pe_sha256"] == sha256(pe).hexdigest()
    saved = sorel._read_tool_report(job, row, "die")
    finding = saved["result"]["reports"]["recursive"]["report"]["detects"][0]["values"][0]
    assert finding["extra"] == {"kept": True}
    monkeypatch.setattr(sorel, "assess_packing", lambda *args: pytest.fail("must not rescan"))
    monkeypatch.setattr(sorel, "_tool", lambda *args: pytest.fail("must not inspect tools"))
    monkeypatch.setattr(sorel, "download_source", lambda *args: pytest.fail("must not download"))
    monkeypatch.setattr(
        sorel,
        "_run_lief_worker",
        lambda *args, **kwargs: pytest.fail("must not parse PE"),
    )
    assert main(["data", "sorel-export", "--job-dir", str(job), "--config", "absent.yaml"]) == 0
    summary = json.loads((job / "export-summary.json").read_text())
    assert summary["saved_tool_reports"] == {"file": 1, "die": 1, "lief": 1}
    with (job / "die-detections.csv").open(encoding="utf-8-sig", newline="") as stream:
        findings = list(csv.DictReader(stream))
    assert len(findings) == 3
    assert findings[0]["name"] == "'=synthetic"  # Excel must not evaluate a scanner string.
    with (job / "lief-sections.csv").open(encoding="utf-8-sig", newline="") as stream:
        section = next(csv.DictReader(stream))
    assert int(section["copied_bytes"]) == 0x20
    (job / row["file_report_path"]).write_text("corrupt")
    with pytest.raises(sorel.SorelError, match="corrupt"):
        sorel.export_sorel(job)


def test_legacy_export_marks_missing_evidence_without_inventing_it(tmp_path):
    job, _, _ = _job(tmp_path, count=1)
    row = {
        "original_sha256": "0" * 64,
        "status": "success",
        "packing": "not_detected",
        "architecture": "unknown",
        "file_status": "success",
        "file_description": "PE32",
        "die_modes": {"deep": "success"},
        "warnings": [],
    }
    with sqlite3.connect(job / "state.sqlite") as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS outcomes (id TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT INTO outcomes VALUES (?, ?)", (row["original_sha256"], json.dumps(row))
        )
    summary = sorel.export_sorel(job)
    assert summary["saved_tool_reports"] == {"file": 0, "die": 0, "lief": 0}
    with (job / "tool-runs.csv").open(encoding="utf-8-sig", newline="") as stream:
        reports = list(csv.DictReader(stream))
    assert {record["status"] for record in reports} == {"full_report_not_saved"}


def test_invalid_config_cli_and_changed_tool_reject_resume(tmp_path, monkeypatch):
    config_path = tmp_path / "bad.yaml"
    config_path.write_text("samples: wrong\n")
    assert (
        main(
            [
                "data",
                "sorel-download-plan",
                "--config",
                str(config_path),
                "--job-dir",
                str(tmp_path),
            ]
        )
        == 2
    )
    job, config, _ = _job(tmp_path, count=1)
    _scanners(monkeypatch)
    _stage(job, config, b"bad zlib")
    sorel.run_sorel(job, config, staged=True)
    monkeypatch.setattr(
        sorel, "_tool", lambda name: {"path": name, "version": "changed", "sha256": "changed"}
    )
    with pytest.raises(sorel.SorelError, match="changed"):
        sorel.run_sorel(job, config, staged=True)


def test_free_space_guard_preserves_pending_and_staged_sources(tmp_path, monkeypatch):
    job, config, _ = _job(tmp_path, count=1)
    _scanners(monkeypatch)
    _stage(job, config, zlib.compress(b"synthetic"))
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(sorel.shutil, "disk_usage", lambda *args: usage(100, 99, 1))
    with pytest.raises(sorel.SorelError, match="free space"):
        sorel.run_sorel(job, config, staged=True)
    assert len(list((job / "spool").iterdir())) == 1
    with sqlite3.connect(job / "state.sqlite") as connection:
        assert connection.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0] == 0


def test_existing_output_conflict_never_overwritten(tmp_path, monkeypatch):
    job, config, _ = _job(tmp_path, count=1)
    _scanners(monkeypatch)
    pe = _synthetic_pe([(b".text", 0x400, 0x20, IMAGE_SCN_CNT_CODE)])
    _stage(job, config, zlib.compress(pe))
    digest = sha256(b"A" * 32).hexdigest()
    output = job / "exe" / digest[:2] / f"{digest}.exe"
    output.parent.mkdir(parents=True)
    output.write_bytes(b"conflicting synthetic bytes")
    with pytest.raises(sorel.SorelError, match="Conflicting"):
        sorel.run_sorel(job, config, staged=True)
    assert output.read_bytes() == b"conflicting synthetic bytes"
    assert list((job / "spool").iterdir())
