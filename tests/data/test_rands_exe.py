"""Synthetic tests for full-corpus, resumable RanDS EXE extraction."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import struct

import pytest

from malweave.cli import main
from malweave.data.dataset_config import (
    RandsDatasetConfig,
    RandsDatasetLocations,
    RandsExpectedCounts,
    RandsProtocol,
)
from malweave.data.pe_sections import IMAGE_SCN_CNT_CODE
from malweave.data.rands import BENIGN_HEADER, RANSOMWARE_ACTUAL_HEADER
from malweave.data.rands_exe import (
    RandsExeError,
    enumerate_rands_sources,
    extract_rands_exe,
    write_rands_exe_outputs,
)
from malweave.data.rands_products import build_rands_products, load_exe_inputs


def _synthetic_pe(*, code: bool, section_byte: bytes = b"X") -> bytes:
    content = bytearray(0x600)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", content, 0x84, 0x14C)
    struct.pack_into("<H", content, 0x86, 1)
    struct.pack_into("<H", content, 0x94, 0xE0)
    struct.pack_into("<H", content, 0x98, 0x10B)
    section_header = 0x178
    content[section_header : section_header + 8] = b".code\0\0\0"
    struct.pack_into("<I", content, section_header + 16, 0x20)
    struct.pack_into("<I", content, section_header + 20, 0x400)
    struct.pack_into("<I", content, section_header + 36, IMAGE_SCN_CNT_CODE if code else 0)
    content[0x400:0x420] = section_byte * 0x20
    return bytes(content)


def _fixture(tmp_path: Path) -> tuple[Path, RandsDatasetConfig, dict[str, str]]:
    root = tmp_path / "rands"
    (root / "dataset").mkdir(parents=True)
    contents = {"benign": _synthetic_pe(code=True), "ransomware": _synthetic_pe(code=False)}
    shas = {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()}
    for name, content in contents.items():
        path = root / "dataset" / shas[name][:2]
        path.mkdir(parents=True, exist_ok=True)
        (path / shas[name]).write_bytes(content)
    with (root / "Benign.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(BENIGN_HEADER)
        writer.writerow(
            [
                shas["benign"],
                "a" * 40,
                "b" * 32,
                len(contents["benign"]),
                "exe",
                "I386",
                0,
                1.0,
                2020,
                "ignored",
            ]
        )
    with (root / "Ransomware.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(RANSOMWARE_ACTUAL_HEADER)
        writer.writerow(
            [
                shas["ransomware"],
                "c" * 40,
                "d" * 32,
                len(contents["ransomware"]),
                "exe",
                "I386",
                0,
                1.0,
                "Synthetic",
                2021,
                "ignored",
            ]
        )
    config = RandsDatasetConfig(
        name="rands",
        snapshot="test",
        root_env="TEST_RANDS_ROOT",
        benign_csv="Benign.csv",
        ransomware_csv="Ransomware.csv",
        samples_dir="dataset",
        expected=RandsExpectedCounts(
            shards=len({value[:2] for value in shas.values()}),
            files=2,
            labels={"benign": 1, "ransomware": 1},
        ),
        protocols={"full": RandsProtocol()},
    )
    return root, config, shas


def test_full_extraction_commits_each_source_and_resumes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, config, shas = _fixture(tmp_path)
    representation_root = tmp_path / "representations"
    state_path = tmp_path / "state" / "exe.sqlite"
    first_rows, first_summary = extract_rands_exe(
        config, root, representation_root, state_path, limit=1, progress_every=1
    )
    assert len(first_rows) == 1
    assert first_summary["job"] == {
        "sources_total": 2,
        "sources_completed": 1,
        "sources_pending": 1,
        "complete": False,
    }
    assert "[extract-exe] 1/2 (50.0%)" in capsys.readouterr().err
    rows, summary = extract_rands_exe(config, root, representation_root, state_path, resume=True)
    assert [row.source_sha256 for row in rows] == sorted(shas.values())
    assert summary["job"]["complete"] is True
    assert summary["extraction"]["statuses"] == {"no_executable_section": 1, "success": 1}
    assert (
        representation_root / shas["benign"][:2] / f"{shas['benign']}.bin"
    ).read_bytes() == b"X" * 0x20
    manifest_path = tmp_path / "exe-manifest.csv"
    summary_path = tmp_path / "summary.json"
    written = write_rands_exe_outputs(rows, summary, manifest_path, summary_path)
    assert written["manifest"]["rows"] == 2
    assert json.loads(summary_path.read_text(encoding="utf-8"))["job"]["complete"] is True


def test_state_requires_explicit_resume(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)
    state_path = tmp_path / "state.sqlite"
    extract_rands_exe(config, root, tmp_path / "exe", state_path, limit=1)
    with pytest.raises(RandsExeError, match="state already exists"):
        extract_rands_exe(config, root, tmp_path / "exe", state_path)


def test_products_derive_full_audited_source_list(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)
    raw_root = tmp_path / "raw"
    metadata_root = tmp_path / "metadata"
    raw_root.mkdir()
    metadata_root.mkdir()
    (root / "dataset").rename(raw_root / "dataset")
    (root / "Benign.csv").rename(metadata_root / "Benign.csv")
    (root / "Ransomware.csv").rename(metadata_root / "Ransomware.csv")
    locations = RandsDatasetLocations(raw_root=raw_root, metadata_root=metadata_root)
    exe_root = tmp_path / "exe"
    rows, summary = extract_rands_exe(config, locations, exe_root, tmp_path / "state.sqlite")
    manifest_path = tmp_path / "exe.csv"
    write_rands_exe_outputs(rows, summary, manifest_path, tmp_path / "summary.json")
    products, product_summary = build_rands_products(
        config, locations, load_exe_inputs(manifest_path), exe_root
    )
    assert len(enumerate_rands_sources(config, locations)) == 2
    assert {row.representation for row in products} == {"raw", "exe"}
    assert product_summary["source_cohort"] == {
        "total": 2,
        "raw_available": 2,
        "exe_available": 1,
        "exe_excluded": {"no_executable_section": 1},
    }


def test_cli_uses_full_corpus_without_a_source_manifest(tmp_path: Path) -> None:
    root, _, _ = _fixture(tmp_path)
    raw_root = tmp_path / "raw"
    metadata_root = tmp_path / "metadata"
    raw_root.mkdir()
    metadata_root.mkdir()
    (root / "dataset").rename(raw_root / "dataset")
    (root / "Benign.csv").rename(metadata_root / "Benign.csv")
    (root / "Ransomware.csv").rename(metadata_root / "Ransomware.csv")
    config_path = tmp_path / "dataset.yaml"
    config_path.write_text(
        """dataset: {name: rands, snapshot: test, root_env: TEST_RANDS_ROOT}
layout: {benign_csv: Benign.csv, ransomware_csv: Ransomware.csv, samples_dir: dataset}
expected: {shards: 2, files: 2, labels: {benign: 1, ransomware: 1}}
protocols: {full: {}}
""",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "data",
                "extract-exe",
                "--dataset",
                "rands",
                "--config",
                str(config_path),
                "--root",
                str(raw_root),
                "--metadata-root",
                str(metadata_root),
                "--representation-dir",
                str(tmp_path / "exe"),
                "--state-db",
                str(tmp_path / "state.sqlite"),
                "--manifest",
                str(tmp_path / "exe.csv"),
                "--summary",
                str(tmp_path / "summary.json"),
            ]
        )
        == 0
    )
