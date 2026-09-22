"""Synthetic tests for full-corpus, resumable RanDS EXE extraction."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import struct
import subprocess

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
from malweave.data.rands_ghidra import (
    RandsGhidraError,
    _ghidra_command,
    extract_rands_ghidra,
    normalize_decompilation,
    normalize_disassembly,
    plan_rands_ghidra_shards,
    write_rands_ghidra_outputs,
)
from malweave.data.rands_pe_assessment import (
    RandsPeAssessmentError,
    assess_rands_pe,
    write_rands_pe_assessment_outputs,
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
                1,
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


def _static_tool(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_analyze_headless(tmp_path: Path) -> Path:
    return _static_tool(
        tmp_path,
        "fake-analyzeHeadless",
        """source=''
out=''
target=''
previous=''
for arg in "$@"; do
  if [ "$previous" = '-import' ]; then source="$arg"; fi
  if [ "$previous" = '-postScript' ]; then
    if [ "$arg" = 'Disassembler.java' ] || [ "$arg" = 'Decompiler.java' ]; then target="$arg"; fi
  elif [ -n "$target" ] && [ -z "$out" ]; then out="$arg"; fi
  previous="$arg"
done
mkdir -p "$out"
name=$(basename "$source")
if [ "$target" = 'Disassembler.java' ]; then
  printf 'header\\nram\\t0000\\t0000\\t90\\tmov eax, ebx\\n' > "$out/$name.asm"
else
  printf '%s\\n' 'int main(void) { /* generated */ return 0; }' > "$out/$name.c"
fi""",
    )


def _fake_analyzer(tmp_path: Path, *, dis_output: bytes, dec_output: bytes) -> Path:
    dis_hex = dis_output.hex()
    dec_hex = dec_output.hex()
    return _static_tool(
        tmp_path,
        "fake-analyzeHeadless",
        f"""source=''
out=''
target=''
previous=''
for arg in "$@"; do
  if [ "$previous" = '-import' ]; then source="$arg"; fi
  if [ "$previous" = '-postScript' ]; then
    if [ "$arg" = 'Disassembler.java' ] || [ "$arg" = 'Decompiler.java' ]; then target="$arg"; fi
  elif [ -n "$target" ] && [ -z "$out" ]; then out="$arg"; fi
  previous="$arg"
done
mkdir -p "$out"
name=$(basename "$source")
if [ "$target" = 'Disassembler.java' ]; then
  printf '%s' '{dis_hex}' | xxd -r -p > "$out/$name.asm"
else
  printf '%s' '{dec_hex}' | xxd -r -p > "$out/$name.c"
fi""",
    )


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


def test_ghidra_extracts_metadata_i386_with_both_packing_annotations_and_resumes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, config, shas = _fixture(tmp_path)
    analyzer = _fake_analyze_headless(tmp_path)
    script_root = Path(__file__).parents[2] / "ghidra_scripts"
    state_path = tmp_path / "dis.sqlite"
    representation_root = tmp_path / "dis"
    first_rows, first_summary = extract_rands_ghidra(
        config,
        root,
        representation_root,
        state_path,
        representation="dis",
        analyze_headless=analyzer,
        script_root=script_root,
        limit=1,
        progress_every=1,
    )
    assert len(first_rows) == 1
    assert first_summary["job"]["complete"] is False
    assert "[extract-dis] 1/2 (50.0%)" in capsys.readouterr().err
    rows, summary = extract_rands_ghidra(
        config,
        root,
        representation_root,
        state_path,
        representation="dis",
        analyze_headless=analyzer,
        script_root=script_root,
        resume=True,
        workers=2,
    )
    assert [row.source_sha256 for row in rows] == sorted(shas.values())
    assert {row.metadata_packed for row in rows} == {False, True}
    assert summary["cohort"]["selection"].endswith("not filtered")
    assert all(row.extraction_status == "success" for row in rows)
    assert all(
        (representation_root / row.representation_relative_path).read_text(encoding="ascii")
        == "mov eax, ebx"
        for row in rows
        if row.representation_relative_path
    )
    manifest_path = tmp_path / "dis.csv"
    written = write_rands_ghidra_outputs(rows, summary, manifest_path, tmp_path / "dis.json")
    assert written["manifest"]["rows"] == 2
    assert "metadata_packed" in manifest_path.read_text(encoding="utf-8")
    dec_rows, dec_summary = extract_rands_ghidra(
        config,
        root,
        tmp_path / "dec",
        tmp_path / "dec.sqlite",
        representation="dec",
        analyze_headless=analyzer,
        script_root=script_root,
    )
    assert dec_summary["job"]["complete"] is True
    assert all(row.extraction_status == "success" for row in dec_rows)
    assert all(
        (tmp_path / "dec" / row.representation_relative_path)
        .read_text(encoding="ascii")
        .startswith("int main")
        for row in dec_rows
        if row.representation_relative_path
    )


def test_ghidra_normalizers_match_rawbyteclf_rules() -> None:
    assert normalize_disassembly(b"signature\nram\t1\t2\t90\tnop\n") == b"nop"
    assert (
        normalize_decompilation(b"int x; /* remove\ncomment */\nreturn 0;")
        == b"int x; \nreturn 0;"
    )


def test_unified_ghidra_extracts_dis_and_dec_and_resumes(tmp_path: Path) -> None:
    root, config, shas = _fixture(tmp_path)
    analyzer = _fake_analyze_headless(tmp_path)
    script_root = Path(__file__).parents[2] / "ghidra_scripts"
    state_path = tmp_path / "unified.sqlite"
    first_rows, first_summary = extract_rands_ghidra(
        config,
        root,
        state_path,
        representations=["dis", "dec"],
        dis_representation_root=tmp_path / "dis",
        dec_representation_root=tmp_path / "dec",
        analyze_headless=analyzer,
        script_root=script_root,
        limit=1,
    )
    assert set(first_rows) == {"dis", "dec"}
    assert first_summary["job"]["sources_completed"] == 1
    assert first_summary["job"]["complete"] is False
    assert all(len(rows) == 1 for rows in first_rows.values())

    rows, summary = extract_rands_ghidra(
        config,
        root,
        state_path,
        representations=["dis", "dec"],
        dis_representation_root=tmp_path / "dis",
        dec_representation_root=tmp_path / "dec",
        analyze_headless=analyzer,
        script_root=script_root,
        resume=True,
    )
    assert summary["job"]["complete"] is True
    assert {row.source_sha256 for row in rows["dis"]} == set(shas.values())
    assert {row.source_sha256 for row in rows["dec"]} == set(shas.values())
    assert all(row.extraction_status == "success" for view in rows.values() for row in view)
    assert all(
        (tmp_path / "dis" / row.representation_relative_path).read_text(encoding="ascii")
        == "mov eax, ebx"
        for row in rows["dis"]
        if row.representation_relative_path
    )
    assert all(
        (tmp_path / "dec" / row.representation_relative_path)
        .read_text(encoding="ascii")
        .startswith("int main")
        for row in rows["dec"]
        if row.representation_relative_path
    )
    output = write_rands_ghidra_outputs(
        rows,
        summary,
        ["dis", "dec"],
        tmp_path / "dis.csv",
        tmp_path / "dec.csv",
        tmp_path / "summary.json",
    )
    assert output["manifests"]["dis"]["rows"] == 2
    assert output["manifests"]["dec"]["rows"] == 2


def test_unified_ghidra_requires_output_contracts(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)
    with pytest.raises(RandsGhidraError, match="--dec-representation-dir"):
        extract_rands_ghidra(
            config,
            root,
            tmp_path / "state.sqlite",
            representations=["dis", "dec"],
            dis_representation_root=tmp_path / "dis",
            analyze_headless=_fake_analyze_headless(tmp_path),
            script_root=Path(__file__).parents[2] / "ghidra_scripts",
        )


def test_cli_writes_both_unified_ghidra_manifests(tmp_path: Path) -> None:
    root, _, _ = _fixture(tmp_path)
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
                "extract-ghidra",
                "--dataset",
                "rands",
                "--config",
                str(config_path),
                "--root",
                str(root),
                "--representations",
                "dis",
                "dec",
                "--analyze-headless",
                str(_fake_analyze_headless(tmp_path)),
                "--dis-representation-dir",
                str(tmp_path / "dis"),
                "--dec-representation-dir",
                str(tmp_path / "dec"),
                "--state-db",
                str(tmp_path / "state.sqlite"),
                "--dis-manifest",
                str(tmp_path / "dis.csv"),
                "--dec-manifest",
                str(tmp_path / "dec.csv"),
                "--summary",
                str(tmp_path / "summary.json"),
            ]
        )
        == 0
    )
    assert (tmp_path / "dis.csv").exists()
    assert (tmp_path / "dec.csv").exists()
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["manifests"]["dis"]["rows"] == 2
    assert summary["manifests"]["dec"]["rows"] == 2


def test_merge_script_accepts_completed_unified_section(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)
    state_dir = tmp_path / "state"
    rows, summary = extract_rands_ghidra(
        config,
        root,
        state_dir / "section-1.sqlite",
        representations=["dis", "dec"],
        dis_representation_root=tmp_path / "dis",
        dec_representation_root=tmp_path / "dec",
        analyze_headless=_fake_analyze_headless(tmp_path),
        script_root=Path(__file__).parents[2] / "ghidra_scripts",
    )
    write_rands_ghidra_outputs(
        rows,
        summary,
        ["dis", "dec"],
        state_dir / "dis-section-1.csv",
        state_dir / "dec-section-1.csv",
        state_dir / "section-1.json",
    )
    output_dir = tmp_path / "merged-dis"
    subprocess.run(
        [
            str(Path(__file__).parents[2] / "scripts" / "merge-ghidra-sections.sh"),
            "dis",
            str(output_dir),
            str(state_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    merged = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert merged["job"]["complete"] is True
    assert merged["extraction"]["successful"] == 2


def test_ghidra_command_keeps_rawbyteclf_lifting_contract(tmp_path: Path) -> None:
    command = _ghidra_command(
        analyze_headless=tmp_path / "analyzeHeadless",
        representation="dis",
        script_root=tmp_path / "scripts",
        source_path=tmp_path / "sample.exe",
        project_root=tmp_path / "project",
        output_root=tmp_path / "output",
        timeout_per_file_seconds=60,
        timeout_per_function_seconds=30,
        analysis_timeout_per_file_seconds=300,
        max_cpu=1,
    )
    assert command[command.index("-processor") + 1] == "x86:LE:32:default"
    assert command[command.index("-loader") + 1] == "PeLoader"
    assert command[command.index("-analysisTimeoutPerFile") + 1] == "300"
    assert command[command.index("-preScript") + 1] == "SetAnalysisOptionsForDisassembly.java"
    assert command[command.index("-postScript") + 1] == "Disassembler.java"
    assert command[-2:] == ["-deleteProject", "-okToDelete"]


def test_pe_assessment_records_i386_and_diec_annotation_then_resumes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, config, shas = _fixture(tmp_path)
    file_tool = _static_tool(
        tmp_path,
        "fake-file",
        "printf '%s\\n' 'PE32 executable (GUI) Intel 80386, for MS Windows'",
    )
    die_tool = _static_tool(
        tmp_path,
        "fake-diec",
        'printf \'%s\\n\' \'{"detects":[{"values":[{"type":"Packer"}]}]}\'',
    )
    state_path = tmp_path / "assessment.sqlite"
    first_rows, first_summary = assess_rands_pe(
        config,
        RandsDatasetLocations(raw_root=root, metadata_root=root),
        state_path,
        file_command=str(file_tool),
        die_command=str(die_tool),
        limit=1,
        progress_every=1,
    )
    assert len(first_rows) == 1
    assert first_summary["job"]["complete"] is False
    assert "[assess-pe] 1/2 (50.0%)" in capsys.readouterr().err

    rows, summary = assess_rands_pe(
        config,
        RandsDatasetLocations(raw_root=root, metadata_root=root),
        state_path,
        file_command=str(file_tool),
        die_command=str(die_tool),
        resume=True,
        workers=2,
    )
    assert [row.source_sha256 for row in rows] == sorted(shas.values())
    assert {row.pe_architecture for row in rows} == {"i386"}
    assert {row.die_obfuscated for row in rows} == {"true"}
    assert {row.i386_unobfuscated_eligible for row in rows} == {"false"}
    assert summary["die"]["detected_types"] == {"Packer": 2}
    manifest_path = tmp_path / "pe-assessment.csv"
    output = write_rands_pe_assessment_outputs(
        rows, summary, manifest_path, tmp_path / "pe-assessment.json"
    )
    assert output["manifest"]["rows"] == 2
    assert "i386_unobfuscated_eligible" in manifest_path.read_text(encoding="utf-8")


def test_pe_assessment_marks_incomplete_diec_as_unknown(tmp_path: Path) -> None:
    root, config, _ = _fixture(tmp_path)
    file_tool = _static_tool(tmp_path, "fake-file", "printf '%s\\n' 'PE32 executable Intel 80386'")
    die_tool = _static_tool(
        tmp_path,
        "fake-diec",
        'if [ "$1" = "--deepscan" ]; then exit 7; fi\nprintf \'%s\\n\' \'{"detects":[]}\'',
    )
    rows, summary = assess_rands_pe(
        config,
        RandsDatasetLocations(raw_root=root, metadata_root=root),
        tmp_path / "assessment.sqlite",
        file_command=str(file_tool),
        die_command=str(die_tool),
    )
    assert {row.die_status for row in rows} == {"incomplete"}
    assert {row.die_obfuscated for row in rows} == {"unknown"}
    assert {row.i386_unobfuscated_eligible for row in rows} == {"unknown"}
    assert summary["die"]["statuses"] == {"incomplete": 2}

    with pytest.raises(RandsPeAssessmentError, match="state already exists"):
        assess_rands_pe(
            config,
            RandsDatasetLocations(raw_root=root, metadata_root=root),
            tmp_path / "assessment.sqlite",
            file_command=str(file_tool),
            die_command=str(die_tool),
        )


def test_cli_assesses_full_corpus_without_leaking_source_identities(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, _, shas = _fixture(tmp_path)
    config_path = tmp_path / "dataset.yaml"
    config_path.write_text(
        """dataset: {name: rands, snapshot: test, root_env: TEST_RANDS_ROOT}
layout: {benign_csv: Benign.csv, ransomware_csv: Ransomware.csv, samples_dir: dataset}
expected: {shards: 2, files: 2, labels: {benign: 1, ransomware: 1}}
protocols: {full: {}}
""",
        encoding="utf-8",
    )
    file_tool = _static_tool(tmp_path, "fake-file", "printf '%s\\n' 'PE32 executable Intel 80386'")
    die_tool = _static_tool(tmp_path, "fake-diec", "printf '%s\\n' '{\"detects\":[]}'")
    assert (
        main(
            [
                "data",
                "assess-pe",
                "--dataset",
                "rands",
                "--config",
                str(config_path),
                "--root",
                str(root),
                "--state-db",
                str(tmp_path / "assessment.sqlite"),
                "--manifest",
                str(tmp_path / "assessment.csv"),
                "--summary",
                str(tmp_path / "assessment.json"),
                "--file-command",
                str(file_tool),
                "--die-command",
                str(die_tool),
            ]
        )
        == 0
    )
    stdout = capsys.readouterr().out
    assert shas["benign"] not in stdout
    assert shas["ransomware"] not in stdout


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


def test_ghidra_shard_plan_splits_deterministically_and_section_extraction_matches(
    tmp_path: Path,
) -> None:
    root, config, shas = _fixture(tmp_path)
    (tmp_path / "ghidra_scripts").mkdir()
    for name in ["Lifter.java", "Disassembler.java", "SetAnalysisOptionsForDisassembly.java"]:
        (tmp_path / "ghidra_scripts" / name).write_text("// placeholder", encoding="utf-8")
    analyzer = _fake_analyzer(
        tmp_path, dis_output=b"\tmov eax, ebx\n", dec_output=b"int main() {}"
    )
    plan_dir = tmp_path / "plan"
    plan_result = plan_rands_ghidra_shards(config, root, total_sections=2, output_dir=plan_dir)
    assert plan_result["total_sections"] == 2
    assert plan_result["total_sources"] == 2
    assert (plan_dir / "plan.json").exists()
    assert (plan_dir / "section-1.csv").exists()
    assert (plan_dir / "section-2.csv").exists()
    plan_data = json.loads((plan_dir / "plan.json").read_text(encoding="utf-8"))
    assert plan_data["total_sections"] == 2
    assert plan_data["total_sources"] == 2
    section_1_count = plan_data["sections"]["1"]["source_count"]
    section_2_count = plan_data["sections"]["2"]["source_count"]
    assert section_1_count + section_2_count == 2
    with (plan_dir / "section-1.csv").open(encoding="utf-8", newline="") as f:
        section_1_rows = list(csv.DictReader(f))
    assert len(section_1_rows) == section_1_count
    assert all("source_sha256" in row for row in section_1_rows)
    state_1 = tmp_path / "state-1.sqlite"
    rows_1, summary_1 = extract_rands_ghidra(
        config,
        root,
        tmp_path / "dis",
        state_1,
        representation="dis",
        analyze_headless=analyzer,
        script_root=tmp_path / "ghidra_scripts",
        shard_plan_dir=plan_dir,
        section=1,
    )
    assert len(rows_1) == section_1_count
    assert summary_1["job"]["complete"] is True
    state_2 = tmp_path / "state-2.sqlite"
    rows_2, _ = extract_rands_ghidra(
        config,
        root,
        tmp_path / "dis",
        state_2,
        representation="dis",
        analyze_headless=analyzer,
        script_root=tmp_path / "ghidra_scripts",
        shard_plan_dir=plan_dir,
        section=2,
    )
    assert len(rows_2) == section_2_count
    combined_shas = {row.source_sha256 for row in rows_1} | {row.source_sha256 for row in rows_2}
    assert combined_shas == set(shas.values())
