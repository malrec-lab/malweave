"""Command-line entrypoint for reproducible MalWeave workflows."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import replace
import json
import os
from pathlib import Path
import sys

from dotenv import load_dotenv

from malweave.config import CONFIGS_DIR, PROJECT_ROOT
from malweave.data.dataset_config import DatasetConfigError, load_rands_dataset_config
from malweave.data.rands import RandsDataError, inspect_rands, write_rands_manifest
from malweave.data.rands_exe import (
    RandsExeError,
    exe_console_summary,
    extract_rands_exe,
    write_rands_exe_outputs,
)
from malweave.data.rands_ghidra import (
    SCRIPT_ROOT,
    RandsGhidraError,
    extract_rands_ghidra,
    plan_rands_ghidra_shards,
    write_rands_ghidra_outputs,
)
from malweave.data.rands_pe_assessment import (
    RandsPeAssessmentError,
    assess_rands_pe,
    write_rands_pe_assessment_outputs,
)
from malweave.data.rands_products import (
    RandsProductError,
    build_rands_products,
    load_exe_inputs,
    write_rands_product_outputs,
)
from malweave.data.rands_training import (
    Progress,
    RandsTrainingError,
    check_storage,
    fetch_exe,
    prepare_exe,
)
from malweave.data.sorel import (
    SorelError,
    export_sorel,
    load_sorel_config,
    plan_sorel_download,
    prepare_sorel,
    run_sorel,
    verify_sorel,
)
from malweave.experiments.rands_comparison import (
    RandsComparisonError,
    build_rands_comparison_cohort,
    load_rands_comparison_config,
    load_rands_product_manifest,
    split_rands_comparison_cohort,
    write_rands_comparison_split_outputs,
)
from malweave.training.contracts import SupervisedTrainingError

DEFAULT_RANDS_CONFIG = CONFIGS_DIR / "datasets" / "rands-raw-2026.yaml"
DOTENV_PATH = PROJECT_ROOT / ".env"


def _load_project_environment(path: Path | None = None) -> None:
    """Load machine-local settings without overriding the caller's environment."""
    load_dotenv(dotenv_path=path or DOTENV_PATH, override=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="malweave", description="MalWeave research tooling.")
    commands = parser.add_subparsers(dest="command", required=True)
    data = commands.add_parser("data", help="Inspect and prepare research datasets.")
    data_commands = data.add_subparsers(dest="data_command", required=True)
    rawmal = data_commands.add_parser("rawmal-die", help="Statically assess RawMal PE packing.")
    rawmal.add_argument("action", choices=("run", "status", "publish"))
    rawmal.add_argument("--job-dir", type=Path, required=True)
    rawmal.add_argument("--bucket", default=os.environ.get("MALWEAVE_RAWMAL_S3_BUCKET"))
    rawmal.add_argument("--cohort", default="format=pe,pe_machine=0x014c")
    rawmal.add_argument("--workers", type=int)
    rawmal.add_argument("--limit", type=int)
    rawmal.add_argument("--retry-unknown", action="store_true")
    rawmal.add_argument("--publish-prefix")
    rawmal.add_argument("--max-file-bytes", type=int, default=256 * 1024**2)
    rawmal.add_argument("--max-inflight-bytes", type=int, default=4 * 1024**3)
    rands_die = data_commands.add_parser(
        "rands-die", help="Stream S3 RanDS PEs through LMLM DiE checks with durable progress."
    )
    rands_die.add_argument("action", choices=("run", "status"))
    rands_die.add_argument("--job-dir", type=Path, required=True)
    rands_die.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    rands_die.add_argument(
        "--s3-prefix", help="Raw PE root; defaults to MALWEAVE_RANDS_METADATA_S3_PREFIX."
    )
    rands_die.add_argument("--workers", type=int, default=10)
    rands_die.add_argument("--die-command", default="diec")
    rands_die.add_argument("--retry-seconds", type=float, default=60)
    rands_die.add_argument("--limit", type=int)
    rands_ghidra = data_commands.add_parser(
        "rands-ghidra", help="Extract DIS/DEC from audited S3 RanDS PEs in 16-worker batches."
    )
    rands_ghidra.add_argument("action", choices=("run", "status"))
    rands_ghidra.add_argument("--job-dir", type=Path, required=True)
    rands_ghidra.add_argument("--die-job", type=Path)
    rands_ghidra.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    rands_ghidra.add_argument("--analyze-headless", type=Path)
    rands_ghidra.add_argument("--script-root", type=Path, default=SCRIPT_ROOT)
    rands_ghidra.add_argument("--limit", type=int, help="Cap pending sources before batching.")
    rands_ghidra.add_argument("--heap-mb", type=int, default=1024)
    rands_ghidra.add_argument("--min-free-gib", type=float, default=5)
    rands_ghidra.add_argument(
        "--execution-mode",
        choices=("separate", "shared-full"),
        default="separate",
        help="Experimental shared-full imports/analyzes once and runs both scripts in one JVM.",
    )
    setup = data_commands.add_parser(
        "sorel-setup", help="Fetch verified metadata and portable DiE."
    )
    setup.add_argument("--skip-metadata", action="store_true")
    s3_check = data_commands.add_parser(
        "sorel-s3-check", help="Check AWS identity, destination and optional text round trip."
    )
    s3_check.add_argument("--s3-prefix")
    s3_check.add_argument(
        "--write-test", action="store_true", help="Upload/download/delete a tiny text probe."
    )
    for operation in (
        "prepare",
        "download-plan",
        "extract",
        "run",
        "export",
        "verify",
        "status",
        "restore",
        "checkpoint",
    ):
        sorel = data_commands.add_parser(
            f"sorel-{operation}", help=f"SOREL preparation: {operation}."
        )
        sorel.add_argument("--config", type=Path)
        sorel.add_argument("--job-dir", type=Path)
        sorel.add_argument(
            "--s3-prefix", help="Collection S3 root; defaults to MALWEAVE_SOREL_S3_PREFIX."
        )
        sorel.add_argument(
            "--part",
            type=int,
            choices=range(1, 6),
            metavar="1..5",
            help="Use the fixed full-corpus partition and its default job directory.",
        )
        if operation in ("prepare", "run"):
            sorel.add_argument(
                "--metadata", type=Path, default=PROJECT_ROOT / "data/raw/sorel/metadata/meta.db"
            )
        if operation in ("extract", "run"):
            sorel.add_argument(
                "--staged",
                action="store_true",
                help="Read the planned curl batch, deleting compressed inputs after commit.",
            )
            sorel.add_argument("--limit", type=int, default=None)
            sorel.add_argument(
                "--progress-seconds",
                type=float,
                default=5,
                help="Heartbeat interval while waiting; also report every committed source.",
            )
    container = data_commands.add_parser(
        "sorel-container", help="Launch the frozen CPU Docker worker."
    )
    container.add_argument("action", choices=("benchmark", "run", "status", "export"))
    container.add_argument("--part", type=int, choices=range(1, 6), default=1)
    container.add_argument("--image", default="malweave-sorel:v3")
    container.add_argument(
        "--metadata", type=Path, default=PROJECT_ROOT / "data/raw/sorel/metadata/meta.db"
    )
    container.add_argument("--job-dir", type=Path)
    container.add_argument("--workers", type=int)
    container.add_argument("--limit", type=int)
    container.add_argument("--takeover")
    convert = data_commands.add_parser(
        "sorel-convert", help="Approved v3 consecutive-part conversion."
    )
    convert.add_argument("action", choices=("run", "benchmark", "status", "export", "audit"))
    convert.add_argument("--part", type=int, choices=range(1, 6), default=1)
    convert.add_argument("--config", type=Path, default=CONFIGS_DIR / "datasets/sorel-full.yaml")
    convert.add_argument("--job-dir", type=Path)
    convert.add_argument(
        "--metadata", type=Path, default=PROJECT_ROOT / "data/raw/sorel/metadata/meta.db"
    )
    convert.add_argument("--s3-prefix", help="Collection root; /v3.1/part-NN is appended.")
    convert.add_argument(
        "--local-only",
        action="store_true",
        help="Retain outputs locally; publication is not benchmarked.",
    )
    convert.add_argument("--limit", type=int)
    convert.add_argument("--workers", type=int)
    convert.add_argument(
        "--takeover",
        metavar="OLD_OWNER_TOKEN",
        help="Use only after verifying the previous coordinator stopped.",
    )
    convert.add_argument(
        "--retry",
        nargs="+",
        metavar="STATUS",
        help="Explicitly retry failed/deferred groups, preserving history.",
    )
    experiment = commands.add_parser("experiment", help="Freeze and run declared experiments.")
    experiment_commands = experiment.add_subparsers(dest="experiment_command", required=True)

    scratch_config = CONFIGS_DIR / "experiments/rands-exe-scratch.yaml"
    rands_check = experiment_commands.add_parser(
        "rands-check", help="Check RanDS input permissions and training output storage."
    )
    rands_check.add_argument("--write-test", action="store_true")
    scratch_data = PROJECT_ROOT / "data/processed/rands-scratch/inputs"
    prepare = experiment_commands.add_parser(
        "rands-prepare", help="Fetch EXE only, hash, quarantine and freeze RanDS splits."
    )
    prepare.add_argument("--config", type=Path, default=scratch_config)
    prepare.add_argument("--data-dir", type=Path, default=scratch_data)
    prepare.add_argument(
        "--download",
        action="store_true",
        help="Download EXE and the two metadata CSVs from private S3 settings.",
    )
    prepare.add_argument("--exe-prefix", help="Defaults to MALWEAVE_RANDS_EXE_S3_PREFIX.")
    prepare.add_argument(
        "--metadata-prefix", help="Defaults to MALWEAVE_RANDS_METADATA_S3_PREFIX."
    )
    prepare.add_argument("--hash-workers", type=int, default=4)
    scratch = experiment_commands.add_parser(
        "rands-train", help="Train RanDS EXE from random weights, with durable resume."
    )
    scratch.add_argument("--config", type=Path, default=scratch_config)
    scratch.add_argument("--data-dir", type=Path, default=scratch_data)
    scratch.add_argument(
        "--runs-dir", type=Path, default=PROJECT_ROOT / "data/processed/rands-scratch/runs"
    )
    scratch.add_argument("--run-id", required=True)
    scratch.add_argument("--device", default="cuda:0")
    scratch.add_argument("--resume", action="store_true")
    scratch.add_argument(
        "--max-steps",
        type=int,
        help="Stop at this total optimizer-update count, saving a resumable checkpoint.",
    )
    scratch.add_argument(
        "--s3-prefix",
        help="Defaults to MALWEAVE_RANDS_TRAIN_S3_PREFIX; optional remote checkpoints.",
    )
    scratch_smoke = experiment_commands.add_parser(
        "rands-smoke", help="Synthetic EXE-only BPE/train/checkpoint/evaluation smoke; no S3."
    )
    scratch_smoke.add_argument("--work-dir", type=Path, required=True)
    scratch_smoke.add_argument("--device", default="cuda:0")

    inspect = data_commands.add_parser("inspect", help="Audit a local dataset without mutation.")
    inspect.add_argument("--dataset", choices=("rands",), required=True)
    inspect.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    inspect.add_argument("--root", type=Path, default=None)
    inspect.add_argument(
        "--metadata-root",
        type=Path,
        default=None,
        help="Optional separate directory containing Benign.csv and Ransomware.csv.",
    )
    inspect.add_argument(
        "--verify-hashes",
        choices=("none", "sample", "all"),
        default="none",
        help="Hash no files, one deterministic file per shard, or the full corpus.",
    )
    inspect.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Optional aggregate JSON output; safe summaries contain no sample hashes.",
    )
    inspect.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Optional local CSV inventory containing sample hashes; never commit it.",
    )

    extract_exe = data_commands.add_parser(
        "extract-exe",
        help="Statically extract executable PE-section bytes from the full audited corpus.",
    )
    extract_exe.add_argument("--dataset", choices=("rands",), required=True)
    extract_exe.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    extract_exe.add_argument("--root", type=Path, default=None)
    extract_exe.add_argument(
        "--metadata-root",
        type=Path,
        default=None,
        help="Optional separate directory containing Benign.csv and Ransomware.csv.",
    )
    extract_exe.add_argument(
        "--state-db",
        type=Path,
        required=True,
        help="Ignored SQLite progress state; commit after every source and use it to resume.",
    )
    extract_exe.add_argument(
        "--resume", action="store_true", help="Continue the exact state-db job."
    )
    extract_exe.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most this many pending sources; useful for a controlled local check.",
    )
    extract_exe.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Write one aggregate progress update to stderr after this many sources.",
    )
    products = data_commands.add_parser(
        "build-products",
        help="Freeze deterministic RAW and EXE products for the full audited corpus.",
    )
    products.add_argument("--dataset", choices=("rands",), required=True)
    products.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    products.add_argument("--root", type=Path, default=None)
    products.add_argument(
        "--metadata-root",
        type=Path,
        default=None,
        help="Optional separate directory containing Benign.csv and Ransomware.csv.",
    )
    products.add_argument("--exe-manifest", type=Path, required=True)
    products.add_argument("--exe-dir", type=Path, required=True)
    products.add_argument("--manifest", type=Path, required=True)
    products.add_argument("--duplicate-groups", type=Path, required=True)
    products.add_argument("--summary", type=Path, required=True)
    split = experiment_commands.add_parser(
        "freeze-rands-comparison",
        help="Freeze a deduplicated, group-aware RAW/EXE RanDS comparison split.",
    )
    split.add_argument("--products", type=Path, required=True)
    split.add_argument("--experiment", type=Path, required=True)
    split.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Ignored private split CSV with source and representation identities.",
    )
    split.add_argument(
        "--summary",
        type=Path,
        required=True,
        help="Aggregate split JSON; it deliberately omits sample identities.",
    )
    cohort = experiment_commands.add_parser(
        "freeze-rands-metadata", help="Freeze the metadata-filtered temporal RanDS cohort."
    )
    cohort.add_argument("--metadata-dir", type=Path, required=True)
    cohort.add_argument("--exe-manifest", type=Path, required=True)
    cohort.add_argument("--experiment", type=Path, required=True)
    cohort.add_argument("--output-dir", type=Path, required=True)
    cohort.add_argument(
        "--input-audit",
        type=Path,
        required=True,
        help="Complete private exact-token audit directory.",
    )
    stage = experiment_commands.add_parser(
        "stage-rands-exe", help="Download and verify only EXEs in a frozen cohort."
    )
    stage.add_argument("--split-manifest", type=Path, required=True)
    stage.add_argument("--exe-root", type=Path, required=True)
    stage.add_argument("--workers", type=int, default=8)
    original_smoke = experiment_commands.add_parser(
        "prepare-e1-smoke", help="Generate original MalConvGCT synthetic capacity/recovery inputs."
    )
    original_smoke.add_argument("--output-dir", type=Path, required=True)
    original_smoke.add_argument("--sample-bytes", type=int, default=4096)
    original_smoke.add_argument("--tiny-model", action="store_true")
    smoke = experiment_commands.add_parser(
        "prepare-e2-smoke", help="Generate synthetic non-PE E2 benchmark/recovery inputs."
    )
    smoke.add_argument("--output-dir", type=Path, required=True)
    smoke.add_argument("--max-tokens", type=int, default=4096)
    smoke.add_argument(
        "--full-length",
        action="store_true",
        help="Distinct deterministic synthetic bytes; every input reaches the token limit.",
    )
    smoke.add_argument(
        "--tiny-model", action="store_true", help="Small CPU regression model only."
    )
    train = experiment_commands.add_parser(
        "train",
        help="Train one declared supervised track from a frozen private split.",
    )
    train.add_argument("--track", choices=("malconvgct", "hrrformer", "mamba"), required=True)
    train.add_argument("--split-manifest", type=Path, required=True)
    train.add_argument("--experiment", type=Path, required=True)
    train.add_argument("--raw-root", type=Path, help="Required for the RAW malconvgct track.")
    train.add_argument("--exe-root", type=Path, required=True)
    train.add_argument("--artifact-root", type=Path, required=True)
    train.add_argument("--run-id", required=True)
    train.add_argument("--device", required=True, help="Explicit torch device, e.g. cuda:0.")
    train.add_argument("--gradient-accumulation-steps", type=int, required=True)
    train.add_argument("--seed", type=int, required=True)
    evaluate_a = experiment_commands.add_parser(
        "evaluate-a",
        help="Evaluate the intact released detector on frozen RanDS test; no training.",
    )
    evaluate_a.add_argument("--experiment", type=Path, required=True)
    evaluate_a.add_argument("--checkpoint", type=Path, required=True)
    evaluate_a.add_argument("--split-manifest", type=Path, required=True)
    evaluate_a.add_argument("--exe-root", type=Path, required=True)
    evaluate_a.add_argument("--output-dir", type=Path, required=True)
    evaluate_a.add_argument("--device", required=True)
    evaluate_a.add_argument("--resume", action="store_true")
    evaluate_a.add_argument(
        "--max-samples", type=int, help="Pause after this many new predictions."
    )
    evaluate_a.add_argument(
        "--max-seconds", type=float, help="Pause after a committed prediction."
    )
    probe_a = experiment_commands.add_parser(
        "probe-a", help="Measure intact-detector FP32 capacity on synthetic bytes/tokens only."
    )
    probe_a.add_argument("--checkpoint", type=Path, required=True)
    probe_a.add_argument("--output-dir", type=Path, required=True)
    probe_a.add_argument("--device", default="cuda:0")
    train.add_argument(
        "--resume", action="store_true", help="Resume last committed training state."
    )
    train.add_argument(
        "--max-updates",
        type=int,
        help="Pause at this total update count without evaluating test; preserve full schedule.",
    )
    train.add_argument(
        "--max-seconds",
        type=float,
        help="E1/E2: pause after an optimizer update when this session budget is reached.",
    )
    train.add_argument("--raw-samples-dir", default="dataset")
    train.add_argument(
        "--checkpoint",
        type=Path,
        help="Released EXE BiMamba MLM checkpoint; requires an explicit finetuning config.",
    )
    extract_exe.add_argument(
        "--representation-dir",
        type=Path,
        required=True,
        help="Ignored local directory for EXE bytes; inside the repository use data/processed/.",
    )
    extract_exe.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Ignored local EXE representation manifest containing sample hashes.",
    )
    extract_exe.add_argument(
        "--summary",
        type=Path,
        required=True,
        help="Aggregate local JSON extraction report containing no individual sample hashes.",
    )
    assess_pe = data_commands.add_parser(
        "assess-pe",
        help="Statically annotate PE architecture and DiE obfuscation without filtering sources.",
    )
    assess_pe.add_argument("--dataset", choices=("rands",), required=True)
    assess_pe.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    assess_pe.add_argument("--root", type=Path, default=None)
    assess_pe.add_argument(
        "--metadata-root",
        type=Path,
        default=None,
        help="Optional separate directory containing Benign.csv and Ransomware.csv.",
    )
    assess_pe.add_argument(
        "--state-db",
        type=Path,
        required=True,
        help="Ignored SQLite progress state; commit after every source and use it to resume.",
    )
    assess_pe.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Ignored private PE assessment CSV containing sample hashes.",
    )
    assess_pe.add_argument(
        "--summary",
        type=Path,
        required=True,
        help="Aggregate assessment JSON containing no individual sample hashes.",
    )
    assess_pe.add_argument(
        "--file-command",
        default="file",
        help="Path or PATH command for the static file-identification tool.",
    )
    assess_pe.add_argument(
        "--die-command",
        default="diec",
        help="Path or PATH command for Detect-It-Easy's diec binary.",
    )
    assess_pe.add_argument("--file-timeout-seconds", type=float, default=10.0)
    assess_pe.add_argument("--die-timeout-seconds", type=float, default=10.0)
    assess_pe.add_argument("--workers", type=int, default=1)
    assess_pe.add_argument(
        "--resume", action="store_true", help="Continue the exact state-db job."
    )
    assess_pe.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Assess at most this many pending sources; useful for a controlled local check.",
    )
    assess_pe.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Write one aggregate progress update to stderr after this many sources.",
    )
    extract_ghidra = data_commands.add_parser(
        "extract-ghidra",
        help="Extract normalized DIS or DEC from metadata-I386 RanDS sources using Ghidra headless.",
    )
    extract_ghidra.add_argument("--dataset", choices=("rands",), required=True)
    extract_ghidra.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    extract_ghidra.add_argument("--root", type=Path, default=None)
    extract_ghidra.add_argument(
        "--metadata-root",
        type=Path,
        default=None,
        help="Optional separate directory containing Benign.csv and Ransomware.csv.",
    )
    extract_ghidra.add_argument(
        "--representations",
        nargs="+",
        choices=("dis", "dec"),
        required=True,
        help="Representations in one job, with a separate headless run per view: dis, dec, or both.",
    )
    extract_ghidra.add_argument(
        "--analyze-headless",
        type=Path,
        required=True,
        help="Executable Ghidra support/analyzeHeadless launcher.",
    )
    extract_ghidra.add_argument(
        "--script-root",
        type=Path,
        default=SCRIPT_ROOT,
        help="Directory containing the versioned RawByteClf-compatible Ghidra scripts.",
    )
    extract_ghidra.add_argument(
        "--dis-representation-dir",
        type=Path,
        default=None,
        help="Ignored local directory for normalized DIS text.",
    )
    extract_ghidra.add_argument(
        "--dec-representation-dir",
        type=Path,
        default=None,
        help="Ignored local directory for normalized DEC text.",
    )
    extract_ghidra.add_argument(
        "--state-db",
        type=Path,
        required=True,
        help="Ignored SQLite progress state; commit after every source and use it to resume.",
    )
    extract_ghidra.add_argument(
        "--dis-manifest", type=Path, default=None, help="Private DIS manifest output."
    )
    extract_ghidra.add_argument(
        "--dec-manifest", type=Path, default=None, help="Private DEC manifest output."
    )
    extract_ghidra.add_argument(
        "--summary",
        type=Path,
        required=True,
        help="Aggregate extraction report containing no individual source identities.",
    )
    extract_ghidra.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="Temporary Ghidra project/output directory; defaults beside --state-db.",
    )
    extract_ghidra.add_argument(
        "--timeout-per-file-seconds",
        type=int,
        default=None,
        help="RawByteClf defaults: 60 seconds for DIS and 300 seconds for DEC.",
    )
    extract_ghidra.add_argument(
        "--timeout-per-function-seconds",
        type=int,
        default=None,
        help="RawByteClf defaults: 30 seconds for DIS and 60 seconds for DEC.",
    )
    extract_ghidra.add_argument(
        "--analysis-timeout-per-file-seconds",
        type=int,
        default=300,
        help="Ghidra analysis timeout passed to analyzeHeadless, matching RawByteClf.",
    )
    extract_ghidra.add_argument(
        "--max-cpu",
        type=int,
        default=1,
        help="Ghidra CPU limit per worker process; increase only after measuring memory use.",
    )
    extract_ghidra.add_argument(
        "--process-timeout-seconds",
        type=int,
        default=None,
        help="Hard timeout for analyzeHeadless; defaults to file timeout plus 120 seconds.",
    )
    extract_ghidra.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Concurrent isolated analyzeHeadless processes; set for the available CPU and memory.",
    )
    extract_ghidra.add_argument(
        "--resume", action="store_true", help="Continue the exact state-db job."
    )
    extract_ghidra.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most this many pending sources; useful for a controlled static check.",
    )
    extract_ghidra.add_argument(
        "--progress-every",
        type=int,
        default=10,
        help="Write one aggregate progress update to stderr after this many sources.",
    )
    extract_ghidra.add_argument(
        "--shard-plan",
        type=Path,
        default=None,
        help="Path to shard plan directory created by plan-ghidra-shards.",
    )
    extract_ghidra.add_argument(
        "--section",
        type=int,
        default=None,
        help="1-indexed section number to process from the shard plan.",
    )

    plan_shards = data_commands.add_parser(
        "plan-ghidra-shards",
        help="Split I386 metadata sources into deterministic sections for distributed extraction.",
    )
    plan_shards.add_argument("--dataset", choices=("rands",), required=True)
    plan_shards.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    plan_shards.add_argument("--root", type=Path, default=None)
    plan_shards.add_argument(
        "--metadata-root",
        type=Path,
        default=None,
        help="Optional separate directory containing Benign.csv and Ransomware.csv.",
    )
    plan_shards.add_argument("--sections", type=int, required=True)
    plan_shards.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to write plan.json and section-*.csv files.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit status."""
    if sys.platform == "win32":
        print("error: Windows is unsupported; run MalWeave on macOS or Linux.", file=sys.stderr)
        return 2
    parser = _parser()
    args = parser.parse_args(argv)
    _load_project_environment()

    try:
        if args.command == "data" and args.data_command == "rawmal-die":
            from botocore.exceptions import BotoCoreError, ClientError

            from malweave.data.rawmal_die import publish_rawmal_die, run_rawmal_die

            if args.action == "status":
                print((args.job_dir / "progress.json").read_text())
                return 0
            try:
                if args.action == "publish":
                    if not args.publish_prefix:
                        raise SorelError("Pass --publish-prefix rawmal-filtered-<version>.")
                    result = publish_rawmal_die(
                        args.job_dir,
                        args.publish_prefix,
                        8 if args.workers is None else args.workers,
                    )
                else:
                    bucket = args.bucket or os.environ.get("MALWEAVE_RAWMAL_S3_BUCKET")
                    if not bucket:
                        raise SorelError("Pass --bucket or set MALWEAVE_RAWMAL_S3_BUCKET.")
                    if args.publish_prefix:
                        raise SorelError("Use the separate publish action for S3 writes.")
                    result = run_rawmal_die(
                        args.job_dir,
                        bucket=bucket,
                        cohort=args.cohort,
                        workers=64 if args.workers is None else args.workers,
                        limit=args.limit,
                        max_file_bytes=args.max_file_bytes,
                        max_inflight_bytes=args.max_inflight_bytes,
                        retry_unknown=args.retry_unknown,
                    )
            except (BotoCoreError, ClientError) as error:
                raise SorelError(
                    "RawMal S3 request failed; check permissions and network."
                ) from error
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "data" and args.data_command == "rands-ghidra":
            if args.action == "status":
                print((args.job_dir / "progress.json").read_text())
                return 0
            from malweave.data.rands_ghidra_stream import run_rands_ghidra

            headless = args.analyze_headless
            if headless is None and os.environ.get("GHIDRA_ROOT"):
                headless = Path(os.environ["GHIDRA_ROOT"]) / "support/analyzeHeadless"
            if headless is None or args.die_job is None:
                raise SorelError("Pass --die-job and --analyze-headless (or set GHIDRA_ROOT).")
            result = run_rands_ghidra(
                args.job_dir,
                args.die_job,
                load_rands_dataset_config(args.config),
                headless,
                script_root=args.script_root,
                limit=args.limit,
                heap_mb=args.heap_mb,
                min_free_bytes=int(args.min_free_gib * 1024**3),
                execution_mode=args.execution_mode,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1 if any(v["failed"] for v in result["representations"].values()) else 0
        if args.command == "data" and args.data_command == "rands-die":
            if args.action == "status":
                print((args.job_dir / "progress.json").read_text())
                return 0
            from malweave.data.rands_die import run_rands_die

            prefix = args.s3_prefix or os.environ.get("MALWEAVE_RANDS_METADATA_S3_PREFIX")
            if not prefix:
                raise SorelError("Set MALWEAVE_RANDS_METADATA_S3_PREFIX or pass --s3-prefix.")
            portable = (
                PROJECT_ROOT / "data/external/tools/die-portable-3.21/die_linux_portable/base"
            )
            die_command = args.die_command
            if die_command == "diec" and (portable / "diec").is_file():
                die_command = str(portable / "diec")
                os.environ["LD_LIBRARY_PATH"] = (
                    str(portable) + ":" + os.environ.get("LD_LIBRARY_PATH", "")
                )
            result = run_rands_die(
                args.job_dir,
                load_rands_dataset_config(args.config),
                prefix,
                workers=args.workers,
                die_command=die_command,
                retry_seconds=args.retry_seconds,
                limit=args.limit,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1 if result["failed"] else 0
        if args.command == "data" and args.data_command == "sorel-setup":
            from malweave.data.sorel_setup import setup_sorel

            print(json.dumps(setup_sorel(PROJECT_ROOT, metadata=not args.skip_metadata), indent=2))
            return 0
        if args.command == "data" and args.data_command == "sorel-s3-check":
            from malweave.data.sorel_s3 import check_sorel_s3

            prefix = args.s3_prefix or os.environ.get("MALWEAVE_SOREL_S3_PREFIX")
            if not prefix:
                raise SorelError("Set MALWEAVE_SOREL_S3_PREFIX or pass --s3-prefix.")
            print(json.dumps(check_sorel_s3(prefix, write_test=args.write_test), indent=2))
            return 0
        if args.command == "data" and args.data_command == "sorel-container":
            from malweave.data.sorel_container import launch

            prefix = os.environ.get("MALWEAVE_SOREL_S3_PREFIX")
            if not prefix:
                raise SorelError("Set MALWEAVE_SOREL_S3_PREFIX in .env before launching Docker")
            return launch(
                args.action,
                args.part,
                args.image,
                args.metadata,
                args.job_dir
                or PROJECT_ROOT / "data/processed/sorel/v3.1" / f"part-{args.part:02d}",
                prefix=prefix,
                workers=args.workers,
                limit=args.limit,
                takeover=args.takeover,
            )
        if args.command == "data" and args.data_command == "sorel-convert":
            from contextlib import closing

            from malweave.data import sorel_conversion as conversion
            from malweave.data import sorel_protocol as protocol
            from malweave.data.sorel_io import job_lock

            job = (
                args.job_dir
                or PROJECT_ROOT / "data/processed/sorel/v3.1" / f"part-{args.part:02d}"
            )
            rules, runtime = protocol.load(args.config, part=args.part)
            if args.workers is not None:
                if args.workers < 1:
                    raise SorelError("--workers must be positive")
                runtime = replace(runtime, workers=args.workers)
            prefix = (
                None
                if args.local_only
                else (args.s3_prefix or os.environ.get("MALWEAVE_SOREL_S3_PREFIX"))
            )
            if prefix:
                prefix = prefix.rstrip("/") + f"/v3.1/part-{args.part:02d}"
            portable = (
                PROJECT_ROOT / "data/external/tools/die-portable-3.21/die_linux_portable/base"
            )
            if not __import__("shutil").which("diec") and (portable / "diec").exists():
                os.environ["PATH"] = str(portable) + os.pathsep + os.environ.get("PATH", "")
                os.environ["LD_LIBRARY_PATH"] = (
                    str(portable) + os.pathsep + os.environ.get("LD_LIBRARY_PATH", "")
                )
            if args.action == "status":
                result = conversion.status(job)
            elif args.action == "audit":
                with job_lock(job):
                    result = conversion.audit(job)
                    if result["full_launch_ready"] and prefix:
                        from uuid import uuid4

                        from malweave.data.sorel_publication import AWS
                        from malweave.data.sorel_tools import Processes

                        aws = AWS(job, Processes(), runtime.upload_timeout_seconds)
                        owner = {
                            "schema": 3,
                            "token": uuid4().hex,
                            "purpose": "release-audit",
                            "started_at_utc": protocol.now(),
                        }
                        etag = aws.acquire(prefix, owner, args.takeover)
                        aws.put(job / "release-audit.json", prefix + "/main/release-audit.json")
                        aws.put(
                            job / "release-audit.json",
                            prefix.rsplit("/part-", 1)[0] + "/main/release-audit.json",
                        )
                        aws.release(prefix, etag)
            elif args.action == "export":
                with job_lock(job), closing(protocol.connect(job)) as db:
                    protocol.csv_export(db, job / "results.csv")
                result = {"csv": str(job / "results.csv")}
            else:
                if not prefix and not args.local_only:
                    raise SorelError(
                        "Set MALWEAVE_SOREL_S3_PREFIX or explicitly choose --local-only"
                    )
                result = conversion.run(
                    job,
                    args.metadata,
                    rules,
                    runtime,
                    prefix=prefix,
                    limit=1000 if args.action == "benchmark" else args.limit,
                    takeover=args.takeover,
                    retry=args.retry,
                    benchmark=args.action == "benchmark",
                )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if args.action != "audit" or result["full_launch_ready"] else 1
        if args.command == "data" and args.data_command.startswith("sorel-"):
            if args.part is not None:
                args.job_dir = args.job_dir or (
                    PROJECT_ROOT / "data/processed/sorel/full" / f"part-{args.part:02d}"
                )
            if args.job_dir is None:
                raise SorelError("Pass --part 1..5 or --job-dir.")
            s3_prefix = args.s3_prefix or os.environ.get("MALWEAVE_SOREL_S3_PREFIX")
            if s3_prefix and args.part is not None:
                s3_prefix = s3_prefix.rstrip("/") + f"/part-{args.part:02d}"
            if args.data_command == "sorel-restore":
                from malweave.data.sorel_archive import restore
                from malweave.data.sorel_io import job_lock

                if not s3_prefix:
                    raise SorelError("Set MALWEAVE_SOREL_S3_PREFIX or pass --s3-prefix.")
                with job_lock(args.job_dir):
                    restore(args.job_dir, s3_prefix)
                print(json.dumps({"restored": True, "job_dir": str(args.job_dir)}))
                return 0
            if args.data_command == "sorel-checkpoint":
                from contextlib import closing

                from malweave.data import sorel_ledger
                from malweave.data.sorel_archive import SorelArchive
                from malweave.data.sorel_io import job_lock

                saved_config = json.loads((args.job_dir / "selection.json").read_text())["config"]
                from malweave.data.sorel import SorelConfig

                remote = args.job_dir / "remote.json"
                s3_prefix = s3_prefix or (
                    json.loads(remote.read_text())["prefix"] if remote.exists() else None
                )
                if not s3_prefix:
                    raise SorelError("Set MALWEAVE_SOREL_S3_PREFIX or pass --s3-prefix.")
                with (
                    job_lock(args.job_dir),
                    closing(sorel_ledger.connect(args.job_dir / "state.sqlite")) as db,
                ):
                    store = SorelArchive(args.job_dir, s3_prefix, SorelConfig(**saved_config))
                    store.flush(db)
                    store.checkpoint(db)
                print(json.dumps({"checkpointed": True, "job_dir": str(args.job_dir)}))
                return 0
            if args.data_command == "sorel-status":
                from malweave.data.sorel_partitions import part_status

                print(json.dumps(part_status(args.job_dir), indent=2, sort_keys=True))
                return 0
            if args.data_command == "sorel-export":
                print(json.dumps(export_sorel(args.job_dir), indent=2, sort_keys=True))
                return 0
            if args.data_command == "sorel-verify":
                print(json.dumps(verify_sorel(args.job_dir), indent=2, sort_keys=True))
                return 0
            config = load_sorel_config(
                args.config
                or CONFIGS_DIR
                / "datasets"
                / ("sorel-full.yaml" if args.part is not None else "sorel-pilot.yaml")
            )
            if args.part is not None:
                if config.partition_count != 5 or config.samples != 0:
                    raise SorelError("--part requires samples: 0 and partition_count: 5.")
                config = replace(config, partition_index=args.part)
            if args.data_command == "sorel-prepare":
                summary = prepare_sorel(args.metadata, args.job_dir, config)
            elif args.data_command == "sorel-download-plan":
                summary = plan_sorel_download(args.job_dir, config)
            else:
                if (
                    args.data_command == "sorel-run"
                    and s3_prefix
                    and not (args.job_dir / "selection.json").exists()
                ):
                    from malweave.data.sorel_archive import restore
                    from malweave.data.sorel_io import job_lock

                    with job_lock(args.job_dir):
                        restore(args.job_dir, s3_prefix, missing_ok=True)
                if (
                    args.data_command == "sorel-run"
                    and not (args.job_dir / "selection.json").exists()
                ):
                    if args.metadata is None:
                        raise SorelError("A new job requires --metadata; resuming does not.")
                    prepare_sorel(args.metadata, args.job_dir, config)
                summary = run_sorel(
                    args.job_dir,
                    config,
                    staged=args.staged,
                    limit=args.limit,
                    progress_seconds=args.progress_seconds,
                    s3_prefix=s3_prefix,
                )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "data" and args.data_command == "inspect":
            config = load_rands_dataset_config(args.config)
            locations = config.resolve_locations(args.root, args.metadata_root)
            summary, metadata, present_shas = inspect_rands(
                config, locations, hash_mode=args.verify_hashes
            )
            rendered = json.dumps(summary, indent=2, sort_keys=True)
            print(rendered)

            if args.summary is not None:
                args.summary.parent.mkdir(parents=True, exist_ok=True)
                args.summary.write_text(rendered + "\n", encoding="utf-8")
            if args.manifest is not None:
                write_rands_manifest(args.manifest, config, metadata, present_shas)
            return 0 if summary["contract"]["passed"] else 1
        if args.command == "data" and args.data_command == "extract-exe":
            dataset_config = load_rands_dataset_config(args.config)
            locations = dataset_config.resolve_locations(args.root, args.metadata_root)
            rows, summary = extract_rands_exe(
                dataset_config,
                locations,
                args.representation_dir,
                args.state_db,
                resume=args.resume,
                limit=args.limit,
                progress_every=args.progress_every,
            )
            summary = write_rands_exe_outputs(rows, summary, args.manifest, args.summary)
            print(json.dumps(exe_console_summary(summary), indent=2, sort_keys=True))
            return 0
        if args.command == "data" and args.data_command == "assess-pe":
            dataset_config = load_rands_dataset_config(args.config)
            locations = dataset_config.resolve_locations(args.root, args.metadata_root)
            rows, summary = assess_rands_pe(
                dataset_config,
                locations,
                args.state_db,
                file_command=args.file_command,
                die_command=args.die_command,
                file_timeout_seconds=args.file_timeout_seconds,
                die_timeout_seconds=args.die_timeout_seconds,
                workers=args.workers,
                resume=args.resume,
                limit=args.limit,
                progress_every=args.progress_every,
            )
            summary = write_rands_pe_assessment_outputs(rows, summary, args.manifest, args.summary)
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "data" and args.data_command == "extract-ghidra":
            dataset_config = load_rands_dataset_config(args.config)
            locations = dataset_config.resolve_locations(args.root, args.metadata_root)
            rows, summary = extract_rands_ghidra(
                dataset_config,
                locations,
                args.state_db,
                representations=args.representations,
                dis_representation_root=args.dis_representation_dir,
                dec_representation_root=args.dec_representation_dir,
                analyze_headless=args.analyze_headless,
                script_root=args.script_root,
                work_root=args.work_dir,
                timeout_per_file_seconds=args.timeout_per_file_seconds,
                timeout_per_function_seconds=args.timeout_per_function_seconds,
                analysis_timeout_per_file_seconds=args.analysis_timeout_per_file_seconds,
                max_cpu=args.max_cpu,
                process_timeout_seconds=args.process_timeout_seconds,
                workers=args.workers,
                resume=args.resume,
                limit=args.limit,
                progress_every=args.progress_every,
                shard_plan_dir=args.shard_plan,
                section=args.section,
            )
            summary = write_rands_ghidra_outputs(
                rows,
                summary,
                args.representations,
                args.dis_manifest,
                args.dec_manifest,
                args.summary,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "data" and args.data_command == "plan-ghidra-shards":
            dataset_config = load_rands_dataset_config(args.config)
            locations = dataset_config.resolve_locations(args.root, args.metadata_root)
            plan_summary = plan_rands_ghidra_shards(
                dataset_config,
                locations,
                total_sections=args.sections,
                output_dir=args.output_dir,
            )
            print(json.dumps(plan_summary, indent=2, sort_keys=True))
            return 0
        if args.command == "data" and args.data_command == "build-products":
            dataset_config = load_rands_dataset_config(args.config)
            locations = dataset_config.resolve_locations(args.root, args.metadata_root)
            rows, summary = build_rands_products(
                dataset_config,
                locations,
                load_exe_inputs(args.exe_manifest),
                args.exe_dir,
            )
            summary = write_rands_product_outputs(
                rows, summary, args.manifest, args.duplicate_groups, args.summary
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "experiment" and args.experiment_command == "rands-check":
            prefixes = [
                os.environ.get(name)
                for name in [
                    "MALWEAVE_RANDS_EXE_S3_PREFIX",
                    "MALWEAVE_RANDS_METADATA_S3_PREFIX",
                    "MALWEAVE_RANDS_TRAIN_S3_PREFIX",
                ]
            ]
            if not all(prefixes):
                raise RandsTrainingError("Set all three RanDS S3 prefixes in the private .env.")
            print(json.dumps(check_storage(*prefixes, write_test=args.write_test), indent=2))
            return 0
        if args.command == "experiment" and args.experiment_command == "rands-prepare":
            if args.hash_workers < 1:
                raise RandsTrainingError("hash-workers must be positive.")
            with Progress() as progress:
                if args.download:
                    exe_prefix = args.exe_prefix or os.environ.get("MALWEAVE_RANDS_EXE_S3_PREFIX")
                    metadata_prefix = args.metadata_prefix or os.environ.get(
                        "MALWEAVE_RANDS_METADATA_S3_PREFIX"
                    )
                    if not exe_prefix or not metadata_prefix:
                        raise RandsTrainingError(
                            "Set the EXE and metadata S3 prefixes in .env or CLI arguments."
                        )
                    fetch_exe(args.data_dir, exe_prefix, metadata_prefix, progress)
                result = prepare_exe(
                    args.data_dir, args.config, hash_workers=args.hash_workers, progress=progress
                )
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "experiment" and args.experiment_command == "rands-smoke":
            from malweave.training.scratch_smoke import smoke

            print(json.dumps(smoke(args.work_dir, device=args.device), indent=2))
            return 0
        if args.command == "experiment" and args.experiment_command == "rands-train":
            from malweave.training.scratch import ScratchRequest, run_scratch

            result = run_scratch(
                ScratchRequest(
                    config=args.config,
                    data=args.data_dir,
                    runs=args.runs_dir,
                    run_id=args.run_id,
                    device=args.device,
                    resume=args.resume,
                    max_steps=args.max_steps,
                    s3_prefix=args.s3_prefix or os.environ.get("MALWEAVE_RANDS_TRAIN_S3_PREFIX"),
                    command=" ".join(("malweave", *(argv if argv is not None else sys.argv[1:]))),
                )
            )
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "experiment" and args.experiment_command == "freeze-rands-comparison":
            split_config = load_rands_comparison_config(args.experiment)
            products = load_rands_product_manifest(args.products)
            cohort, cohort_summary = build_rands_comparison_cohort(products, split_config)
            split_rows, split_summary = split_rands_comparison_cohort(cohort, split_config)
            summary = write_rands_comparison_split_outputs(
                split_rows,
                cohort_summary,
                split_summary,
                args.products,
                args.manifest,
                args.summary,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "experiment" and args.experiment_command == "freeze-rands-metadata":
            from malweave.data.rands_cohort import freeze_metadata_cohort

            result = freeze_metadata_cohort(
                args.metadata_dir,
                args.exe_manifest,
                args.experiment,
                args.output_dir,
                input_audit=args.input_audit,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "experiment" and args.experiment_command == "stage-rands-exe":
            from malweave.data.rands_cohort import stage_cohort_exe

            result = stage_cohort_exe(
                args.split_manifest,
                args.exe_root,
                os.environ.get("MALWEAVE_RANDS_EXE_S3_PREFIX", ""),
                args.workers,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "experiment" and args.experiment_command == "prepare-e1-smoke":
            from malweave.training.e2_smoke import prepare_e1_smoke

            result = prepare_e1_smoke(
                args.output_dir, sample_bytes=args.sample_bytes, tiny_model=args.tiny_model
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "experiment" and args.experiment_command == "prepare-e2-smoke":
            from malweave.training.e2_smoke import prepare_e2_smoke

            result = prepare_e2_smoke(
                args.output_dir,
                max_tokens=args.max_tokens,
                tiny_model=args.tiny_model,
                full_length=args.full_length,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "experiment" and args.experiment_command == "probe-a":
            from malweave.evaluation.lmlm_a import probe_a

            result = probe_a(args.checkpoint, args.output_dir, device_name=args.device)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "experiment" and args.experiment_command == "evaluate-a":
            from malweave.evaluation.lmlm_a import ARequest, run_a

            result = run_a(
                ARequest(
                    config_path=args.experiment,
                    checkpoint_path=args.checkpoint,
                    split_manifest_path=args.split_manifest,
                    exe_root=args.exe_root,
                    output_dir=args.output_dir,
                    device=args.device,
                    resume=args.resume,
                    max_samples=args.max_samples,
                    max_seconds=args.max_seconds,
                )
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1 if result["phase"] == "failed" else 0
        if args.command == "experiment" and args.experiment_command == "train":
            from malweave.training.supervised import SupervisedRunRequest, run_supervised_training

            if args.track == "malconvgct" and args.raw_root is None:
                raise SupervisedTrainingError("--raw-root is required for malconvgct.")
            result = run_supervised_training(
                SupervisedRunRequest(
                    track=args.track,
                    config_path=args.experiment,
                    split_manifest_path=args.split_manifest,
                    raw_root=args.raw_root or Path("."),
                    exe_root=args.exe_root,
                    artifact_root=args.artifact_root,
                    run_id=args.run_id,
                    device=args.device,
                    gradient_accumulation_steps=args.gradient_accumulation_steps,
                    seed=args.seed,
                    command=" ".join(("malweave", *(argv if argv is not None else sys.argv[1:]))),
                    raw_samples_dir=args.raw_samples_dir,
                    checkpoint_path=args.checkpoint,
                    resume=args.resume,
                    max_updates=args.max_updates,
                    max_seconds=args.max_seconds,
                )
            )
            print(json.dumps(result["metrics"], indent=2, sort_keys=True))
            return 0
    except ModuleNotFoundError as error:
        if (error.name or "").split(".")[0] not in {
            "torch",
            "tokenizers",
            "transformers",
            "safetensors",
            "sklearn",
            "boto3",
            "botocore",
        }:
            raise
        print(
            "error: Training dependencies are not installed. Run training commands with "
            "uv run --locked --no-default-groups --group train malweave ...",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        print(
            "interrupted: durable state was preserved; rerun the same command "
            "(add --resume only if that command supports it).",
            file=sys.stderr,
        )
        return 130
    except (
        DatasetConfigError,
        SorelError,
        RandsDataError,
        RandsExeError,
        RandsGhidraError,
        RandsPeAssessmentError,
        RandsProductError,
        RandsComparisonError,
        SupervisedTrainingError,
        RandsTrainingError,
        OSError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("Unsupported command.")
    return 2
