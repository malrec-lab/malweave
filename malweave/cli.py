"""Command-line entrypoint for reproducible MalWeave workflows."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
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
from malweave.data.storage_io import DataError
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


def _packing_die_command(command: str) -> str:
    from malweave.data.die_tools import PORTABLE_BASE

    portable = PROJECT_ROOT / PORTABLE_BASE
    if command == "diec" and (portable / "diec").is_file():
        existing = os.environ.get("LD_LIBRARY_PATH")
        os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(filter(None, (str(portable), existing)))
        return str(portable / "diec")
    return command


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="malweave", description="MalWeave research tooling.")
    commands = parser.add_subparsers(dest="command", required=True)
    data = commands.add_parser("data", help="Inspect and prepare research datasets.")
    data_commands = data.add_subparsers(dest="data_command", required=True)
    from malweave.data.dataset_storage import ARTIFACTS
    from malweave.data.s3_layout import DATASET_SLUGS

    storage = data_commands.add_parser(
        "dataset-storage", help="Read a published dataset or save audit evidence."
    )
    storage_actions = storage.add_subparsers(dest="action", required=True)
    for action, help_text in (
        ("verify", "Check published table and evidence checksums."),
        ("fetch", "Stage approved tables under the shared local input directory."),
        ("publish-audit", "Publish a completed audit SQLite database under its job ID."),
    ):
        command = storage_actions.add_parser(action, help=help_text)
        command.add_argument("--dataset", choices=tuple(DATASET_SLUGS), required=True)
        command.add_argument(
            "--profile", help="AWS profile; defaults to the normal AWS credential chain."
        )
        if action == "fetch":
            command.add_argument("--artifact", action="append", choices=tuple(ARTIFACTS))
            command.add_argument("--output-dir", type=Path)
        if action == "publish-audit":
            command.add_argument("--job-dir", type=Path, required=True)
    rawmal_exe = data_commands.add_parser(
        "rawmal-exe", help="Extract RawMal-TF PE executable sections in resumable S3 batches."
    )
    rawmal_exe.add_argument("--job-dir", type=Path, required=True)
    rawmal_exe.add_argument("--bucket", required=True)
    rawmal_exe.add_argument("--account", required=True)
    rawmal_exe.add_argument("--profile", required=True)
    rawmal_exe.add_argument("--limit", type=int, help="Stop after this many attempted sources.")
    dataset_audit = data_commands.add_parser(
        "dataset-audit",
        help="Native/.NET classification with one full download per source.",
    )
    dataset_audit.add_argument("action", choices=("run", "status", "report", "export"))
    dataset_audit.add_argument(
        "--output", type=Path, help="Defaults to native-dotnet.csv in the job directory."
    )
    dataset_audit.add_argument("--job-dir", type=Path, required=True)
    dataset_audit.add_argument(
        "--dataset",
        choices=("rands", "rawmal", "vera", "assemblage"),
        help="Required for `run`; other actions use the job identity.",
    )
    dataset_audit.add_argument(
        "--sha-list", type=Path, help="Restrict the job to these sha256 values (one per line)."
    )
    dataset_audit.add_argument(
        "--inventory", type=Path, help="Use an explicit local inventory CSV."
    )
    dataset_audit.add_argument("--workers", type=int, default=16)
    dataset_audit.add_argument("--limit", type=int)
    dataset_audit.add_argument("--retry-errors", action="store_true")
    dataset_audit.add_argument("--profile", help="AWS profile for S3 access.")
    dataset_die = data_commands.add_parser(
        "dataset-die", help="Scan supported datasets’ original PEs for packing."
    )
    dataset_die.add_argument("action", choices=("run", "status", "export"))
    dataset_die.add_argument("--job-dir", type=Path, required=True)
    dataset_die.add_argument(
        "--dataset", choices=("rands", "vera", "rawmal", "assemblage"), help="Required for run."
    )
    dataset_die.add_argument("--inventory", type=Path, help="Use an explicit local inventory CSV.")
    dataset_die.add_argument("--workers", type=int, default=16)
    dataset_die.add_argument("--limit", type=int, help="Maximum pending sources for this run.")
    dataset_die.add_argument("--profile", help="AWS profile for S3 access.")
    dataset_die.add_argument(
        "--retry-errors", action="store_true", help="Retry prior download errors."
    )
    dataset_die.add_argument("--die-command", default="diec")
    dataset_die.add_argument("--labels-csv", type=Path, help="RawMal-TF SHA-256 task labels.")
    dataset_die.add_argument("--sha-list", type=Path, help="One selected SHA-256 per line.")
    dataset_die.add_argument(
        "--timeout-per-mode", type=int, help="Seconds allowed for each DiE mode (default 10)."
    )
    dataset_die.add_argument(
        "--output", type=Path, help="Defaults to packing.csv in the job directory."
    )
    rands_die = data_commands.add_parser(
        "rands-die", help="Stream S3 RanDS PEs through LMLM DiE checks with durable progress."
    )
    rands_die.add_argument("action", choices=("run", "status"))
    rands_die.add_argument("--job-dir", type=Path, required=True)
    rands_die.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    rands_die.add_argument(
        "--s3-prefix", help="Label CSV prefix; defaults to MALWEAVE_RANDS_METADATA_S3_PREFIX."
    )
    rands_die.add_argument(
        "--raw-s3-prefix", help="RAW prefix. Defaults to representations/raw/ in the label bucket."
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
    data_commands.add_parser("die-setup", help="Install the pinned portable DiE scanner.")
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
        if args.command == "data" and args.data_command == "dataset-storage":
            from malweave.data.dataset_storage import (
                fetch_dataset,
                publish_audit_job,
                verify_dataset,
            )

            if args.action == "verify":
                result = verify_dataset(args.dataset, profile=args.profile)
            elif args.action == "fetch":
                result = fetch_dataset(
                    args.dataset,
                    args.output_dir,
                    artifacts=tuple(args.artifact or ("inventory",)),
                    profile=args.profile,
                )
            else:
                result = publish_audit_job(args.dataset, args.job_dir, profile=args.profile)
            print(json.dumps(result, indent=2, default=str))
            return 0
        if args.command == "data" and args.data_command == "dataset-audit":
            from malweave.data.audit_reporting import audit_status, export_dataset_audit, summarize
            from malweave.data.dataset_audit import run_dataset_audit

            if args.action == "export":
                output = args.output or args.job_dir / "native-dotnet.csv"
                print(json.dumps(export_dataset_audit(args.job_dir, output), indent=2))
                return 0
            if args.output is not None:
                raise DataError("--output is only used by dataset-audit export.")
            if args.action == "status":
                print(audit_status(args.job_dir))
                return 0
            if args.action == "report":
                print(json.dumps(summarize(args.job_dir), indent=2, sort_keys=True))
                return 0
            if not args.dataset:
                raise DataError("Pass --dataset for `run`.")
            summary = run_dataset_audit(
                args.job_dir,
                args.dataset,
                sha_list=str(args.sha_list) if args.sha_list else None,
                workers=args.workers,
                limit=args.limit,
                retry_errors=args.retry_errors,
                profile=args.profile,
                inventory=args.inventory,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 1 if summary["retryable_errors"] or summary["version_mismatches"] else 0
        if args.command == "data" and args.data_command == "rawmal-exe":
            from malweave.data.rawmal_exe import run_rawmal_exe

            result = run_rawmal_exe(
                args.job_dir,
                args.bucket,
                args.account,
                args.profile,
                limit=args.limit,
            )
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
                raise DataError("Pass --die-job and --analyze-headless (or set GHIDRA_ROOT).")
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
        if args.command == "data" and args.data_command == "dataset-die":
            from malweave.data.dataset_die import (
                dataset_die_status,
                export_dataset_die,
                run_dataset_die,
            )

            if args.action == "status":
                result = dataset_die_status(args.job_dir)
            elif args.action == "export":
                output = args.output or args.job_dir / "packing.csv"
                result = export_dataset_die(args.job_dir, output)
            else:
                if args.output is not None:
                    raise DataError("--output is only used by dataset-die export.")
                if not args.dataset:
                    raise DataError("Pass --dataset for dataset-die run.")
                result = run_dataset_die(
                    args.job_dir,
                    args.dataset,
                    workers=args.workers,
                    limit=args.limit,
                    profile=args.profile,
                    die_command=_packing_die_command(args.die_command),
                    labels_csv=args.labels_csv,
                    sha_list=args.sha_list,
                    timeout_per_mode=args.timeout_per_mode,
                    inventory=args.inventory,
                    retry_errors=args.retry_errors,
                )
            print(json.dumps(result, indent=2, sort_keys=True))
            return int(args.action == "run" and result["failed"] > 0)
        if args.command == "data" and args.data_command == "rands-die":
            if args.action == "status":
                print((args.job_dir / "progress.json").read_text())
                return 0
            from malweave.data.rands_die import run_rands_die

            prefix = args.s3_prefix or os.environ.get("MALWEAVE_RANDS_METADATA_S3_PREFIX")
            if not prefix:
                raise DataError("Set MALWEAVE_RANDS_METADATA_S3_PREFIX or pass --s3-prefix.")
            result = run_rands_die(
                args.job_dir,
                load_rands_dataset_config(args.config),
                prefix,
                workers=args.workers,
                die_command=_packing_die_command(args.die_command),
                retry_seconds=args.retry_seconds,
                limit=args.limit,
                raw_prefix=args.raw_s3_prefix or os.environ.get("MALWEAVE_RANDS_RAW_S3_PREFIX"),
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1 if result["failed"] else 0
        if args.command == "data" and args.data_command == "die-setup":
            from malweave.data.die_tools import setup_die

            print(json.dumps(setup_die(PROJECT_ROOT), indent=2))
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
        DataError,
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
