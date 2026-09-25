"""Command-line entrypoint for reproducible MalWeave workflows."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
from pathlib import Path
import re
import sys

from dotenv import load_dotenv
import yaml

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
from malweave.data.s3.inventory import S3InventoryError, inventory_s3_prefix
from malweave.data.s3.rands import RandsS3Error, inventory_rands_s3
from malweave.experiments.rands_comparison import (
    RandsComparisonError,
    build_rands_comparison_cohort,
    load_rands_comparison_config,
    load_rands_product_manifest,
    split_rands_comparison_cohort,
    write_rands_comparison_split_outputs,
)
from malweave.experiments.rands_raw_manifest import (
    RandsRawError,
    freeze_rands_raw_manifest,
    load_rands_raw_manifest_preset,
)
from malweave.training.manifest import TrainingManifestError
from malweave.training.sources import ByteSourceError
from malweave.training.stage import StageError, stage_manifest_from_s3
from malweave.training.supervised import (
    SupervisedRunRequest,
    SupervisedTrainingError,
    run_supervised_training,
)

DEFAULT_RANDS_CONFIG = CONFIGS_DIR / "datasets" / "rands-raw-2026.yaml"
DEFAULT_MALCONV_RAW_CONFIG = CONFIGS_DIR / "experiments" / "malconv-raw.yaml"
DOTENV_PATH = PROJECT_ROOT / ".env"


def _load_project_environment(path: Path | None = None) -> None:
    """Load machine-local settings without overriding the caller's environment."""
    load_dotenv(dotenv_path=path or DOTENV_PATH, override=False)


def _experiment_settings(path: Path) -> dict:
    try:
        settings = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise SupervisedTrainingError("Could not read the experiment YAML.") from error
    if not isinstance(settings, dict):
        raise SupervisedTrainingError("Experiment YAML must be a mapping.")
    return settings


def _preset_path(settings: dict, preset: str, field: str) -> Path:
    try:
        value = settings["data"]["manifest_presets"][preset][field]
    except (KeyError, TypeError) as error:
        raise SupervisedTrainingError(f"Preset {preset!r} lacks {field}.") from error
    if not isinstance(value, str) or not value:
        raise SupervisedTrainingError(f"Preset {preset!r} has an invalid {field} path.")
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def _experiment_root_path() -> Path:
    return PROJECT_ROOT / "work"


def _experiment_name(settings: dict, config_path: Path) -> str:
    experiment = settings.get("experiment") or {}
    if not isinstance(experiment, dict):
        raise SupervisedTrainingError("Experiment settings must be a mapping.")
    name = experiment.get("name") or config_path.stem
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name):
        raise SupervisedTrainingError("Experiment name must be a simple path-safe name.")
    return name


def _staging_root(settings: dict, config_path: Path, preset: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", preset):
        raise SupervisedTrainingError("Preset must be a simple path-safe name.")
    return _experiment_root_path() / "staged" / _experiment_name(settings, config_path) / preset


def _training_request(
    args: argparse.Namespace, argv: Sequence[str] | None
) -> SupervisedRunRequest:
    settings = _experiment_settings(args.experiment)
    if args.preset and args.split_manifest:
        raise SupervisedTrainingError("Choose either --preset or --split-manifest.")
    split_manifest = (
        _preset_path(settings, args.preset, "manifest") if args.preset else args.split_manifest
    )
    if split_manifest is None:
        raise SupervisedTrainingError("Supply --preset or --split-manifest.")
    tracks = settings.get("tracks")
    if not isinstance(tracks, dict):
        raise SupervisedTrainingError("Experiment YAML lacks tracks.")
    track = args.track or (next(iter(tracks)) if len(tracks) == 1 else None)
    if track not in tracks:
        raise SupervisedTrainingError("Select a track declared in the experiment YAML.")
    runtime = settings.get("runtime") or {}
    experiment = settings.get("experiment") or {}
    if not isinstance(runtime, dict) or not isinstance(experiment, dict):
        raise SupervisedTrainingError("Experiment and runtime settings must be mappings.")
    device = args.device or runtime.get("device")
    accumulation = (
        args.gradient_accumulation_steps
        if args.gradient_accumulation_steps is not None
        else runtime.get("gradient_accumulation_steps")
    )
    seed = args.seed if args.seed is not None else experiment.get("seed")
    if (
        not isinstance(device, str)
        or not isinstance(accumulation, int)
        or not isinstance(seed, int)
    ):
        raise SupervisedTrainingError(
            "Declare device, gradient accumulation, and seed in YAML or CLI."
        )
    return SupervisedRunRequest(
        track=track,
        config_path=args.experiment,
        split_manifest_path=split_manifest,
        raw_root=args.raw_root,
        exe_root=args.exe_root,
        artifact_root=args.artifact_root
        or _experiment_root_path() / "runs" / _experiment_name(settings, args.experiment),
        run_id=args.run_id,
        device=device,
        gradient_accumulation_steps=accumulation,
        seed=seed,
        command=" ".join(("malweave", *(argv if argv is not None else sys.argv[1:]))),
        raw_samples_dir=args.raw_samples_dir,
        staging_report=args.staging_report
        or (
            _staging_root(settings, args.experiment, args.preset) / "staging-summary.json"
            if args.preset
            else None
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="malweave", description="MalWeave research tooling.")
    commands = parser.add_subparsers(dest="command", required=True)
    data = commands.add_parser("data", help="Inspect and prepare research datasets.")
    data_commands = data.add_subparsers(dest="data_command", required=True)
    experiment = commands.add_parser("experiment", help="Freeze and run declared experiments.")
    experiment_commands = experiment.add_subparsers(dest="experiment_command", required=True)

    generic_inventory = data_commands.add_parser(
        "inventory-s3", help="List any S3 prefix into a private, unlabeled object inventory."
    )
    generic_inventory.add_argument("--bucket-env", default="MALWEAVE_S3_BUCKET")
    generic_inventory.add_argument("--prefix", required=True)
    generic_inventory.add_argument("--state-db", type=Path, required=True)
    generic_inventory.add_argument("--manifest", type=Path, required=True)
    generic_inventory.add_argument("--summary", type=Path, required=True)
    generic_inventory.add_argument("--suffix", default=None)
    generic_inventory.add_argument("--min-size", type=int, default=0)
    generic_inventory.add_argument("--max-size", type=int, default=None)
    generic_inventory.add_argument("--resume", action="store_true")
    generic_inventory.add_argument("--progress-every", type=int, default=25)

    inventory = data_commands.add_parser(
        "inventory-rands-s3",
        help="Audit RanDS S3 objects and save RAW metadata candidates, including missing ones.",
    )
    inventory.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    inventory.add_argument("--metadata-root", type=Path, required=True)
    inventory.add_argument("--bucket-env", default="MALWEAVE_RANDS_S3_BUCKET")
    inventory.add_argument("--prefix", required=True)
    inventory.add_argument("--protocol", default="lmlm_x86_unpacked")
    inventory.add_argument("--state-db", type=Path, required=True)
    inventory.add_argument("--manifest", type=Path, required=True)
    inventory.add_argument("--summary", type=Path, required=True)
    inventory.add_argument("--resume", action="store_true")
    inventory.add_argument("--progress-every", type=int, default=25)

    freeze_raw = experiment_commands.add_parser(
        "freeze-rands-raw",
        help="Freeze a RAW split from available S3 candidates (all by default).",
    )
    freeze_raw.add_argument("--experiment", type=Path, default=DEFAULT_MALCONV_RAW_CONFIG)
    freeze_raw.add_argument("--preset", choices=("full", "pilot"), default=None)
    freeze_raw.add_argument("--inventory", type=Path, default=None)
    freeze_raw.add_argument("--inventory-summary", type=Path, default=None)
    freeze_raw.add_argument("--manifest", type=Path, default=None)
    freeze_raw.add_argument("--summary", type=Path, default=None)
    freeze_raw.add_argument("--total", type=int, default=None)
    freeze_raw.add_argument("--balanced", action="store_true")
    freeze_raw.add_argument("--label-count", action="append", default=[], metavar="LABEL=N")
    freeze_raw.add_argument("--where", action="append", default=[], metavar="COLUMN=VALUE")
    freeze_raw.add_argument("--seed", default=None)
    freeze_raw.add_argument("--min-year", type=int, default=None)
    freeze_raw.add_argument("--max-year", type=int, default=None)

    stage = experiment_commands.add_parser(
        "stage-inputs",
        help="Download and verify a complete frozen S3 split on an isolated training worker.",
    )
    stage.add_argument("--experiment", type=Path, default=DEFAULT_MALCONV_RAW_CONFIG)
    stage.add_argument("--preset", default=None)
    stage.add_argument("--manifest", type=Path, default=None)
    stage.add_argument("--manifest-summary", type=Path, default=None)
    stage.add_argument("--representation", choices=("raw", "exe"), default="raw")
    stage.add_argument("--bucket-env", default=None)
    stage.add_argument(
        "--output-root",
        type=Path,
        help="Override <project>/work/staged/<experiment>/<preset>.",
    )
    stage.add_argument("--resume", action="store_true")
    stage.add_argument("--progress-every", type=int, default=100)

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
    train = experiment_commands.add_parser(
        "train",
        help="Train one declared supervised track from a frozen private split.",
    )
    train.add_argument("--track", choices=("malconvgct", "hrrformer", "mamba"))
    train.add_argument("--split-manifest", type=Path)
    train.add_argument("--preset")
    train.add_argument("--experiment", type=Path, required=True)
    train.add_argument("--raw-root", type=Path, default=None)
    train.add_argument("--exe-root", type=Path, default=None)
    train.add_argument(
        "--artifact-root", type=Path, help="Override <project>/work/runs/<experiment>."
    )
    train.add_argument("--run-id", required=True)
    train.add_argument("--device", help="Override the declared torch device, e.g. cuda:0.")
    train.add_argument("--gradient-accumulation-steps", type=int)
    train.add_argument("--seed", type=int)
    train.add_argument("--raw-samples-dir", default="dataset")
    train.add_argument("--staging-report", type=Path, default=None)
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
        help="Representations to extract in one Ghidra pass; choose dis, dec, or both.",
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
        if args.command == "data" and args.data_command == "inventory-s3":
            bucket = os.environ.get(args.bucket_env)
            if not bucket:
                raise S3InventoryError(f"Set {args.bucket_env} to the private S3 bucket name.")
            summary = inventory_s3_prefix(
                bucket=bucket,
                prefix=args.prefix,
                state_path=args.state_db,
                manifest_path=args.manifest,
                summary_path=args.summary,
                suffix=args.suffix,
                min_size=args.min_size,
                max_size=args.max_size,
                resume=args.resume,
                progress_every=args.progress_every,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "data" and args.data_command == "inventory-rands-s3":
            bucket = os.environ.get(args.bucket_env)
            if not bucket:
                raise RandsS3Error(f"Set {args.bucket_env} to the private S3 bucket name.")
            summary = inventory_rands_s3(
                load_rands_dataset_config(args.config),
                args.metadata_root,
                bucket=bucket,
                prefix=args.prefix,
                protocol=args.protocol,
                state_path=args.state_db,
                manifest_path=args.manifest,
                summary_path=args.summary,
                resume=args.resume,
                progress_every=args.progress_every,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "experiment" and args.experiment_command == "freeze-rands-raw":
            custom_selection = (
                args.total is not None
                or args.balanced
                or bool(args.label_count)
                or bool(args.where)
                or args.seed is not None
                or args.min_year is not None
                or args.max_year is not None
            )
            if args.preset is not None and custom_selection:
                raise RandsRawError(
                    "A named preset cannot be combined with selection overrides; "
                    "omit --preset and provide new --manifest and --summary paths."
                )
            preset_name = args.preset or (
                "custom" if custom_selection or args.manifest or args.summary else "full"
            )
            preset = load_rands_raw_manifest_preset(
                args.experiment, "full" if preset_name == "custom" else preset_name
            )
            manifest_path = args.manifest or (preset.manifest if preset_name != "custom" else None)
            summary_path = args.summary or (preset.summary if preset_name != "custom" else None)
            if manifest_path is None or summary_path is None:
                raise RandsRawError(
                    "Custom selections require both --manifest and --summary output paths."
                )
            label_counts = {}
            for item in args.label_count:
                label, separator, count = item.partition("=")
                if not separator or not count.isdigit() or label in label_counts:
                    raise RandsRawError("--label-count must be unique LABEL=N values.")
                label_counts[label] = int(count)
            where = []
            for item in args.where:
                column, separator, value = item.partition("=")
                if not separator or not column or not value:
                    raise RandsRawError("--where must be COLUMN=VALUE.")
                where.append((column, value))
            summary = freeze_rands_raw_manifest(
                args.inventory or preset.inventory,
                args.inventory_summary or preset.inventory_summary,
                args.experiment,
                manifest_path,
                summary_path,
                total=preset.total if preset_name != "custom" else args.total,
                balanced=preset.balanced if preset_name != "custom" else args.balanced,
                label_counts=label_counts,
                where=tuple(where),
                seed=args.seed,
                min_year=args.min_year,
                max_year=args.max_year,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "experiment" and args.experiment_command == "stage-inputs":
            if args.preset is None and args.manifest is None:
                raise StageError(
                    "Choose --preset pilot/full or supply an explicit split manifest."
                )
            if (args.manifest is None) != (args.manifest_summary is None):
                raise StageError("Custom staging needs both --manifest and --manifest-summary.")
            settings = _experiment_settings(args.experiment)
            data = settings.get("data") or {}
            if not isinstance(data, dict):
                raise StageError("Experiment data settings must be a mapping.")
            bucket_env = args.bucket_env or data.get("bucket_env")
            if not isinstance(bucket_env, str) or not bucket_env:
                raise StageError("Declare the S3 bucket environment variable in YAML or CLI.")
            bucket = os.environ.get(bucket_env)
            if not bucket:
                raise StageError(f"Set {bucket_env} on the isolated training worker.")
            manifest = args.manifest or _preset_path(settings, args.preset, "manifest")
            manifest_summary = args.manifest_summary or _preset_path(
                settings, args.preset, "summary"
            )
            output_root = args.output_root or (
                _staging_root(settings, args.experiment, args.preset) if args.preset else None
            )
            if output_root is None:
                raise StageError("Custom staging needs --output-root.")
            summary = stage_manifest_from_s3(
                manifest,
                manifest_summary,
                output_root,
                bucket=bucket,
                representation=args.representation,
                resume=args.resume,
                progress_every=args.progress_every,
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
        if args.command == "experiment" and args.experiment_command == "train":
            result = run_supervised_training(_training_request(args, argv))
            print(json.dumps(result["metrics"], indent=2, sort_keys=True))
            return 0
    except KeyboardInterrupt:
        print(
            "interrupted: durable state was preserved; rerun the same command with --resume.",
            file=sys.stderr,
        )
        return 130
    except (
        DatasetConfigError,
        RandsDataError,
        RandsExeError,
        RandsGhidraError,
        RandsPeAssessmentError,
        RandsProductError,
        RandsComparisonError,
        RandsRawError,
        RandsS3Error,
        S3InventoryError,
        SupervisedTrainingError,
        TrainingManifestError,
        ByteSourceError,
        StageError,
        OSError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("Unsupported command.")
    return 2
