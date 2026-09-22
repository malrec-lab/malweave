"""Command-line entrypoint for reproducible MalWeave workflows."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
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
from malweave.experiments.rands_comparison import (
    RandsComparisonError,
    build_rands_comparison_cohort,
    load_rands_comparison_config,
    load_rands_product_manifest,
    split_rands_comparison_cohort,
    write_rands_comparison_split_outputs,
)
from malweave.training.supervised import (
    SupervisedRunRequest,
    SupervisedTrainingError,
    run_supervised_training,
)

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
    experiment = commands.add_parser("experiment", help="Freeze and run declared experiments.")
    experiment_commands = experiment.add_subparsers(dest="experiment_command", required=True)

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
    train.add_argument("--track", choices=("malconvgct", "hrrformer", "mamba"), required=True)
    train.add_argument("--split-manifest", type=Path, required=True)
    train.add_argument("--experiment", type=Path, required=True)
    train.add_argument("--raw-root", type=Path, required=True)
    train.add_argument("--exe-root", type=Path, required=True)
    train.add_argument("--artifact-root", type=Path, required=True)
    train.add_argument("--run-id", required=True)
    train.add_argument("--device", required=True, help="Explicit torch device, e.g. cuda:0.")
    train.add_argument("--gradient-accumulation-steps", type=int, required=True)
    train.add_argument("--seed", type=int, required=True)
    train.add_argument("--raw-samples-dir", default="dataset")
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
    parser = _parser()
    args = parser.parse_args(argv)
    _load_project_environment()

    try:
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
            result = run_supervised_training(
                SupervisedRunRequest(
                    track=args.track,
                    config_path=args.experiment,
                    split_manifest_path=args.split_manifest,
                    raw_root=args.raw_root,
                    exe_root=args.exe_root,
                    artifact_root=args.artifact_root,
                    run_id=args.run_id,
                    device=args.device,
                    gradient_accumulation_steps=args.gradient_accumulation_steps,
                    seed=args.seed,
                    command=" ".join(("malweave", *(argv if argv is not None else sys.argv[1:]))),
                    raw_samples_dir=args.raw_samples_dir,
                )
            )
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
        SupervisedTrainingError,
        OSError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("Unsupported command.")
    return 2
