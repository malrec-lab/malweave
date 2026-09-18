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
    except (
        DatasetConfigError,
        RandsDataError,
        RandsExeError,
        RandsProductError,
        RandsComparisonError,
        SupervisedTrainingError,
        OSError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("Unsupported command.")
    return 2
