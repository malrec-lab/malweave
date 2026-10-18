# Source Package

Place reusable, testable Python code in this package rather than embedding it in notebooks or shell history. Keep the boundaries intentional:

- `data/`: acquisition adapters, schema checks, byte/BPE utilities and deterministic transformations.
- `experiments/`: experiment-specific cohorts, leakage grouping and split construction.
- `models/`: architectures, tokenizer interfaces, and checkpoint loading.
- `training/`: training loops, callbacks, and run orchestration.
- `evaluation/`: metrics, benchmark protocols, calibration, and error analysis.
- `utils/`: small shared helpers that do not depend on a particular dataset or model family.

`config.py` is the only place that defines project paths. Set `MALWEAVE_DATA_DIR`, `MALWEAVE_MODELS_DIR`, or `MALWEAVE_REPORTS_DIR` when artifacts must live outside the repository; no directory is created merely by importing the package.

Add package dependencies through uv in the narrowest appropriate group; do not install undeclared packages directly into `.venv`. The canonical workflow and dependency policy are documented in `docs/mkdocs/docs/development/environment.md` and `CONTRIBUTING.md`.
