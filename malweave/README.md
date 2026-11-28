# Source Package

Place reusable, testable Python code in this package rather than embedding it in notebooks or shell history. Keep the boundaries intentional:

- `data/`: acquisition adapters, schema checks, byte/BPE utilities and deterministic transformations.
- `experiments/`: experiment-specific cohorts, leakage grouping and split construction.
- `models/`: architectures, tokenizer interfaces, and checkpoint loading.
- `training/`: training loops, callbacks, and run orchestration.
- `evaluation/`, `utils/`: reserved packages for shared evaluation and utilities.

`config.py` defines shared project paths. The environment guide lists paths that
can be configured for mounted storage. Imports do not create directories.

Add package dependencies through uv in the narrowest appropriate group; do not install undeclared packages directly into `.venv`. The canonical workflow and dependency policy are documented in `docs/mkdocs/docs/development/environment.md` and `CONTRIBUTING.md`.

Current research priority and decision status belong to the
[research overview](../docs/mkdocs/docs/workflows/research-protocol.md).
The [project structure](../docs/mkdocs/docs/project-structure.md#existing-code-capabilities)
catalogues current capabilities; existing components are not proof of checkpoint compatibility.
