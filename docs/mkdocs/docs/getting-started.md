# Getting Started

## 1. Prepare a local environment

Use Python 3.10 or newer. The baseline test suite uses only the standard library; install the optional extras when linting or building the documentation:

```bash
python -m venv .venv
source .venv/bin/activate
make test
python -m pip install -e ".[dev,docs]"
make lint
make docs
```

## 2. Select data safely

Read the relevant [dataset card](datasets/index.md) before downloading anything. Each card states the source, access terms, evaluation constraints, and malware handling requirements. Never put raw samples, feature archives, credentials, or sample inventories into the repository.

Set `MALWEAVE_DATA_DIR` when data must live in an isolated or access-controlled location. The package then uses that directory in place of the repository's ignored `data/` directory. `MALWEAVE_MODELS_DIR` and `MALWEAVE_REPORTS_DIR` provide the same option for large model and report outputs.

## 3. Start an experiment

1. Add a reviewed, non-sensitive dataset description in `configs/datasets/`.
2. Add an experiment configuration in `configs/experiments/` before running it.
3. Implement reusable loaders and transforms in `malweave/data/`; leave exploratory analysis in a numbered notebook.
4. Keep model components, training, and evaluation code in their separate package modules.
5. Save the resolved configuration, dataset release identifier, seed, Git commit, metrics, and artifact paths with every local run.

Run `make test` whenever reusable code changes. Add a focused regression test alongside each new loader, transformation, split policy, or metric.
