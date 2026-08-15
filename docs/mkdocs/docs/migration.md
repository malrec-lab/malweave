# Migration Report

## What Changed

This repository was scaffolded from the official [Cookiecutter Data Science](https://github.com/drivendataorg/cookiecutter-data-science) template, release 2.3.0, using its maintained `ccds` generator. The scaffold adds the standard data lifecycle (`raw`, `external`, `interim`, `processed`), source package, tests, notebooks, references, models, reports, and MkDocs documentation site.

The repository was initially documentation-only. Its dataset research pages were retained substantively and relocated from `docs/datasets/` to `docs/mkdocs/docs/datasets/`, where they are now navigable as a documentation site. The prior catalog `README.md` is now `datasets/index.md`; its location and source formatting changed.

The generated placeholder scripts and intentionally failing sample tests were not retained. Instead, `malweave/` supplies clear package boundaries and a side-effect-free path configuration, while `tests/test_config.py` verifies the base path contract. The project has no model-specific dependency or fabricated training implementation yet.

## Why This Structure

- **Safety and access control:** malware data, provider credentials, and derived artifacts can be sensitive. Data, models, and generated reports are ignored by Git and may be relocated with environment variables.
- **Reproducibility:** experiment and dataset specifications are versioned in `configs/`, while output artifacts record their resolved configuration and source revision.
- **Maintainability:** reusable code lives in a small importable package with distinct data, model, training, and evaluation modules. Notebooks remain for exploration rather than becoming the production pipeline.
- **Research communication:** stable methodology and dataset notes are versioned documentation; generated plots and reports remain local outputs.

## How To Use It

1. Read the relevant dataset card and create a safe, reviewed configuration in `configs/datasets/`.
2. Acquire approved data into `data/raw/` or an isolated `MALWEAVE_DATA_DIR`; retain provenance beside the local data rather than committing it.
3. Add deterministic preparation code to `malweave/data/` and write a targeted test.
4. Define an experiment under `configs/experiments/`, implement model/training/ evaluation components in their respective modules, and preserve the exact resolved configuration with the output run.
5. Use `make test`, `make lint`, and `make docs` before sharing work.

## Deliberate Non-Changes

No datasets, samples, checkpoints, licenses, or provider terms were changed or added. No raw malware was downloaded. Existing dataset prose and links remain substantively intact; their documentation location and source formatting were standardized.
