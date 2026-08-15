# MalWeave

[![CCDS](https://img.shields.io/badge/CCDS-2.3.0-328F97?logo=cookiecutter)](https://cookiecutter-data-science.drivendata.org/)

MalWeave is a research codebase for reproducing and extending malware language modeling approaches for malware detection and analysis. The repository is organized with [Cookiecutter Data Science](https://cookiecutter-data-science.drivendata.org/) so experiments can grow without mixing source code, data, model artifacts, and research evidence.

## Research Scope

This project initially focuses on reproducing and extending Large Malware Language Models (LMLM).

The implementation is intended as an independent research codebase, not as the official implementation of the original LMLM paper.

## Start Here

The repository currently provides the research foundation; it does not include a trained model or any dataset. Use Python 3.10 or later, then run the structural checks:

```bash
python -m venv .venv
source .venv/bin/activate
make test
```

Install optional tooling only when needed:

```bash
python -m pip install -e ".[dev,docs]"
make lint
make docs
```

Serve the research documentation locally with:

```bash
python -m mkdocs serve --config-file docs/mkdocs/mkdocs.yml
```

## Project Map

```text
.
├── configs/             Versioned dataset and experiment specifications
├── data/                Local, Git-ignored raw/external/interim/processed data
├── docs/mkdocs/docs/    Maintained project and dataset documentation
├── malweave/            Importable Python package for the research pipeline
├── models/              Local, Git-ignored checkpoints and predictions
├── notebooks/           Ordered, exploratory notebooks
├── references/          Papers, datasheets, and external reference material
├── reports/             Local, Git-ignored generated reports and figures
└── tests/               Automated checks for reusable research code
```

Read the full [project structure guide](docs/mkdocs/docs/project-structure.md) before starting a new pipeline. The [migration report](docs/mkdocs/docs/migration.md) records what changed and why. Dataset acquisition, licensing, evaluation, and safety notes are in the [dataset catalog](docs/mkdocs/docs/datasets/index.md).

## Research Workflow

1. Choose and document a dataset in `configs/datasets/`; follow its corresponding dataset card before downloading anything.
2. Store immutable downloads in `data/raw/` or third-party inputs in `data/external/`. Keep these directories out of Git.
3. Make deterministic transformations through `data/interim/` to `data/processed/`, with code in `malweave/data/` and configuration in `configs/`.
4. Put reusable model components in `malweave/models/`, orchestration in `malweave/training/`, and metrics/split logic in `malweave/evaluation/`.
5. Save checkpoints and predictions under `models/`, then create figures and generated reports under `reports/`. Record each run's configuration, seed, dataset release, and metrics together.

## Data and Safety Policy

No raw samples, credentials, proprietary data, extracted malware features, or model checkpoints belong in version control. Several documented datasets contain or describe malicious PE files. Obtain them only under their stated terms and handle them in an isolated, access-controlled analysis environment. The data directories are ignored deliberately; their [local data guide](data/README.md) explains the lifecycle.

## Conventions

- Name notebooks as `<order>-<initials>-<topic>.ipynb`, for example `01-nv-dataset-audit.ipynb`. Promote durable notebook logic into `malweave/`.
- Give every experiment a committed configuration in `configs/experiments/` and keep an immutable copy beside its outputs.
- Split data before fitting tokenizers, normalizers, feature selectors, or other learned transforms. Preserve dataset-specific temporal and family/provenance constraints recorded in the catalog.
- Add tests for reusable loaders, transformations, splitters, and evaluation code; use `make test` before sharing changes.
