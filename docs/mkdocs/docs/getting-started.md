# Getting Started

## 1. Prepare a local environment

Install uv 0.11.9, then synchronize the repository from its committed lock:

```bash
uv sync --locked
make check
```

The canonical environment is CPython 3.12.12, recorded in `.python-version`. The package supports
Python 3.10 through 3.12. CI checks Python 3.10 on Ubuntu and Python 3.12.12 on Ubuntu, macOS, and
Windows. uv creates `.venv` and installs the exact dependency versions and hashes recorded in
`uv.lock`; shell activation is optional because Make targets use `uv run --locked`.

Do not use `pip install` inside the project environment. Add or update dependencies through uv so `pyproject.toml` and `uv.lock` remain synchronized. Read [Environment and dependencies](development/environment.md) for dependency groups, controlled upgrades, CI behavior, and the future GPU policy.

## 2. Select data safely

Read the relevant [dataset card](datasets/index.md) before downloading anything. Each card states the source, access terms, evaluation constraints, and malware handling requirements. Never put raw samples, feature archives, credentials, or sample inventories into the repository.

Set `MALWEAVE_DATA_DIR` when data must live in an isolated or access-controlled location. The package then uses that directory in place of the repository's ignored `data/` directory. `MALWEAVE_MODELS_DIR` and `MALWEAVE_REPORTS_DIR` provide the same option for large model and report outputs.

For the current RanDS raw-PE snapshot, keep its machine-specific root outside Git and run the
read-only release audit before preprocessing:

```bash
cp .env.example .env
# Edit .env: MALWEAVE_RANDS_DIR points to raw/dataset and
# MALWEAVE_RANDS_METADATA_DIR points to the directory holding both CSV files.
uv run --locked malweave data inspect --dataset rands
```

The MalWeave CLI loads `.env` automatically. A variable already exported by the shell or supplied
by CI takes precedence over `.env`, and explicit `--root` and `--metadata-root` arguments take
precedence over both. `--root` means the raw root; omit `--metadata-root` only for the legacy
combined layout.
Never commit `.env`; only `.env.example` is versioned.

See [LMLM on RanDS](workflows/lmlm-rands.md) for the release contract, bounded hash
verification, local manifest creation, and the RanDS data workflow.

## 3. Implement a research task

After setup, use [Onboarding a Research Task](onboarding.md). It is the single guide for reading
task boundaries, code placement, focused tests, documentation updates, and review before commit.
