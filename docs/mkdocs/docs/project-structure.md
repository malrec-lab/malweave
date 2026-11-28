# Project Structure

The layout follows Cookiecutter Data Science 2.3.0, adapted for deep-learning research where malware data, checkpoints, and experiment evidence need clear separation.

```text
configs/                 Versioned, non-sensitive inputs to a run
  datasets/              Release and preprocessing specifications
  experiments/           Model, training, and evaluation settings
data/                    Local data lifecycle; Git-ignored
  raw/                   Immutable downloads
  external/              Third-party inputs
  interim/               Reproducible working transformations
  processed/             Canonical model-ready data
docs/mkdocs/docs/        Versioned research and dataset documentation
malweave/                Importable, testable implementation
  data/                  Loaders, validation, EXE transformations, byte/BPE utilities
  experiments/           Benchmark cohorts, leakage groups and splits
  models/                Architectures and checkpoint interfaces
  training/              Orchestration and training loops
  evaluation/            Released detector loading and resumable evaluation
  utils/                 Reserved package for shared utilities
models/                  Local checkpoints, tokenizers, predictions; Git-ignored
notebooks/               Ordered exploratory work
references/              Small, redistributable reference material
reports/                 Local generated reports and figures; Git-ignored
tests/                   Automated tests for reusable behavior
```

## Local data layout

Each dataset has its own inventory and final audit CSVs. Shared run directories
under `data/processed/audit/jobs/` retain SQLite, progress and evidence.

| Location | Contents |
| --- | --- |
| `data/interim/s3/<dataset>/inventory.csv` | Verified S3 inventory staged by `dataset-storage fetch` for new audit jobs. |
| `data/processed/<dataset>/audit/packing.csv` | Final DiE results in the shared 11-column schema. |
| `data/processed/rands/audit/packing-first-pass-10s.csv`, `data/processed/rands/file-descriptions.csv.gz` | First-pass 22-column RanDS DiE export and source `file` descriptions. |
| `data/processed/<dataset>/inventory.csv` | Original local inventory kept with release and audit evidence. |
| [S3 layout](datasets/s3-layout.md) | Shared S3 paths for RAW, EXE, inventory, metadata, audit evidence and experiments. |
| `data/processed/<dataset>/audit/native-dotnet-<job>.csv` | Final runtime labels and PE architecture fields (12 columns). The checked full exports use `native-dotnet-20261122.csv`. |
| `data/processed/audit/jobs/<dataset>-<job>/` | Per-dataset run state (SQLite, self-checkpointed) |
| `models/rands/legacy/<run>/`, `reports/rands/{checks,monitors}/legacy/` | Archived old-design runs and checks |
| `data/interim/rands-scratch/` | Synthetic scratch working runs |

## Existing code capabilities

These are implementation capabilities. See the [research overview](workflows/research-protocol.md)
for the current design and the role of earlier runs.

| Location | Current scope and limitations |
| --- | --- |
| `cli.py` | Shared data/experiment CLI; `experiment train --checkpoint` supports EXE BiMamba transfer with explicit config and synthetic coverage. |
| `data/dataset_storage.py`, `data/s3_layout.py` | Shared S3 key conventions, verified input staging and SQLite audit publication. |
| `data/dataset_audit.py`, `data/audit_reporting.py` | Shared native/.NET audit, resumable state and CSV export. |
| `data/dataset_die.py`, `data/die_tools.py` | Shared full or SHA-selected packing scans and pinned DiE installation. |
| `data/rawmal_exe.py` | RawMal-TF EXE extraction with bounded S3 batches, a manifest and resumable state. |
| `data/rands*.py`, `data/pe_*.py` | RanDS audit, EXE extraction, provenance and architecture/packing assessment; scratch preparation also implements EXE acquisition, grouping and splits. |
| `data/byte_inputs.py` | RAW byte IDs, scratch EXE BPE and batching. `data/lmlm_inputs.py` separately implements released BPE/Unigram contiguous-byte inference. |
| `models/` | BiMamba, HRRFormer and MalConvGCT models. The earlier RanDS BiMamba workflow used native CUDA kernels on A100; the new Mini/Tiny setup needs its own profiling. |
| `training/` | Supervised RAW/EXE runner, released-BiMamba transfer and separate original E1/LMLM E2 MalConvGCT protocols with atomic optimizer/scheduler/RNG resume and source differential CPU tests; independent scratch orchestration also has token cache and local/S3 resume. Historical E1/E2 GPU runs are documented in the RanDS checkpoint workflow. |
| `experiments/` | RanDS cohort, duplicate-group and split builders; their policies are not automatically the checkpoint protocol. |
| `evaluation/lmlm_a.py` | Released EXE detector evaluation, parity/capacity probe and resumable predictions. |
| `scripts/run-dataset-audit-kaggle.py` | Shared Kaggle runner for native/.NET and DiE jobs, including SQLite backup and export. |
| `scripts/`, `ghidra_scripts/` | Audit notebook support and optional Ghidra DIS/DEC tooling. |

The proposed full-EXE Mini/Tiny and distillation workflows are pending. See the [earlier RanDS checkpoint workflow](workflows/lmlm-checkpoints.md)
for the measured GPU runs and supported recovery commands.

## Why These Boundaries Matter

| Boundary | Prevents | Required practice |
| --- | --- | --- |
| `configs/` vs. `models/` | An untraceable checkpoint or a secret in Git | Commit safe configuration; save its resolved copy with local artifacts. |
| `data/raw/` vs. `data/processed/` | Accidental mutation of a benchmark or unclear provenance | Preserve originals and derive model inputs deterministically. |
| `malweave/` vs. `notebooks/` | Logic that cannot be tested or reused | Prototype in a notebook, then promote stable code into the package. |
| `experiments/` vs. `training/` | Benchmark policy silently changing with the model loop | Keep cohort/split policy independently reviewable; keep evaluation logic in `evaluation/`. |
| `docs/` vs. `reports/` | Generated output being confused with project guidance | Keep method and policy docs versioned; regenerate run-specific reports locally. |

## Reproducibility Contract

Every reported result should be recoverable from five pieces of information:

1. Dataset name, release/revision, acquisition date, access conditions, and local checksum record.
2. The committed dataset and experiment configuration, plus the resolved copy.
3. Source revision and package environment used for execution.
4. Split protocol, preprocessing fit scope, random seed, and evaluation metrics.
5. Checkpoint and prediction locations, retained in approved local storage.

The base Python toolchain is reconstructed with uv 0.11.9, `.python-version`, and the committed `uv.lock`. Training dependencies already live in `train`; additional dependencies belong there or in a narrowly scoped model/dataset group; GPU drivers and native runtimes require an additional documented compatibility matrix or canonical container. See [Environment and dependencies](development/environment.md).

Do not place restricted malware samples or material that reveals them in a configuration, notebook output, test fixture, documentation build, or Git history. See the dataset catalog for corpus-specific constraints.
