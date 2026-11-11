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
  evaluation/            Reserved package for shared evaluation code
  utils/                 Reserved package for shared utilities
models/                  Local checkpoints, tokenizers, predictions; Git-ignored
notebooks/               Ordered exploratory work
references/              Small, redistributable reference material
reports/                 Local generated reports and figures; Git-ignored
tests/                   Automated tests for reusable behavior
```

## Local RanDS artifacts

Keep model-ready inputs separate from experiment outputs:

| Location | Contents |
| --- | --- |
| `data/processed/rands-lmlm/` | Cohort manifests, split files and input audits. |
| `data/processed/rands-die-local/` | DiE database, complete evidence, exports and release audit. |
| `data/processed/rands-ghidra-local/`, `rands-ghidra-shared-full/` | Ghidra processing state and derived representations. |
| `models/rands/<run>/` | Full E1/E2 run artifacts, final results, checkpoints, predictions and viewer. |
| `reports/rands/checks/` | Source audits, capacity probes and synthetic validation evidence. |
| `reports/rands/ghidra/` | Ghidra preflight, pilot and resource reports. |
| `reports/rands/monitors/` | Local views and history caches for remote training. |
| `reports/rands/maintenance/` | Private relocation and cleanup records. |
| `data/interim/rands-scratch/` | Synthetic scratch working runs. |

Local indexes in `data/processed/`, `models/rands/` and `reports/rands/` describe
the retained files. These generated artifacts remain Git-ignored. Completed
Kaggle runs retain one canonical downloaded result tree and verified final
bootstrap/snapshot archives; compatibility links replace byte-identical local
mirrors. Historical provenance retains paths as recorded at execution time.
Existing open E1 and C viewers have temporary links at their former paths;
new commands use `models/rands/` or `reports/rands/monitors/`.

## Existing code capabilities

These describe implementation, not completed experiments or checkpoint compatibility.
The [checkpoint plan](workflows/lmlm-checkpoints.md) owns current research decisions;
[self-pretraining](workflows/self-pretraining.md) is paused.

| Location | Current scope and limitations |
| --- | --- |
| `cli.py` | Shared data/experiment CLI; `experiment train --checkpoint` supports EXE BiMamba transfer with explicit config and synthetic coverage. |
| `data/sorel_*.py` | Conversion, selection, DiE/LIEF evidence, bounded dispatch, publication, locks and resume. v3.1 is the retained workflow; pilot/round-robin interfaces are legacy. |
| `data/rands*.py`, `data/pe_*.py` | RanDS audit, EXE extraction, provenance and architecture/packing assessment; scratch preparation also implements EXE acquisition, grouping and splits. |
| `data/byte_inputs.py` | RAW byte IDs, scratch EXE BPE and batching. `data/lmlm_inputs.py` separately implements released BPE/Unigram contiguous-byte inference. |
| `models/` | BiMamba, HRRFormer and MalConvGCT sequence classifiers with synthetic tests. Optional HRR padding masking exists. BiMamba native CUDA compatibility is unverified. |
| `training/` | Supervised RAW/EXE runner, released-BiMamba transfer and separate original E1/LMLM E2 MalConvGCT protocols with atomic optimizer/scheduler/RNG resume and source differential CPU tests; independent scratch orchestration also has token cache and local/S3 resume. Final E1/E2 GPU capacity remains unmeasured. |
| `experiments/` | RanDS cohort, duplicate-group and split builders; their policies are not automatically the checkpoint protocol. |
| `evaluation/`, `utils/` | Reserved packages; no separate implementation yet. |
| `Dockerfile.sorel`, `scripts/`, `ghidra_scripts/` | Retained CPU conversion image, source bundling and optional Ghidra DIS/DEC tooling. Runpod startup/SSH and registry work remain unfinished at handover. |

End-to-end MLM pretraining is not implemented. Released EXE BiMamba loading and
synthetic fine-tuning are tested, including a recovered large-model CPU probe. GPU
performance and the RanDS experiment protocol remain unvalidated; see the checkpoint
plan. Ghidra/RAW alternatives remain tools, not additional research directions.

## Why These Boundaries Matter

| Boundary | Prevents | Required practice |
| --- | --- | --- |
| `configs/` vs. `models/` | An untraceable checkpoint or a secret in Git | Commit safe configuration; save its resolved copy with local artifacts. |
| `data/raw/` vs. `data/processed/` | Accidental mutation of a benchmark or unclear provenance | Preserve originals and derive model inputs deterministically. |
| `malweave/` vs. `notebooks/` | Logic that cannot be tested or reused | Prototype in a notebook, then promote stable code into the package. |
| `experiments/` vs. `training/` | Benchmark policy silently changing with the model loop | Keep cohort/split policy independently reviewable; `evaluation/` remains a reserved package for reusable evaluation code. |
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
