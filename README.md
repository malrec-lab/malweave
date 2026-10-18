# MalWeave

MalWeave studies whether self-supervised pretraining on **SOREL malware + Assemblage Windows PE**
improves **RanDS ransomware-versus-benign detection** and reduces the training labels needed.
It is an independent research codebase adapting ideas from LMLM.

The input pipeline is **PE → code/executable-section bytes (EXE) → byte mapping → BPE**.
EXE contains concatenated PE sections in section-table order. The base model is a small
bidirectional Mamba, with HRRFormer as a runtime fallback. The base objective is random-token MLM;
span masking is the first planned extension.

## Plan And Progress

| Stage | Status as of 2026-10-18 |
| --- | --- |
| RanDS PE → EXE and storage | **Converted to EXE and uploaded to S3.** Extraction accounts for 215,404 sources: 215,040 successes and 364 failures. |
| SOREL + Assemblage preparation | Implement source adapters, audit metadata and run bounded extraction pilots. |
| Tokenization and models | Byte/BPE utilities, classifiers and a supervised runner exist; MLM and transfer integration are next. |
| Base experiment | Compare scratch vs pretrained at 10%, 25%, 100% RanDS training-label budgets. |
| Method extension | Compare span masking against the completed random-token MLM baseline. |

## Start Here

```bash
uv sync --locked
make check
make docs-serve
```

Use uv **0.11.9**, canonical CPython **3.12.12**, Linux or macOS. `make docs` builds the site
strictly. GPU/native Mamba compatibility is validated on the selected training machine.

| Need | Read |
| --- | --- |
| Research questions and experiment design | [Research protocol](docs/mkdocs/docs/workflows/research-protocol.md) |
| Data sources, extraction and quality checks | [Data preparation](docs/mkdocs/docs/workflows/data-preparation.md) |
| Implementation status and next tasks | [Research workstreams](docs/mkdocs/docs/workflows/research-workstreams.md) |
| Model and MLM implementation | [Model components](docs/mkdocs/docs/workflows/model-components.md) |
| Setup and dependencies | [Getting started](docs/mkdocs/docs/getting-started.md), [Environment](docs/mkdocs/docs/development/environment.md) |
| Dataset schema and access conditions | [Dataset catalog](docs/mkdocs/docs/datasets/index.md) |
| Code placement and contribution rules | [Project structure](docs/mkdocs/docs/project-structure.md), [AGENTS.md](AGENTS.md) |
| Source LMLM reference | [Paper text](references/papers/lmlm/2026-s103-paper.md) |

## Repository Boundaries

`malweave/data/` prepares deterministic representations; `malweave/models/` contains backbones;
`malweave/training/` contains runners; `malweave/experiments/` owns benchmark cohorts and splits.
Safe configs live in `configs/`; synthetic tests in `tests/`; guidance in `docs/mkdocs/docs/`.
Data, manifests, state, reports and checkpoints remain outside Git.

Raw PEs may be live malware. Perform static analysis only and follow `AGENTS.md` for handling and
provenance requirements. Tests use synthetic fixtures.
