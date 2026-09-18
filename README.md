# MalWeave

[![CCDS](https://img.shields.io/badge/CCDS-2.3.0-328F97?logo=cookiecutter)](https://cookiecutter-data-science.drivendata.org/)

MalWeave is an independent research codebase for reproducing and extending malware language
modeling methods. It currently adapts Large Malware Language Models (LMLM) to the RanDS ransomware
corpus; it is not the paper's official implementation.

## Current State

RanDS supports a read-only release audit, full-corpus resumable static EXE-section extraction,
and frozen RAW/EXE products. Model components for MalConvGCT, HRRFormer, and Mamba are separate
from data preparation. No command executes PE files. Ghidra-derived views remain separate work.

```bash
uv sync --locked
make check
```

## Documentation Map

| If you need to... | Read |
| --- | --- |
| Set up the environment and point the project at local data | [Getting Started](docs/mkdocs/docs/getting-started.md) |
| Implement a research task | [Onboarding a Research Task](docs/mkdocs/docs/onboarding.md) |
| Understand source and artifact boundaries | [Project Structure](docs/mkdocs/docs/project-structure.md) |
| Use the RanDS corpus | [RanDS dataset card](docs/mkdocs/docs/datasets/rands.md) |
| Run the implemented RanDS audit | [LMLM on RanDS workflow](docs/mkdocs/docs/workflows/lmlm-rands.md) |
| Prepare the complete RanDS RAW/EXE corpus | [RanDS data-preparation workflow](docs/mkdocs/docs/workflows/lmlm-rands.md) |
| Understand data, components, and experiments | [Research workstreams](docs/mkdocs/docs/workflows/research-workstreams.md) |
| Change dependencies or contributor workflow | [Environment guide](docs/mkdocs/docs/development/environment.md) and [CONTRIBUTING.md](CONTRIBUTING.md) |

## Safety

Raw PE files may be live malware. Never execute, commit, upload, redistribute, or interactively
open them. Keep raw data and generated artifacts outside Git, and use synthetic fixtures in tests.
Read `AGENTS.md` before changing research code.
