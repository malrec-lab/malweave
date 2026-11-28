# MalWeave

MalWeave implements data preparation, model training and evaluation for malware
language-modeling research.

## Research workflow

The current study — the proposed Mini/Tiny BiMamba full-EXE and distillation
matrix — is designed and tracked outside this repository. MalWeave documents the
runnable pipeline, the audit status and the earlier RanDS checkpoint experiments.

- [Current research and implementation status](docs/mkdocs/docs/workflows/research-protocol.md)
- [Shared audit and EXE preparation](docs/mkdocs/docs/workflows/data-preparation.md)
- [Dataset storage on S3](docs/mkdocs/docs/datasets/s3-layout.md)
- [Earlier A/C/E1/E2 experiments](docs/mkdocs/docs/workflows/lmlm-checkpoints.md)
- [RanDS scratch baseline](docs/mkdocs/docs/workflows/rands-scratch.md)

## Development setup

```bash
uv sync --locked
make check
make docs-serve
```

Use uv **0.11.9**, canonical CPython **3.12.12**, Linux or macOS.
See [getting started](docs/mkdocs/docs/getting-started.md),
[environment](docs/mkdocs/docs/development/environment.md) and
[project structure](docs/mkdocs/docs/project-structure.md).
Dataset descriptions are in the [catalog](docs/mkdocs/docs/datasets/index.md);
the source paper is in [references](references/papers/lmlm/2026-s103-paper.md).

Reusable source lives in `malweave/`, safe configs in `configs/`, and synthetic tests in
`tests/`. Data, state, checkpoints and run artifacts stay outside Git.
Raw PEs may be live malware; follow `AGENTS.md` and use static analysis only.
