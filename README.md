# MalWeave

Research code for preparing Windows PE datasets and training and evaluating malware
language models.

**[Open the documentation site](https://malrec-lab.github.io/malweave/)**

GitHub Actions publishes the site from `main`. The guides below open the source
documentation for the branch you are browsing.

## Find a workflow

| I want to | Start here |
| --- | --- |
| Audit RanDS, VERA, RawMal-TF or Assemblage | [PE audit and EXE preparation](docs/mkdocs/docs/workflows/data-preparation.md) |
| Find datasets, manifests or audit results | [Dataset catalog](docs/mkdocs/docs/datasets/index.md) and [S3 layout](docs/mkdocs/docs/datasets/s3-layout.md) |
| Reproduce earlier RanDS experiments | [LMLM checkpoint experiments and MalConvGCT baselines](docs/mkdocs/docs/workflows/lmlm-checkpoints.md) |
| Find the RanDS scratch baseline | [Paused EXE scratch workflow](docs/mkdocs/docs/workflows/rands-scratch.md) |
| Follow the proposed full-EXE Mini/Tiny BiMamba study | [Research overview and implementation status](docs/mkdocs/docs/workflows/research-protocol.md) |

## Develop locally

Use uv **0.11.9** and CPython **3.12.12** on Linux or macOS. Run from the repository root.

```bash
uv sync --locked
make check
```

Run `make docs-serve` to preview the documentation at
[127.0.0.1:8000](http://127.0.0.1:8000/). For setup details and code navigation, see
[getting started](docs/mkdocs/docs/getting-started.md),
[environment and dependencies](docs/mkdocs/docs/development/environment.md), and
[project structure](docs/mkdocs/docs/project-structure.md).

Keep private data, credentials, checkpoints and run artifacts outside Git. Treat
raw PE samples as potentially live malware and handle them only as data for static
analysis. See [repository instructions](AGENTS.md) and the
[LMLM paper](references/papers/lmlm/2026-s103-paper.md).
