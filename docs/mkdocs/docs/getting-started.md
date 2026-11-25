# Getting started

## Read the plan

Read the [research overview](workflows/research-protocol.md) for the current study
and its status. Use
[data preparation](workflows/data-preparation.md) to find the audit commands and
[the S3 map](datasets/s3-layout.md) to find the existing EXE manifests.

The [earlier RanDS checkpoint experiments](workflows/lmlm-checkpoints.md) document
the available training and evaluation workflow. The proposed full-EXE Mini/Tiny
experiments have a separate design and still need implementation.

## Set up development

Install uv **0.11.9**, then run from the repository root:

```bash
uv sync --locked
make check
```

Canonical CPython is **3.12.12**; supported Python is 3.10–3.12 on Linux/macOS.
uv creates `.venv`; activation is optional. See the
[environment policy](development/environment.md) for dependencies and native GPU limitations.
Synthetic development needs no corpus download.

Private data, credentials and checkpoints stay outside Git. If local configuration is needed,
copy `.env.example` only when `.env` does not exist. The CLI preserves exported variables;
explicit CLI paths take precedence. SOREL has separate path limitations documented in
the environment guide.

## Make a scoped change

Use [onboarding](onboarding.md) and [project structure](project-structure.md).
Existing components are not proof of checkpoint compatibility.
Run appropriate synthetic checks and `make check` before handoff.
