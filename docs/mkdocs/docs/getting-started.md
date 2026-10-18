# Getting Started

## 1. Set Up The Environment

Install uv **0.11.9**, then run from the repository root:

```bash
uv sync --locked
make check
```

Canonical CPython is **3.12.12**; supported Python is 3.10–3.12 on Linux/macOS. Windows is
unsupported. uv creates `.venv`; Make uses the locked environment without shell activation.
Add dependencies through uv; see the [environment policy](development/environment.md).
Validate GPU/native Mamba compatibility on the target training runtime.

## 2. Read The Research And Data Plan

Start with the [research protocol](workflows/research-protocol.md),
[data preparation](workflows/data-preparation.md) and [workstreams](workflows/research-workstreams.md).

**RanDS has been converted to EXE and uploaded to S3.** The next data tasks are SOREL/Assemblage
adapters and pilots, followed by cross-source overlap checks and experiment-view preparation.
Read the [dataset cards](datasets/index.md) for source-specific schemas and identity rules.

Private data, metadata, inventories, EXE bytes and checkpoints stay outside Git. Configure
`MALWEAVE_DATA_DIR`, `MALWEAVE_MODELS_DIR` and `MALWEAVE_REPORTS_DIR` for the target storage layout.
Actual S3 locations/credentials belong in private configuration. An EXE-only storage/manifest
interface is part of the planned implementation; current CLI dataset adapters support RanDS.

If local configuration is needed, copy `.env.example` to `.env` only when `.env` does not exist.
The CLI loads it on execution; exported shell/CI values take precedence, then explicit CLI roots
take highest precedence. Synthetic component development needs no corpus mount.

## 3. Implement A Scoped Task

Use [model components](workflows/model-components.md), [onboarding](onboarding.md) and
[project structure](project-structure.md) for code placement and task boundaries.
Develop data adapters and MLM components alongside one another, then connect them through a
frozen experiment config. Run focused synthetic tests and `make check` before handoff.
