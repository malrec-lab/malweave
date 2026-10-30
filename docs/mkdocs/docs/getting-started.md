# Getting started

## Read the plan

Start with the [research overview](workflows/research-protocol.md) and the
[LMLM checkpoint plan](workflows/lmlm-checkpoints.md), the current priority.
Its detailed design is pending; there is no validated checkpoint fine-tuning command yet.

The [self-pretraining direction](workflows/self-pretraining.md) is paused.
SOREL conversion and RanDS scratch guides document retained workflows, not immediate tasks.
Read the [RanDS card](datasets/rands.md) for downstream data facts.

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
