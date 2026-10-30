# MalWeave

MalWeave studies malware language models inspired by LMLM, using RanDS for downstream
ransomware-versus-benign evaluation.

## Research directions

| Direction | Scope | Status |
| --- | --- | --- |
| [LMLM checkpoints](docs/mkdocs/docs/workflows/lmlm-checkpoints.md) | Use public pretrained LMLM checkpoints, fine-tune and evaluate on RanDS. | **Current priority; detailed design pending.** |
| [Self-pretraining](docs/mkdocs/docs/workflows/self-pretraining.md) | Prepare data following LMLM, pretrain a lightweight model, fine-tune and investigate promising extensions. | **Paused; existing work retained.** |

Start with the [research overview](docs/mkdocs/docs/workflows/research-protocol.md).
Checkpoint contents, tokenizer compatibility and the fine-tuning protocol have not been verified.
Existing scratch or conversion configs do not define the new experiment.

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
