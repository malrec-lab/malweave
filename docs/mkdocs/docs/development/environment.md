# Environment and Dependencies

## Supported Toolchain

| Component | Policy |
| --- | --- |
| uv | Exactly 0.11.9, enforced by `tool.uv.required-version` |
| Canonical Python | CPython 3.12.12, recorded in `.python-version` |
| Supported Python | 3.10 through 3.12 |
| Operating systems | Linux and macOS; Windows is unsupported |
| CI compatibility | Python 3.10 on Ubuntu; CPython 3.12.12 on Ubuntu and macOS |
| Training dependencies | PyTorch, Transformers and Tokenizers already in `train`, included by default through `dev` |
| GPU/native runtime | Validate driver/framework/precision and Mamba fast-kernel compatibility on the target machine; not established by CPU checks. |

`pyproject.toml` declares dependencies/ranges and groups; `uv.lock` pins the resolved packages.
`.python-version` chooses canonical Python. The Makefile and CI use the locked environment.

## Restore And Check

```bash
uv sync --locked
make check
make docs-serve
```

`--locked` refuses a stale lock. uv creates `.venv`; activation is optional. `make check` verifies
the lock, Ruff lint/format, pytest and strict MkDocs build. `make docs` builds without serving.
Do not bypass lock checks or install undeclared packages with pip.

## Local Storage Configuration

Configure raw/EXE, model and report storage for the target environment following
[data preparation](../workflows/data-preparation.md). RanDS EXE is stored on S3. The EXE-only
manifest/storage interface is an implementation task. `.env.example` includes raw RanDS settings
and optional Ghidra worker variables for the corresponding tools.

Copy the template only if `.env` is absent. The CLI loads root `.env` at command execution,
preserving exported shell/CI variables; explicit CLI roots override both. Library imports are
side-effect free. `.env` and machine paths/credentials stay outside Git.

`MALWEAVE_DATA_DIR`, `MALWEAVE_MODELS_DIR` and `MALWEAVE_REPORTS_DIR` relocate private artifact roots.
Raw RanDS operations use `MALWEAVE_RANDS_DIR` and, when separate, `MALWEAVE_RANDS_METADATA_DIR`.
These variables do not implement an S3 data loader. S3 references/credentials belong in private
storage records and the target environment, not committed configs.

## Dependency Groups

| Group | Purpose | Default |
| --- | --- | --- |
| `test` | pytest | Included by `dev` |
| `lint` | Ruff | Included by `dev` |
| `docs` | MkDocs/tooling | Included by `dev` |
| `train` | PyTorch, Transformers, Tokenizers | Included by `dev` |
| `dev` | Includes all four groups above | Yes |

Use the narrowest group when changing dependencies:

```bash
uv add <runtime-package>
uv add --group train <training-package>
uv add --group test <test-package>
uv add --group docs <documentation-package>
uv lock
uv sync --locked
make check
```

Commit/review `pyproject.toml` and `uv.lock` together. For a scoped upgrade use
`uv lock --upgrade-package <package>`. Avoid unrelated upgrades and scheduled dependency bots
unless requested. New dataset/model groups are useful only when their stacks warrant separation.

## Optional External Analysis Tools

The current EXE path uses the locked Python LIEF dependency. Ghidra/Java, `file` and Detect-It-Easy
are not installed by uv and are not blanket prerequisites for external-pretraining development.
Use `file`/DiE when an explicitly scoped architecture/packing annotation requires them; record
version, mode, timeout/error and unknown results independently from extraction.

Ghidra DIS/DEC is outside the research plan. The corresponding scripts and synthetic
`make e2e-ghidra` integration remain in the codebase. The current PE/EXE pipeline uses LIEF
and does not require Ghidra or Java.

## GPU Reproducibility

The Python lock does not lock GPU drivers or all native libraries. Record OS/architecture,
accelerator model/count, driver and CUDA/runtime, framework build/index, native kernels,
precision/determinism, peak memory and throughput. Define a canonical container/system lock when
needed. Validate Mamba native and fallback behavior on the selected runtime before a full run.

Keep CPU quality checks separate from GPU smoke/performance checks. State numerical tolerances;
exact equality across accelerators is not assumed.

## Troubleshooting

- Stale lock: review the intended declaration change, run `uv lock`, review and commit both files.
- uv version rejection: install 0.11.9 rather than weakening the version requirement.
- Moved checkout/invalid virtualenv script path: recreate the locked environment; Python module
  invocations can diagnose it without changing project dependencies.
- Python 3.10-only failure: resolve the regression or explicitly revise support and CI together.
- Data/schema question: consult [data preparation](../workflows/data-preparation.md) and the
  relevant dataset card before configuring a job.
