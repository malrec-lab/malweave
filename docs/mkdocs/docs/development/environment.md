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

## Retained SOREL conversion worker — paused

This worker belongs to the [paused self-pretraining direction](../workflows/self-pretraining.md).
The current priority is [LMLM checkpoints on RanDS](../workflows/lmlm-checkpoints.md);
its exact model/runtime requirements remain unverified. Do not use the conversion image
as an assumed checkpoint-training environment.

If conversion resumes, no GPU or training packages are needed. The base environment is:

```bash
uv sync --locked --no-default-groups
uv run --locked --no-default-groups malweave data sorel-setup
```

Keep `--no-default-groups` on subsequent conversion commands so uv does not install the
default dev/train groups. The data CLI imports model code only for training commands.
System `file`, curl, AWS CLI and portable DiE remain separate prerequisites; see
the [SOREL run guide](../workflows/sorel-conversion.md).

## Local Storage Configuration

Configure raw/EXE, model and report storage for the target environment following
[data preparation](../workflows/data-preparation.md). RanDS EXE is stored on S3. The EXE-only
manifest/storage interface is available for the independent
[scratch baseline](../workflows/rands-scratch.md). `.env.example` includes raw RanDS settings
and optional Ghidra worker variables for the corresponding tools.

Copy the template only if `.env` is absent. The CLI loads root `.env` at command execution,
preserving exported shell/CI variables; explicit CLI roots override both. Library imports are
side-effect free. `.env` and machine paths/credentials stay outside Git.

Shared path constants use `MALWEAVE_DATA_DIR`, `MALWEAVE_MODELS_DIR` and
`MALWEAVE_REPORTS_DIR` from the process environment. CLI-specific path options take
precedence. **SOREL currently defaults to repository-local paths:** pass
`--metadata` and `--job-dir` explicitly for a mounted volume; `sorel-setup` still
writes metadata under the repository. Do not assume `MALWEAVE_DATA_DIR` relocates
the SOREL CLI.
Raw RanDS operations use `MALWEAVE_RANDS_DIR` and, when separate, `MALWEAVE_RANDS_METADATA_DIR`.
The retained, paused scratch commands use `MALWEAVE_RANDS_EXE_S3_PREFIX`,
`MALWEAVE_RANDS_METADATA_S3_PREFIX` and optional `MALWEAVE_RANDS_TRAIN_S3_PREFIX`.
S3 references/credentials belong in private
storage records and the target environment, not committed configs.

## Dependency Groups

| Group | Purpose | Default |
| --- | --- | --- |
| `test` | pytest | Included by `dev` |
| `lint` | Ruff | Included by `dev` |
| `docs` | MkDocs/tooling | Included by `dev` |
| `train` | PyTorch, Transformers, Tokenizers | Included by `dev` |
| `gpu` | `train` plus official Mamba 2.2.4 / causal-conv1d 1.5.0.post8 CUDA wheels; Linux x86_64, Python 3.12, Torch 2.6 ABI | No |
| `dev` | Includes test/lint/docs/train; excludes native GPU wheels | Yes |

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

`malweave data setup-ghidra` provides an opt-in, checksum-verified native Ghidra/JDK
cache; `malweave data pilot-ghidra` adds the existing synthetic DIS/DEC/resume check.
See [the reusable CPU workflow](../workflows/data-preparation.md#reusable-ghidra-setup-and-synthetic-cpu-pilot).
It installs no Python packages outside the uv lock, changes no system Java or shell
profile, and does not install DiE. Tool pins remain Ghidra 11.2.1 / JDK 21.0.13+9.

The current EXE path uses the locked Python LIEF dependency. Ghidra/Java, `file` and Detect-It-Easy
are not installed by uv and are not blanket prerequisites for external-pretraining development.
Use `file`/DiE when an explicitly scoped architecture/packing annotation requires them; record
version, mode, timeout/error and unknown results independently from extraction.

RanDS DIS/DEC extraction is approved as a separate preparation task; see the
[data workflow](../workflows/data-preparation.md#streaming-rands-ghidra-disdec).
The scripts and synthetic `make e2e-ghidra` integration remain available. Ghidra/Java
compatibility and the approved 16-worker schedule were measured in the bounded
2026-11-02 pilot; the research workspace's data-preparation execution notes record
results and limits. Full-corpus runtime, failure handling and storage still need review.
The EXE pipeline uses LIEF and does not require Ghidra or Java.

The local 2026-11-02 installation uses Ghidra 11.2.1 and Temurin JDK
21.0.13+9 under ignored `data/external/tools/`. Both archives matched their
official published SHA-256 values. Synthetic verification passed through the
streaming runner for both DIS and DEC. Java runtimes without `bin/javac` are
rejected before acquisition. The system Java installation is independent.
Use these runtime roots for this installation (or the private `.env` settings):

```bash
export GHIDRA_ROOT="$PWD/data/external/tools/ghidra_11.2.1_PUBLIC"
export JAVA_HOME="$PWD/data/external/tools/jdk-21.0.13+9"
```

## GPU Reproducibility

### Retained Local Operator Setup Notes

The researcher requested that documentation survive the 2026-11-12 branch switch while discarding
the corresponding uncommitted code/configuration. The following describes that discarded tooling,
**not commands supported by this branch**:

- `bash scripts/setup-ghidra-worker.sh --analysis-only` had installed pinned uv/Python and data-only
  dependencies plus JDK/Ghidra/DiE, with synthetic verification, without sudo or `.env` edits.
- `data install-analysis-tools --verify` had managed Ghidra 11.2.1, DiE 3.21 and portable Temurin JDK
  21 for macOS ARM64/Intel and Linux x86_64. Pins were in `configs/tools/analysis-tools.yaml`;
  the file and installer implementation were discarded. It did not install system packages or
  execute package scripts. A tool JSON selected the managed JDK instead of arbitrary system Java.
- `data verify-analysis-tools --tools-file ...` had exercised synthetic DIS/DEC and three DiE modes;
  checking archive hashes was not considered sufficient runtime verification.
- The discarded S3 rolling worker used standard AWS credentials through boto3, not Runpod volume
  keys, and was not a parser sandbox. Data-only startup avoided importing/downloading the training
  stack; actual training still required the training dependency group.

See the [retained rolling-worker notes](../workflows/ghidra-s3-rolling.md) for historical layout
and pilot details. For the **current** supported commands, follow
[data preparation](../workflows/data-preparation.md). Private originals of the local documentation
were also preserved outside Git under `work/branch-switch/`.

### Current GPU Runtime

The Python lock does not lock GPU drivers or all native libraries. Record OS/architecture,
accelerator model/count, driver and CUDA/runtime, framework build/index, native kernels,
precision/determinism, peak memory and throughput. Define a canonical container/system lock when
needed. Validate Mamba native and fallback behavior on the selected runtime before a full run.

The optional `gpu` group pins official CUDA-12/Torch-2.6, CXX11-ABI-false wheels for
CPython 3.12 on Linux x86_64. Restore it on the worker with
`uv sync --locked --python 3.12.12 --no-default-groups --group gpu`.
Their download URLs and lock hashes are verified. On 2026-11-01 they passed native
BF16 full fine-tuning at 65,536 synthetic tokens per file on A100 SXM4 80 GB,
microbatch 8 with accumulation 8; microbatch 16 exceeded VRAM. Native BF16 requires
compute capability 8.0 or newer. These measurements apply to the checkpoint C runtime;
see the [checkpoint workflow](../workflows/lmlm-checkpoints.md) for scope and limits.

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
