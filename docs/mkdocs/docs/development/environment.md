# Environment and Dependencies

MalWeave uses uv to make the Python environment repeatable across developer machines and CI. The package metadata remains reasonably broad for compatibility, while `uv.lock` records the exact resolved environment used by the project.

## Supported and Canonical Versions

| Component | Policy |
| --- | --- |
| uv | Exactly 0.11.9, enforced by `tool.uv.required-version` |
| Canonical Python | CPython 3.12.12, recorded in `.python-version` |
| Supported Python | 3.10 through 3.12, declared in `project.requires-python` |
| Supported operating systems | Linux and macOS only; Windows is unsupported |
| CI compatibility | Python 3.10 on Ubuntu; CPython 3.12.12 on Ubuntu and macOS |
| Accelerator runtime | CPU-only foundation; CUDA/framework matrix will be defined with the first GPU stack |

The canonical version is the default for development and experiments. The minimum-version CI job catches accidental use of newer Python syntax or APIs.

## Files and Responsibilities

| File | Responsibility |
| --- | --- |
| `pyproject.toml` | Abstract package requirements, supported Python range, dependency groups, and tool configuration |
| `uv.lock` | Exact package versions, sources, hashes, markers, and transitive dependencies |
| `.python-version` | Exact default interpreter selected by uv |
| `Makefile` | Stable project commands that always execute through the locked environment |
| `.github/workflows/quality.yml` | Tests compatibility on the minimum and canonical Python versions |
| `.github/workflows/docs.yml` | Builds documentation with the canonical locked environment |

## Create or Restore the Environment

From the repository root:

```bash
uv sync --locked
make check
```

`--locked` makes setup fail if `pyproject.toml` and `uv.lock` disagree instead of silently resolving a different environment. uv creates `.venv` automatically and can install the interpreter recorded in `.python-version` when managed Python downloads are enabled.

Run commands without activating the environment:

```bash
uv run --locked python --version
uv run --locked pytest
```

`make check` is the supported local quality entrypoint on Linux and macOS. The CLI, shell worker
scripts, and Ghidra process cleanup are not supported on Windows.

## Machine-Local Configuration

Copy `.env.example` to `.env` for the default single-worker layout. It keeps the corpus, outputs,
state, work, and shard plan under the checkout's ignored `data/` directory, while Ghidra remains in
`~/ghidra`. Change entries only when this worker uses different mounted corpus or fast-disk paths.
The bootstrap creates this `.env` automatically when it is absent. The MalWeave CLI loads the root
`.env` when a command starts, but does not override variables already supplied by the shell or CI.
Explicit CLI arguments such as `--root` have the highest precedence.

`.env` and other `.env.*` files are ignored because they may contain machine paths or credentials;
only the safe default `.env.example` is versioned. Loading happens at CLI execution time, not
when the `malweave` package is imported, so library imports remain side-effect free.

## Dependency Groups

| Group | Purpose | Installed by default |
| --- | --- | --- |
| `test` | pytest and test-only utilities | Through `dev` |
| `lint` | Ruff and static quality tools | Through `dev` |
| `docs` | MkDocs and documentation tooling | Through `dev` |
| `train` | Model-training dependencies: PyTorch, Transformers, and Tokenizers | Through `dev` |
| `dev` | Includes `test`, `lint`, `docs`, and `train` | Yes |

The `train` group is the Python-level contract for supervised model experiments. CUDA drivers and
Mamba native fast kernels are system-specific prerequisites and must be verified in the target run
environment. Introduce dataset- or
model-specific groups only when their dependency stacks are large, optional, or mutually incompatible.

## External Analysis Tools

`uv sync --locked` installs only Python dependencies. It does not install Ghidra, Java, the raw
corpus, or optional PE assessment tools. Keep these outside the repository and record their exact
versions in the private run record. `scripts/setup-ghidra-worker.sh` is an opt-in worker bootstrap
for the JDK and Ghidra archive; it does not alter `uv.lock`, handle raw samples, or install DiE.

| Tool | Required for | Installation contract |
| --- | --- | --- |
| A JDK supported by the selected Ghidra release | DIS/DEC extraction | Install at the system level and verify with `java -version`. |
| Ghidra release archive | DIS/DEC extraction | Download and extract the official release, or use the opt-in worker bootstrap with a recorded archive checksum. |
| `file` | Optional PE assessment; not needed for metadata-selected RanDS Ghidra | macOS normally includes it; Linux distributions provide it through their system package manager. |
| Detect-It-Easy `diec` | Optional PE assessment; not needed for metadata-selected RanDS Ghidra | Install the matching standalone release yourself; it is not a Python dependency and MalWeave does not download it. |
| Isolated raw corpus storage | Any raw PE operation | Configure `MALWEAVE_RANDS_DIR` and, when separate, `MALWEAVE_RANDS_METADATA_DIR`; never place raw files in Git. |

### Install And Verify Ghidra

Use the official Ghidra release and the JDK version required by that release. Extract Ghidra outside
the repository, then set a shell-local path. The launcher path is platform-specific:

```bash
# macOS or Linux; replace this with the extracted release directory.
GHIDRA_ROOT=/absolute/path/to/ghidra_<version>_PUBLIC
export GHIDRA_ROOT
java -version
test -x "$GHIDRA_ROOT/support/analyzeHeadless"
"$GHIDRA_ROOT/support/analyzeHeadless" -help
```

On macOS, when the installation root is unknown, search common installation locations and derive it
from the launcher rather than leaving `GHIDRA_ROOT` empty:

```bash
GHIDRA_LAUNCHER="$(find /Applications "$HOME/ghidra" "$HOME/Downloads" \
  -type f -path '*/support/analyzeHeadless' -perm -111 -print -quit 2>/dev/null)"
test -n "$GHIDRA_LAUNCHER" || { echo "Ghidra analyzeHeadless was not found" >&2; exit 1; }
export GHIDRA_ROOT="${GHIDRA_LAUNCHER%/support/analyzeHeadless}"
echo "$GHIDRA_ROOT"
test -x "$GHIDRA_ROOT/support/analyzeHeadless"
```

Before a full job, run a ten-source pilot with `--workers 1`. The MalWeave state database records
the selected launcher path and digest, script digest, cohort, timeouts, and output digests. A
launcher or script change therefore requires a new state database rather than silently continuing
an incompatible job. See [RanDS data preparation](../workflows/lmlm-rands.md#extract-dis-and-dec-with-ghidra)
for the pilot and full extraction commands.

### Clean Linux Ghidra E2E

Before provisioning a training worker, run the clean-container smoke test from the repository
root (Docker Compose and internet access for the official Ghidra archive are required):

```bash
make e2e-ghidra
```

The service runs the production `scripts/setup-ghidra-worker.sh` in a fresh Ubuntu image, including
JDK, the pinned `uv` version, locked Python environment, and real Ghidra. It then generates three
private minimal PE32 files with only `NOP`/`RET` instructions and performs EXE plus unified
DIS+DEC extraction. No real corpus, representation, state database, or downloaded Ghidra archive
is written into the checkout. One record is assigned the `ransomware` metadata label only to meet
the loader's two-CSV contract; it is still a synthetic harmless file, never malware.

To remove the stopped test container and its temporary Compose network afterward:

```bash
docker compose -f docker-compose.e2e.yml down
```

## Add or Change Dependencies

Use uv rather than editing an active environment with pip:

```bash
uv add <runtime-package>
uv add --group train <training-package>
uv add --group test <test-package>
uv add --group lint <lint-package>
uv add --group docs <documentation-package>
```

These commands update `pyproject.toml` and `uv.lock` together. For a deliberate upgrade of one package:

```bash
uv lock --upgrade-package <package>
uv sync --locked
make check
```

Review and commit both dependency files. A lock diff may include related transitive packages, but
unrelated broad upgrades should be avoided. Dependency updates are maintainer-initiated and scoped
to a specific need; scheduled update bots are not enabled. Every update must remain visible,
reviewable, and validated by CI.

## CI and Lock Enforcement

The quality workflow installs uv 0.11.9, installs the matrix Python version, synchronizes with `uv sync --locked --python <version>`, and runs pytest plus Ruff lint/format checks with that interpreter selected explicitly. The documentation workflow uses CPython 3.12.12 and installs only the locked documentation group.

Locally, `make lock-check` verifies that dependency declarations and the lock agree. `make check` runs this validation plus lint, formatting, tests, and the strict documentation build.

## GPU and Native Dependencies

`uv.lock` reproduces Python packages but cannot by itself lock GPU drivers, kernel behavior, or all native system libraries. Before adding GPU training, define and document:

- operating system and architecture;
- accelerator model class and count;
- driver and CUDA/runtime versions;
- framework build and package index;
- precision and deterministic-algorithm policy;
- a canonical container or system-level lock when needed.

Keep CPU quality checks fast and separate expensive GPU smoke/integration jobs. Exact numerical equality across GPU models may not be achievable, so experiment records must state the expected reproducibility tolerance.

## Troubleshooting

- If `uv sync --locked` reports that the lock is stale, do not bypass it with `--no-lock`. Confirm the intended `pyproject.toml` change, run `uv lock`, review the diff, and commit both files.
- If uv rejects its own version, install uv 0.11.9 rather than weakening `required-version` locally.
- If a package fails only on Python 3.10, treat it as a compatibility regression or deliberately change the supported range and CI matrix through review.
- If an environment was modified manually, run `uv sync --locked` to restore it to the committed state.
