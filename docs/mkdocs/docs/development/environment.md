# Environment and Dependencies

MalWeave uses uv to make the Python environment repeatable across developer machines and CI. The package metadata remains reasonably broad for compatibility, while `uv.lock` records the exact resolved environment used by the project.

## Supported and Canonical Versions

| Component | Policy |
| --- | --- |
| uv | Exactly 0.11.9, enforced by `tool.uv.required-version` |
| Canonical Python | CPython 3.12.12, recorded in `.python-version` |
| Supported Python | 3.10 through 3.12, declared in `project.requires-python` |
| CI operating systems | Ubuntu, macOS, and Windows GitHub-hosted runners |
| CI compatibility | Python 3.10 on Ubuntu; CPython 3.12.12 on all three operating systems |
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

`make check` is the concise Unix/macOS entrypoint. Windows developers without `make` can run the
same non-mutating checks used by CI:

```powershell
uv lock --check
uv run --locked ruff check malweave tests
uv run --locked ruff format --check malweave tests
uv run --locked pytest -v
uv run --locked python -m mkdocs build --strict --config-file docs/mkdocs/mkdocs.yml
```

## Machine-Local Configuration

Copy `.env.example` to `.env` for paths that differ between machines. The MalWeave CLI loads the
root `.env` when a command starts, but does not override variables already supplied by the shell or
CI. Explicit CLI arguments such as `--root` have the highest precedence.

`.env` and other `.env.*` files are ignored because they may contain machine paths or credentials;
only the placeholder-only `.env.example` is versioned. Loading happens at CLI execution time, not
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
