# Contributing to MalWeave

MalWeave treats environment changes as part of the research record. A pull request that changes a dependency, supported Python version, or execution tool must update the lockfile and relevant documentation in the same change.

## Canonical Environment

- Use uv 0.11.9; `pyproject.toml` rejects other uv versions.
- Use CPython 3.12.12 for normal development and canonical experiment setup.
- Keep code compatible with Python 3.10 through 3.12 on supported POSIX platforms. CI tests Python
  3.10 on Ubuntu and CPython 3.12.12 on Ubuntu and macOS; Windows is unsupported.
- Create the environment with `uv sync --locked`. Do not install project tools into `.venv` with `pip`, because that creates state not represented by `uv.lock`.
- Run `make check` before opening or updating a pull request.

## Dependency Changes

Choose the narrowest dependency scope:

| Scope | Command | Intended contents |
| --- | --- | --- |
| Runtime | `uv add <package>` | Packages required when importing or running MalWeave |
| Training | `uv add --group train <package>` | Model-training frameworks and training-only tools |
| Test | `uv add --group test <package>` | Test runners, fixtures, and test utilities |
| Lint | `uv add --group lint <package>` | Static analysis and formatting tools |
| Documentation | `uv add --group docs <package>` | Documentation build dependencies |

The `dev` group includes `test`, `lint`, and `docs`; it should normally contain group references rather than duplicate package declarations. Dataset- or model-specific groups may be introduced when they prevent large or incompatible stacks from being installed unnecessarily.

After changing a dependency:

```bash
uv lock
uv sync --locked
make check
```

Commit both `pyproject.toml` and `uv.lock`. Review transitive changes in `uv.lock`; do not accept a broad upgrade when only one package was intended to change. For a controlled update, use:

```bash
uv lock --upgrade-package <package>
```

Dependency updates are maintainer-initiated rather than scheduled automatically. Make each update
deliberate and narrowly scoped: review release notes, inspect the lock diff, and require all CI
checks to pass. Do not add dependency-update bots without explicit maintainer approval.

## Python and Accelerator Policy

Changing `.python-version`, `project.requires-python`, the CI matrix, or `tool.uv.required-version` is a compatibility decision and must be made together. Update the root README and environment guide in the same pull request.

The current lock covers a CPU-only foundation. When a GPU framework is added, record the supported OS, accelerator, driver, CUDA/runtime, framework, and precision combinations. Prefer a dedicated dependency group and provide a canonical container or system lock when Python locking alone cannot reproduce the native runtime.

## Code and Documentation Checks

The Make targets run tools from the locked environment:

```bash
make test
make lint
make format-check
make docs
make check
```

`make check` is non-mutating. Use `make format` when you intentionally want Ruff to fix lint and formatting issues, then inspect the diff and run `make check` again.

Update maintained guidance under `docs/mkdocs/docs/` when behavior or workflow changes. Build documentation strictly so broken links and navigation issues fail locally and in CI.

## Research and Malware Safety

Never commit raw samples, restricted metadata, credentials, private URLs, extracted malware features, checkpoints, or secrets. Use the configured external data/model/report directories when artifacts require isolation or access control. Tests must use synthetic, redistributable fixtures rather than real malware.
