# MalWeave Agent Instructions

## Mission

- Build a beginner-friendly, reproducible research codebase for reproducing and extending
  malware language-modeling papers.
- Distinguish a faithful paper protocol from a dataset or methodology extension. Record every
  intentional divergence in configuration and maintained documentation.

## Safety

- Treat raw PE files as live malware. Never execute, upload, redistribute, preview, or open them
  with interactive applications.
- Read raw samples only when the task requires static inspection. Do not modify them in place.
- Never commit raw samples, sample hashes, sample inventories, private URLs, credentials,
  extracted representations, checkpoints, or run artifacts.
- Tests must use synthetic, redistributable fixtures. Do not copy real malware bytes into tests.
- Full-corpus processing requires a passing release audit, durable per-source progress, resumable
  output, and aggregate failure, runtime, output-size, and class-specific coverage reporting.

## Research Invariants

- Preserve source provenance and calculate deterministic digests for derived representations.
- Split data before fitting tokenizers, normalizers, feature selectors, resampling, or tuning.
- Prevent the same source or equivalent representation group from crossing data splits.
- Report missing, malformed, filtered, and failed samples; never silently discard them.
- Keep dataset-specific assumptions in committed config and dataset/workflow documentation.

## Implementation

- Put reusable data code in `malweave/data/` and focused tests in `tests/data/`.
- Use one documented Python CLI instead of adding dataset-specific shell entrypoints.
- Port RawByteClf behavior one small unit at a time. Add attribution and regression tests; do not
  copy broad utility modules or environment-specific orchestration wholesale.
- Use `uv` for dependencies and commands. Do not install undeclared packages with `pip`.
- Do not add scheduled dependency-update bots or repository automation without an explicit
  maintainer request.
- Keep imports and path resolution side-effect free. Do not create directories on package import.

## Required Checks

- Run focused tests while developing and `make check` before handing off changes.
- For data changes, review schema correctness, leakage risk, provenance, failure accounting, and
  safety before style or performance concerns.

## Task Routing

- Read `docs/mkdocs/docs/datasets/rands.md` before changing RanDS handling.
- Read `docs/mkdocs/docs/workflows/lmlm-rands.md` before changing the LMLM-on-RanDS workflow.
- Read `docs/mkdocs/docs/workflows/research-workstreams.md` before planning an LMLM-on-RanDS task.
  Keep data preparation, reusable components, and experiments independently scoped.
- Read `docs/mkdocs/docs/development/environment.md` before changing dependencies or supported
  Python/tool versions.
