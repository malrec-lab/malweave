# Onboarding a Research Task

MalWeave separates data preparation, reusable components, and declared experiments. Read the
[research workstreams](workflows/research-workstreams.md) to identify which boundary a task owns;
do not make unrelated work wait for a linear gate.

## Start With the Task Boundary

Write one sentence stating the input, output, and research purpose. Then classify the task:

| Task type | Owns | Must not silently decide |
| --- | --- | --- |
| Data preparation | Corpus representations and private manifests | Model, split, or metric policy |
| Component | Reusable adapter, model, loss, metric, visualization, or utility | A result-specific dataset decision |
| Experiment | Configured combination of prepared data and components | Changes after observing benchmark results |

Raw PE files may be live malware. Never execute, preview, commit, upload, or redistribute them.
Use synthetic fixtures in all tests.

## Working Sequence

1. Read `AGENTS.md`, the relevant dataset card, and the focused existing test.
2. Define input/output and all reportable failure conditions.
3. Add or update a focused synthetic test alongside reusable code.
4. Put data transformations in `malweave/data/`, model code in `malweave/models/`, training loops
   in `malweave/training/`, and benchmark-specific policy in `malweave/experiments/`.
5. Add a CLI command only when the library interface and tests are clear.
6. For every run, use a committed non-sensitive config and write a resolved copy to its private
   artifact directory.
7. For a benchmark, freeze source/representation leakage groups and the split before fitting a
   tokenizer, normalizer, feature selector, sampler, or tuning policy.
8. Run focused tests, then `make check`; do not commit raw samples, private manifests, artifacts,
   or local paths.

## Repository Map

| Item | Location | Versioned? |
| --- | --- | --- |
| Dataset and experiment configs | `configs/` | Yes, if non-sensitive |
| Raw corpus and generated manifests | `data/raw/`, `data/interim/`, `data/processed/` | No |
| Data preparation | `malweave/data/` | Yes |
| Model architectures | `malweave/models/` | Yes |
| Training loops and artifacts | `malweave/training/` | Yes |
| Benchmark policy and split builders | `malweave/experiments/` | Yes |
| Regression tests | `tests/` mirroring source | Yes |
| Checkpoints, predictions, reports | private artifact root | No |

## Current Research Example

Follow the [PE/EXE data workflow](workflows/data-preparation.md). RanDS has been converted to EXE
and uploaded to S3. In the data workstream, implement SOREL/Assemblage adapters
with synthetic inputs and source-specific identity rules. In the component workstream, add MLM
and transfer smoke coverage to the existing Mamba/HRRFormer classifiers. The experiment workstream
then freezes overlap-controlled views, splits, tokenizer fit and label subsets under the
[research protocol](workflows/research-protocol.md).
