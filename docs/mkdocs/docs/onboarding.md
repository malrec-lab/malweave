# Onboarding a Research Task

Read the [research overview](workflows/research-protocol.md) for the current study
design and status. Use the MalWeave workflow guides for implementation and
operations.

## Start With the Task Boundary

Write one sentence stating the input, output, and research purpose. Then classify the task:

| Task type | Owns | Must not silently decide |
| --- | --- | --- |
| Data preparation | Corpus representations and private manifests | Model, split, or metric policy |
| Component | Reusable adapter, model, loss, metric, visualization, or utility | A result-specific dataset decision |
| Experiment | Configured combination of prepared data and components | Changes after observing benchmark results |

Treat raw PEs as data for static analysis. Use authorized private storage and synthetic test
fixtures. Keep samples, sample identities and derived representations outside Git.

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

## Research decisions and documentation

Use the relevant direction plan for verified findings, approved choices and pending proposals.
An implemented default is not a researcher decision. Discuss new scientific choices before
encoding them in experiment configs. Keep commands in workflow guides, measurements in
execution notes and code capabilities in project structure; link rather than duplicate them.
Do not create additional status/report pages for routine updates.

For the current study, review audit coverage and freeze the cohort and split under the
approved protocol before training. Record experiment decisions in the
researcher-maintained study records, not in this repository.
