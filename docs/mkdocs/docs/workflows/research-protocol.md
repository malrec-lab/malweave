# Research overview

## Current study

The paper design is owned and maintained outside this repository; this page maps the
study onto MalWeave's implementation. Audit evidence lives in the
[dataset catalog](../datasets/index.md), and the runnable audit commands in
[data preparation](data-preparation.md).

The proposed study compares a released Mini BiMamba checkpoint on a fixed prefix and
on the complete extracted EXE. It also considers a smaller Tiny student and knowledge
distillation. The four source audits are available in the [published S3 layout](../datasets/s3-layout.md). The final cohort, split, model
recipes and profiling gates are still open. MalWeave has no maintained training workflow
for the proposed full-EXE Mini/Tiny comparisons yet.

## Earlier workflows

| Workflow | Status |
| --- | --- |
| [LMLM checkpoints on RanDS](lmlm-checkpoints.md) | Earlier A/C/E1/E2 workflows and results. Their metadata round-02 cohort belongs to those runs. |
| [RanDS scratch baseline](rands-scratch.md) | Paused. Runs supervised EXE classification with random initialization and a RanDS-trained tokenizer. |

## Where information belongs

| Information | Maintained location |
| --- | --- |
| Research questions, experiment design and approvals | Maintained outside this repository |
| Dataset facts, storage and audit artifacts | [Dataset catalog](../datasets/index.md) and [S3 map](../datasets/s3-layout.md) |
| Runnable commands and environment | [Data preparation](data-preparation.md), the relevant workflow and [environment](../development/environment.md) |
| Existing code capabilities | [Project structure](../project-structure.md) |
| Measurements and per-run evidence | Private run artifacts, linked from the relevant docs |

Record verified facts, approved choices and proposals with their status. Existing code
and configuration describe capabilities. Research approvals belong in the study design.
