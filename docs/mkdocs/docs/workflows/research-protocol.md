# Research directions

**Updated:** 2026-10-29.

MalWeave retains two directions. The researcher has approved their scope and priority;
detailed design for the checkpoint direction will be discussed after documentation cleanup.

| Direction | Purpose | Status and detailed plan |
| --- | --- | --- |
| LMLM checkpoints | Use public pretrained LMLM models, fine-tune and evaluate on RanDS. | **Current priority.** [Checkpoint plan](lmlm-checkpoints.md). |
| Self-pretraining | Prepare data following LMLM, pretrain a lightweight model, fine-tune and investigate promising extensions. | **Paused.** [Self-pretraining plan](self-pretraining.md). |

RanDS evaluation concerns ransomware versus benign detection. Using RanDS is an adaptation
of LMLM; it does not by itself reproduce the paper's full experiment suite.

## Decision status

- **Verified:** a fact supported by inspected source, artifacts or recorded measurements.
  Historical measurements retain their dates and limitations.
- **Approved:** a research choice explicitly agreed with the researcher.
- **Proposed / pending:** a candidate, unresolved question or unverified claim.

A working implementation or an existing config is not approval for an experiment.
Earlier self-pretraining settings do not automatically apply to checkpoint fine-tuning.
SOREL conversion, self-pretraining, independent scratch training and related deployment
work are paused. The researcher confirmed retaining RanDS scratch as a baseline within
self-pretraining and keeping a short list of candidate extensions on 2026-10-29.
Their detailed roles belong to the [self-pretraining plan](self-pretraining.md).
Remove obsolete documentation; ask about unclear relevance instead of preserving an archive.

## Where information belongs

| Information | Maintained location |
| --- | --- |
| Direction priority and shared decision rules | This overview |
| Scientific design and open questions | The corresponding direction plan |
| Dataset facts and known schema issues | [Dataset cards](../datasets/index.md) |
| Actual commands and environment requirements | The relevant workflow guide and [environment](../development/environment.md) |
| Existing code capabilities | [Project structure](../project-structure.md) |
| Measurements, failures and evidence | Research workspace execution notes and private run artifacts |

The research workspace's `research-notes/lmlm/overview.md` is a reading index.
Its data notes retain RanDS/SOREL results; they are not another active experiment plan.
New checkpoint findings should be recorded only after inspection. No checkpoint run guide
or experiment config is established yet.
