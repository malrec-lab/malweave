# LMLM checkpoints on RanDS

**Status:** current priority. **Updated:** 2026-10-28.

## Approved scope

Use public pretrained LMLM checkpoints, fine-tune and evaluate on RanDS.
Detailed experiment design will be agreed with the researcher after cleanup.
Self-pretraining and further SOREL conversion are not prerequisites for investigating
the released checkpoints.

## Evidence available so far

- The researcher reports finding a public LMLM `upload-to-drive` source that appears
  to contain pretrained checkpoints. Its exact location and contents have not been
  inspected in this workspace; checkpoint availability and identity remain unverified.
- RanDS EXE conversion and S3 publication are recorded in the existing data notes.
  The [RanDS card](../datasets/rands.md) describes the release and schema issues.
- Existing classifiers and supervised runners are catalogued in
  [project structure](../project-structure.md). Their compatibility with released
  LMLM checkpoints has not been established.

## Questions to resolve together

| Topic | Pending information or decision |
| --- | --- |
| Source artifacts | Exact source URL/revision, artifact inventory, provenance, usage conditions and digests. |
| Model | Which architectures and checkpoints are available; which to evaluate. |
| Inputs | Associated tokenizer, vocabulary, special tokens, representation and context policy; compatibility with existing RanDS EXE. |
| Weight loading | Original model/config/code versions, backbone/head mapping and a verified loading path. |
| RanDS protocol | Eligible cohort, duplicate/conflicting-label policy and train/validation/test separation. |
| Evaluation | Comparisons, metrics, threshold selection, seeds and acceptance criteria. |
| Training and resources | Fine-tuning method, schedule, target runtime and measured feasibility/cost. |
| Exposure limitations | What is known about pretraining data and possible RanDS overlap; what cannot be verified. |

These are discussion topics, not an approved execution sequence or experiment matrix.
Do not assume a model, reuse the scratch tokenizer, or inherit its five-epoch schedule,
split ratios, label budgets or GPU choice. Preserve the released model/tokenizer pairing
when investigating compatibility. No checkpoint-specific download/training commands
or deployment config have been validated.
