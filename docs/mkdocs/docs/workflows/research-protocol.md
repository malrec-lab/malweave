# Research Protocol: External PE/EXE Pretraining

This is the active plan as of **2026-10-18**, not a completed experiment. MalWeave adapts LMLM
methods; RanDS measures ransomware-versus-benign detection, not general malware detection.

## Scope And Questions

- Pretrain random-token MLM on a registered subset of SOREL malware and Assemblage **Windows PE**.
  Assemblage is background software with build provenance, not AV-certified benign ground truth.
- Use PE code/executable-section bytes (EXE) with byte mapping and BPE. Keep complete EXE outputs;
  context truncation belongs to the model input policy, not extraction.
- Start with a small bidirectional Mamba; use HRRFormer if runtime feasibility requires it.
- Compare externally pretrained and randomly initialized weights on RanDS with **10%, 25%, 100%**
  training labels. Ask whether transfer improves quality and reduces labels needed for that quality.
- After the base comparison, prioritize span masking as one controlled extension. Novelty remains
  unestablished and needs a related-work review and experimental evidence.

## Stable Data Contracts

| Topic | Contract |
| --- | --- |
| Source identity | Retain dataset, snapshot, original identifier and digest of the bytes actually read. |
| EXE extraction | LIEF 0.15.1; concatenate raw section ranges with `CODE` or `EXECUTE` flags in section-table order; clip invalid ranges and record warnings. |
| RanDS | EXE is the downstream representation; retain source identity, labels/family, representation digest, extraction status and snapshot provenance. |
| SOREL | Preserve original ID separately from disarmed/released-byte digest and EXE digest; no raw benign is publicly released. Do not restore executable headers. |
| Assemblage | Match the Windows PE archive and metadata revision; retain repository/project and build identity. |
| Failure accounting | Missing, unreadable, malformed and non-extractable sources remain explicit; no silent replacement. |
| Representation groups | Identical EXE digests stay together; retain many-source-to-one-representation provenance. |

Architecture/packing annotation is separate from extraction. Audit x86-32/x86-64 and unknown
coverage across sources/classes before freezing cohorts. SOREL's modified `Machine` field makes
the same architecture filter across sources inappropriate; PE32/PE32+ alone does not prove the ISA.
RanDS architecture differs substantially by class, so report stratified coverage and performance.
Ghidra, DIS/DEC, CFG and dynamic views are deferred.

LMLM Section II-A filters x86-32 and removes packed/obfuscated binaries **before** extraction.
The SOREL implementation screens with DiE recursive/deep/heuristic modes and excludes positive
or incomplete results before producing EXE. Its initial `architecture_policy: annotate` measures
coverage on disarmed PEs; it is not a faithful x86-32 cohort. Decide the architecture/cohort policy
from architecture evidence before corpus conversion. Preserve RanDS's existing complete extraction and apply any
future cohort policy through manifests. Do not substitute SOREL vendor tag counts for DiE results.

## Freeze Before Training

1. Audit external-to-RanDS overlap using comparable original IDs and exact EXE digests; exclude
   external equivalents of the downstream corpus from the experiment's pretraining view. Preserve
   originals. Audit near duplicates where feasible; exact grouping does not prove absence of leakage.
2. Declare a policy for conflicting-label EXE groups; the current report has **73** such groups.
   Quarantining all conflicting groups is a candidate policy. Report affected samples and freeze
   the decision before training; never silently take a majority label.
3. Freeze a group-safe RanDS train/validation/test split (initial proposal **70/15/15**, subject to
   audit), plus external training/validation groups. Keep Assemblage project/build variants together.
4. Fit BPE on the external training partition only, after overlap removal. Use the same tokenizer
   for scratch and pretrained models. Scratch means random model weights; it still uses an
   externally learned tokenizer and must be described that way.
5. Select model size/context and pretraining scope through feasibility measurements; freeze config,
   seeds, sampling, mask policy, optimizer and tuning rules. A 1:1 token sampling ratio between
   external sources is an initial pilot choice, not a validated optimum.

## Base Experiment

Use nested, class-stratified **10% ⊂ 25% ⊂ 100%** subsets from the training partition. Group integrity
has priority over hitting an exact percentage; report realized source/group counts. Both methods
use identical subsets, tokenizer, validation/test data and checkpoint-selection rules, with a fair
tuning/convergence policy. Count validation labels separately in label-efficiency claims.

Start with one seed to validate the run, then target three downstream seeds for the main table:
**two initialization conditions × three budgets = six fine-tuning runs per seed**, plus pretraining.
One pretraining seed limits conclusions about pretraining variance; disclose that limitation.

Report F1, balanced accuracy, precision/recall and PR-AUC with ransomware as positive. Choose
thresholds on validation; report recall at a predefined FPR only when benign test support permits
a useful estimate. Include seed variation, runtime, peak memory and pretraining cost separately.
MLM loss alone does not demonstrate a better detector.

Family-held-out detection and ransomware-family classification are later tasks with distinct
protocols. Do not claim unseen-family exposure without auditing external pretraining as well.

## Reproducibility And Next Extension

Each run retains resolved configuration, data/split/tokenizer digests, source revision, lock digest,
command, seeds, environment, checkpoints and predictions in private storage. Define EXE-only
pretraining and downstream configurations with the comparison settings above.

Compare span masking against random-token MLM with the same backbone, corpus, mask rate and
compute budget. Byte/BPE spans are not instruction/function boundaries; implementing span masking
alone is not the full SpanBERT objective. Freeze the base path before adding another factor.
