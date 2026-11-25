# Self-pretraining with lightweight models

**Status:** paused. **Updated:** 2026-10-29.
See the [research overview](research-protocol.md) for the current study.

## Approved direction and retained work

Prepare data following LMLM, pretrain a lightweight model, fine-tune and investigate
promising extensions. The existing PE → EXE → byte mapping → BPE work remains relevant.
The earlier plan prioritized mini/bidirectional Mamba; no 16-layer reduction was approved.
Final training configuration is not frozen.

This page retains the earlier study design. The detailed label budgets, split ratios,
sampling, seeds and experiment matrix below are retained design proposals, not a newly
approved execution plan. Previously approved SOREL conversion rules remain in their
[protocol](sorel-protocol.md); pending decisions remain pending.

| Area | Last recorded state |
| --- | --- |
| RanDS | EXE conversion and S3 publication complete; duplicate/conflicting-label findings retained in execution notes. |
| SOREL v3.1 | 1,000 source outcomes published; continuation/image checks recorded on 2026-10-27. No full-corpus run established. |
| Conversion deployment | Runpod startup/SSH, registry and source revision preparation unfinished at handover; no specific host/cost approved. |
| Assemblage | A PE snapshot has been audited and converted to EXE. Use in self-pretraining remains paused. See the [dataset card](../datasets/assemblage.md). |
| Models and supervised training | Existing classifiers and resumable scratch runner; see [code capabilities](../project-structure.md#existing-code-capabilities). |
| MLM pretraining | End-to-end self-pretraining is unimplemented. The [earlier LMLM transfer study](lmlm-checkpoints.md) has a separate training path. |

The retained deployment preparation targeted Runpod with local SSD. Recheck host, cost,
tools and resources before resuming; historical measurements are not current rental estimates.
The [data workflow](data-preparation.md), [SOREL run guide](sorel-conversion.md) and
[conversion protocol](sorel-protocol.md) support this direction.

The researcher confirmed on 2026-10-29 that the [RanDS scratch workflow](rands-scratch.md)
remains a baseline within this direction: random weights and RanDS-training-only BPE.
It remains paused and cannot substitute for the shared-tokenizer comparison below.

Before implementing MLM, validate token-aligned states in both directions, reverse padding/alignment,
masked-position loss and backbone/tokenizer checkpoint round-trips using synthetic data.
Sequence-classifier tests alone do not establish these properties.

## Retained study design

- Pretrain random-token MLM on a registered subset of SOREL malware and Assemblage **Windows PE**.
  Assemblage is background software with build provenance, not AV-certified benign ground truth.
- Use PE code/executable-section bytes (EXE) with byte mapping and BPE. Keep complete EXE outputs;
  context truncation belongs to the model input policy, not extraction.
- Use bidirectional Mamba. The scratch baseline defaults to the paper-scale 32 layers per
  direction and hidden size 384; a reduced-depth 16-layer-per-direction setting is an
  unselected experiment option. Kernel availability is a deployment prerequisite.
- Compare externally pretrained and randomly initialized weights on RanDS with **10%, 25%, 100%**
  training labels. Ask whether transfer improves quality and reduces labels needed for that quality.

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

The [SOREL conversion protocol](sorel-protocol.md) defines the retained screening,
extraction and publication contract. Its verified i386/amd64 cohort extends LMLM's
x86-32 cohort; final unknown-ISA policy remains pending. Preserve RanDS's existing
complete extraction and express future cohort policy through manifests.

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

## Proposed base experiment

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

## Reproducibility

Each run retains resolved configuration, data/split/tokenizer digests, source revision, lock digest,
command, seeds, environment, checkpoints and predictions in private storage. Define EXE-only
pretraining and downstream configurations with the comparison settings above.

## Candidate extensions

The researcher chose to retain this shortlist on 2026-10-29.
These are candidates for this direction, not approved experiments or a priority order.
Choose a specific hypothesis and controls together before implementation.
Their novelty and effectiveness on RanDS remain unverified.

| Candidate | Question and essential constraint |
| --- | --- |
| [Span masking](https://aclanthology.org/2020.tacl-1.5/) | Does masking token spans improve on random-token MLM at matched compute? BPE spans are not instructions; masking alone is not full SpanBERT. |
| [BPE-Dropout](https://aclanthology.org/2020.acl-main.170/) | Does segmentation variation improve generalization? Preserve the same byte region, vocabulary and byte coverage; measure context inflation. |
| [R-Drop](https://proceedings.neurips.cc/paper_files/paper/2021/hash/5a66b9200f29ac3fa0ae244cc2a51b39-Abstract.html) / prediction consistency | Do dropout or segmentation views give more stable predictions? Verify actual stochasticity and account for additional passes. |
| [Contrastive learning](https://aclanthology.org/2021.emnlp-main.552/) | Do same-source or family-aware pairs improve representations? Control duplicates, false negatives and additional family supervision. |
| [DAPT/TAPT](https://aclanthology.org/2020.acl-main.740/) | Does continued self-supervision reduce domain mismatch? Use the allowed training pool only and a matched-compute control. |
| [LoRA](https://arxiv.org/abs/2106.09685) / QLoRA | Can adapters reduce adaptation cost? Validate Mamba kernel support and compare with full/head-only fine-tuning before adding quantization. |
| [Knowledge distillation](https://arxiv.org/abs/1503.02531) | Can a smaller student retain teacher quality? Count teacher cost and measure inference latency, memory and detection quality. |
| [Replaced-token detection](https://arxiv.org/abs/2003.10555) | Is an ELECTRA-style objective more efficient than MLM? Include generator compute and check replacement artifacts. |
| Semi-supervised consistency / pseudo-labeling | Can unlabeled training examples help with fewer labels? Control confirmation bias, class imbalance and equal access to the unlabeled pool. |

Changing the downstream dataset or combining established methods does not establish novelty.
No candidate is added to the current checkpoint evaluation protocol by this shortlist.
