# MalConv RAW

This is an independent engineering experiment for testing an end-to-end RAW-byte path on RanDS.
It is deliberately separate from the LMLM-on-RanDS roadmap and does not claim to reproduce
*Beyond Raw Bytes* or its reported scores.

The YAML configuration contains only run settings. This page retains the safety, provenance,
leakage, and reporting rules that code should not silently choose.

## Scope

- Read immutable original PE bytes from the restricted S3 RAW prefix.
- Clean the snapshot metadata first: count missing or malformed identities/labels, duplicate rows,
  and conflicting labels for the same source SHA-256. Exclude sources without a valid identity or
  with conflicting labels; deduplicate by source SHA-256.
- Keep only metadata rows with `Arch=I386` and `Packed=0` (the RanDS metadata proxy for 32-bit x86
  and unpacked). Count exclusions by class and reason. These fields do not reproduce the paper's
  independent `file`/`diec` checks; report that methodological difference.
- Partition the remaining sources by metadata `Year` first: train through 2022, validation in
  2023, and test from 2024 onward. The default `full` preset deterministically selects the
  largest equal benign/ransomware count in **train only** (50/50, no fixed total).
  Validation and test retain every eligible available row at their original class ratios; a
  bounded balanced 1,000-sample pilot is selected deterministically by SHA-256 within each class
  and partition (targets: train 350+350, validation 75+75, test 75+75).
  Do not backfill a short partition using another year range; fail and report the shortage instead.
  Do not filter by filename extension or file size.
- Record each selected PE's static parse status for diagnostics and verify its source SHA-256 after
  fetch. A parse result alone does not filter a RAW model input; failed reads or digest mismatches
  are reported and excluded, never silently skipped.
- Use the first 1 MiB of each source. The byte adapter maps byte values `0..255` to model IDs
  `1..256`; batch padding uses ID `0` on the right.
- Train MalConvGCT as a binary classifier: benign `0`, ransomware `1`, only after frozen,
  group-disjoint splits exist.

No source PE, source hash, object key, restricted manifest, cache entry, checkpoint, or run output
may be committed to Git. The RAW source object is never modified, executed, previewed, or uploaded.

## Leakage rule

The training input is RAW and split groups use the restricted source SHA-256 manifest. Year ranges
must be disjoint and ordered: `max(train.Year) < min(validation.Year)` and
`max(validation.Year) < min(test.Year)`. RanDS `Year` is a first-submission year, not the precise
timestamps used by the paper; the cutoff years are a declared RanDS-specific choice. A missing
source digest or a group with conflicting labels is an exclusion, not a reason to weaken the split
rule. This prevents exact-source leakage only; it does not detect different PE files that contain
equivalent executable code.

## Results required before interpreting metrics

1. Aggregate cohort and exclusion report.
2. Frozen manifest digest and proof of group-disjoint, year-ordered splits and class counts.
3. Tiny-cohort overfit result.
4. One-epoch pilot: runtime, read/hash/validation failures, cache statistics, input-length summary,
   and class-wise metrics.
5. Repeat evaluation of the same predictions with identical results.

The committed experiment contract is `configs/experiments/malconv-raw.yaml`. The read-only
S3 inventory, release audit, reusable selection options, and example commands are described in
[S3 inventories and RAW manifests](s3-manifests.md). Inventory and freezing list metadata only;
staging on an isolated worker then downloads and verifies **every selected object** before training.
Use the `pilot` preset first. The `full` preset is a separate cohort and must not be inferred from
pilot results. Keep staged PE files, SQLite progress, reports, and model artifacts outside Git.

The cohort-selection salt remains unchanged after the experiment was renamed, so the already
frozen local RAW manifests keep exactly the same rows and ordering.

## Paired RAW/EXE cohort with balanced evaluation

This optional protocol replaces neither historical manifests nor historical results. It follows
the paper's 50/50 per-split class balance, but remains a RanDS adaptation (Year-based cutoffs,
EXE-byte rather than DEC-based exact deduplication, and optional early stopping). Balance does
not guarantee better accuracy, ROC-AUC, or checkpoint selection. It changes the evaluation
population; do not choose a sampling seed based on model scores.

`freeze-balanced-common` reads metadata only. It requires the audited EXE cohort to be a subset
of RAW with identical source/split/label/year/snapshot assignments. It validates both complete
input manifests before selection, including source and representation cross-split groups.
The input EXE manifest must already be representation-deduplicated. Training must already be
balanced and its source set is preserved. The command downsamples the majority class in each
evaluation split to that split's minority count, without moving years, duplicating samples,
fitting a tokenizer, or using prediction scores. RAW and EXE outputs use the same selected source
order and EXE leakage groups. This creates a conditional-on-EXE-availability benchmark, not an
estimate for every RanDS source.

The selection contract is `configs/datasets/rands-common-balanced.yaml`. To reproduce the local
metadata audit and freeze a **new** paired cohort:

```bash
uv run --locked malweave experiment freeze-balanced-common \
  --raw-manifest reports/runpod-reports/staged/raw-full-train-balanced/split-manifest.csv \
  --raw-audit reports/runpod-reports/staged/raw-full-train-balanced/manifest-summary.json \
  --exe-manifest reports/runpod-reports/staged/exe-full-train-balanced-dedup/split-manifest.csv \
  --exe-audit reports/runpod-reports/staged/exe-full-train-balanced-dedup/manifest-summary.json \
  --output-dir data/processed/rands/common-balanced-v1
```

For the current frozen input pair, the metadata audit yields:

| Split | Before: benign / ransomware | After: benign / ransomware | Removed |
| --- | ---: | ---: | ---: |
| Train | 17,925 / 17,925 | 17,925 / 17,925 | 0 |
| Validation | 1,005 / 5,183 | 1,005 / 1,005 | 4,178 ransomware |
| Test | 5,830 / 5,276 | 5,276 / 5,276 | 554 benign |

There are 48,412 selected sources. The command writes `raw-split.csv`, `exe-split.csv`, their
`*-summary.json` metadata audits, `cohort-summary.json`, and private `excluded.csv` (including
RAW-only exclusions). Reports retain input/config digests, counts and removal reasons. These
are **not staging certificates**. Do not edit an old staging report's counts or `passed` flag
to bypass byte verification. The older ad-hoc `scripts/make_common_cohort.py` generated a derived
report without these checks; use this CLI and the shared stager for the new balanced protocol.

On the isolated worker with the matching code, manifests and existing RAW/EXE caches, run:

```bash
uv run --locked malweave experiment stage-inputs \
  --experiment configs/experiments/malconv-raw.yaml \
  --manifest data/processed/rands/common-balanced-v1/raw-split.csv \
  --manifest-summary data/processed/rands/common-balanced-v1/raw-summary.json \
  --output-root work/staged/rands-common-balanced-v1/raw \
  --reuse-root work/staged/rands-malconv-raw/full-train-balanced

uv run --locked malweave experiment stage-inputs \
  --experiment configs/experiments/malconv-exe.yaml \
  --manifest data/processed/rands/common-balanced-v1/exe-split.csv \
  --manifest-summary data/processed/rands/common-balanced-v1/exe-summary.json \
  --output-root work/staged/rands-common-balanced-v1/exe \
  --reuse-root work/staged/rands-malconv-exe/full-train-balanced-dedup
```

Reuse verifies bytes and hardlinks valid cached files where supported; unavailable cached files
may be fetched from the configured S3 source. Keep a new state/output root and one writer per
root; use `--resume` only after an interrupted staging operation. Both staging reports must
pass before training. Pass the new `--split-manifest` and `--staging-report` explicitly to
`experiment train`; **do not use the old full preset**. Keep RAW/EXE run IDs separate and keep
the chosen one-epoch or 30-epoch/patience-5 training settings unchanged between paired runs.

Historical EXE early-stopping runs cannot serve as the matched balanced-validation baseline:
validation, checkpoint selection, threshold and possibly data order have changed. Retrain the
paired comparison, and evaluate test only after model/threshold selection on validation. Saved
one-epoch models can be rescored without retraining if only test membership changes and their
training order/protocol is otherwise accepted as fixed. Keep old results separate. Family
overlap is allowed and should be reported; balance does not prove unseen-family generalization.
The smaller benign evaluation pool also limits low-FPR precision, especially at FPR=1e-4.

## Frozen pilot settings

The first bounded feasibility run uses seed `42`, one epoch, an effective batch of up to 64 (one file per
forward pass and 64 gradient accumulation steps), AdamW with learning rate `0.001` and weight
decay `0.01`, a 5% learning-rate warmup, gradient clipping at `1.0`, and full-precision training
on `cuda:0`. The effective batch size and learning rate follow the paper's MalConv classification
settings; the one-file microbatch and accumulation factor are an engineering choice (the upstream
job generator specifies a 16-file microbatch and four accumulation steps). The MalConvGCT shape in
the YAML repeats the current implementation defaults so a future default change cannot silently
alter this run; in particular, `kernel_size: 256` is deliberately retained from the YAML and
differs from the upstream job generator's `64`. The one-epoch duration remains an engineering
pilot rather than the paper's five-epoch training. The temporal split targets 70/15/15 by class
within the 1,000-sample pilot. Unlike the paper's 25K/8K train/test dataset, this pilot reserves a
separate validation year for model selection; neither its sample counts nor its year cutoffs claim
to reproduce the paper.

The supervised runner accepts the frozen RAW-only split and reads only local, hash-verified
representations. It requires a passing staging report bound to that exact manifest before any
S3-origin split can train. Staging remains a distinct command, so an incomplete download cannot
silently become a smaller training cohort. For a config with one track, `train` reads the track,
device, seed, and gradient accumulation from YAML; `--preset pilot` selects its frozen split.
The worker still supplies its staging report, artifact root, and unique run ID. Changing the YAML
alone is not enough to switch to another labeled dataset: its adapter must produce an audited,
group-disjoint manifest with the same training schema and declared label mapping.
