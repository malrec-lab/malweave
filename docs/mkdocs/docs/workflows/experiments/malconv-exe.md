# MalConvGCT EXE: full network staging and local pilot

EXE means executable-section **bytes already extracted from RAW**, not running an `.exe`.
No sections are extracted again. This workflow independently joins EXE objects and extraction
metadata to RanDS label metadata, then uses the same local/network stagers and trainer as RAW.
It does not read RAW manifests, RAW inventories, RAW samples or RAW staging reports.
Byte IDs, 1 MiB truncation, model, optimizer and temporal boundaries match RAW.
This is a RanDS feasibility extension, not a reproduction of the paper's original dataset.

## Cohort and leakage policy

- Full selects from all available, eligible EXE objects, independently of RAW experiments.
  Shared `Benign.csv`/`Ransomware.csv` provide labels, years, architecture and packing status.
- Train alone is downsampled deterministically to 50/50, **after EXE availability and dedup**.
  Validation/test retain all eligible source rows; they are not balanced or reassigned.
- EXE assigns its own splits from Year: train through 2022, validation 2023, test from 2024.
- Pilot starts with 1,000 source candidates using temporal allocation. Unlike the historical
  RAW balanced pilot, it does not balance evaluation. Final EXE count can be smaller after train
  balancing or missing/unsuccessful EXE exclusions. Full remains uncapped.
- Missing metadata, unsuccessful extraction and missing S3 objects are counted by split/class.
  EXE size, label or snapshot mismatches fail rather than being silently accepted.
- Same-source duplicates are rejected by the shared loader. Dedup groups eligible samples by
  full EXE representation SHA-256 before pilot sampling and train balancing. Conflicting-label
  groups are excluded entirely. For same-label groups, keep the earliest Year, breaking ties by
  lexicographically smallest source SHA-256. This removes same-split duplicates and later-split
  copies without moving any sample across years. S3 objects are never deleted or modified.
- The report records removal counts by reason/split/label; private `dedup-decisions.csv` in the
  metadata state directory records every excluded source and its retained representative, if any.
  If dedup empties a required split/class, publication fails rather than restoring duplicates.
  Test scores now describe representations unseen in earlier splits, not an unfiltered population.
- If EXE eligibility changes the cohort, RAW/EXE scores are not a paired comparison. A paired
  experiment would need a separately declared common cohort; these experiments are independent.

## 1. Prepare independent EXE S3 manifest: metadata only

```bash
uv run --locked malweave experiment prepare-rands-exe --experiment configs/experiments/malconv-exe.yaml --preset full
```

This automatically caches RanDS `Benign.csv`/`Ransomware.csv` (normalizing the release's header
issue), caches `rands/representations/exe/manifest.csv`, and uses the common resumable S3 inventory
to record object keys, ETags and sizes. It **does not GET any RAW or EXE sample**. The manifest
includes expected EXE SHA-256, local relative path, source identity, split and label.
Staging subsequently verifies the actual bytes against that expected digest. Metadata-only
release checks validate extraction counts, source identities, labels, snapshot and object layout.
The shared dataset config named `rands-raw-2026.yaml` supplies release metadata/schema/counts only;
its raw root environment variable is never resolved in this workflow.

`freeze-rands-exe` is an alias for this same command; do **not** run both commands as separate steps.
For pilot use `--preset pilot`. No `inventory-rands-s3` or `freeze-rands-raw` prerequisite exists.

For interrupted metadata preparation add `--resume`. State pins metadata digests, bucket, prefix,
filters, temporal ranges, size limit and output paths. On leakage/coverage failure inspect the summary;
no training manifest is published. Use new paths/state for a changed policy or snapshot.

Full output: `data/processed/rands/exe-s3/exe-train-balanced-full-dedup.csv`.
Pilot output: `data/processed/rands/exe-s3/exe-train-balanced-pilot-dedup.csv`.
Reports: `reports/rands/exe-s3/`. Metadata state:
`data/processed/rands/exe-s3/metadata-dedup/<preset>/`. Dedup policy is pinned in the resume
contract. Do not resume the previous fail-on-duplicates state with this new policy; old reports
and outputs remain intact under their original paths.

## 2a. Full: common Network Volume staging

Run on an authorized isolated worker, not a personal workstation. Sample bytes pass through RAM.
Configure the AWS source bucket and separate `RUNPOD_S3_*` destination credentials privately.

```bash
uv run --locked malweave experiment stage-network --experiment configs/experiments/malconv-exe.yaml --preset full --workers 4 --acknowledge-isolated-worker
```

Representation is inferred from YAML (`data.representation: exe`); no separate EXE uploader.
This uses bounded parallel transfer, durable per-source state, source/destination SHA-256 checks,
and metadata publication after success. Resume using the identical command plus `--resume`.
Only one worker may own a destination prefix.

Attach the volume to the GPU Pod at `/workspace`. Default full output root:

```text
/workspace/malweave/work/staged/rands-malconv-exe/full-train-balanced-dedup/
```

On the GPU Pod, after deploying matching code and installing the locked environment:

The two RanDS CSVs provide source SHA-256, label, Year, Arch, and Packed. The `.bin` object contains
the executable-section representation used by the model. `prepare-rands-exe` pins every download by
ETag, computes its representation SHA-256, writes it atomically, and publishes that digest in the
training manifest.

## 1. Inventory source metadata

Skip this command when the passing inventory already exists.

```bash
uv run --locked malweave data inventory-rands-s3 \
  --experiment configs/experiments/malconv-exe.yaml
```

This lists the source identities and joins `Benign.csv` and `Ransomware.csv`. It does not download
RAW PE bytes. Resume an interrupted listing with the same command plus `--resume`.

## 2. Freeze the 1,000-source temporal pilot

Skip this command when the frozen pilot and its passing report already exist.

```bash
uv run --locked malweave experiment freeze-rands-exe \
  --experiment configs/experiments/malconv-exe.yaml \
  --preset pilot
```

This freezes identities, labels, and splits for the EXE run; it does not stage or train RAW bytes. The balanced pilot assigns 700 sources to train, 150 to validation, and
150 to test using the declared year boundaries.

## 3. Stage EXE objects directly from S3

```bash
uv run --locked malweave experiment prepare-rands-exe \
  --experiment configs/experiments/malconv-exe.yaml \
  --preset pilot
```

The command reads the frozen source split, constructs keys under
`rands/representations/exe/<shard>/<source-sha256>.bin`, downloads those objects directly, and saves
durable per-source outcomes in `data/processed/rands/exe-s3/state/pilot.sqlite`.

For a bounded check, start with `--limit 10`. It intentionally reports an incomplete run without
publishing the training manifest. Continue it with:

```bash
uv run --locked malweave experiment prepare-rands-exe \
  --experiment configs/experiments/malconv-exe.yaml \
  --preset pilot \
  --resume
```

Output:

```text
data/processed/rands/exe-s3/representations/exe/<shard>/<source-sha256>.bin
data/processed/rands/exe-s3/state/pilot.sqlite
data/processed/rands/exe-s3/exe-pilot-1000-v2.csv
reports/rands/exe-s3/exe-pilot-1000-v2.json
```

The report accounts for S3 read failures by split, label, and status. Exact duplicates inside one
split retain every source row and share one representation group ID. Entire groups duplicated across
splits are excluded so equivalent EXE bytes cannot leak across train, validation, and test.
Cross-label duplicates prevent publication. Review `passed`, `published`, status counts, class
coverage, and duplicate counts before training. The published count may be below 1,000 when a
selected EXE object is unavailable or a cross-split group must be excluded.

## 4. Train MalConvGCT on EXE bytes

```bash
uv run --locked malweave experiment train \
  --experiment configs/experiments/malconv-exe.yaml \
  --split-manifest work/staged/rands-malconv-exe/full-train-balanced-dedup/split-manifest.csv \
  --staging-report work/staged/rands-malconv-exe/full-train-balanced-dedup/staging-summary.json \
  --run-id malconv-exe-full-001
```

## 2b. Pilot: common local staging

Local means disk on an approved isolated test worker, not downloading malware to a personal Mac.
Synthetic unit tests are safe on the development machine. After step 1 with `--preset pilot`:

```bash
uv run --locked malweave experiment stage-inputs --experiment configs/experiments/malconv-exe.yaml --preset pilot --workers 4
uv run --locked malweave experiment train --experiment configs/experiments/malconv-exe.yaml --preset pilot --run-id malconv-exe-pilot-001
```

The shared stage report resolves the EXE root automatically; no `--exe-root` is needed.
An intentional CPU check can use `--device cpu`. Keep a unique run ID for each run.

## Training and artifacts

Training reads only staged files and verifies each EXE digest on every read. MalConv uses byte IDs
`1..256`, pad `0`, no BPE, batch 1 with gradient accumulation 64, and one epoch.
Validation selects checkpoint/threshold; test is evaluated afterwards. Artifacts live in
`work/runs/rands-malconv-exe/<run-id>/`: `best.pt`, `metrics.json`, `test-predictions.csv`,
and `run-manifest.json`. Keep that directory on the mounted volume for persistence across Pods.

## Migration from the old EXE pilot CLI

`prepare-rands-exe` now prepares **metadata only**. Its former `--exe-root`, `--state-db`,
`--limit` and download-progress options are removed; use `--state-root` for metadata state and
the shared stagers for byte transfer. Old manifests/artifacts remain untouched.
The legacy Python `prepare_rands_exe_inputs` API remains for old callers but is not the current
CLI workflow. New outputs use `dedup` paths, separate from previous local pilot manifests.
The former `--source-manifest` and `--source-manifest-summary` options are removed.
Use `--metadata-root` only to supply a local directory with the two RanDS metadata CSVs.
