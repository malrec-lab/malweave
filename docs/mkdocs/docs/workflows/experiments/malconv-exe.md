# MalConvGCT EXE Pilot

This workflow trains MalConvGCT on the EXE representations already stored in S3 at
`rands/representations/exe/`. It does not download RAW PE files and does not extract PE sections.
The existing RanDS metadata and frozen temporal split are reused only to select source identities,
labels, and train/validation/test assignments.

## S3 layout

```text
RanDS_PE_Dataset/Benign.csv
RanDS_PE_Dataset/Ransomware.csv
rands/representations/exe/manifest.csv
rands/representations/exe/<sha-prefix>/<source-sha256>.bin
```

The two RanDS CSVs provide source SHA-256, label, Year, Arch, and Packed. The `.bin` object contains
the executable-section representation used by the model. `prepare-rands-exe` pins every download by
ETag, computes its representation SHA-256, writes it atomically, and publishes that digest in the
training manifest.

## 1. Inventory source metadata

Skip this command when the passing inventory already exists.

```bash
uv run --locked malweave data inventory-rands-s3 \
  --experiment configs/experiments/malconv-raw.yaml
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
data/processed/rands/exe-s3/exe-pilot-1000.csv
reports/rands/exe-s3/exe-pilot-1000.json
```

The report accounts for S3 read failures by split, label, and status. Same-split exact duplicates are
reduced deterministically. Cross-label or cross-split representation duplicates prevent manifest
publication. Review `passed`, `published`, status counts, class coverage, and duplicate counts before
training. The published count may be below 1,000 when a selected EXE object is unavailable or an
exact duplicate is removed.

## 4. Train MalConvGCT on EXE bytes

```bash
uv run --locked malweave experiment train \
  --experiment configs/experiments/malconv-exe.yaml \
  --preset pilot \
  --exe-root data/processed/rands/exe-s3/representations \
  --run-id malconv-exe-pilot-001
```

The runner verifies every local representation SHA-256 on every read, maps byte values directly to
IDs `1..256`, pads with ID `0`, and keeps the first 1 MiB. It does not fit a tokenizer. Outputs are
written under `work/runs/rands-malconv-exe/<run-id>/`; use a new run ID for every run.

`prepare-rands-exe` supports `--source-manifest`, `--source-manifest-summary`, `--bucket-env`,
`--exe-root`, `--state-db`, `--manifest`, `--summary`, `--progress-every`, `--limit`, and `--resume`
for controlled or non-default deployments.
