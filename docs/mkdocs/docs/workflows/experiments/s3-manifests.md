# S3 inventories and RAW manifests

The code has three layers under `malweave/data/s3/`:

| Layer | Responsibility | Reuse |
| --- | --- | --- |
| `client.py`, `inventory.py` | Generic listing, bounded explicit object reads with provenance, and resumable **unlabeled** inventories. Inventory listing never reads sample bytes. | Reuse unchanged for another S3 folder. |
| `rands_metadata.py` | Fetch only the named RanDS CSVs; schema-validate and cache an immutable metadata snapshot. | Used by RanDS S3 inventory; no PE downloads. |
| `rands.py` | Join the RanDS metadata snapshot to S3 objects, validate its key layout and expected release counts, and report availability by class. Its candidate CSV deliberately includes missing objects. | Replace this adapter for another dataset. |
| `manifest.py` | Filter labeled rows and select full, balanced, proportional-total, or explicit class-count cohorts deterministically within existing splits. | Reuse unchanged from another dataset adapter. |

`malweave/experiments/rands_raw_manifest.py` supplies the RanDS-specific year split and RAW
experiment policy. A different folder alone can use `inventory-s3`; a different *labeled dataset*
needs a small adapter defining identity, labels, eligibility, split, and an appropriate source audit.
An S3 key name is not a trustworthy label. Keep private inventories and manifests in ignored
`data/interim/` or `data/processed/`, and aggregate reports in ignored `reports/`.

## RanDS example

Set `MALWEAVE_RANDS_S3_BUCKET` in your local environment. The bucket value, credentials, source
identities, and generated manifests must not be committed. Configure AWS read credentials through
the standard provider chain or a private `.env`; prefer temporary credentials scoped to the two
metadata CSVs and selected dataset prefix. Listing requires `s3:ListBucket`, downloads require
`s3:GetObject` (and `s3:GetObjectVersion` for versioned metadata); SSE-KMS objects may additionally
require KMS decryption access. Never reuse credentials exposed in chat or logs.

On a new worker, the CLI reads defaults from `configs/experiments/malconv-raw.yaml`:

```sh
uv run --locked malweave data inventory-rands-s3
```

It fetches `RanDS_PE_Dataset/Benign.csv` and `RanDS_PE_Dataset/Ransomware.csv`, validates them
using the release-aware RanDS loader, and publishes the complete pair under
`data/processed/rands/raw-s3/metadata/`. A private `provenance.json` records source keys,
ETags/version IDs, sizes, and SHA-256 digests. Downloads are HEAD-pinned, bounded to 128 MiB per
CSV, and never fetch PE samples. Subsequent runs verify and reuse this frozen cache without
silently refreshing it. A partial download is discarded; a changed cache or source is rejected.
To use a different snapshot, choose fresh cache, state, manifest, and report paths.

`data.inventory` declares the metadata prefix/cache, scan state, and filter protocol;
`data.raw_prefix` and `data.manifest_inputs` declare the sample prefix and inventory outputs.
Use `--experiment` to select another YAML. Existing options still override YAML defaults.
Use `--metadata-root /private/path/to/csvs` to bypass downloads with an existing local pair;
do not combine it with `--metadata-prefix` or `--metadata-cache`.

After an interrupted scan with an existing SQLite state, rerun with the **same arguments** plus
`--resume`. If interrupted during metadata download before the state exists, rerun without it.
Each completed page
and its continuation token are committed together. The RanDS adapter writes the private manifest
only after the expected release counts and class availability pass its aggregate audit. It checks
S3 keys and sizes against metadata, not PE content hashes or PE parseability. S3 version IDs are
not frozen by this listing; training must verify downloaded bytes and use immutable/versioned
source objects in an isolated environment.

The MalConv RAW YAML supplies the inventory path, audit-report path, output paths, and two named
presets. The default keeps **all available** `I386`, `Packed=0` rows within the declared year
ranges. `--preset pilot` creates an optional balanced 1,000-sample cohort; split allocations are
70/15/15 *within each class*, so each split remains class-balanced. These are separate frozen
manifests:

```sh
uv run malweave experiment freeze-rands-raw
uv run malweave experiment freeze-rands-raw --preset pilot
```

`raw-metadata-candidates.csv` has every metadata-eligible `I386`, `Packed=0` source, including
those with `availability=missing` or `size_mismatch`; it is an audit input, **not** a training
manifest. The default writes every **available** candidate to
`raw-all-available-split.csv` (with a corresponding JSON report). The word "all" refers only to
the metadata-eligible, S3-available cohort, not the entire RanDS release. No file-content hash
has been checked by these commands.

The paths are project-relative in `configs/experiments/malconv-raw.yaml` and can be overridden
with `--inventory`, `--inventory-summary`, `--manifest`, or `--summary`. Existing outputs are
never overwritten. Private artifacts on one machine are not transferred by Git clone. Create
them with these commands on a new worker, or transfer the matching audited artifacts privately.
Use fresh output paths if you want another manifest.

For a custom cohort, omit `--preset`, give new `--manifest` and `--summary` paths, then use
`--total N`, `--balanced`, repeatable `--label-count LABEL=N`, repeatable
`--where COLUMN=VALUE`, `--min-year`, `--max-year`, or `--seed` as needed. `--balanced` without
`--total` keeps the largest equal class count in each split; `--total N` alone allocates by the
eligible class proportions. `--label-count` cannot combine with `--total` or `--balanced`.
Selections fail on a split/class shortfall; they do not borrow rows across time boundaries.

## Stage selected bytes before training

Run the following only on an isolated training worker with restricted S3 access and enough
encrypted local storage for the **entire selected cohort**. The pilot and full manifests are
independent. Staging checks the frozen manifest against its passing source audit, downloads every
selected object, verifies its full SHA-256 and size, and records each source outcome in SQLite.
It writes an aggregate report even when some objects fail. Resume the same output root after a
transient failure; do not train until that report passes. By default, staging uses
`<project>/work/staged/<experiment>/<preset>` and training writes to
`<project>/work/runs/<experiment>`, independent of the shell's current directory. On a server
with separate private storage, override these with `--output-root` for staging and
`--staging-report` plus `--artifact-root` for training. Never commit or open staged PE files.

```sh
uv run malweave experiment stage-inputs --preset pilot
uv run malweave experiment stage-inputs --preset pilot --resume
```

On the same isolated worker, train against the exact frozen split and staging report. The sole
track, device, seed, and accumulation setting come from `malconv-raw.yaml`; the run directory
must be new. The trainer prints aggregate batch progress and evaluation phases to stderr while it
runs; metrics are written at completion. No S3 object is fetched by the training command.

```sh
uv run malweave experiment train \
  --experiment configs/experiments/malconv-raw.yaml \
  --preset pilot \
  --run-id malconv-raw-pilot-001
```

For a different cohort, supply its audited split manifest and summary to `stage-inputs`, then
use the same split manifest and the resulting staging report for `train`. A new dataset still
needs an adapter that creates trustworthy labels, grouping, source provenance, and an audit.

For another S3 prefix, set `MALWEAVE_S3_BUCKET` and use `malweave data inventory-s3 --prefix
other/folder/ --state-db ... --manifest ... --summary ...`. Optional `--suffix`, `--min-size`,
`--max-size`, `--progress-every`, and `--resume` are available. This produces an **unlabeled**
inventory; do not train from it directly. Implement a dataset adapter in `malweave/data/s3/` and
pass audited, labeled rows to `select_labeled_rows` in `manifest.py`.

For paper-comparison pilots, 50/50 labels are useful. Keep the complete audited inventory too:
the full eligible cohort need not discard majority-class data solely to force 50/50. Evaluate
both a balanced comparison set and, where the intended deployment distribution is known, a
prevalence-aware set. RanDS benign-versus-ransomware labels do not measure general malware
detection performance.
