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
presets. The default `full` balances **train only**, selecting equal class counts from
available `I386`, `Packed=0` training rows. Validation and test retain all eligible available
rows without balancing. No fixed total is imposed. `--preset pilot` creates an optional balanced 1,000-sample cohort; split allocations are
70/15/15 *within each class*, so each split remains class-balanced. These are separate frozen
manifests:

```sh
uv run malweave experiment freeze-rands-raw
uv run malweave experiment freeze-rands-raw --preset pilot
```

`raw-metadata-candidates.csv` has every metadata-eligible `I386`, `Packed=0` source, including
those with `availability=missing` or `size_mismatch`; it is an audit input, **not** a training
manifest. The default writes the balanced cohort to
`raw-train-balanced-full-split.csv` (with a corresponding JSON report). The previous all-split
balanced `raw-balanced-full-split.csv` is superseded; do not use it for this experiment.
The previous unbalanced
`raw-all-available-split.csv` remains an immutable historical artifact; it is no longer the
default full experiment. No file-content hash
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

Use `balance_splits: [train]` in a preset, or repeatable `--balance-split train` for a custom
cohort, to balance only named splits. Other splits retain all eligible rows. This option
cannot combine with `balanced`, `total`, or explicit label counts. The summary records
the balancing scope and available/selected counts per split and class.

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

Run only one staging process per output root. An OS lock rejects concurrent writers,
including a second `--resume`, before any download or SQLite update. The sibling
`<output-root>.staging.lock` file stays on disk; its presence does not mean a process is
running. Do not delete it: ownership is released automatically when the process exits.
Progress `checked`, `verified`, and `failed` all refer to the current pass; on resume,
existing files are reverified and old failure states are repaired without redownloading
valid content. Filesystem failures retain symbolic errno values such as
`write_error:ENOSPC`, `write_error:EDQUOT`, or `write_error:EIO` in SQLite and reports.

The train-balanced `full` preset declares `staging_name: full-train-balanced` and a `reuse_root` pointing
to the previous `work/staged/rands-malconv-raw/full` cache. Its first staging invocation omits
`--resume`; later invocations use it. New manifests always get their own state and report.
The trainer resolves the new staging report from the same preset. The original full manifest,
SQLite state, report, and bytes are not overwritten.

Generic `--reuse-root PATH` overrides the preset cache. Selected cached bytes must match their
declared size and SHA-256 before they are hardlinked into the new output root. Missing cached
files are downloaded; conflicting cached files fail explicitly without modifying the cache.
Hardlinks require the same filesystem (otherwise `write_error:EXDEV`); they share disk bytes
and must remain immutable. Cache and output roots must be separate, non-nested directories.
No sample is copied or moved between temporal partitions. Full balancing is deterministic
undersampling, not oversampling or a forced 70/15/15 temporal split.

Use `--workers N` (1 through 32, default 1) for bounded concurrent downloads within that
**single process**. For example, after the old staging process has exited:

```sh
uv run --locked malweave experiment stage-inputs --preset full --resume --workers 4
```

Worker count can change on resume without changing the frozen cohort. Each worker streams
1 MiB chunks to a temporary file, verifies the full size and digest, and only then publishes
the file. SQLite remains single-writer with one durable transaction per recorded outcome.
Already valid local files are rehashed and reused. Staging does not require a GPU.

Progress includes reused files, files/second, downloaded MiB/second, and an approximate ETA.
ETA can change sharply when resume moves from local verification to new downloads. Compare
worker counts on comparable workloads; more workers are not guaranteed to help when disk,
SQLite, or bandwidth is already saturated. No real-corpus speedup is assumed.

Reports include wall time and timing sums for source reads/hashing, workers, and SQLite.
Worker timing sums overlap and must not be interpreted as elapsed wall time. Transfer-byte
accounting covers recorded outcomes only, not network overhead, SDK retries, or unrecorded
in-flight work when stopped early. Storage errors `ENOSPC`, `EDQUOT`, `EACCES`, and `EROFS`
stop scheduling early; fix storage before resuming. Cancellation drains running workers before
releasing the lock; a published file without a committed outcome is reverified on resume.

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

## Stage directly into a Runpod Network Volume

`stage-network` is an explicitly authorized private transfer, separate from the read-only
dataset preparation workflow. Run it only on an isolated transfer worker: sample bytes pass
through that worker's RAM even though no sample file is written to its disk. Do not run it on
a personal workstation. It does not create Pods, volumes, or GPU resources. Source AWS
credentials need read access; separate Runpod credentials need destination read, write, and
multipart-abort access. This is a relay, not a server-side cross-provider copy.

Configure `MALWEAVE_RANDS_S3_BUCKET` and the normal AWS credential provider chain for the source.
For the destination, set `RUNPOD_S3_BUCKET`, `RUNPOD_S3_ENDPOINT_URL`, `RUNPOD_S3_REGION`,
`RUNPOD_S3_ACCESS_KEY_ID`, and `RUNPOD_S3_SECRET_ACCESS_KEY` privately. Runpod keys never replace
the source SDK credentials. See the [Runpod S3 API documentation](https://docs.runpod.io/storage/s3-api)
for endpoint selection, multipart support, and quota restrictions.

Once the selected frozen manifest and passing source audit exist on the transfer worker:

```sh
uv run --locked --no-default-groups --inexact malweave experiment stage-network --preset full --workers 4 --acknowledge-isolated-worker
```

The data CLI does not import PyTorch, tokenizers, or model code. `--no-default-groups` avoids
installing the training/dev groups; `--inexact` preserves any already-installed packages.
After an interruption with an existing state DB, use the same command plus `--resume`.
Workers may change, but manifest/audit digests, source/destination identity, prefix, region,
representation and mount path must not change. Private SQLite records one durable outcome
per completed source; failed samples remain explicit in aggregate class coverage reports.

By default the train-balanced full data lands at
`malweave/work/staged/rands-malconv-raw/full-train-balanced/` inside the volume. Override the path
with `--destination-prefix`; override private local state using `--state-root`. Custom cohorts
require both of those plus `--manifest` and `--manifest-summary`. RAW and EXE manifests are
supported via `--representation`. This command does not rebalance or resplit data.

Source reads are ETag/version-pinned and SHA-256/size-checked. Small objects use bounded
buffering; larger objects stream multipart parts of 8 MiB. Objects are published only after
source verification, then fully downloaded from the destination for hash verification.
This readback adds network traffic/time. Resume rechecks destination bytes and avoids reading
the source again for valid completed objects. Conflicting destination bytes fail without
overwriting them. Sample bytes never enter local state or logs.

Use **one writer per destination prefix**, across all machines. The local lock prevents two
processes sharing a state root; the remote contract detects different manifests, but neither
is an atomic distributed lock. Do not modify volume files from a mounted Pod during staging.
Multipart IDs are journaled and aborted on failure/resume. A hard kill immediately after
multipart creation but before journal persistence can leave orphaned parts; inspect them
before deleting state. Never delete another job's uploads or rerun into a shared prefix.

After every selected object passes, the command publishes `split-manifest.csv`,
`manifest-summary.json`, and finally `staging-summary.json` under that same prefix. Local
`network-staging-summary.json` additionally records timing, class failures, reused files,
successful uploaded payload bytes (excluding retries/failed transfers/readback traffic),
and `publication_complete`. No code, credentials, checkpoints, or old unbalanced corpus
are automatically uploaded.

Attach the volume to a GPU Pod at creation. At the default `/workspace` mount, use the
exported manifest and staging report rather than a newly generated manifest:

```sh
uv run --locked malweave experiment train \
  --experiment configs/experiments/malconv-raw.yaml \
  --split-manifest /workspace/malweave/work/staged/rands-malconv-raw/full-train-balanced/split-manifest.csv \
  --staging-report /workspace/malweave/work/staged/rands-malconv-raw/full-train-balanced/staging-summary.json \
  --run-id malconv-raw-balanced-001
```

Install the matching code/config separately on that Pod. If mounting elsewhere, declare
`--mount-root` before transfer so the staging report points at the correct filesystem root.
The remote report is immutable evidence of a completed verification, not protection against
later edits on a writable volume; keep outputs immutable and retain training-time byte checks.
