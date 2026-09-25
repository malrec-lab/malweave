# S3 inventories and RAW manifests

The code has three layers under `malweave/data/s3/`:

| Layer | Responsibility | Reuse |
| --- | --- | --- |
| `client.py`, `inventory.py` | List object metadata under **any** S3 prefix; save a resumable SQLite scan and optional size/suffix-filtered, **unlabeled** inventory. Never read object bytes. | Reuse unchanged for another S3 folder. |
| `rands.py` | Join the RanDS metadata snapshot to S3 objects, validate its key layout and expected release counts, and report availability by class. Its candidate CSV deliberately includes missing objects. | Replace this adapter for another dataset. |
| `manifest.py` | Filter labeled rows and select full, balanced, proportional-total, or explicit class-count cohorts deterministically within existing splits. | Reuse unchanged from another dataset adapter. |

`malweave/experiments/rands_raw_manifest.py` supplies the RanDS-specific year split and RAW
experiment policy. A different folder alone can use `inventory-s3`; a different *labeled dataset*
needs a small adapter defining identity, labels, eligibility, split, and an appropriate source audit.
An S3 key name is not a trustworthy label. Keep private inventories and manifests in ignored
`data/interim/` or `data/processed/`, and aggregate reports in ignored `reports/`.

## RanDS example

Set `MALWEAVE_RANDS_S3_BUCKET` in your local environment. The bucket value, credentials, source
identities, and generated manifests must not be committed. The metadata CSVs must be the audited
snapshot corresponding to the S3 prefix. The commands list metadata only; no PE bytes are fetched.

```sh
uv run malweave data inventory-rands-s3 \
  --metadata-root /private/path/to/rands-metadata \
  --prefix RanDS_PE_Dataset/dataset/ \
  --state-db data/processed/rands/raw-s3/inventory.sqlite \
  --manifest data/processed/rands/raw-s3/raw-metadata-candidates.csv \
  --summary reports/rands/raw-s3/inventory.json
```

After an interrupted scan, rerun with the **same arguments** plus `--resume`. Each completed page
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
never overwritten. The two commands above have already been run for the current snapshot; use
fresh output paths if you want another manifest.

For a custom cohort, omit `--preset`, give new `--manifest` and `--summary` paths, then use
`--total N`, `--balanced`, repeatable `--label-count LABEL=N`, repeatable
`--where COLUMN=VALUE`, `--min-year`, `--max-year`, or `--seed` as needed. `--balanced` without
`--total` keeps the largest equal class count in each split; `--total N` alone allocates by the
eligible class proportions. `--label-count` cannot combine with `--total` or `--balanced`.
Selections fail on a split/class shortfall; they do not borrow rows across time boundaries.

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
