# S3 dataset layout

RanDS, VERA, RawMal-TF and Assemblage use one private bucket per dataset in
`ap-southeast-1`. New jobs use this layout. Start using each bucket once its
`dataset.json` receipt reports `phase=verified`.

| Dataset | CLI ID | Bucket name |
| --- | --- | --- |
| RanDS | `rands` | `malweave-rands-<account-id>` |
| VERA | `vera` | `malweave-vera-<account-id>` |
| RawMal-TF | `rawmal` | `malweave-rawmal-tf-<account-id>` |
| Assemblage | `assemblage` | `malweave-assemblage-<account-id>` |

## Bucket contents

```text
<dataset-bucket>/
├── dataset.json
├── inventory.csv
├── representations/
│   ├── raw/<shard>/<source-sha256>
│   ├── exe/
│   │   ├── <shard>/<exe-sha256>
│   │   └── manifest.csv
│   ├── dis/                          RanDS
│   ├── dec/                          RanDS
│   ├── pe-header/                    RanDS
│   └── features/                     VERA and RawMal-TF
├── audit/
│   ├── packing.csv
│   ├── native-dotnet.csv
│   ├── jobs/<job-id>/state.sqlite3
│   ├── extraction/
│   │   ├── evidence/<shard>/<source-sha256>.json.gz   VERA and Assemblage
│   │   └── summary.json                             Assemblage
│   └── legacy/                       RanDS and Assemblage historical CSVs
├── metadata/
│   ├── exe-manifest-before-migration.csv
│   └── <dataset-specific metadata>
└── experiments/<run-id>/             RanDS
```

| Path | What it contains |
| --- | --- |
| `dataset.json` | Publication receipt with the plan digest, scope, source counts and extraction outcomes, checksums for the main tables, and selected audit jobs and evidence gaps. |
| `inventory.csv` | One record for each source in the shared audit population. Core fields are `sha256`, `s3_key`, `size` in bytes and `etag`. The ETag pins the S3 object read by audit workers. Workers verify the full SHA-256 separately. |
| `representations/raw/` | Original source bytes, stored once per source SHA-256. RawMal-TF also retains non-PE sources here. |
| `representations/exe/` | Executable-section bytes, stored once per output SHA-256. The name EXE refers to the derived representation used by the model. |
| `representations/exe/manifest.csv` | One extraction outcome per source, including failures. Core fields are `source_sha256`, `source_key`, `status`, `exe_sha256`, `exe_key` and `exe_bytes`. Several sources may point to the same EXE object. |
| `representations/dis/`, `representations/dec/`, `representations/pe-header/` | RanDS disassembly, decompilation and PE-header views. Each view has its own processing scope. |
| `representations/features/` | VERA upstream features and RawMal-TF `type/` and `family/` feature sets. |
| `audit/packing.csv` | Final shared 11-column DiE 3.21 packing export, with the outcome of each scan mode. |
| `audit/native-dotnet.csv` | Final shared 12-column runtime and architecture export, including verdict and reason. |
| `audit/jobs/<job-id>/state.sqlite3` | SQLite evidence for reviewed audit jobs. Published jobs retain a unique job ID. |
| `audit/extraction/` | VERA and Assemblage extraction reports keyed by source SHA-256. Assemblage also has a summary. |
| `audit/legacy/` | Earlier packing exports for provenance. RanDS keeps `packing-first-pass-10s.csv` and Assemblage keeps `packing-die-4.0.0.csv`. |
| `metadata/exe-manifest-before-migration.csv` | Original manifest retained as provenance for the normalized EXE mappings. Its keys describe the source release. |
| `experiments/<run-id>/` | RanDS cohort definitions, checkpoints and results grouped by run. |

The shard is the first two lowercase hexadecimal characters of the respective
digest. RAW uses the source digest and EXE uses the output digest. Join
`inventory.csv` and the two audit exports on `sha256`. Join the EXE manifest
on `source_sha256`. To stage EXE bytes, select `status=success` and use `exe_key`,
`exe_sha256` and `exe_bytes`. Retain both digests for duplicate grouping when
building a split.

## Naming conventions

Use the bucket names in the table above. RawMal-TF uses `rawmal-tf` in its
bucket name and `rawmal` as its CLI ID and local dataset directory.

| Item | Convention and example |
| --- | --- |
| Published tables | Keep the exact names shown in the tree. For example, teams read the reviewed packing table at `audit/packing.csv` and the extraction mapping at `representations/exe/manifest.csv`. |
| RAW and EXE objects | Use two lowercase hex characters for the shard and the full lowercase SHA-256 as the filename, without an extension. RAW uses the source hash. EXE uses the hash of the extracted bytes. |
| Audit job ID | Use lowercase letters, digits and internal hyphens. Include the dataset, audit and scope, then a run number or date, such as `vera-die-full-20261128` or `rands-native-pilot-01`. Use the same ID in the local job directory and `audit/jobs/<job-id>/state.sqlite3` on S3. |
| Experiment run ID | Prefer the same lowercase, hyphenated style. Include the dataset and run details that distinguish its outputs, such as `rands-minimamba-full-exe-seed0`. Store the run's files together under `experiments/<run-id>/`. |
| Historical and upstream files | Name historical exports for the run or setting they preserve, such as `packing-first-pass-10s.csv` or `packing-die-4.0.0.csv`. Keep upstream filenames already listed in the layout, such as `metadata/Benign.csv`. |

For manually named artifacts, use short words that identify the contents and
scope. Use lowercase words separated by hyphens. Store each file under its
corresponding prefix in the tree. Keep the configured job or run ID when
resuming the same inputs and settings. Use a new ID when either changes.

## Dataset-specific files

| Dataset | Source and audit scope | Additional keys |
| --- | --- | --- |
| RanDS | 215,404 source objects and audit rows. | `metadata/Benign.csv` and `metadata/Ransomware.csv` supply class labels and source metadata. |
| VERA | 38,282 unique sources and audit rows from 38,285 upstream occurrences. | `metadata/release.json` records the release, `metadata/labels/` keeps upstream labels, and `metadata/raw-occurrences.csv.gz` maps active/latent occurrences to canonical RAW objects. |
| RawMal-TF | 188,951 unique sources. The shared audit covers 78,934 PE sources. The EXE manifest also records outcomes for sources outside that audit. | `metadata/samples.csv` contains the ingestion inventory, `metadata/ingestion.sqlite` preserves member occurrences and ingestion evidence, and `metadata/labels/rawmal-task-labels.csv` records type/family labels. |
| Assemblage | 86,585 source objects and audit rows. | `metadata/samples.csv` records source rows, `metadata/source.json` records acquisition provenance and `metadata/ingestion.sqlite` preserves ingestion state. |

## Using a published bucket

Configure the profile and account ID in the
[environment guide](../development/environment.md#dataset-s3-configuration).
Follow [data preparation](../workflows/data-preparation.md#download-a-published-inventory)
to verify the receipt and fetch the selected dataset's inventory. The Kaggle audit
runner fetches both artifacts from the dataset bucket with the same code.
After a new audit, use the [job publication command](../workflows/data-preparation.md#save-a-completed-audit-on-s3)
to save its SQLite evidence under the same layout.

The old migration runner's temporary `_migration/` prefix contains its source
inventory, plan and progress. Research workflows use the published keys above.

## Local audit inputs and evidence

The source tables and local audit exports used for publication remain under
`data/processed/<dataset>/`. New jobs use the destination-backed inventory under
`data/interim/s3/<dataset>/`.

| Dataset | Local packing evidence |
| --- | --- |
| RanDS | The final packing CSV includes 871 rerun rows with evidence in `data/processed/audit/jobs/rands-die-rerun/state.sqlite3`. The 10-second first-pass CSV has 22 columns. Its SQLite was unavailable. |
| VERA | The final packing CSV includes 102 rerun rows. The full and rerun jobs have separate SQLite files. |
| RawMal-TF | The final packing CSV includes 1,780 rerun rows. The full and rerun jobs have separate SQLite files. |
| Assemblage | The final packing CSV combines five DiE 3.21 jobs at 90 seconds per mode. The 17-column DiE 4.0.0 CSV records the earlier assessment. |

For all four datasets, local `audit/native-dotnet-20261122.csv` maps to the
published `audit/native-dotnet.csv`. Local job state lives under
`data/processed/audit/jobs/<job-id>/`. These local records retain their original
object keys and ETags as provenance.
