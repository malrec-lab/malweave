# S3 layout — where the dataset bytes live

Object counts and byte sizes come from the 2026-11-16 audit and the 2026-11-19 recount. Access: AWS profile `sorel-worker`
(region ap-southeast-1), account `xxxxx`. The audit pipeline reads with
ETag-pinned complete-object requests and verifies each original PE SHA-256.

## Buckets and prefixes

| Bucket / prefix | Objects | Bytes | Contents |
| --- | ---: | ---: | --- |
| `rands-malware-research-xxxxx` → `RanDS_PE_Dataset/` | 215,406 | 182.2 GB | Raw RanDS PEs (`dataset/<2-hex>/<sha>`), `Benign.csv`, `Ransomware.csv` (256 shards) |
| `rands-malware-research-xxxxx` → `rands/` | 1,094,182 | 181.4 GB | Extracted EXEs (`representations/exe/`), pe-header manifests, extraction state |
| `rands-malware-research-xxxxx` → `malweave/` | 2 | 504.7 MB | Private benchmark bundles |
| `rands-malware-research-xxxxx` → `vera/`, `assemblage/` | 108 | 3.7 GB | Small copies pulled for earlier verification |
| `rands-malware-research-xxxxx` → `experiments/`, `analysis/` | 10,708 | — | Archives of the old C/E1/E2 runs and private batches (outside every audit) |
| `rawmal-malware-research-xxxxx` → `raw/` | 188,951 of 244,940 | 198.2 GB | RawMal-TF sources (`raw/<2-hex>/<sha>`); 78,934 are PE — the rest PDF/HTML/ELF/unknown stay out of the audit |
| `rawmal-malware-research-xxxxx` → `exe/`, `details/` | 55,989 | — | Extracted EXEs and conversion state (`rawmal-exe.sqlite`, `state.sqlite`) |
| `vera-malware-research-xxxxx` → `vera/zenodo-17904705-v1/` | 145,413 | 55.6 GB | `binaries/{active,latent}/<2-hex>/<sha>` (38,285 keys / 38,282 unique), `exe/lief-0.15.1-v1/`, `labels/`, `features/` |
| Dataset buckets → `audit/kaggle/inputs/` | — | — | Private source and inventory bundles for Kaggle audit notebooks; the RanDS bundle includes a resumable SQLite checkpoint |
| `assemblage-malware-research-xxxxx` → `raw/` | 86,585 | 38.9 GB | Assemblage PEs (`raw/<2-hex>/<sha>`); `details/`, `main/`, `representations/` hold DiE assessment, conversion and metadata |
| `sorel-malware-research-xxxxx` → `malweave/datasets/sorel-20m/` | 615 | 1.3 GB | Pilot-converted SOREL (part 1 of 5) — paused |
| `sorel-20m` (public, no sign-in) → `09-DEC-2020/` | ~20 M files | ~8 TB | Upstream SOREL source — read-only reference, never audited here |

## EXE manifests

| Dataset bucket | Manifest object key |
| --- | --- |
| RanDS | `rands/representations/exe/manifest.csv` |
| VERA | `vera/zenodo-17904705-v1/exe/lief-0.15.1-v1/manifest.csv` |
| RawMal-TF | `main/exe.csv` |
| Assemblage | `representations/exe/manifest.csv` |

The local `inventory.csv` addresses raw PEs. Join its `sha256` and the two audit
CSVs to the matching EXE manifest's `source_sha256` in the same dataset. Use the
manifest's output key, digest and size for the extracted EXE. Its presence in
an audit table alone does not guarantee that extraction succeeded. Preserve the
source-to-EXE relationship when grouping repeated EXE content before a split.

## Local audit inputs and evidence

For each of `rands`, `vera`, `rawmal` and `assemblage`, use these files under
`data/processed/<dataset>/`: `inventory.csv`, `audit/packing.csv` (11 columns)
and `audit/native-dotnet-20261122.csv` (12 columns). The three files cover the same
source SHA-256 set within each dataset. The audit reads source objects using the
stored ETag. See the
[data preparation guide](../workflows/data-preparation.md)
for run directories and CSV export.

| Artifact | Verified location or status |
| --- | --- |
| RanDS packing | `data/processed/rands/audit/packing.csv` uses the shared 11-column schema for 215,404 sources and includes 871 rows from `rands-die-rerun`, joined by SHA-256. The rerun's SQLite file retains evidence at the 90-second timeout. The original 10-second rows have blank evidence hashes. |
| RanDS first-pass packing export | `data/processed/rands/audit/packing-first-pass-10s.csv` preserves all 22 columns, including architecture, detection details and error summaries. Its S3 key is `rands/private-evidence/die-assessment/2026-11-01/rands-die-results.csv`. |
| Assemblage packing | `data/processed/assemblage/audit/packing.csv` combines 86,585 DiE 3.21 results from five non-overlapping parts. Each part under `data/processed/audit/jobs/assemblage-die-part-01` through `assemblage-die-part-05` retains its CSV and SQLite evidence. All parts use a 90-second timeout per mode. |
| Assemblage DiE 4.0.0 packing export | `data/processed/assemblage/audit/packing-die-4.0.0.csv` preserves the 17-column DiE 4.0.0 assessment export dated 2026-11-13. S3 retains the reports and per-source evidence under `details/die-assessment/`. See [local DiE packing results](assemblage.md#local-die-packing-results) for the two CSVs. |
| VERA packing | `data/processed/vera/audit/packing.csv` combines the 38,282-row DiE 3.21 export from `vera-die-20261122` with 102 rows from `vera-die-rerun`, joined by SHA-256. The two job directories under `data/processed/audit/jobs/` retain their CSV and SQLite evidence for the 10- and 90-second timeouts. |
| RawMal-TF packing | `data/processed/rawmal/audit/packing.csv` combines the 78,934-row DiE 3.21 export from `rawmal-die-20261123` with 1,780 rows from `rawmal-die-rerun`, joined by SHA-256. The two job directories under `data/processed/audit/jobs/` retain CSV and SQLite evidence for the 10- and 90-second timeouts. |
| Audit state and exports | `data/processed/audit/jobs/<dataset>-<job>/` holds SQLite evidence. `data/processed/<dataset>/audit/native-dotnet-<job>.csv` holds the exported table. |
