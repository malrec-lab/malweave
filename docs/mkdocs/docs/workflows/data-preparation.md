# Prepare SOREL And Assemblage EXE Data

Prepare SOREL malware and Assemblage Windows PE for pretraining. **RanDS is converted to EXE and
uploaded to S3** and supplies downstream data plus overlap checks. This is a preparation plan;
measurements and execution notes will be recorded after the jobs run.

```text
SOREL metadata → selected S3 binaries → zlib decompress ─┐
                                                       ├→ shared EXE extractor
Assemblage SQLite + binaries.tar.xz → selected PE bytes ┘
    → pilot both sources → choose scope → convert → check overlap → split-ready inputs
```

## 1. Inputs

| Source | Selected release | Required data |
| --- | --- | --- |
| SOREL | `s3://sorel-20m/09-DEC-2020/` | `processed-data/meta.db` and selected objects under `binaries/`. |
| Assemblage | `changliu8541/Assemblage_PE`, revision `19a8f947f5a04d03edea78e61790226b55f92ac2` | `winpe.sqlite.tar.xz` and `binaries.tar.xz`. |
| RanDS | Prepared EXE dataset | EXE/source mapping, labels/families and extraction status. |

SOREL has no public raw benign binaries. Assemblage is background software from licensed source
repositories, not AV-certified benign ground truth. MLM does not use these class labels as targets.

## 2. SOREL: Metadata, Selection And Reader

1. Download `processed-data/meta.db` (about **3.8 GB**, 3.53 GiB) and inspect the SQLite `meta` table.
   Select 100 records with `is_malware = 1`, using a fixed seed, and save the selected IDs privately.
   EMBER features, full PE metadata dumps and baseline models are not needed for this pipeline.
2. Read each selected `binaries/<original-ID>` object anonymously from S3. Objects have the original
   SHA-256 filename without an extension. Decompress zlib in memory, then pass PE bytes to LIEF.
   Each worker handles bounded per-file data; the full roughly 8 TB corpus is not required locally.
3. Implement request retry, per-source progress and explicit read/decompression/missing failures.
   Do not replace failed sources silently. Keep original ID, decompressed-byte digest and EXE digest
   separate: the release sets `Machine` and `Subsystem` to zero, so released bytes do not need to
   hash to the original filename. Do not restore headers.

**Required output:** the selected source list and a reader that can produce PE bytes or an explicit
failure for every selected source. The SOREL CLI adapter still needs implementation.

## 3. Assemblage: Metadata, Archive And Reader

Use the **GitHub Windows PE** release, not Linux ELF, Rust, vcpkg or DeepHistory. Pin both downloads
to the revision above.

| Published file | Compressed size | Purpose |
| --- | ---: | --- |
| `winpe.sqlite.tar.xz` | 9.32 GB | Binary/project/build metadata. |
| `binaries.tar.xz` | 33.83 GB | PE bytes for EXE extraction. |

The current file listing contains these two archives. The card mentions CSV files and
`winpe_pdbs.sqlite.tar.xz`, but those filenames are not present at the selected revision. Use the
actual listing. Do not combine the card's 91k and the project page's 88k counts as one release count.

1. Download and inspect the metadata archive, extract the database and open it read-only. Inspect
   `binaries` columns before querying. Read the binary ID, path/hash, size, repository/project,
   license and build fields that actually exist. Function/PDB/source-code tables are not needed.
2. Download `binaries.tar.xz` once. The two archives alone total **43.15 GB**; also budget for the
   extracted database, EXE outputs and download cache. Measure the extracted sizes before scaling.
3. Match the database path (`path` or `binary_path`, depending on schema) with tar member names,
   using hashes as additional checks when available. Report missing matches explicitly.
4. Choose roughly 100 binaries across projects/build settings with a saved seed/list. Read regular
   file members sequentially from `tar.xz` and feed their bytes into the shared extractor. No full
   PE extraction to disk is required. This archive is not independent per-PE S3 objects; selecting
   100 PEs does not imply downloading only those 100 PEs.
5. Keep project/build relations and source-repository licenses. On resume, a compressed archive may
   need rescanning; skip completed extraction rows and include scan/decompression cost in timings.

**Required output:** a selected source list, correct metadata-to-member mapping and an archive
reader connected to the shared extractor. The Assemblage CLI adapter still needs implementation.

## 4. Shared Extractor And Two Pilots

Use `malweave/data/pe_sections.py` and locked **LIEF 0.15.1**. Concatenate raw ranges of sections with
`CODE` or `EXECUTE` flags in section-table order, clipping invalid ranges and recording warnings.
Preserve complete EXE bytes; context truncation belongs to later model input processing.

Add source configs, CLI integration, durable progress and synthetic tests for both readers.
Cover malformed/empty/no-code PE, multiple sections, decompression/read failures, conflicting output
digests and interruption/resume. Then process the two saved pilot lists.

For **each source**, require:

- An outcome for every attempted source and valid, hash-checked EXE output for every success.
- Resume that preserves completed results and rejects conflicting output/changed job inputs.
- Counts by failure reason, download/scan/decompression/extraction times and input/output size.
- Architecture/packing summaries where available, with unknowns retained. SOREL's `Machine=0`
  or PE32/PE32+ alone cannot establish ISA.

These pilots validate code and resource needs, not detector quality.

## 5. Choose Scope And Convert

Estimate throughput and storage separately for the two sources. Include SOREL request overhead
and Assemblage's fixed archive download/scan cost. Choose source counts, workers and output storage
from the measured budget. Audit the full selected lists for metadata/path coverage and access
conditions before launching a large job; freeze those lists and configs.

Convert with per-source durable progress and explicit failures. Changed source lists/extraction
contracts require distinct jobs. Group selected Assemblage work into one archive pass where possible.

**Required output:** an accounted result for every chosen source, EXE outputs and per-source
aggregate coverage/failure/runtime/size reports.

## 6. Combined Checks And EXE Input Interface

1. Normalize result fields: dataset/release, original ID, actual PE digest, EXE digest/path/size,
   status/error, plus Assemblage project/build and RanDS label/family fields.
2. Compare compatible original IDs and exact EXE hashes across sources. Exclude external
   equivalents of RanDS from the pretraining list while retaining original source records and
   exclusion reasons. Keep duplicate groups together for future splits; audit near duplicates
   where feasible.
3. Preserve Assemblage project groups for external train/validation. Declare the policy for RanDS's
   73 conflicting-label EXE groups before downstream splits.
4. Report architecture/packing/unknown coverage by source and RanDS class to identify confounding.
5. Implement EXE-only manifest/storage loading independent of RAW inputs. Validate paths, size and
   trusted checksums; multipart S3 ETags are not SHA-256. Existing product/runner code also expects
   RAW, so this interface is part of the work.

## Completion And Handoff

Deliver EXE bytes, common result tables, resumable job state, source/project/duplicate/overlap
relations, quality reports and a working EXE reader. Record release, acquisition/access terms,
source/lock/tool versions and resolved commands/configs with private artifacts. Keep raw sources
immutable and SQLite backups consistent.

The next stage selects cohorts, freezes splits and fits BPE on overlap-controlled external
training data under the [research protocol](research-protocol.md). Synthetic model development can
proceed while conversion runs. See the [dataset cards](../datasets/index.md) and
[workstreams](research-workstreams.md) for source details and component tasks.
