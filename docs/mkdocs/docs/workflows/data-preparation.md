# Prepare SOREL And Assemblage EXE Data

Prepare SOREL malware and Assemblage Windows PE for pretraining. **RanDS is converted to EXE and
uploaded to S3** and supplies downstream data plus overlap checks.

```text
SOREL metadata → selected S3 batches → zlib decompress ─┐
                                                       ├→ PE screening → shared EXE extractor
Assemblage SQLite + binaries.tar.xz → selected PE bytes ┘
    → quality and overlap checks → split-ready inputs
```

## 1. SOREL

Use `s3://sorel-20m/09-DEC-2020/`. The bucket is public; no AWS credentials are needed.

1. Download `processed-data/meta.db` (about **3.8 GB**, 3.53 GiB). Audit SQLite integrity, schema,
   labels and IDs. Select malware rows; raw benign binaries are not public. EMBER features and
   baseline models are not required for EXE.
2. Choose the corpus scope and filtering policy, retaining a fixed source list and sampling seed
   when applicable. Resolve architecture handling before corpus conversion: SOREL zeroes `Machine`
   and `Subsystem`, and PE32 alone does not prove x86. Do not restore headers. Document deviations
   from LMLM's x86-32 cohort.
3. Read selected `binaries/<original-ID>` objects in bounded batches, decompress zlib, screen and
   extract EXE. Remove temporary inputs after durable outcomes. Bound file sizes and concurrency;
   the full raw corpus is not required locally.
4. Retain per-source progress, EXE and explicit filtered/error outcomes. Retry network failures;
   do not silently replace missing or malformed sources. Keep original ID, released-PE digest and
   EXE digest separate because released bytes differ from the original hashed file.

SOREL metadata has been audited; corpus conversion is pending. See the
[SOREL dataset card](../datasets/sorel-20m.md) for audited counts and source details.

### CLI And Job State

Use one command to prepare a new job and process successive batches:

```bash
uv run --locked python -m malweave data sorel-run \
  --metadata data/raw/sorel/metadata/meta.db \
  --config <reviewed-config.yaml> --job-dir <new-job>
```

Resume with the same command, config and job directory; `--metadata` can be omitted after
preparation. The existing default config is a development smoke test; pass an explicit config for
corpus work. `--limit N` stops after at most N additional sources in this invocation. The CLI does
not upload outputs.

The source selection and per-source outcomes live in SQLite. `selection.json` records the config,
metadata audit and selection digest. Indexed pending rows and transactional counters avoid reading
all previous outcomes every batch. Each outcome, completed flag, aggregate delta and unique EXE
accounting commit together. Remove compressed input only after that commit. One writer is allowed
per job. If interrupted, committed sources are skipped; verified pending downloads are reused.
Uncommitted screening/extraction may run again. Stop with Ctrl-C and allow bounded in-flight work
to finish before restarting.

The default downloader is curl >= 7.70; `download_backend: urllib` is also available. Each attempt
has a durable JSON log with HTTP status, retries, observed bytes, duration, command and diagnostics
under `downloads/`. A start record preserves evidence if the process dies during transfer;
recovered interrupted attempts mark duration unknown and byte counts as lower bounds. Transient
failures retry within `request_attempts`; missing/forbidden objects and size limits are accounted
separately. Exhausted source failures are terminal outcomes; resuming does not retry completed
failures. Storage write errors stop the runner and preserve pending state.

Changed configs, inputs, code or tool identities require a new job. Schema-1 jobs are export-only.
Resume checks selection and the frozen contract once, then checks each newly produced result.
For a full audit of saved reports, download history, progress and EXE hashes, run:

```bash
uv run --locked python -m malweave data sorel-verify --job-dir <job>
```

### Saved Tool Evidence And Statistics

Each new SOREL outcome links to hash-checked JSON under `tool-reports/<tool>/<shard>/<source>.json`:

| Tool | Saved evidence |
| --- | --- |
| `file` | Command, stdout, stderr, return code or timeout/error, runtime and binary identity. |
| DiE | Original stdout/stderr, parsed complete JSON, status/runtime/command for recursive, deep and heuristic modes; binary/rule identity. Includes compiler/linker/packer names and all other returned fields. |
| LIEF 0.15.1 | Structured `lief.to_json` PE data, every section's raw/virtual offsets, sizes and flags, selection, effective extraction ranges, output offsets, warnings and EXE digest. An isolated subprocess captures native stdout/stderr, command, runtime and exit status. Timeouts (`lief_timeout_seconds`) and worker crashes are per-source failures; other sources continue. |

Reports retain source ID, released-PE hash, tool version and timestamp. Save screening evidence
before filtering; LIEF is not run for samples rejected before extraction. Missing inputs and failed
stages are recorded without pretending subsequent tools ran. Keep original metadata databases.

Update `summary.json` after each batch. Once all selected sources are accounted for, automatically
export `manifest.json`, `results.csv`, `tool-runs.csv`, `die-detections.csv`, `lief-sections.csv`,
`downloads.csv` and `export-summary.json`. Export streams saved rows instead of loading the entire
history into memory. CSVs use UTF-8 with BOM for Excel; these are CSV files, not an XLSX workbook.
JSON remains the full evidence when nested data or long scanner output does not fit a spreadsheet
cell. Network-byte/time totals come from receipts; interrupted transfers explicitly mark incomplete
measurement. Summed worker durations are not elapsed job time.

To regenerate tables from saved state only:

```bash
uv run --locked python -m malweave data sorel-export --job-dir <job>
```

Stop the runner before exporting an unfinished job. This command does not download or scan PEs
and does not require the original tool environment.
Historical jobs without full reports are exported with `full_report_not_saved`; unattempted stages
are `not_run`. The earlier SOREL test retained summaries only, so its full DiE/LIEF evidence cannot
be recovered through export. Existing jobs remain unchanged; the updated audit code requires a new
processing job because code identity is part of the resume contract.

The older manual path remains available: `data sorel-download-plan --config <config> --job-dir <job>`,
`curl -sS --config <job>/download.curl`, then
`data sorel-extract --config <config> --job-dir <job> --staged`. It processes one staged batch;
repeat only while sources remain. It does not retain automatic per-attempt HTTP receipts, and
local spool-read time is not network time. Prefer `sorel-run` for audited transfers. Sandboxed
environments may restrict subprocess networking as well as Python networking.

## 2. Assemblage Windows PE

Use [changliu8541/Assemblage_PE](https://huggingface.co/datasets/changliu8541/Assemblage_PE/tree/19a8f947f5a04d03edea78e61790226b55f92ac2),
revision `19a8f947f5a04d03edea78e61790226b55f92ac2`. Select GitHub Windows PE.

| Required file | Compressed size | Purpose |
| --- | ---: | --- |
| `winpe.sqlite.tar.xz` | 9.32 GB | Binary/project/build metadata. |
| `binaries.tar.xz` | 33.83 GB | PE bytes. |

1. Download metadata first, extract its database and inspect it read-only. Use the actual schema
   for binary ID, path/hash, project, license and build fields. Function/source/PDB tables are not
   required. The selected revision contains the two archives above, not the CSVs mentioned by the card.
2. Download the binary archive. Budget **43.15 GB** for compressed archives plus extracted metadata,
   EXE and download cache. Match database paths to tar members, checking hashes when available;
   report missing members. Count the selected release from its data rather than website totals.
3. Choose source scope and retain project/build relations. Implement sequential regular-member
   reads into the shared screening/extraction pipeline without unpacking all PEs to disk. Preserve
   progress; rescanning compressed archives on resume must be included in runtime measurements.

Assemblage provides background software from source repositories, not AV-certified benign labels.
Retain repository licenses; the generator's MIT license does not cover every binary. MLM does not
use these class labels as targets. The Assemblage adapter remains to be implemented.
See its [dataset card](../datasets/assemblage.md).

## 3. Shared Screening, Extraction And Operation

- Before extraction, annotate architecture with `file` and run DiE recursive, deep and heuristic
  modes. Require valid PE reports from all modes with no detected obfuscation. Account for detected
  and unknown results separately. SOREL's vendor `packed` tag does not replace DiE. LMLM filters
  x86-32 before extraction; freeze and document this study's source-specific architecture policy.
- Use `malweave/data/pe_sections.py` and locked **LIEF 0.15.1**. Concatenate raw ranges of sections
  with `CODE` or `EXECUTE` flags in section-table order, clipping invalid ranges with warnings.
  Preserve complete EXE; context truncation belongs to later model input processing.
- Check readers, malformed/empty/no-code PEs, multiple sections, read/decompression failures,
  output digests and resume using synthetic fixtures. Verify real outputs against recorded results.
- Choose workers and output storage within available resources. Keep each job's inputs/config/tools
  fixed, commit per-source outcomes durably and report counts, screening coverage, failures,
  download/scan/screening/extraction time and storage. Retain outputs and state outside Git.

## 4. Combined Checks And EXE Input Interface

1. Normalize fields: dataset/release, original ID, actual PE digest, EXE digest/path/size and
   status/error, plus Assemblage project/build and RanDS label/family.
2. Compare compatible original IDs and exact EXE hashes across sources. Exclude external equivalents
   of RanDS from pretraining, preserving source records and exclusion reasons. Keep duplicate and
   Assemblage project/build groups together in future splits. Audit near duplicates where feasible;
   EXE-only preparation does not reproduce LMLM's DEC-based grouping.
3. Declare a policy for RanDS's **73 conflicting-label EXE groups** before downstream splits.
4. Report architecture/packing/unknown coverage by source and RanDS class to identify confounding.
5. Implement EXE-only manifest/storage loading independent of RAW. Validate paths, sizes and trusted
   checksums; multipart S3 ETags are not SHA-256. Current product/runner code also expects RAW.

## Completion And Handoff

Both external sources must account for the selected scope, with verified EXE, common result tables,
resumable state, quality reports, project/duplicate/overlap relations and a working EXE-only reader.
Record release, terms, tool versions and resolved config with private artifacts. Keep raw bytes
unchanged and SQLite backups consistent. Dataset inventories, per-sample hashes and credentials
stay outside Git.

The next stage freezes cohorts/splits and fits BPE on overlap-controlled external training data
under the [research protocol](research-protocol.md). Synthetic model development can proceed while
conversion runs. See [workstreams](research-workstreams.md) for component tasks.
