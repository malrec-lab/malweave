# Data preparation

The shared PE audits cover RanDS, VERA, RawMal-TF and Assemblage. The
[S3 layout](../datasets/s3-layout.md) defines the shared object keys, schemas and
dataset-specific evidence.

The audit and extraction artifacts support building the current study's cohort. The
final cohort and split belong to the [study design](research-protocol.md).

## Download a published inventory

Set up the AWS profile and private `.env` once using the
[environment guide](../development/environment.md#dataset-s3-configuration).
From the repository root, select `rands`, `vera`, `rawmal` or `assemblage`.

```bash
dataset=rands
uv run --locked malweave data dataset-storage verify --dataset "$dataset" --profile malweave-worker
uv run --locked malweave data dataset-storage fetch --dataset "$dataset" --profile malweave-worker
```

`verify` checks the published checksum of each main table and the evidence listed
in the release receipt. `fetch` verifies the downloaded inventory against that
receipt and saves both files under `data/interim/s3/<dataset>/`. It reuses a
verified local copy on a repeat run. Kaggle calls the same fetch code.

To stage other tables, repeat `--artifact` with `inventory`, `exe-manifest`,
`packing` or `native-dotnet`. RanDS also accepts `rands-benign` and
`rands-ransomware`. For RawMal-TF packing, add
`--artifact inventory --artifact rawmal-labels`. Files retain their S3-relative
paths below the local dataset directory. Use `--output-dir` to stage them on a
different private volume.

## Native/.NET dataset audit

The audit reads `data/interim/s3/<dataset>/inventory.csv` by default. Each row
supplies a source SHA-256, S3 key, size and ETag. Both `dataset-audit` and
`dataset-die` accept `--inventory PATH` for a copy stored elsewhere. Use a fresh
job directory when changing inventory. The job pins inventory and audit settings.

```text
Start 16 workers by default, each handling one file at a time.
For each source:
  Stream the entire pinned PE to a private temporary file and verify its size and SHA-256.
  Read the PE header with pefile and record Machine and OptionalHeader.Magic.
  Incomplete data directories or section table -> unknown with a reason.
  Complete header, CLR entry undeclared or both RVA and size zero -> native.
  Exactly one CLR field is zero -> unknown (inconsistent_clr_directory).
  Nonzero CLR RVA and size -> use dnfile on the same local file.
    Readable CLR header, metadata root and tables stream -> dotnet.
    Recognized malformed CLR structure                  -> dotnet_invalid.
    Other parser errors                                -> unknown with a reason.
  Close and remove the local copy. Save the result and evidence in SQLite.
  Take the next source.
```

A transport error is recorded per source and can be retried. An ETag or SHA-256
mismatch requires an inventory review. The full-file method has no 64 MiB limit
and can transfer the entire selected inventory. It never needs more than one
temporary source file per active worker. A resumed run cleans up its own
temporary files left by a hard stop.

The `native-dotnet` audit records the declared and parsed
directory and section counts, and saves the CLR RVA and size when the entry can
be read. Missing data directories or section records detected by these checks
have separate reason codes. A header rejected by pefile receives
`unknown(invalid_pe_header)`.

The runtime label and architecture fields describe separate checks. For example,
an AMD64 PE32+ can be labeled `native`. Research cohort selection later applies
the independent `I386` (`0x014C`) plus `PE32` (`0x010B`) rule and joins packing and
extraction evidence. The managed predicate requires dnfile to expose the CLR header,
metadata root and tables stream. SQLite retains raw CLR flags and parser warnings.

### Run, inspect and export one dataset

Run from the MalWeave repository with `boto3` available and a private inventory for the
chosen dataset. The example uses a fresh job name. Keep the job path and inventory
fixed when resuming it. For the completed exports, see the [artifact map](../datasets/s3-layout.md).

```bash
job=data/processed/audit/jobs/rands-native-check
uv run --locked malweave data dataset-audit run --dataset rands \
  --job-dir "$job" --profile malweave-worker
uv run --locked malweave data dataset-audit status --job-dir "$job"
uv run --locked malweave data dataset-audit export --job-dir "$job"
```

Use `--workers` to override the default of 16 and `--limit 1000` to cap one
invocation at 1,000 sources. Use `--retry-errors` to retry recorded transport
failures. Status reports `awaiting`, `finalized`, `retryable_errors` and
`version_mismatches` for the job. `current_run` reports the latest invocation's
progress and download bytes. An `unknown` or `dotnet_invalid` verdict can be finalized.
Transport and identity failures remain unresolved and prevent export. The 12-column CSV separates
the inventory's `source_label` from the audit's runtime `label` and includes
machine, optional-header magic, CLR presence, status and reason. Keep SQLite for
the detailed evidence and resume.

The pilot is deterministic for a published inventory. Its strata use only fields
in that inventory. Generate a source list and pass it as `--sha-list`:

```bash
uv run --locked python scripts/pilot_sample.py --dataset rands --limit 250 \
  --output data/processed/audit/jobs/rands-new-pilot/sha-list.txt
uv run --locked malweave data dataset-audit run --dataset rands \
  --profile malweave-worker --job-dir data/processed/audit/jobs/rands-new-pilot \
  --sha-list data/processed/audit/jobs/rands-new-pilot/sha-list.txt
```

## Shared DiE packing audit

`dataset-die` supports `rands`, `vera`, `rawmal` and `assemblage`. The packing standard
is DiE **3.21**. The Linux x86-64 setup below installs the pinned portable build.
For a custom install, supply `--die-command` and check the version in `tools.json`.
The CLI falls back to `diec` in `PATH` when the portable build is absent.
The published inventory uses `representations/raw/` and the source digest shard
for every row. Fetch the VERA inventory before running the example below.

On a new job, the runner validates the inventory, then checks the selected keys, sizes
and ETags against S3. Each of 16 workers by default downloads and verifies one original
PE, runs `file` and the three DiE modes sequentially, and removes its temporary PE.
A SQLite commit preserves each attempt, including tool output and errors.

```bash
uv run --locked --no-default-groups malweave data die-setup
job=data/processed/audit/jobs/vera-die-check
uv run --locked malweave data dataset-die run --dataset vera \
  --job-dir "$job" --profile malweave-worker --workers 16 --timeout-per-mode 10
uv run --locked malweave data dataset-die status --job-dir "$job"
uv run --locked malweave data dataset-die export --job-dir "$job"
```

For RawMal-TF type/family coverage, pass `--labels-csv` with a local copy of
`data/interim/s3/rawmal/metadata/labels/rawmal-task-labels.csv`
staged by `dataset-storage fetch`.
`--limit` caps attempts per invocation. `--sha-list` defines a subset job. Reuse the
same job directory for resume with the same source set, tool and timeout. The
historical full passes for RanDS, VERA and RawMal-TF used **10 seconds per DiE mode**
with selected reruns at **90 seconds**. Assemblage used 90 seconds for all five parts.
Changing the timeout requires a new job directory. Use `--retry-errors` to retry
DiE downloads that failed in the same job. SQLite retains earlier failed attempts.
Resolve a source hash or ETag mismatch against the published release.

DiE records `obfuscated` if any mode finds a matching detection. `not_detected` requires
three successful negative reports. With missing or invalid mode evidence and no positive
match, the verdict is `unknown`. The 11-column export includes all attempted outcomes
when the job has no pending sources. See the [artifact map](../datasets/s3-layout.md) for
the joined local results and per-job evidence.

## Save a completed audit on S3

Choose a unique ID using the [S3 naming conventions](../datasets/s3-layout.md#naming-conventions),
such as `vera-die-review-01`. Its local directory
under `data/processed/audit/jobs/` contains `state.sqlite3` and the CSV exported
as `packing.csv` or `native-dotnet.csv`. Resume the same job with the same
inventory, selection and tool settings. A changed setting gets a new job ID.

After reviewing a completed run, use a profile with write access to
`audit/jobs/` to store its SQLite evidence in the matching dataset bucket.

```bash
uv run --locked malweave data dataset-storage publish-audit --dataset vera \
  --job-dir "$job" --profile malweave-worker
```

This checks the job's dataset and source identities against the published inventory,
then backs up SQLite using `audit/jobs/<job-id>/state.sqlite3`. For DiE, tool errors
remain evidence, but unresolved download or identity errors block publication.
Packing evidence published by this command uses DiE 3.21. Retrying with the same
evidence reuses the object. A job ID with different evidence fails. The release's
top-level audit CSVs are the reviewed exports recorded in `dataset.json`.

Notebook outputs use the same file names. Download the output into a local job
directory named for the dataset and run, then use the same publication command.
A complete SQLite job also allows local report or CSV regeneration. Fetch the
reviewed release CSV to reproduce an earlier combined export, including any historical
evidence gaps documented in the [S3 layout](../datasets/s3-layout.md#local-audit-inputs-and-evidence).

## Streaming RanDS DiE assessment

This earlier RanDS-specific command produces the SQLite evidence used by
`rands-ghidra`. Use `dataset-die` above for shared packing scans.

Set `MALWEAVE_RANDS_METADATA_S3_PREFIX` to `s3://YOUR-RANDS-BUCKET/metadata`.
`malweave data rands-die` reads the label CSVs there and derives `representations/raw/`
in the same bucket. New Ghidra runs consume SQLite evidence from a RanDS DiE job
created with this layout.
It reuses `data/pe_assessment.py`, which ports the RawByteClf packing protocol.
The scanner runs recursive, deep and heuristic JSON scans with 10 seconds per mode
and combines detections across the original obfuscation types.
Every source is assessed; this command does not choose a training cohort.

The S3 inventory must pass the configured release counts, class counts, shard,
metadata and size checks before any PE downloads. Each PE download is pinned to
the audited S3 ETag and must match its advertised SHA-256 before static scanning.
Ten workers each download one PE, run the three modes sequentially and delete
their temporary PE. This follows RawByteClf's temporary-download lifetime.
Only metadata and results remain locally. Samples are never executed.

The current researcher explicitly requested static processing on the current
machine. Keep private run artifacts in ignored `data/processed/`; the dataset
card's general handling guidance still applies to other acquisition workflows.

Use the existing portable DiE installation (automatically detected), or supply
`--die-command /absolute/path/to/diec` with its required library environment:

```bash
mkdir -p data/processed/rands/packing-scan-s3
nohup uv run --locked --no-default-groups malweave data rands-die run \
  --job-dir data/processed/rands/packing-scan-s3 --workers 10 \
  > data/processed/rands/packing-scan-s3/run.log 2>&1 < /dev/null &
```

The CLI loads the private `.env` for AWS profile/region and the S3 prefix.
It retries unavailable S3 startup requests every 60 seconds, showing
`waiting_for_s3`; use `--retry-seconds 0` to fail immediately. A failed release
contract stops the job. `--limit N` caps pending scans after the full release
audit, for a controlled first run. Rerun the same command/directory to resume;
recorded outcomes, including failures, are retained and skipped. Changed dataset,
tool, rule or scanner identities require a new job directory. Per-source transfer
failures are recorded; AWS performs bounded request retries. They are not silently
reclassified or retried on resume. Low disk space stops further scheduling after
recording the resource failure.

```bash
uv run --locked --no-default-groups malweave data rands-die status \
  --job-dir data/processed/rands/packing-scan-s3
tail -f data/processed/rands/packing-scan-s3/run.log
```

`progress.json` and the flushed JSON-line log update every five seconds, even
while an S3 call is pending. Inspect the PID in `pid.json` with `ps -p PID`;
`kill -TERM PID` stops the runner, waiting for bounded active tasks to finish.
Interrupted tasks without a committed result are attempted again on resume.
Progress includes totals, failures, class coverage, runtime and result sizes.
`summary.json` is written at completion or a limit stop. `release-audit.json`
and `tools.json` record release and scanner identities.

`state.sqlite3` uses WAL and FULL synchronization and commits each source result.
The `result.evidence_gzip` column holds the complete gzip-compressed UTF-8 JSON
record: metadata, S3 identity, verified input digest, `file` evidence and all
three DiE commands, stdout/stderr, parsed reports, errors and runtimes. Its digest
is in `result.evidence_sha256`; the `source` table supplies source inventory and
labels. These records support rebuilding statistics without rescanning. A missing,
invalid or timed-out DiE mode cannot establish a negative packing result. A positive
match in another mode remains recorded, with the overall tool failure counted.
This DiE-only workflow does not generate LIEF/extraction evidence or EXE products.

## Streaming RanDS Ghidra DIS/DEC

The [checkpoint direction plan](lmlm-checkpoints.md#approved-rands-disdec-extraction)
records the approved extraction scope and distinguishes it from training.
`malweave data rands-ghidra` reads an existing `rands-die` job **without writing to
it**, checks its passing release audit, source inventory and metadata checksums,
and freezes admission from the stored complete DiE evidence. It requires
`Arch=I386`, `Packed=false`, and three valid negative DiE reports. It does not
rerun DiE. Missing reports, timeouts, detected obfuscation and metadata rejection
remain visible in `selection.csv` and `selection.json`; corrupted or conflicting
evidence stops preparation before downloads.

Install/validate a compatible Ghidra and Java runtime separately, then run the
synthetic integration check before processing original PEs. The repository's
external-tool bootstrap currently proposes Ghidra 11.2.1 with JDK 21; an installed
Java 25 alone does not establish compatibility. A full JDK, including `javac`, is
required. The approved local installation, synthetic verification and 32-PE pilot
are complete. Full-corpus execution awaits review of the pilot's DEC failures,
runtime and output storage.

For a fresh job, a bounded two-batch pilot uses the production schedule. Point
`RANDS_DIE_JOB` to the path of a completed `rands-die` directory with the release
audit and SQLite.

```bash
uv run --locked --no-default-groups malweave data rands-ghidra run \
  --die-job "${RANDS_DIE_JOB:?Set RANDS_DIE_JOB to the completed RanDS DiE job}" \
  --job-dir data/processed/rands-ghidra-review \
  --analyze-headless "$GHIDRA_ROOT/support/analyzeHeadless" \
  --limit 32
```

The schedule is fixed to **16 source workers**, one CPU per Ghidra process and
batches of at most 16. It downloads the first batch, starts processing it, and
downloads one next batch concurrently. Each worker runs DIS then DEC in separate
headless processes. Thus at most 16 Ghidra processes run simultaneously, with at
most 32 staged PE inputs. Imported projects, logs and outputs consume additional
disk. No third download batch starts until the old batch scratch is removed.
Tail batches can contain fewer than 16 sources.

Every download uses the audited ETag and verifies length and SHA-256 before
Ghidra. Results are committed independently for DIS and DEC in SQLite WAL with
FULL synchronization. Batch cleanup runs after both views have terminal records;
it deletes only the job's PE/project/log/temporary-cache scratch, retaining result evidence,
normalized output and partial output. Shutdown stops Ghidra process groups,
waits for bounded S3 requests, commits available results, then cleans scratch.
Startup removes stale scratch only after validating the saved job contract.
Java/Ghidra temporary directories and native `TMPDIR` are isolated under each
view's scratch, including when an inherited environment points elsewhere.

Default heap is 1,024 MiB per JVM (`--heap-mb`), with additional native/OS memory
outside that limit. Sixteen workers were measured on the current machine in the
bounded pilot; this does not establish full-corpus capacity. The runner reserves
5 GiB free disk (`--min-free-gib`) plus planned PE
staging space and stops scheduling when the reserve cannot be maintained.
Projects and representations may grow during a task; this reserve is not a bound
on their maximum size. Measure RSS, disk expansion, throughput and class-specific
failure rates in the pilot before a full run.

```bash
uv run --locked --no-default-groups malweave data rands-ghidra status \
  --job-dir data/processed/rands-ghidra-review
```

`progress.json` refreshes while waiting and after batches. `summary.json` and
`dis-manifest.csv`/`dec-manifest.csv` are rebuilt from durable state at orderly
exit, including interruption. `state.sqlite3` contains selection decisions,
transfer attempts and gzip-compressed per-view evidence: commands, complete
stdout/stderr, ETag/hash verification and output digests. Normalized complete
outputs are under `representations/{dis,dec}`; nonempty incomplete outputs are
under `partial/{dis,dec}` and are counted as failures. Exit code zero and a
nonempty file alone cannot establish successful extraction: the script must
confirm completion, analysis must not time out, and decompiler failures must be
absent. Preserve upstream scripts and normalization rules for attribution.

For an unchanged job contract, rerunning without `--limit` continues after full-run
approval and storage planning. The recorded 2026-11-02 pilot used the runner before
temporary-directory isolation. Use a fresh job directory with the revised runner
and retain any recovered artifacts from the pilot as historical evidence.
Resume automatically skips every recorded terminal view, including failures, and
retries only uncommitted views. A crash after DIS commits can resume just DEC.
Changed tool/script/runner identities, metadata, inventory or admission evidence
require a new job directory. Resume checks recorded output digests before reuse.
Keep the job directory private and outside Git; it contains sample identities
and extracted representations. Output storage for the whole corpus must be
sized from measured expansion; streaming inputs does not bound retained output.
This streaming runner stores outputs locally. S3 publication and remote-backed
output eviction are not implemented here and require a separate storage plan.

### Experimental shared analysis benchmark

`--execution-mode shared-full` uses one import and one full DEC-style analysis,
then runs `Disassembler.java` and `Decompiler.java` in the same JVM. The default
mode remains `separate`. Shared analysis omits DIS's preScript that disables
`Stack` and `Decompiler Parameter ID`; output equivalence must be measured before
adopting this analysis profile. The researcher requested a bounded timing comparison
against the same 32 original sources as the separate-process pilot. This is not
approval for a full-corpus run or a change to training inputs.

```bash
uv run --locked --no-default-groups malweave data rands-ghidra run \
  --die-job "${RANDS_DIE_JOB:?Set RANDS_DIE_JOB to the completed RanDS DiE job}" \
  --job-dir data/processed/rands-ghidra-shared-full-revised \
  --analyze-headless "$GHIDRA_ROOT/support/analyzeHeadless" \
  --execution-mode shared-full --limit 32
```

The same 16 workers, two-batch PE limit, heap and script timeouts apply. One
process has a 780-second hard limit for analysis plus both scripts and overhead.
Each view's completion/error markers are read only from its own script's log
prefix. A completed DIS can succeed even when DEC later fails or the process
times out. A script that never starts is recorded as `not_started`; partial
outputs remain evidence. Both per-view results are committed after the shared
process returns; an interruption before that can require repeating uncommitted
work. Resume requests only missing views. Per-view `seconds` in this mode includes
the shared process wall time and overlaps between views; do not add DIS and DEC
totals to infer elapsed time. Execution mode is part of the immutable job contract.

## RawMal-TF EXE extraction and resume

The [S3 layout](../datasets/s3-layout.md#bucket-contents) records the published
EXE manifest. Use it when preparing experiments. For a RawMal-TF extraction job
on an unpublished bucket, use the matching ingestion snapshot, canonical RAW
objects and a profile with bucket access.

```bash
uv run --locked malweave data rawmal-exe \
  --job-dir data/processed/rawmal/exe-job \
  --bucket "$RAWMAL_BUCKET" --account "$RAWMAL_AWS_ACCOUNT" --profile "$RAWMAL_PROFILE"
```

The command validates `metadata/ingestion.sqlite`, processes SHA-256-verified
sources in batches of 16 with 16 workers, and writes content-addressed EXE objects
under `representations/exe/`. Conversion state goes to
`audit/jobs/rawmal-exe/state.sqlite3`, which a fresh local job can restore.
Use `--limit` to bound attempts and allow scratch for the active batch and a
5 GiB reserve. The command writes `representations/exe/manifest.csv` once all
sources have an outcome. For an existing published bucket, fetch its verified
manifest with `dataset-storage fetch --dataset rawmal --artifact exe-manifest`.
This extractor writes to a private staging bucket prepared from the pinned
ingestion snapshot and canonical RAW objects.

For Assemblage project-disjoint splits, use the build and license provenance
described in the [Assemblage dataset card](../datasets/assemblage.md).
