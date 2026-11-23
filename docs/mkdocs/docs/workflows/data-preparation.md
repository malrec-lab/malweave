# Data preparation

RanDS is the downstream dataset shared by the two [research directions](research-protocol.md).
Existing RanDS audit/conversion evidence is retained. Additional SOREL/Assemblage processing
belongs to the **paused self-pretraining direction**.

## RanDS and the checkpoint direction

RanDS EXE has already been converted and uploaded to S3. The
[dataset card](../datasets/rands.md) documents release counts and the metadata-header issue.
Execution notes in the research workspace retain conversion, duplicate and conflicting-label
findings, including 73 conflicting-label EXE groups.

The [checkpoint plan](lmlm-checkpoints.md) must establish input/tokenizer compatibility
and cohort/split policy before reuse. Existing scratch preparation choices do not
automatically define checkpoint evaluation. Do not repeat conversion merely because an
older guide starts with data preparation.

## RawMal packing audit on a local machine

Use the private RawMal bucket and `main/samples.csv`. The pilot defaults to
PE/I386 without excluding CLR, and selects pending sources in SHA-256 order.
It is a throughput/health check, not a representative packing-rate estimate.

```bash
uv run --locked --no-default-groups --group train malweave data rawmal-die run \
  --bucket "$RAWMAL_BUCKET" --job-dir data/processed/rawmal-die-3.21-v1 \
  --workers 64 --limit 1000
```

There is one pool for download and static scanning. Temporary PE files are
verified by size and SHA-256 before scanning and removed after the SQLite result
commit. The defaults reserve at most 4 GiB in flight, leave disk headroom and
record files over 256 MiB as deferred. Review timeout/error counts before removing
`--limit` to resume; the full run first checks the selected S3 inventory. Resume
skips recorded outcomes, including failures. The job retains private
`assessment.csv`, `filtered.csv`, and full scan evidence in SQLite. `filtered.csv`
requires all three valid negative DiE reports and a successful `file` call.

To retry unresolved download/tool errors after analysis, rerun with
`--retry-unknown --workers 8` instead of `--limit`. This makes one additional
attempt per eligible source, archives the old result and evidence, and refreshes
both CSVs. Repeating the command after interruption skips committed retries.

The run does not write to S3. After a completed audited run, `rawmal-die publish`
with the same `--job-dir` and an unused `--publish-prefix rawmal-filtered-<version>`
copies accepted source objects within the private bucket and publishes CSVs.
Do not reuse the prefix for a different job. The original `raw/` is not modified.

## Streaming RanDS DiE assessment

`malweave data rands-die` downloads original PEs from the private S3 root in
`MALWEAVE_RANDS_METADATA_S3_PREFIX`. It reuses `data/pe_assessment.py`, ported from
RawByteClf's `src/data/detect_packing_sorel.py`: recursive, deep and heuristic JSON
scans, 10 seconds per mode, and the union of the original obfuscation types.
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
mkdir -p data/processed/rands-die-local
nohup uv run --locked --no-default-groups malweave data rands-die run \
  --job-dir data/processed/rands-die-local --workers 10 \
  > data/processed/rands-die-local/run.log 2>&1 < /dev/null &
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
  --job-dir data/processed/rands-die-local
tail -f data/processed/rands-die-local/run.log
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
runtime and output storage. Measured results belong to the research workspace's
`research-notes/lmlm/notes/01-data-preparation.md`, section 2.6.

For a fresh job, a bounded two-batch pilot uses the production schedule:

```bash
uv run --locked --no-default-groups malweave data rands-ghidra run \
  --die-job data/processed/rands-die-local \
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
temporary-directory isolation; keep its `rands-ghidra-local` artifacts intact and
use a new job directory with the revised runner. There is no implicit state migration.
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
  --die-job data/processed/rands-die-local \
  --job-dir data/processed/rands-ghidra-shared-full \
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

## Retained self-pretraining workflow — paused

- [SOREL run guide](sorel-conversion.md): existing setup, continuation, publication and resume commands.
- [SOREL protocol](sorel-protocol.md): approved conversion rules and unresolved unknown-ISA policy.
- [Assemblage card](../datasets/assemblage.md): retained source revision, archive and metadata requirements.
- [Self-pretraining plan](self-pretraining.md): external overlap checks, representation/project grouping,
  external-training-only BPE and proposed downstream comparisons.

If this direction resumes, audit Assemblage metadata before writing an adapter; retain
project/build/license provenance and explicit failures. Assemblage is background software,
not AV-certified benign ground truth. Audit external-to-RanDS overlap before fitting BPE,
and preserve complete EXE files, source records and extraction evidence.
