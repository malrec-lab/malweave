# Data preparation

RanDS is the downstream dataset shared by the two [research directions](research-protocol.md).
Existing RanDS audit/conversion evidence is retained. Additional SOREL/Assemblage processing
belongs to the **paused self-pretraining direction**.

## RanDS and the checkpoint direction

### Reusable Ghidra setup and synthetic CPU pilot

From a checkout on Linux x86_64 (Kaggle/CPU server), macOS ARM64 or macOS x86_64:

```bash
uv sync --locked --no-default-groups
uv run --locked --no-default-groups malweave data pilot-ghidra \
  --cache-dir "$HOME/.cache/malweave/ghidra" \
  --output-dir work/ghidra-pilot-first
```

This one command installs checksum-pinned Ghidra/JDK without sudo, generates the existing
three harmless PE fixtures, invokes the existing EXE and separate DIS/DEC extraction
commands, checks outputs and repeats extraction with `--resume`. It also verifies that
the tool cache is reusable. It does not read/download a research corpus or execute a PE.
One fixture has a synthetic ransomware **metadata label** only to exercise the schema;
all three binaries are harmless. This is an environment compatibility test, not a
malware-coverage or corpus-throughput pilot.

Add `--verify-unlimited` to compare the opt-in no-deadline drivers against both
baseline representations on all three harmless inputs before deploying them.

For setup alone use `malweave data setup-ghidra --cache-dir PATH`. The pins are in
`configs/tools/ghidra.yaml`: Ghidra 11.2.1 and Temurin JDK 21.0.13+9, retaining the existing
extraction versions. Native installation support is not proof of runtime parity across
hosts; retain each host's pilot report before using it for research extraction.
Linux ARM64 and Windows are rejected, not emulated.

The cache retains verified official archives and a digest-bound native installation.
Later calls verify the installed tree and reuse it without downloading again. Cache
directories can be copied/restored to another path on the **same OS/architecture**;
paths are resolved at use time. Do not reuse a Linux JDK on macOS. Modified or conflicting
installations are rejected rather than overwritten.

On Kaggle choose **Accelerator: None**, enable Internet for first setup, use
`/kaggle/temp/ghidra-cache` for tools and `/kaggle/working/ghidra-pilot` for outputs.
The pilot needs neither GPU quota nor cloud credentials. Fresh Kaggle sessions lose
temporary tool storage: restore a verified cache from private persistent storage or
attach a tool bundle, then use a writable cache directory. Merely closing the notebook
does not make that temporary installation persistent.

Keep `pilot-report.json`, phase logs, per-view manifests, output digests and closed
SQLite progress in private durable storage. The CLI deliberately does not guess a
bucket or embed credentials; a credentialed coordinator may publish these outputs.
Do not treat credential scrubbing as a parser sandbox. Real-malware processing still
needs an isolated worker, approved frozen cohort and per-source durable publication;
the synthetic pilot does not authorize full-corpus extraction.

For an explicitly approved real-PE timing pilot, the coordinator freezes
equal I386 sources per class from the audited snapshot and verifies selected S3
size/ETag references. A private manifest supplies digest-bound originals and
object-scoped, expiring HTTPS transfer URLs:

```bash
uv run --locked --no-default-groups malweave data benchmark-ghidra \
  --manifest PRIVATE_PILOT_MANIFEST.json --cache-dir TOOL_CACHE \
  --output-dir PRIVATE_NEW_ATTEMPT --workers 1 --isolated-worker
```

The initial benchmark uses ten sources at one/two workers and the original
2 GiB heap/time limits. A separate approved Fibonacci sweep uses the same 64
sources (32 per class) at 1/2/3/5/8 workers, fixes all heaps to 1 GiB and sets
the private manifest's `timeout_policy` to `unlimited`.
It retains metadata packing values; it does not claim negative DiE admission.
DIS/DEC retain independent analysis and rendering, with one CPU per JVM.
The no-deadline adapter omits `-analysisTimeoutPerFile`, uses the separate
`*Unlimited.java` drivers and Ghidra's `timeoutSecs=0` for functions, and does not
kill a parser merely because elapsed time is large. This intentional extension
is not the unchanged paper timeout protocol. Actual parser errors remain
partial/failed; removing deadlines does not repair invalid code or metadata.
The transfer coordinator verifies original bytes, starts parser
subprocesses without cloud credentials/URLs in their environment/configuration,
and publishes and reads back each source's output/diagnostics before evicting its
raw copy. Raw inputs and Ghidra projects remain in temporary scratch, not notebook
output. Parser subprocess isolation is still an operator/host responsibility;
`--isolated-worker` is an acknowledgement, not a sandbox.

Each source has a private archive. The no-deadline sweep additionally publishes
each completed view while the next view is running, and refreshes its heartbeat
about once per minute. An interrupted attempt may retain its last
unfinished input only in temporary scratch; already-published source evidence is
durable. This pilot command does not yet implement cross-session receipt-based
resume or full-corpus scheduling. Do not resubmit into the same authoritative
output prefix or describe it as a production rolling-cache runner.

Compare only configurations with the **same cohort, heap and timeout policy**.

### Fixed-size batches

The same command also accepts a batch manifest that declares `"mode": "batch"`,
`"heap_mb": 1024` and `"timeout_policy": "unlimited"`. Batch manifests are not
10/32/64 comparisons: they accept up to 1000 unique metadata-I386 sources with
either class mix, while still requiring sequential indices, verified identities,
1 GiB heaps and no per-file deadline. The report records `mode`, `batch_id` and
`tier`, and keeps pilot validation untouched for the earlier sweeps.

Batch planning for the RanDS corpus is recorded in
`configs/datasets/rands-ghidra-batches.yaml`. Priority only decides the run
order; every audited source stays queued. P1 combines both admission signals:
metadata-I386, three successful DiE modes with no obfuscation finding, catalogue
`Packed=0`, and EXE-digest-representative status (the dedupe rule of
`rands_training.prepare`). Samples where DiE reports no obfuscation but the
catalogue marks `Packed=1` are deferred to P2 instead of being dropped;
duplicates, conflicting labels, incomplete DiE, obfuscated samples and non-I386
binaries follow. The private manifest lists 682 batches of at most 400 sources
and about 300 MiB each. Grouping uses the EXE representation ETag, so it is an
equivalence proxy until EXE bytes are staged and hashed locally; train/val/test
assignment still belongs to `rands_training.prepare`, not to this plan.

On 2026-11-20 the researcher authorized replacing the current account's five
Ghidra jobs with five fresh attempts of 100 unfinished sources each, using
`--workers 12`, unchanged 1 GiB heaps and unlimited analysis. This is an execution
tuning attempt, not evidence of higher throughput. Preserve prior archives and
checkpoint evidence; freeze new membership only after old sessions stop and their
final evidence is reconciled. Sources beyond the selected 500 remain queued.
Do not change the running jobs on other accounts or silently retry terminal
partial/failed sources.
New attempts retain per-source current DIS/DEC phase and a bounded private stdout
tail while parsers run. Resource telemetry includes best-effort cgroup-v2 memory
usage/limit/events and CPU usage/quota/throttling counters when available. These are
container counters, not proof about one parser; OOM counters are cumulative.
Unavailable counters are explicit, not reconstructed as zeros. This does not
change analysis options, function traversal, deadlines or output normalization.

#### Native versus managed input routing

New `benchmark-ghidra` **batch-mode** runtimes inspect verified source bytes using
`pe-clr-routing-v2-exclude-dotnet` before launching Ghidra. RanDS `I386`, PE32 and a negative DiE
packing assessment do **not** establish that code is native x86.

- PE32/I386 without a declared CLR directory remains a native **candidate**, using
  the unchanged separate DIS/DEC profiles and timeout policy.
- A declared CLR directory with nonzero RVA and size routes IL-only, mixed-mode and
  managed-native-header inputs to `excluded_dotnet`, per the researcher's
  2026-11-20 approval. Record further CLR validation warnings without re-admitting
  declared managed sources.
- Malformed/ambiguous PE/CLR declarations and unsupported machines route to
  `pending_review`; they never fall through to forced x86 analysis.

Each source retains `routing.json` and its input digest in private evidence archives,
plus routing and explicit excluded/deferred DIS/DEC statuses in `parser-result.json` and the
source report. Excluded/deferred sources publish **no canonical representation**. The fixed
benchmark report retains their membership in `pending_sources`, per-class pending
counts, `excluded_sources`, per-class excluded counts and `remaining_representation_sources`. A final evidence archive means an
attempt was preserved, **not** that a deferred source was processed successfully:
resume/reconciliation must inspect these statuses and keep such sources queued.
The dashboard separates .NET exclusions and deferred records from partial/parser
errors. Exclusions are accounted for separately, never as successful representations.
For the post-exclusion P1 pool, pin the private membership list with
`pool.members_path` and `pool.members_sha256` in the dashboard registry, with
`pool.total: 27941`. All cross-attempt coverage sets are intersected with that
membership, so historical managed outputs cannot inflate the numerator. During
initial report loading, counts are provisional; inspect `reports_loaded` before
interpreting an apparent zero or a changing total of processed sources.

There is **no .NET DIS/DEC backend** in this plan; declared managed inputs are
excluded, not queued for IL/C# extraction. Never write C# as `.c` or call an entry
stub complete IL.
Historical success markers remain historical script-completion evidence, not
retroactive validation of managed-code coverage. No old evidence is deleted or
rewritten, and changing local source does not update already-running Kaggle jobs.
Deploy only in a fresh digest-bound runtime/attempt after reconciliation; do not
overwrite an active bundle. Legacy pilot mode retains its historical protocol.

Filter the full source plan **before** applying the unchanged P1–P7 priority order
and forming new 100-source batches:

```bash
uv run --locked malweave data filter-ghidra-plan \
  --plan work/ghidra-batches-v1/batches.csv \
  --evidence-db data/processed/rands/pe-header-all/state.sqlite \
  --inventory-db data/processed/rands/raw-s3/inventory.sqlite \
  --release-audit data/processed/rands/pe-header-all/release-audit.json \
  --output-dir work/ghidra-batches-native-v2 --batch-size 100
```

The operation reads retained structured LIEF data only, without source downloads,
Ghidra runs or binary execution. It requires a passing full-inventory release audit,
matches per-source key/size/ETag/label to that inventory, and retains each evidence
body's SHA-256 in resumable SQLite state. Historical ETag/size-based source verification
is inherited **as recorded**, not upgraded to fresh full-source SHA verification.
Use the same command with `--resume` after interruption; changed inputs or policy
require a new directory. Fixed `progress.json` records durable 100-source checkpoints.

Private `included.private.csv`, `excluded_dotnet.private.csv` and
`pending_review.private.csv` partition the original source membership. `batches.csv`
contains included sources only; `manifest.private.json` and `summary.json` retain
parent digests, priority/class counts, runtime and byte/batch accounting. No tier is
promoted, resampled or silently dropped. List these counts before launching jobs.
Reconcile all accounts' prior terminal evidence and active assignments before
selecting the current account's next five 100-source jobs. Non-I386 later tiers
remain planned but cannot run through the unchanged I386 benchmark admission.

The historical ten-source pilot is not a controlled baseline for the 64-source sweep.
Per-source timings include private publication; class-specific failure counts are
reported rather than discarded. Reports also retain file/byte throughput, size-bin
timings, sampled process-tree peak RSS and peak active parser count. File-count
batch proposals use ten usable hours, two hours of reserve and the slowest input.
The volume proposal additionally discounts MiB/hour by 25% and assumes a comparable
mix, not that time is linear in bytes. A small pilot
cannot establish a corpus tail; validate a larger authorized pilot before a full
run. A separate empty-notebook capacity probe on the current account received
`Maximum batch CPU session count of 5 reached.` This measured session limit is
distinct from each notebook's source worker count and may differ by account.

### Local Ghidra progress dashboard

Monitor registered Kaggle jobs across accounts without changing Kaggle login:

```bash
uv run --locked --no-default-groups --group train malweave data ghidra-dashboard \
  --registry work/ghidra-dashboard/jobs.private.json
```

Open `http://127.0.0.1:8765`. The server binds only to IPv4 loopback. It reads
explicit S3 report keys for current jobs every 60 seconds (configurable with
`--interval`, minimum 30); historical attempts use a separate polling pool every
15 minutes (or the current-job interval if longer). Historical log-heavy reports
cannot block current-job refresh. Conditional GETs use ETags to avoid downloading
unchanged reports. Browser refreshes use the in-memory cache. `--port` changes the local port.
The backend uses the existing AWS credential chain/project `.env` and
`MALWEAVE_RANDS_S3_BUCKET`; it needs only `s3:GetObject` for the registered reports.
No Kaggle credentials are needed for this read-only dashboard.

Keep the registry private and outside Git. Its schema is:

```json
{
  "pool": {"name": "P1", "total": 70028},
  "jobs": [
    {
      "account": "example-user",
      "name": "Batch 1",
      "slug": "example-ghidra-batch-1",
      "report_key": "analysis/private-batches/example/batch-0001/workers-21/benchmark-report.json",
      "historical": false
    }
  ]
}
```

Account membership comes from this explicit submission registry, not from S3
owner inference. Add a row when submitting a new job; restart the dashboard to
reload registry changes. Historical attempts can be shown separately; aggregate
totals count displayed attempts, **not unique corpus sources** across resumes.
The optional `pool` block adds a separate global coverage panel with an explicit
denominator. Register only jobs belonging to that pool. This panel unions source
SHA-256 identities across all registered reports, including historical attempts,
independently of account/history filters. Identities remain in backend memory;
only counts reach the browser. Both-view success can be satisfied across attempts.
It reports terminal source coverage (including failures) separately from both-view
success. Sources absent from report results, including unfinalized checkpoints,
are not counted. Missing reports/identities are flagged; this is report-based
coverage, not an authoritative full-store archive or representation audit.

The page displays terminal counts, both-view success, partial/failed counts,
per-view success, durable DIS checkpoints from unfinished sources, publication
receipt counts, report runtime, heartbeat age and sampled process-tree peak RSS.
Counts are claims from the report, not a fresh output-object checksum audit.
Parser success is not a representation-quality assessment. Partial outputs are
not automatically unusable samples. Process-tree RSS can double-count shared
pages and is not cgroup usage or proof of OOM.

A fresh heartbeat means the coordinator published recently; it does not prove
parser progress or current Kaggle session status. A running report older than
180 seconds is marked stale, not live. Read failures retain prior counts with
an explicit S3 read-error warning; a delayed collector/cache has a separate
"dashboard updating slowly" state and is not labelled a connection failure.
Historical caches have their own longer refresh budget.
Absent reports are unknown, not zero progress.
The browser receives only allowlisted aggregates and public notebook links,
never source digests, report logs, S3 keys, signed URLs or AWS credentials.
There are no start/stop controls, S3 writes or raw-sample downloads.
Stop with Ctrl-C; remote jobs are unchanged. Do not expose the server through a
public tunnel or reverse proxy.

### Approved VERA ratio-study staging

The researcher-approved VERA/Assemblage extension follows the
[ratio-study decision record](lmlm-checkpoints.md#approved-activelatent-ratio-study-2026-11-15),
not the paused self-pretraining preparation policy. Preparation does not authorize
the 21 full training runs.

When staging multiple ratio memberships together, use
`malweave.data.vera_training_release.stage_ratio_releases` with the
`(membership, config, output)` paths for each run. It shares a fresh in-process
token-digest cache across runs, keyed by verified EXE digest, tokenizer,
checkpoint configuration, adapter identity and truncation limits. Each unique
input is tokenized once; every membership still checks file bytes, its expected
token digest, labels, splits and ratios. The cache stores only digests, not
sample bytes or token arrays, and is not a persistent training-input cache.
Rebuild the private runtime bundle before deploying this API to Kaggle; an
already-running job does not pick up local code changes.

Verify restored private Assemblage DiE records with:

```bash
uv run --locked malweave data vera-benign-evidence-audit \
  --directory PRIVATE_ASSESSMENT_DIRECTORY --contract-id RECORDED_CONTRACT_ID
```

After the VERA admission scan finishes, build the complete per-source eligibility
table (including rejected/unknown outcomes) without rescanning:

```bash
uv run --locked malweave data vera-eligibility \
  --vera-directory PRIVATE_COMPLETE_VERA_ADMISSION_DIRECTORY \
  --benign-directory PRIVATE_ASSESSMENT_DIRECTORY \
  --contract-id RECORDED_CONTRACT_ID --output-dir PRIVATE_NEW_ELIGIBILITY_DIRECTORY
```

Incomplete VERA coverage, mismatched source identity or altered compressed evidence
blocks export. Use `eligibility.csv` for `vera-presplit --non-temporal`; no timestamp
admission is applied. Numeric sampling seeds remain explicit inputs, not defaults.
Eligibility retains known architecture and packing outcomes. Presplit reports
non-I386 and obfuscated exclusions separately from unknown evidence, and failed
assessments separately from architecture failures. Export into a new directory;
do not overwrite an earlier digest-bound cohort audit.

After admission and non-temporal ordered dedup, export ratio memberships with
`malweave data vera-ratios` and explicit recorded sampling/holdout seeds. Membership
tables are not training releases. Stage selected EXEs under `EXE_ROOT/vera/EXE_DIGEST`
or `EXE_ROOT/assemblage/EXE_DIGEST`, retaining original private S3 provenance. Then:

```bash
uv run --locked malweave data vera-stage-ratio \
  --membership PRIVATE_RATIO_DIRECTORY/split.csv \
  --config PRIVATE_FROZEN_RATIO_CONFIG.yaml --checkpoint ORIGINAL_MLM_DIRECTORY \
  --exe-root EXE_ROOT --output-dir PRIVATE_NEW_RELEASE_DIRECTORY
```

This verifies all EXE bytes, sizes and exact final tokens, group isolation and
class/state composition before writing the supervised-loader schema and matching
input-audit summary. Admission evidence and final researcher authorization remain
separate requirements. Missing/corrupt inputs abort staging; no silent filtering.

RanDS EXE has already been converted and uploaded to S3. The
[dataset card](../datasets/rands.md) documents release counts and the metadata-header issue.
Execution notes in the research workspace retain conversion, duplicate and conflicting-label
findings, including 73 conflicting-label EXE groups.

The [checkpoint plan](lmlm-checkpoints.md) must establish input/tokenizer compatibility
and cohort/split policy before reuse. Existing scratch preparation choices do not
automatically define checkpoint evaluation. Do not repeat conversion merely because an
older guide starts with data preparation.

## Streaming RanDS DiE assessment

### Hash-sharded Header migration

The researcher approved copying completed all-RAW Header outputs to the EXE-style
layout `rands/representations/pe-header/<source-prefix-2>/<source-sha256>.bin`.
This is a storage migration, not re-extraction or a changed dataset protocol.

```bash
uv run --locked malweave data pe-header-migrate \
  --manifest data/processed/rands/pe-header-all/manifest.csv \
  --bucket YOUR-PRIVATE-BUCKET \
  --output-dir data/processed/rands/pe-header-hash-migration --workers 128
```

The command retains original objects and reports, copies Header bytes server-side,
then reads every destination and verifies SHA256/size before a durable SQLite
checkpoint. Existing differing destination bytes abort rather than being overwritten.
Resume the identical command after interruption. Failed extraction rows are retained
in the new manifest. Only after all successful rows verify does it publish the new
manifest, summary and migration contract under `pe-header/layout-migrations/hash-sharded-v1/`.
The new manifest includes `historical_header_key`; original reports/contracts are
not rewritten. Local `progress.json` reports verified coverage and elapsed time.
The historical extractor still writes run-scoped outputs; this migration command
does not silently change that extractor's existing resume contract. Original-object
cleanup and extractor layout changes remain separate operations.

### Resumable PE Header run

The researcher subsequently expanded admission to **all 215,404 available RAWs**,
without architecture/packing selection. Use a separate run to preserve earlier
cohort outputs. The full admission manifest is
`data/processed/rands/pe-header-all-inputs/all-raw.csv`, with `split=unassigned`;
preparation does not invent train/validation/test assignments. Its admission audit
matches every inventory key/size to normalized RanDS metadata, verifies 110,788
benign and 104,616 ransomware sources, and accounts for 16,353 benign plus 5,930
ransomware metadata rows without RAW in a separate missing-source CSV. Total RAW
transfer is 182,133,336,077 bytes; temporary originals are removed per source.

```bash
uv run --locked malweave data pe-header-run \
  --manifest data/processed/rands/pe-header-all-inputs/all-raw.csv \
  --inventory data/processed/rands/raw-s3/inventory.sqlite \
  --job-dir data/processed/rands/pe-header-all \
  --output-prefix rands/representations/pe-header/runs/rands-all-raw-v1 \
  --workers 4
```

This is extraction only; tokenizer fitting, split selection and training remain
separate. The prior 62,563-source job is stopped and retained, not overwritten.

On 2026-11-12 the researcher authorized processing the full manifest used in the
Header pilot, preserving its existing labels/splits (62,563 sources, not all RanDS).
This authorizes extraction, not training or changes to split/dedup policy.

```bash
uv run --locked malweave data pe-header-run \
  --manifest data/processed/rands/raw-s3/raw-train-balanced-full-split.csv \
  --inventory data/processed/rands/raw-s3/inventory.sqlite \
  --job-dir data/processed/rands/pe-header-full \
  --output-prefix rands/representations/pe-header/runs/rands-manifest-v1 \
  --workers 4
```

Before admission, require a completed inventory and match every source's key, size,
ETag, label/split validity and unique identity. The release audit reports admitted
class/split counts and bytes. Baseline Mini Mamba split equivalence remains unverified.
The cohort is inherited, not newly selected as a training protocol. Remote contract
pins manifest, extractor/runner code and LIEF version; changes reject resume.
Use one machine/writer per S3 run prefix; local locking does not coordinate hosts.

Each worker downloads one ETag-pinned RAW, checks size without rehashing full source,
and invokes LIEF in an isolated child. Temporary RAWs are removed after each source.
Immutable Header bytes and complete structured extraction evidence/history are uploaded
before the recoverable source pointer and FULL-synchronous local SQLite checkpoint.
Upload failures stop the run. Local checkpoint loss recovers per-source S3 pointers;
restored successful Headers have their digests checked. Partial work without a pointer
is safely attempted again. Historical failed attempts are retained.

`Ctrl-C` or `kill -TERM PID` stops admission and drains active workers. Restart the
same command/directory to resume. A power-off can lose active work, not committed
source checkpoints. Orphan temporary directories can remain after hard termination;
they are ignored on resume. Do not run two instances against the same remote prefix.
Add `--retry-failures` to explicitly retry accounted failures without deleting history;
ordinary resume retains failures as failures, never as successful extraction.

The first run stopped on an interrupted S3 evidence read-back (`IncompleteRead`),
not a PE rejection. The transport patch retries interrupted response reads up to
six times with backoff and enables SDK request retries. To resume that existing
run with the explicitly verified transport-only runner revision, append
`--inherit-runner-sha256 4fa19e24c365ed50d8ae4c024206e7ede700d8aebed28c34f45d84a58259f26a`
to its command. This preserves the original immutable contract, checks every other
contract field unchanged, and publishes the new runner identity/reason separately.
It is not permission to inherit arbitrary extraction or cohort changes.

The all-RAW run subsequently exited with code 137 while restoring its large
checkpoint; SIGKILL/memory pressure is suspected, not independently established.
The runner now retains only compact source/status/Header reporting fields in RAM.
Complete per-source evidence remains unchanged in SQLite and S3, and extraction
semantics are unchanged. For this reviewed memory-only revision, resume the
all-RAW command with
`--inherit-runner-sha256 852d44604039a0efe79915d2be49dde80b037d6cd6135b475e5d3824c68f14e8`.
This pins the existing contract and records the new runner revision separately.
The researcher subsequently requested 16 Header workers. The runner now accepts
1–16; the reviewed concurrency-only limit change uses the same original-contract
inheritance flag above and records its own runner revision. Resume with
`--workers 16` only after the previous writer has drained and released the job
lock. This does not increase VERA scan workers or change extraction semantics.

`pid.json`, `progress.json`, `state.sqlite`, and final `manifest.csv`/`summary.json`
live in the job directory. Progress reports status/class/split coverage, runtime and
output bytes. Manifest/summary upload at graceful stop/completion; per-source S3
records remain authoritative if final export is interrupted. Full-corpus Header
duplicate and token-input leakage audits remain required before training.

### Bounded PE Header pilot

The researcher authorized a Header download/extract/upload batch on 2026-11-12.
This is representation preparation only, not authorization for full-corpus processing
or a frozen scratch-training protocol. Use a private bucket and a fresh pilot prefix:

```bash
uv run --locked malweave data pe-header-pilot \
  --manifest data/processed/rands/raw-s3/raw-train-balanced-full-split.csv \
  --bucket YOUR-PRIVATE-BUCKET \
  --output-prefix rands/representations/pe-header/pilots/UNIQUE-ATTEMPT \
  --job-dir data/processed/rands/pe-header-pilot/UNIQUE-ATTEMPT
```

Default admission is two available sources per label/split (12 total). The supplied
manifest's labels/splits are inherited, not certified as the Mini Mamba baseline.
RAW downloads use the stored ETag and size; the existing source SHA-256 is inherited,
not recalculated or claimed independently verified. ETags are not content SHA-256.
LIEF parses the PE and retains structured evidence; raw bytes `[0:SizeOfHeaders]`
are sliced without rebuilding, including padding. Invalid sizes are rejected, not clipped.
Each Header and evidence record is uploaded with no-overwrite semantics and read-back
digest verification. Temporary downloaded RAWs are removed; S3 originals/EXE are unchanged.
Failures remain in records/manifest; upload failure stops the pilot. Use a fresh directory
on rerun: this bounded pilot does not implement full-corpus resume. Full processing requires
a release audit, durable resume and agreed baseline/cohort identities first.

The first 12-source pilot completed 12/12 extractions and verified uploads, producing
15,360 Header bytes in 12.84 seconds, with no exact cross-split Header duplicates in
that batch only. This does not establish corpus-wide duplicate safety. Private manifests,
complete LIEF evidence and summaries remain under the pilot job directory and S3 prefix.

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
