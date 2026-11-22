# Four-machine Ghidra + DiE with a rolling S3 cache

> Retained at the researcher's request during the branch switch on 2026-11-12.
> The local rolling-cache implementation, worker image files and installer commands described
> below were discarded, not merged into this branch. Do not run this as a current branch guide.
> Its layout and pilot notes are historical; current preparation uses
> [the maintained data workflow](data-preparation.md).

This workflow extends the existing local-corpus workflow without requiring a copy of the corpus
on each machine. It uses AWS S3, not Runpod volume credentials. The current extraction scope
remains **metadata I386, both packing values**. Architecture expansion is deferred; the plan
reports non-I386 exclusions explicitly. Do not describe this selection as the complete RanDS corpus.

## Safety and prerequisites

### Current S3 layout (supersedes older pilot prefixes below)

Use `--output-prefix rands/representations/_control/JOB_ID` for **all** plan publication,
worker, status and merge commands. The plan is stored as `manifest.json`, including the four-way
source assignment. Assignment never appears in representation keys:

```text
rands/representations/
  exe/                         # existing product, untouched
  dis/<sha256[:2]>/<sha256>.dis
  dis/manifest.csv
  dec/<sha256[:2]>/<sha256>.dec
  dec/manifest.csv
  _control/JOB_ID/
    manifest.json              # frozen plan and assignments
    _state/sources/<shard>/<sha256>/  # stage checkpoints, DiE, receipts, logs
    _state/workers/<id>/        # exclusive locks and per-worker progress
    _state/attempts/<id>/       # runtime provenance
```

This matches the existing EXE product's direct hash-sharded layout (no `dataset/` layer).
Original `RanDS_PE_Dataset/Benign.csv` and `Ransomware.csv` remain the label authority; do not
copy the full raw metadata into a selected derived cohort. Merge publishes per-view `manifest.csv`
only after exact source coverage and artifact verification, including failed sources as explicit
status rows. Before merge, durable receipts/checkpoints are authoritative for pilot progress.
The worker control records are deliberately separate: independent locks and conditional progress
updates cannot safely be collapsed into one JSON file written by all four machines.

Existing representation keys are never overwritten with conflicting bytes. Changing protocol
requires a separate representation root, for example `rands/representations-v2/_control/JOB_ID`.
A root-level `_control/representation-contracts/` record reserves each view for its frozen
extraction contract before workers publish any bytes, even across different job IDs.
A new job ID alone does not authorize replacing `dis/` or `dec/`. Old `part-*` prefixes are not
automatically adopted or migrated. Do not resume an earlier layout with this code.

### Prebuilt Linux worker image

Build before renting compute:

```bash
docker build --platform linux/amd64 -f docker/analysis/Dockerfile \
  -t YOUR_REGISTRY/malweave-analysis:VERSION .
docker run --rm --platform linux/amd64 YOUR_REGISTRY/malweave-analysis:VERSION \
  malweave data verify-analysis-tools --tools-file /opt/analysis-tools/analysis-tools.json \
  --work-dir /workspace/verify
docker push YOUR_REGISTRY/malweave-analysis:VERSION
```

Select this image directly when creating a Runpod CPU pod; pin its registry digest for deployment.
The default command serves SSH (public-key authentication only, using Runpod's `PUBLIC_KEY`).
The image uses Ubuntu 20.04 and explicitly installs `libicu66`: the pinned DiE portable binary
links to ICU 66 and does not run against Ubuntu 22.04's ICU 70 alone. Ubuntu 20.04 is outside
standard maintenance; production deployment needs an explicit security-maintenance decision
(ESM or a separately pinned and verified newer DiE build). Do not treat this image as a sandbox
or expose SSH publicly without the worker's network/access controls.
An explicit command runs instead of SSH. Software lives in `/opt/malweave`; mount runtime work at
`/workspace`. Tool paths are in `/opt/analysis-tools/analysis-tools.json`. No training stack, raw
samples, private plans, `.env`, AWS keys or Runpod management keys are included. Credentials must
be supplied at runtime with least privilege; never use Docker build arguments for secrets.
Build-time and runtime verification use a generated benign PE, not corpus samples. A Mac ARM
build uses emulation for amd64 verification; actual Runpod network/resource suitability still
requires a bounded pilot. No automatic pod shutdown is configured.

- Use dedicated isolated macOS/Linux analysis workers, not a personal workstation with live
  credentials/shared folders. The `--isolated-worker` flag is an operator acknowledgement, not a
  sandbox. Credential scrubbing does not prevent filesystem/network access by a compromised parser;
  enforce that isolation at the OS/VM level. Only the coordinator needs AWS access.
- Install a compatible Ghidra/JDK and native `diec` release from official sources. Freeze the entire
  installation including the DiE signature database. Installation is opt-in via the command below.
  Tool/script hashes and the managed DiE installation tree (including signatures/libraries) are
  recorded. Changing signature files invalidates resume, even if the launcher is unchanged.
- `uv sync --locked --no-default-groups` installs only the data-worker Python dependencies,
  including boto3, not PyTorch/CUDA. Use `uv run --locked --no-default-groups ...` on lean workers.
  Configure `AWS_*`
  in the private `.env` or a least-privilege AWS profile. S3 permissions must include listing/reading
  source objects and listing/reading/writing the chosen output prefix. Conditional object writes
  (`IfMatch`, `IfNoneMatch`) are required for part ownership and immutable records.
- Do not put hashes, manifests, raw bytes or outputs in Git. `work/` is ignored. Use private S3
  output prefixes, distinct from the original release prefix, with appropriate lifecycle/backups.

## 1. Coordinator: audit and freeze one plan

Replace bucket placeholders with private values. The CLI loads `.env` automatically; placeholders
in these examples are not environment variables and are not sample paths.

```bash
uv run --locked malweave data plan-ghidra-s3 \
  --bucket YOUR_RANDS_BUCKET \
  --source-prefix RanDS_PE_Dataset \
  --output work/ghidra-s3/plan.json
```

Only metadata CSVs and S3 listings are read. The audit checks full-release file/class/shard counts,
metadata joins, object paths and sizes before selecting I386. Missing metadata-backed files are
counted separately. Byte hashes are checked on the worker after each RAW download, not by listing.

Sources are assigned to exactly four parts using descending size and SHA-256 tie-breaking,
always choosing the least-loaded part. The plan includes its own digest and cannot be overwritten.
Copy **that same private plan** to each worker. Do not generate four independent plans.

## 2. Verify tools on every actual machine

Before renting a worker, publish the audited frozen plan from the local coordinator:

```bash
uv run --locked malweave data publish-ghidra-plan \
  --plan work/ghidra-s3/plan.json --output-bucket YOUR_OUTPUT_BUCKET \
  --output-prefix rands/representations/_control/JOB_ID
```

Transfer the same private plan with the immutable code/config bundle to workers. Startup checks
S3's server-validated full-object SHA-256 and length using HEAD with checksum mode, not a 55 MB
GET. ETag or user-supplied metadata is not accepted as a checksum. Legacy plans without the
checksum are rejected; prepare a new prefix locally rather than overwriting an existing run.
All worker commands must use this same prepared prefix (the examples below are illustrative).

From a checkout with Bash and curl, bootstrap pinned uv/Python, data-only dependencies and
JDK/Ghidra/DiE, then verify using a generated benign PE:

```bash
bash scripts/setup-ghidra-worker.sh --analysis-only
```

Logs: `work/setup-analysis/setup.log`. Only `SETUP PASSED` confirms runtime verification.
This mode needs no sudo, system Java, credentials or RAW inputs, and does not install training
dependencies or edit `.env`. Do not use the legacy mode (without `--analysis-only`) on lean pods.
On minimal Ubuntu 20.04 images the portable DiE release additionally requires system runtime
packages `libpcre2-16-0` and `libdouble-conversion3`. Have the image administrator install them
before setup (the bootstrap does not run apt or sudo). Bundled Qt alone is not sufficient.
First-time downloads still take time; this cannot eliminate network or Linux compatibility checks.
Prepare/cache pinned archives before starting paid compute where possible.

Docker is optional. Bootstrap native tools with the **same command on both machines**:

```bash
uv run --locked --no-default-groups malweave data install-analysis-tools \
  --install-dir "$HOME/.local/share/malweave/tools" --verify
```

The bootstrap detects macOS ARM64/Intel or Linux x86_64, downloads the official pinned Ghidra
11.2.1, DiE 3.21 and Temurin JDK 21.0.13+9 assets, checks committed SHA-256 values **before extraction**,
and writes `analysis-tools.json` containing the native executable paths and `java_home`.
The ARM64 macOS `.pkg` is expanded
with `pkgutil --expand-full` into the user directory: package install scripts are not executed.
No Docker, sudo, shell-profile changes, `.env` changes, or malware downloads are involved.
Archives are discarded after extraction. Existing recognized installs are reused; conflicting
installs are not overwritten. Pins live in `configs/tools/analysis-tools.yaml`.

The `--verify` flag performs the synthetic smoke test before reporting setup success. JDK selection
is passed explicitly to parser processes through the tool JSON; no `brew`, `apt`, manual exports,
or changes to the system Java are required. Java/Ghidra user caches are isolated inside each job.
Java versions other than 21 fail early with an actionable message instead of an opaque OSGi error.
Java is forced into true headless mode to avoid AWT shutdown threads keeping completed Mac jobs
alive. Ctrl+C/SIGTERM terminates this coordinator's parser groups and preserves resumable checkpoints.
Ghidra application caches and JVM temporary files are placed inside each source's metered cache
directory, rather than the shared `/var/tmp` cache, and are removed after verified publication.

Linux uses the Ubuntu 20.04 x86_64 portable DiE release; libc/Qt compatibility must still be checked
on the actual distribution. Its managed `malweave-diec` launcher sets the bundled Qt library path
and preserves quoted file arguments; do not substitute the raw `base/diec` binary.
Linux ARM64 is not silently emulated and needs a separately verified
native build. The bootstrap does not install missing OS shared libraries; verification detects
runtime incompatibilities on the actual machine. All machines still need the repository and the
pinned `uv` version; the native setup command does not clone code or replace the Python environment.

Then verify the installed paths without manually copying the long package paths:

```bash
uv run --locked --no-default-groups malweave data verify-analysis-tools \
  --tools-file "$HOME/.local/share/malweave/tools/analysis-tools.json" \
  --work-dir work/ghidra-tool-check
```

Alternatively, supply both tool paths explicitly:

```bash
uv run --locked --no-default-groups malweave data verify-analysis-tools \
  --analyze-headless /opt/ghidra/support/analyzeHeadless \
  --die-command /opt/die/diec \
  --work-dir work/ghidra-tool-check
```

Use native absolute tool paths on macOS as well. This runs the existing DIS and DEC scripts and
all three DiE modes on a generated harmless NOP/RET PE, never a malware sample. Inspect the local
`tool-verification.json` and log. The command fails if any required tool stage fails. Merely having
Java in PATH is not sufficient. A synthetic success does not establish corpus coverage or safety.

## 3. Worker: pilot one unique part, then resume

Use part IDs **1, 2, 3, 4**, each on a different machine, and one common output prefix:

```bash
uv run --locked --no-default-groups malweave data run-ghidra-s3 \
  --plan work/ghidra-s3/plan.json --part 1 \
  --output-bucket YOUR_OUTPUT_BUCKET --output-prefix rands/representations/_control/JOB_ID \
  --analyze-headless /opt/ghidra/support/analyzeHeadless \
  --die-command /opt/die/diec \
  --work-dir work/ghidra-part-1 --isolated-worker \
  --workers 1 --max-cpu 1 --heap-mib 2048 \
  --cache-gib 4 --job-gib 1 --reserve-gib 2 --limit 10
```

The worker also accepts `--tools-file` instead of the two explicit tool path flags above.

After inspecting pilot results, rerun **the same command without `--limit 10`**. Resume is automatic;
existing remote receipts and their actual output bytes are verified before they are skipped.
Repeated limited runs advance pending work. Changing extraction settings/tools/config requires a
new output prefix/work directory. Concurrency and disk budgets can change without changing content.
Use a supervisor/tmux on Linux or an approved non-sleeping macOS worker; the CLI itself is foreground.

The worker does not stage a whole part. Each source goes through:

```text
bounded download -> size + SHA-256 verification -> DIS -> DEC -> DiE
    -> upload results/log -> read back and hash -> immutable receipt -> delete local source/output
```

DIS/DEC/DiE checkpoints are independent and published on S3 as soon as each stage completes. If a
machine disappears before its final source receipt, another compatible host restores those verified
artifacts and runs only the remaining stages. Finished representations are not uploaded twice.
The S3 worker now imports/analyzes each source once and chains DIS then DEC, following RawByteClf
commit `2502450e40ac00363e168106662aac29821d4a93` (`run/liftMini.sh`). Analysis timeout defaults
to 300 seconds; DIS uses 60/30 seconds per file/function and DEC uses 300/60. Unlike the legacy
separate-view runner, shared analysis does not use the DIS-only analysis pre-script. This intentionally
changes the extraction contract: use a new output prefix, never mix earlier separate-view receipts.
`LiftCheckpointed.java` calls the unchanged upstream lifting scripts and marks each stage only after
the script returns. The Python watchdog normalizes/publishes completed DIS while DEC is running;
partial output without a completion marker is not accepted after a crash. A replacement host must
repeat import/analysis if only one view remains, but skips the completed lifting script.
Per-view runtime includes shared analysis and is not additive; use coordinator wall time for
throughput. This scheduling change is not evidence of identical outputs to the prior DIS pre-script
configuration or of measured corpus speedup. Ghidra 11.2.1 and the RanDS cohort remain extensions.
A parser timeout/failure remains a terminal result, and DiE
still runs; DiE results never gate Ghidra. Tool failures are not silently retried into a different
cohort. Use a new, documented repair job if terminal parser failures need another attempt.

Upload errors retain the local source and completed analysis. After a failed batch, no more sources
are scheduled; already running workers finish. No raw originals are deleted from S3. Cleanup only
touches the matching source cache after verified publication. Compact state and receipts remain local.

### Resource controls

- `--workers` limits source jobs. A free slot is refilled immediately, without waiting for the slowest
  source in a batch. Each slot sequentially handles transfers, Ghidra and DiE; dedicated prefetch/
  uploader pools are deferred until pilot measurements show those stages are a bottleneck.
- A worker is one source-processing slot, not one machine or a permanent Java process. Four machines
  can each run multiple workers. Active slots are capped at
  `min(--workers, floor(--cache-gib / --job-gib))`. Admission checks use CPU affinity/cgroup RAM
  where available. CPU oversubscription is allowed with a warning; an impossible aggregate heap
  budget is rejected. The RAM estimate includes 512 MiB native overhead per worker plus 2 GiB
  coordinator/OS reserve, but is not a hard per-process RAM quota or a guarantee against OOM.
  Four parts do not impose a four-worker global limit.
- `--max-cpu` bounds Ghidra analysis CPUs; `--heap-mib` caps each Java heap. Native/JVM overhead and
  the Python source buffer still need RAM. Start at one worker and measure RSS before increasing.
- `--cache-gib` bounds reserved active cache slots; `--job-gib` reserves space for one RAW plus
  projects/output/logs, not just input size. Each active job has a periodic disk watchdog. This is a
  soft limit (polling can overshoot), not an OS filesystem quota. Provision a hard quota if required.
- Free space must also cover `--reserve-gib`. A disk-budget failure stops work and retains evidence;
  increase the budget before resuming. Very large sources fail preflight rather than disappear.
- Summary updates after each completion and at exit include class/packing coverage,
  failures, output size, runtime and maximum observed parser-child RSS. RSS is not total simultaneous
  machine RAM. Sources/hour includes receipt verification on resume, not only fresh analysis.

For a 16 GiB / 8-core Mac, start at one worker with a 2 GiB Java heap and one analysis CPU, then
benchmark two workers; do not assume eight workers fit just because there are eight cores.
The practical ceiling is the minimum of CPU capacity, measured per-job peak RAM after OS reserve,
and cache slots. Bigger servers can try 2/4/8 workers only when those budgets allow it. Java heap
alone is not an adequate RAM estimate.

For an explicitly requested **stress test** on 32 allocated CPU threads / 128 GB RAM / 100 GB
disk, the following uses 64 source slots with one analysis CPU and a 1 GiB heap each:

```bash
uv run --locked --no-default-groups malweave data run-ghidra-s3 \
  --plan work/ghidra-s3/plan.json --part 1 \
  --output-bucket YOUR_OUTPUT_BUCKET --output-prefix rands/representations/_control/PILOT_ID \
  --tools-file "$HOME/.local/share/malweave/tools/analysis-tools.json" \
  --work-dir work/pilot-100-w64 --isolated-worker \
  --workers 64 --max-cpu 1 --heap-mib 1024 \
  --cache-gib 64 --job-gib 1 --reserve-gib 8 --limit 100
```

This is 2x CPU oversubscription, **not a recommendation that it is fastest**. A 1 GiB heap is a
distinct extraction configuration and may increase failures; do not combine its artifacts with a
2 GiB job under one contract. With 64 workers, 100 sources cover fewer than two waves and cannot
establish steady-state full-corpus throughput. Inspect failures and resource usage before scaling.
Do not extrapolate from a stalled JVM or a failed tool-verification run to a rental budget.

### Ownership and recovery

Progress is published to `<output-prefix>/_state/workers/N/progress.json` on S3 after every verified source,
at startup/exit, and approximately every 15 seconds while waiting for tools. The same snapshot is
kept in the local work directory and logged to stderr. Phases are `running`, `paused` (pilot limit
reached), `complete`, `interrupted`, and `failed`. Hard power loss cannot publish a final event:
check `updated_utc` for a stale heartbeat, stop the old owner, then recover its lock explicitly.

The private frozen plan is also uploaded once to `<output-prefix>/manifest.json`. Verified per-source
`receipt.json` objects remain the resume authority, not the mutable aggregate progress counter.
`durable_receipts` counts receipt objects discovered on S3; `published` and coverage count receipts
whose output bytes were verified in this invocation. Those verification counters restart on resume;
this is not loss of durable work. A progress upload failure stops further scheduling and keeps
existing receipts/results; a subsequent run reconciles those receipts even with no local state.
Snapshots contain aggregate counts, worker/cache counts, UTC timestamps and opaque contract/owner
identifiers, not per-source inventories or credentials. Conditional writes reject stale publishers.
`new_receipts_this_invocation` and `pending_source_limit` distinguish a 100-source pilot from the
whole part. The S3 HTTP connection pool scales with configured concurrency, with bounded retries.

Contract schema 2 permits different installation/config paths on a replacement host with the same
OS/architecture, tool bytes/signatures, code, config digest and analysis settings. Absolute paths and
runtime provenance are saved under `_state/attempts/<owner>/environment.json`, not used as semantic
identity. Existing legacy contracts are not silently upgraded: use a new output prefix for them.
An already-running process does not pick up new progress code. Do not hot-restart an active run
under a changed code contract or silently overwrite its existing prefix.

One local file lock and a conditional S3 lock protect each part. A crash can leave an active remote
lock: **first stop the old owner**, then add `--recover-lock` once. Never recover a live owner's lock.
Moving a part between Mac and Linux remains blocked by native tool/platform identity. Separate
Mac/Linux parts can use different native installations; cross-platform output parity is not proven.

Read progress without SSH, or restore the private plan on a replacement worker:

```bash
uv run --locked --no-default-groups malweave data status-ghidra-s3 \
  --output-bucket YOUR_OUTPUT_BUCKET --output-prefix rands/representations/_control/JOB_ID --part 1

uv run --locked --no-default-groups malweave data fetch-ghidra-plan \
  --output-bucket YOUR_OUTPUT_BUCKET --output-prefix rands/representations/_control/JOB_ID \
  --output work/ghidra-s3/plan.json
```

### Fresh replacement worker (no retained disk)

Keep the exact deployed code bundle, `uv.lock`, dataset config, tool pins, output bucket/prefix,
part number and analysis settings outside the disposable machine. A Git branch name alone is not
an immutable deployment snapshot. Do not deploy a newer checkout into an existing job contract.
The setup command below requires that checkout/bundle to be present; it does not fetch code or
credentials. Provision AWS access privately after setup; never embed it in an image or bundle.

1. Stop the previous owner before taking over its part. A stale heartbeat alone is not proof
   that the previous owner is stopped.
2. Restore the exact deployment bundle/config on a Linux x86_64 replacement worker and run:

   ```bash
   bash scripts/setup-ghidra-worker.sh --analysis-only
   ```

3. With private AWS access configured, fetch the frozen plan using `fetch-ghidra-plan` above.
   If this is the first launch and the plan has never been published, restore the original audited
   private plan instead; do not silently generate a new assignment.
4. Run the same `run-ghidra-s3` command, with the same part, bucket/prefix, heap and analysis
   settings, but a fresh `--work-dir` and the replacement machine's `--tools-file`. Add
   `--recover-lock` only if the stopped old owner left an active lock. Worker count and cache
   budgets may change; extraction settings may not.
5. Verified receipts skip completed sources. Remote stage checkpoints restore finished DIS/DEC/DiE
   for incomplete sources. Only work not durably checkpointed must be repeated. Receipt verification
   reads derived S3 outputs, so resume still has network/verification cost.

Never erase an old contract to make an incompatible resume pass. Runs made before shared Ghidra
analysis require their original code/config or a separate new prefix, not mixed receipts.

## 4. Verify and merge all four parts

```bash
uv run --locked malweave data merge-ghidra-s3 \
  --plan work/ghidra-s3/plan.json \
  --output-bucket YOUR_OUTPUT_BUCKET --output-prefix rands/representations/_control/JOB_ID \
  --summary reports/ghidra-s3/merged-summary.json
```

The merger rejects missing/extra source receipts, incompatible code/config/analysis settings,
source mismatches and corrupted output bytes. Native binary differences are recorded but cannot
prove semantic equivalence; pin matching release versions across machines. A complete run means
all sources have durable results, **not** that every DIS/DEC/DiE attempt succeeded. Keep those
failure and class-specific coverage counts when forming a later experiment cohort.

DiE's `unpacked=true` means all three scans completed without a configured obfuscation-type
detection. `false` means such a detection occurred; `null` means incomplete/unknown. This is a tool
annotation, not ground truth or proof of a file being safe. Provider `metadata_packed` is retained
independently. No packing result removes a source.
