# SOREL conversion protocol (v3.1)

**Status: paused**, under [self-pretraining](self-pretraining.md).
Previously approved rules below remain preserved; [checkpoint evaluation](lmlm-checkpoints.md)
is the current priority.

Approved with the researcher on 2026-10-25. This is the maintained conversion contract
for `sorel-exe-v3.1`, schema 3. Use the [run guide](sorel-conversion.md) for commands
and [self-pretraining](self-pretraining.md) for recorded progress. Pending decisions
remain pending; implementation defaults are not researcher approval.

## Scope and scientific contract

- Process all 9,962,820 malware metadata rows from release 09-DEC-2020. Assemblage,
  tokenizers and training are deferred. No PE sample is executed or re-armed.
- Sort malware source IDs lexicographically and divide into five **consecutive** equal
  processing parts (1,992,564 sources each), not round-robin. These are not ML splits.
- Preserve every source, all 15 original metadata fields/counts and all outcomes. Keep
  original ID, compressed SHA-256, released-PE SHA-256 and EXE SHA-256 distinct.
- Intended ISA cohort: x86-32 and x86-64. Verify a hash-only recovery of erased header
  **metadata** against original IDs, without creating modified PE bytes/files. PE32/PE32+
  alone is not ISA evidence. Adding amd64 extends LMLM's x86-32 cohort.
  Unverified sources remain explicitly deferred; the final
  unknown-cohort policy requires evidence and researcher review before a full launch.
- Run DiE recursive, deep and heuristic as three separate invocations. Recursive means
  directory recursion in DiE 3.21, not embedded-file recursion. Any positive result in
  Packer/Protector/Protection/Crypter/Cryptor/patcher/scrambler/sfx/Archive/Joiner excludes
  a sample before extraction. Compiler/Linker/Library alone do not exclude it.
- Invalid/failed scans are not negative findings. Retry only a failed mode, two more
  times (three total); preserve successful results. Exhaustion has its own error status.
- LIEF selects CODE **or** EXECUTE sections, in section-table order. Clip at EOF and
  the next nonempty section; retain warnings and declared/effective ranges. Skip an
  empty/reversed section while retaining other bytes. No output for an entirely empty
  extraction, no eligible section or structurally invalid PE; retain distinct reasons.
  Preserve the complete extraction: no padding to 100 KB or model-context truncation.
- A normal LIEF parse rejection is not retried. Timeout/crash: two additional attempts,
  three total. No automatic retry of exhausted outcomes on ordinary resume.
- LIEF/file/each DiE invocation: 10 seconds. Source connection: 20 seconds within a
  120-second total transfer. Transient download errors: three total attempts, delays
  1 and 2 seconds. HTTP 404 is recorded without immediate retry; source HTTP 403 stops
  the job with the source still pending. Decompression errors are recorded without
  automatic redownload.

## Resource and execution contract

- No permanent rejection solely at 32 MiB compressed or 128 MiB PE. Resource ceilings
  defer work explicitly instead of classifying a sample as malformed or converted.
- Download to SSD, stream decompression to a private PE temporary file, hash in chunks.
  Native tools read files. LIEF still needs a separately controlled RAM budget.
- Worker completion immediately refills available capacity. Source fetch batches and
  upload groups are independent; a slow source must not hold an entire processing batch.
- Bound active work and unpublished disk usage. Stop scheduling if disk space is
  insufficient; preserve committed progress. Worker/batch/upload settings, memory and
  disk budgets and upload deadline are selected from measurements on the target machine.
- Compressed input may be removed after validated decompression/receipt; PE input after
  an outcome and evidence are durable locally. EXE/evidence may be removed only after
  their S3 uploads and local publication-index commit succeed and no task still uses them.

## S3, main records and detailed evidence

Each part has an independent S3 prefix and state. Within it:

```text
part-01/
  exe/<first-two-EXE-hash-characters>/<EXE-SHA256>.exe
  main/       # authoritative state, consistent CSV and latest snapshot pointer
  details/    # bounded, immutable compressed groups of detailed evidence
```

- Exact EXE duplicates share one object within a part. Keep each source/label separately;
  report successful sources and distinct EXE separately. Cross-part duplicates may remain.
- Upload EXE/groups in the background with a bounded queue. Each EXE remains a separate
  S3 object: grouping CLI invocations does not remove its individual PUT request.
- Group full download/file/DiE/LIEF evidence, section ranges and detailed CSVs into
  immutable tar.gz archives. Include outcomes/manifests for successful, filtered and
  failed sources. **Do not merge into one giant archive at part completion.** The earlier
  merge-and-delete decision was explicitly superseded.
- Preserve each historical attempt. The main CSV has one current row per processed
  source, including filtered/error/deferred outcomes; pending sources remain in SQLite.
  All parts use one fixed CSV schema. Missing values are distinguishable from not-run,
  rejected, failed or resource-deferred stages. Source `packed` is separate from DiE.
- Main records include all source fields, four identities, ISA evidence, scan findings,
  sizes, timings, retry counts, extraction warnings, actual upload state, EXE location
  and directly usable evidence location. Full nested findings stay in details.
- Upload DB and CSV from one consistent snapshot every 30 minutes, plus a clean stop or
  completion. Publish a latest pointer only after all snapshot objects are durable.
- Restore the last snapshot then replay complete groups published afterward. Uploaded
  group manifests must be verifiable, idempotent and versioned; pending uploads cannot
  appear complete. A snapshot/upload failure preserves the previous published snapshot.
- AWS CLI standard retry: three attempts per request, no additional outer retry loop.
  Once exhausted, stop scheduling, retain unpublished data and exit with a clear error.
  Upload timeout is an operational setting chosen by benchmark, not an assumed optimum.

## Ownership, resume, stopping and logs

- One active coordinator per part, enforced by local and conditional S3 ownership locks.
  Different parts can run concurrently. Normal handover saves state then releases the
  lock. Abnormal loss needs explicit takeover after confirming the old job stopped;
  do not auto-steal based only on an expired heartbeat.
- Resume may change workers, fetch batch, uploader settings and local paths. Scientific
  rules, source selection and tool identities stay fixed. Record each run's environment.
- First Ctrl+C stops new scheduling, drains active samples and uploads, publishes a
  final snapshot then releases ownership. Second Ctrl+C aborts active subprocesses,
  preserves committed local state and incomplete handover; unfinished work may repeat.
- Explicit retry selects failure groups, preserves history and updates the current
  result. Reuse prior stages only with identical PE hash, tool identity and rules;
  redownload inputs if temporary files were removed. Filtered is not synonymous with error.
- Emit aggregate logs every five seconds, including during upload/snapshots, and report
  fatal failures immediately. Distinguish processed sources, successful sources,
  fully published sources, unique EXE, filtered/errors/resource-deferred/upload-pending.
- Report processing and full-publication rates using real wall time. ETA uses a recent
  five-minute publication window for the current run; unavailable before enough evidence.
  Deferred-resource work and future explicit retries are outside this pass's ETA.

## Deployment and acceptance

- CPU-only Docker image: Ubuntu 24.04 LTS x86-64, Python 3.12.12, LIEF 0.15.1,
  DiE 3.21 plus its frozen signatures and libraries. Resolve a fixed image digest.
  LIEF 0.15.1 matches an author environment; DiE exact author version is unverified and
  Python differs from their 3.10 environment. Disclose rather than claim exact reproduction.
- Use the locked base Python dependencies, not training/CUDA. Record system tools and
  complete signature identity. Credentials, private environment files, samples and
  metadata are outside the image. Data is mounted from the rented machine's local SSD;
  no separately rented persistent volume initially.
- Use AWS profile `sorel-worker`, scoped to the SOREL collection: read/write plus needed
  lock/checkpoint/probe cleanup, without granting data deletion unnecessarily. Credentials
  are configured separately. Public source downloads are unsigned.
- Synthetic tests only: ISA/section correctness, retry isolation, continuous dispatch,
  queue/resource bounds, publication failures, snapshot atomicity, replay, ownership,
  history, resume and interrupt behavior. Run focused tests and `make check`.
- Initial acceptance uses **1,000 real sources directly**, without a separate 10-source stage.
  Use the beginning of part 1. Retain valid outcomes as real progress only if the protocol
  remains unchanged. Measure setup separately, throughput, tool coverage/errors/timeouts,
  CPU/RAM/disk/network and publication/checkpoint traffic. Never execute source PEs.
- A paid instance requires concrete host/cost approval. Full-corpus launch also requires
  a passing release audit. The limited continuation test is described in the run guide.
  Docker publication needs a concrete destination and reviewable image.
