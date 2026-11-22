# Distributed RanDS Ghidra and DiE implementation plan

> Retained at the researcher's request during the branch switch on 2026-11-12.
> The uncommitted implementation described below was discarded, not merged into this branch.
> Treat its implementation/status claims as historical. Current supported preparation is
> documented in [data preparation](data-preparation.md).

Status: initial S3 rolling-cache implementation available; see
[the runnable workflow and current limitations](ghidra-s3-rolling.md). Full-corpus architecture
expansion, dedicated transfer queues and cross-platform same-part portability remain planned.
No full-corpus job is started by this document.

## Scope and invariants

- Use original PE objects on AWS S3, not the extracted EXE section products.
- Freeze the full available RanDS snapshot before assigning work. The historical release has
  215,404 sources; revalidate current availability rather than assuming that count.
- Retain all sources, classes, architectures, and metadata packing values. Unsupported inputs
  receive explicit statuses, never silent exclusions. DiE is annotation, not an eligibility gate.
- No training split changes, model work, unpacking, or binary execution in this workstream.
- Raw samples stay immutable and private. Run parsers headlessly on isolated analysis workers,
  not a personal Mac environment with credentials or shared folders. Mac support means an approved
  dedicated/disposable analysis environment, not permission to download malware onto a workstation.
- Separate credentialed S3 transfer from offline parser processes. Do not pass cloud credentials
  into Ghidra/DiE environments. Use least-privilege download and private-output upload permissions.

## Existing code to reuse

- `malweave/data/rands_ghidra.py`: source verification, independent DIS/DEC attempts, process-group
  termination, normalization, output digests, SQLite progress, extraction-contract validation.
- Existing `data assess-pe`: `file` plus recursive/deep/heuristic DiE annotations and resumable state.
- Existing `data extract-ghidra`: extend the unified Python CLI; no dataset-specific shell runner.
- Existing `plan_rands_ghidra_shards` and `--shard-plan`/`--section` already support deterministic
  equal-count I386 sections, numbered from 1. Extend these contracts rather than add a second planner;
  keep the old algorithm available for existing plans and version the new size-aware algorithm.
- Important limitation: current enumeration selects metadata I386 and the launcher forces
  `x86:LE:32:default`. It also expects a complete local release. A part-local S3 workflow needs
  a separate frozen-inventory input path, not a weakened full-release audit.

## 1. Freeze inventory and assign exactly four parts

1. Audit metadata schemas, counts, missing files, S3 sizes and snapshot identity. Preserve canonical
   source SHA-256, label, family, architecture, metadata packing, object key/version where available,
   and expected size. Verify bytes against source SHA-256 after download; ETag is not a content hash.
2. Produce an immutable private inventory and contract digest. Every source occurs exactly once.
3. Make a deterministic, size-aware four-way assignment: sort by descending source size, tie-break
   by canonical SHA-256, assign to the part with the lowest estimated load, tie-break by part ID.
   Start with size as a cost proxy; replace weights only before freezing the production contract
   if pilot timings show a better size/architecture/packing cost model. Equal file counts do not
   guarantee equal runtimes. Record per-part class/architecture/packing counts, bytes and cost.
4. Save four manifests plus their digests and the algorithm/version. Validate disjointness and
   exact union with the inventory. Worker flags use explicit IDs `1..4`; no random re-partitioning.
5. Part identity is independent of host: moving a part between Mac/Linux retains its assignment.
   A later transfer must stop the old owner and reconcile receipts before a new owner starts.

## 2. Per-machine bounded pipeline

```text
frozen part manifest -> bounded S3 prefetch -> SHA-256 verified local cache
                                             |-> DiE annotation queue
                                             |-> Ghidra DIS/DEC queue
outputs + durable local status -> bounded uploader -> remote hash verification -> receipt
```

- One process owns each part's local SQLite database; threads/tasks report results to that writer.
  Never put a shared writable SQLite database on S3 or a network filesystem.
- Separate download, analysis and upload concurrency. Bound queues by bytes as well as item count;
  stop prefetch when disk free space reaches a reserve. Use local SSD for projects and temporary
  files, not S3 mounts/network storage. Stream transfers and hashing instead of reading whole files.
- Required rolling-cache policy: never stage the full part/corpus locally. Download only the bounded
  active/prefetch window. After all required Ghidra views and DiE assessment have terminal records,
  upload outputs and diagnostics under the retention policy, verify remote hashes, and durably commit
  the receipt before evicting that source's local raw cache entry and uploaded derived artifacts.
  Release disk capacity for the next source immediately; keep only compact coordinator state/logs.
  Reference-count active readers so cleanup cannot delete a file still used by either tool. Failed
  tools produce uploaded failure records; pending retries retain input only within the cache budget
  or redownload and reverify later. If upload/verification fails, backpressure downloads rather than
  deleting unprotected results. Cleanup is idempotent and restricted to job-owned cache/temp paths;
  remote original objects and unrelated local data must never be removed.
- DiE and Ghidra consume the same verified source independently; a failure in either does not skip
  the other. DIS and DEC have independent terminal states and retry policies.
- Use temporary output paths, then atomic rename and durable state commit. On restart reconcile
  orphaned files using their hashes; reset interrupted leases, not completed work.
- Do not delete cached inputs/outputs before required results are durably uploaded and verified.
  Keep raw originals in S3; never modify or delete them. Cap retained diagnostic logs explicitly.

## 3. Durability and merge contract

- Track stages separately: pending, running, successful, timeout, unsupported, malformed, failed;
  distinguish retryable transfer failures from terminal parser failures. Store attempts and errors.
- Use unique immutable job/part/attempt output prefixes. Do not let two machines overwrite one
  part's authoritative result. Initial design uses four exclusive owners, not a shared cloud queue.
- Private upload receipts record source, view, byte size, SHA-256 and contract digest. Checkpoint
  manifests/state snapshots atomically; capture SQLite via its backup API, not a live file copy.
- Resume on another machine validates the contract and remote receipts. Successful verified views
  are skipped; missing/corrupt artifacts are requeued with an auditable repair record.
- Merge checks four expected part digests, exact source union, no duplicate ownership, compatible
  extraction contracts, output hashes, and terminal status for every source/view/DiE assessment.
- Report incomplete work explicitly. Never describe a run as complete solely because processes exit.
- Preserve a verified second copy of final manifests/reports. Raw-source preservation and durable
  artifacts protect against worker loss; no design guarantees recovery from deletion of all copies.

## 4. Ghidra architecture and performance policy

- Add tested architecture dispatch using PE headers plus recorded metadata reconciliation. Do not
  force x86-32 for other architectures. Report unsupported/mismatched inputs, keep them in inventory.
- Pin compatible Ghidra, JDK, scripts and analysis settings across Mac/Linux; record versions and
  script/config digests. Binary launcher digests and host details differ by OS: preserve them as
  provenance without making cross-host resume impossible. Benchmark cross-platform output parity.
- Preserve separate RawByteClf-compatible DIS and DEC invocations initially: their analysis options
  differ. Reusing a project or batching imports is an optional optimization requiring regression
  evidence; do not silently change representation semantics to save JVM startup time.
- Expose per-process `max_cpu`, JVM heap ceiling, process/function/analysis timeouts and worker count.
  Do not shorten timeout budgets just to claim higher throughput; record partial-output policy.
- Prefer parallel independent samples over excessive CPU threads per sample, subject to pilot data.
  CPU and RAM, not GPU, determine the useful worker budget for these tools.
- Bound total active processes across both tools. Initial Ghidra concurrency ceiling:
  `min(floor(usable_cpu / cpu_per_process), floor(ram_budget / measured_peak_process_ram))`.
  Reserve RAM for OS, filesystem cache, downloader, DiE and coordinator. JVM heap is not total RSS.
- Mac: prevent sleep during an authorized job, constrain memory to avoid swap/pressure, benchmark
  native supported JDK/tool builds. Linux: use resource limits and a persistent supervised process.
  Do not assume heterogeneous machines finish one part at the same time.

## 5. DiE annotations, not filtering

- Preserve original `metadata_packed` independently from tool-derived results.
- Record DiE version/database identity, scan modes, statuses, detected packer/protector/obfuscation
  types and per-mode elapsed time; retain conflicting and incomplete observations.
- Keep existing three-mode assessment semantics. Define `die_unpacking_assessment` as
  `detected`, `not_detected`, or `unknown`; `not_detected` means all required scans succeeded with
  no relevant detection, not proof that a sample is truly unpacked. A convenient unpacked label
  must document this operational definition and never map failed scans to unpacked.
- Join annotations by canonical source SHA-256, not row order or filenames. No DiE result removes
  a source from Ghidra, and no Ghidra failure removes a DiE record.

## 6. Pilot, worker tuning and ETA

1. Synthetic fixtures first; then release audit and a frozen private pilot spanning both classes,
   architectures, packing values, size buckets and large/slow outliers. No data in Git.
2. Start with 10 samples/one Ghidra worker to validate environment and durability, then 100–1,000
   representative samples for throughput measurement on each actual machine.
3. Sweep Ghidra concurrency `1, 2, 4, ...` only within memory/CPU limits; vary `max_cpu` separately.
   Start DiE conservatively and sweep with Ghidra running, rather than assuming independent capacity.
4. Measure sources/hour, per-view success/hour, p50/p95 time, peak RSS, CPU utilization, swap,
   disk queue/free space, S3 transfer rates, output bytes, errors and coverage per class/architecture.
5. Increase prefetch only when compute starves; reduce workers when swapping or I/O contention
   worsens throughput. More processes do not necessarily mean faster completion.
6. Estimate each part from its measured workload; overall ETA is the slowest part plus upload/merge
   and retry overhead, not single-machine duration divided by four. Provide ranges for slow tails.

## 7. Implementation increments and acceptance gates

1. Inventory/partition module, frozen contract and synthetic tests for determinism, disjoint union,
   missing/duplicate sources and stable part ownership.
2. S3 staging/publishing adapter with bounded queues, hash verification, atomic outputs and receipts;
   tests use fake S3 and synthetic bytes, including corrupt downloads and interrupted uploads.
   Test rolling-cache eviction, active-reader protection, disk-budget backpressure, crash recovery
   between receipt and deletion, and refusal to evict results before verified durable publication.
3. Manifest-based Ghidra input and architecture dispatch without bypassing release provenance;
   preserve existing local I386 behavior. Test resume, timeout cleanup and partial DIS/DEC recovery.
4. Independent DiE annotation integration and explicit three-state labels; test incomplete scans,
   disagreement and annotation/Ghidra failure independence.
5. Four-part coordinator, exclusive owner checks, portable state export/import and strict merger;
   simulate machine loss, reassignment, stale owner writes, mismatched contracts and corrupt output.
6. Document one Python CLI workflow for plan/run/status/resume/merge on macOS and Linux, private
   output paths, native external-tool setup, safe isolation and bounded worker configuration.
7. Run focused tests during implementation and `make check` before handoff. Full-corpus launch
   requires passing release audit, successful recovery pilot and aggregate coverage/resource report.

Before production: confirm the four hosts' CPU/RAM/local SSD, supported tool versions, approved
isolation, output destination and storage budget. No fixed worker counts or completion times until
those measurements exist. This plan does not install tools, launch cloud machines or process malware.
