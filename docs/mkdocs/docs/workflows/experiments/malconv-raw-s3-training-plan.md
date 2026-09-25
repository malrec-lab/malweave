# MalConv RAW S3 Training Plan

> **Status: historical design plan.** The implemented MalConv RAW path now stages the complete
> selected manifest on an isolated worker before training. Use
> [S3 inventories and RAW manifests](s3-manifests.md) for current commands and
> [MalConv RAW](malconv-raw.md) for the current experiment contract. The bounded cache and direct
> S3 training sections below remain future proposals, not instructions for the present runner.

## Purpose and non-goals

The goal is to run a bounded, reproducible feasibility experiment from a private, read-only S3
source without copying raw PEs to a developer workstation. The implemented path stages every
object in the selected cohort on the isolated training VM before training. The first experiment is
[MalConv RAW](malconv-raw.md): supervised MalConvGCT classification of the original
RAW bytes with benign and ransomware labels.

Raw PEs are live malware. The workflow reads them only as opaque bytes in an approved, isolated
cloud environment. It never executes, installs, previews, uploads, or changes a source object.

## Storage layout

Names below are placeholders, not committed bucket names or access paths. Bucket names, prefixes,
AWS account details, and credentials belong in the training environment, never in Git.

```text
private S3 bucket
  raw/                         immutable source PEs; training role has GetObject only
  manifests/                   restricted manifests; contains source identities and S3 object keys
  derived/                     optional derived EXE data products, after their phase gate passes
  outputs/<run-id>/            checkpoints, metrics, resolved config, and aggregate reports

training VM (encrypted temporary disk; never a personal workstation)
  /work/cache/                 bounded LRU cache of source or representation bytes
  /work/run/                   temporary logs and resolved run state

repository (source only; no restricted artifacts)
  configs/datasets/            versioned public dataset contract, with no private S3 location
  configs/experiments/         versioned model/training protocol
  malweave/data/               S3 object reader, manifest validation, cache, split utilities
  malweave/models/             MalConvGCT implementation
  malweave/training/           train loop, checkpoint/resume, resource measurements
  malweave/evaluation/         fixed-split metrics and reporting
  tests/data/                  synthetic-only S3/cache/manifest fixtures
  data/interim/                ignored local restricted manifests, when needed
  data/processed/              ignored local derived representations, when needed
  models/, reports/            ignored local outputs; cloud outputs live under S3 outputs/
```

The raw prefix is immutable: source objects are versioned and protected from overwrite/delete;
the training identity has no write permission to it. Derived data and outputs use separate prefixes
so a bug cannot modify the source corpus.

## Access model

Use an isolated GPU VM in the same AWS Region as the S3 bucket. Its instance role should have only:

- `GetObject` (and minimal listing if required) for the raw and manifest prefixes;
- read/write permissions only under its designated outputs prefix;
- no write or delete permission for `raw/`;
- no long-lived AWS credentials saved in the repository or the VM filesystem.

The VM cache is a performance optimization, not a second dataset source. Begin with a 30--50 GB
encrypted cache. It may evict files, but it must never change source bytes. Increase it only after
the pilot reports a cache-related throughput problem.

## Required manifest contract

Create manifests only in the restricted S3 `manifests/` location or an ignored local directory.
Never commit them because source identities and object keys are sensitive inventory information.

Each row must include at least:

| Field | Purpose |
| --- | --- |
| `source_sha256` | Canonical identity and post-download integrity check. |
| `label` | `benign` or `ransomware`. |
| `family` | Cohort accounting; empty for benign where appropriate. |
| `snapshot` | RanDS release identity. |
| `representation` | `raw` or the approved derived representation. |
| `object_key` and `object_version` | Exact immutable S3 source object. |
| `split` | `train`, `validation`, or `test`, created only after leakage groups exist. |
| `group_id` | Source/representation-equivalence group; one group may appear in one split only. |

The manifest itself has a deterministic digest. The resolved experiment configuration records that
digest, Git revision, dependency lock digest, hardware, and image/runtime versions.

## Workstream-aligned implementation order

### A — data workstream: prepare the restricted input view

- [x] List S3 object metadata, audit release counts and join the RanDS metadata snapshot; generate
  the restricted metadata-candidate inventory, including unavailable objects. This does not verify
  PE content hashes or parseability.
- [x] Freeze the optional bounded 1,000-sample MalConv RAW cohort using its
  committed config: keep `Arch=I386` and `Packed=0`; do not filter by extension or size. Treat
  these RanDS fields as proxies, not the paper's independent `file`/`diec` checks.
- [ ] Deduplicate by source SHA-256; exclude and count missing/malformed identities and labels,
  duplicate rows, conflicting-label groups, and architecture/packing exclusions by class.
- [x] Partition by metadata `Year` before cohort selection: train through 2022, validation in
  2023, test from 2024; select balanced class targets within each partition and fail on shortfall.
  Verify strict year order and source-group disjointness; document that RanDS years are not the
  paper's precise timestamps.
- [x] Generate and retain the restricted cohort and split manifests plus deterministic digests.
- [x] Report class-specific S3 availability and selection exclusions before a model sees input.

### B — reusable data component: build and test the S3 access layer

- [ ] Add a side-effect-free S3 object-reader interface in `malweave/data/`.
- [ ] Add an on-disk bounded LRU cache in `malweave/data/`; make cache size configurable.
- [ ] Verify the source SHA-256 after every fetch before providing bytes to the model.
- [ ] Count and surface: missing object, access error, version mismatch, hash mismatch, cache hit,
  cache miss, eviction, and read time.
- [ ] Add synthetic tests in `tests/data/`; no raw PE bytes, real S3 keys, or credentials in tests.
- [ ] Keep all imports and path resolution side-effect free.

### C — experiment workstream: freeze a feasibility run

- [ ] Use the committed `malconv-raw.yaml` contract for the first RAW-byte run.
- [ ] Create year-ordered train/validation/test manifests after grouping, before any fit, tuning,
  or resampling.
- [ ] Check every split is group-disjoint and source-disjoint.
- [ ] Store the restricted manifest and its digest outside Git.
- [ ] Resolve and save the config, manifest digests, Git revision, dependency-lock digest, command,
  seed, and runtime environment with the private run outputs.

### D — component workstream: smoke test and runner integration

- [ ] Use the existing supervised runner and RAW-byte components where their focused synthetic
  tests already establish forward/backward and checkpoint behavior.
- [ ] Add an M1-compatible synthetic smoke test where possible; do not use real samples locally.
- [ ] Prove a tiny synthetic cohort can overfit before the real-data pilot.
- [ ] Implement deterministic fixed-prediction evaluation in `malweave/evaluation/`.
- [ ] Document the selected CUDA/framework image and accelerator runtime before the cloud run.

### E — isolated cloud feasibility pilot

- [ ] Start one GPU VM with a read-only raw-data role and encrypted bounded cache.
- [ ] Verify all 1,000 manifest objects and hashes before the training epoch.
- [ ] Run a few batches, then one fixed pilot epoch.
- [ ] Write checkpoints and aggregate reports to the dedicated S3 outputs prefix.
- [ ] Report missing/hash/version failures by class, cache size/hit rate, bytes fetched,
  samples/second, GPU peak memory, epoch duration, and checkpoint-resume result.
- [ ] Run `make check` for repository changes before handoff.

Only a passed feasibility pilot permits a measured 10,000-sample canary. A benchmark or
full-corpus run requires its own frozen experiment configuration and approval; it is not implied by
this plan.

## Pilot success criteria

The bounded pilot passes only when all of these are true:

1. Each manifest object has an explicit outcome; none silently disappear.
2. Every training byte sequence is hash-verified against its manifest identity.
3. No source SHA-256 group crosses a split boundary.
4. The run resumes from a checkpoint without changing the manifest, config, or split.
5. The report includes all requested storage, performance, integrity, and class-specific counts.
6. Raw sources remain unchanged and are absent from the workstation, repository, tests, and outputs.

## Current implementation

The metadata-only manifest does not prove byte integrity. `stage-inputs` now verifies every
selected object and writes resumable per-source state plus aggregate coverage; `train` requires
a passing report tied to that manifest. This has synthetic test coverage. The pilot has not been
run against the private corpus, and the proposed bounded cache and cloud feasibility steps above
remain open.
