# Research Workstreams

MalWeave is organized around independent workstreams that meet at a declared experiment. A data
task must not block model implementation, and an architecture task must not alter a frozen
benchmark after results are observed.

The project adapts the LMLM methodology to RanDS. It does not claim to reproduce the original
paper dataset or its reported scores.

## Operating Model

```text
Corpus -> deterministic representations -> private manifests
Models -> adapters, tokenizers, loss, metrics, checkpointing
Experiment config -> resolved inputs, training choices, evaluation policy
Run -> private artifacts, results, and provenance
```

Every completed run is reproducible from its resolved configuration, data-manifest digests, source
revision, dependency lock, command, seed, and recorded runtime environment. A benchmark run adds a
frozen split and train-only fitted transforms; a smoke or feasibility run need not make a scientific
comparison claim.

## Data Workstream

This workstream prepares immutable, auditable corpus views. It does not define the architecture or
the train/validation/test policy for a future experiment.

| Capability | Status | Evidence |
| --- | --- | --- |
| RanDS release audit | Implemented | Read-only metadata/filesystem contract and optional local manifest |
| PE architecture/obfuscation assessment | Implemented | Full-corpus resumable `file` and three-mode DiE annotations; no source filtering |
| EXE extraction | Implemented | Full-corpus static extraction with per-source durable state and representation digest |
| RAW/EXE products | Implemented locally | Full-corpus product manifest, duplicate groups, and aggregate report |
| DIS representation | Implemented locally | Resumable Ghidra extraction of metadata-I386 samples; packed metadata retained |
| DEC representation | Implemented locally | Resumable Ghidra decompilation of metadata-I386 samples; packed metadata retained |

All derived representation manifests preserve source identity, representation digest, status, size,
and provenance. Raw PE files and private manifests never enter Git. A source or representation
failure is recorded, not silently replaced.

## Component Workstream

This workstream builds composable code with synthetic tests. It may proceed using safe synthetic
bytes before a private corpus run exists.

| Component | Status | Scope |
| --- | --- | --- |
| RAW byte IDs and EXE word/BPE utilities | Implemented | Reversible byte IDs; train-partition BPE support |
| MalConvGCT port | Implemented | Raw-byte baseline with low-memory scan and global-context gates |
| HRRFormer port | Implemented | Bidirectional sequence classifier |
| Mamba port | Implemented | Bidirectional sequence classifier; CUDA fast path remains runtime-specific |
| Supervised runner | Implemented locally | Checkpoint selection, metrics, artifacts, and private paths |
| Local smoke command | Planned | CPU-safe end-to-end validation on synthetic bytes |

No component test may use real malware bytes. A component is ready when its focused tests cover
forward/backward behavior, checkpoint round-trip, and relevant upstream parity.

## Experiment Workstream

An experiment config selects an existing data view and components. It is the only place that fixes
choices such as representation, model architecture, tokenizer, loss, optimizer, seed, epochs,
metrics, and evaluation split.

| Run kind | Purpose | Split and fit policy |
| --- | --- | --- |
| `smoke` | Validate end-to-end code on synthetic inputs | No research split or scientific claim |
| `feasibility` | Measure runtime, memory, and basic learning behavior | Explicit local input manifest; no comparative claim |
| `benchmark` | Compare models or representations | Freeze leakage-safe split before tokenizer/scaler/tuning fit |

An eventual RanDS benchmark can compare MalConvGCT on RAW against HRRFormer and Mamba on EXE. It
must use the successful RAW/EXE intersection, deduplicate exact EXE groups, and freeze its split
from the completed full-corpus products. No fixed cohort or split is a repository-wide gate.

## Target Run Artifacts

The generic experiment runner will write an immutable private directory containing:

```text
resolved-config.yaml
run-manifest.json
metrics.json
metrics-history.jsonl
plots/
best.pt
tokenizer.json                # when the experiment fits one
test-predictions.csv          # benchmark runs only
```

The run manifest will record input and split digests, tokenizer digest, Git revision,
dependency-lock digest, command, seed, platform, accelerator, runtime, peak memory, and artifact
names. It will be the source of truth for reproducing a completed run. The existing supervised
runner already records the core checkpoint, metric, prediction, and manifest artifacts; the generic
layout is completed in the experiment-runner workstream.

## Current Priorities

1. Keep data preparation and model/component work independent.
2. Complete a CPU-safe local smoke path before spending on CUDA infrastructure.
3. Declare a comparison config only when starting a specific benchmark.
4. Add DIS and DEC as data workstream capabilities without making them prerequisites for EXE work.
5. Preserve each run's resolved configuration, frozen inputs, and split.
