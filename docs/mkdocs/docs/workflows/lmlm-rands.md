# RanDS Data Preparation

This workflow prepares full-corpus data representations. It does not choose a model, a split, a
tokenizer, or hyperparameters. Those choices belong to a later experiment configuration.

Raw RanDS files are live malware. Run this only in the approved isolated storage environment; the
commands statically read bytes and never execute, upload, or modify the source files.

## Locate And Audit The Corpus

Create a local `.env` from the template. Its default combined layout expects the corpus at
`data/raw/rands` in the checkout; change these entries only when the raw bytes and metadata are
mounted elsewhere:

```dotenv
MALWEAVE_RANDS_DIR=data/raw/rands
MALWEAVE_RANDS_METADATA_DIR=data/raw/rands
```

The raw root contains the SHA-256-sharded `dataset/` directory. The metadata root contains
`Benign.csv` and `Ransomware.csv`; one label source can therefore serve RAW, EXE, DIS, and DEC.
When `MALWEAVE_RANDS_METADATA_DIR` and `--metadata-root` are omitted, MalWeave retains compatibility
with the legacy combined root containing all three entries. Before producing a representation, audit
the release contract:

```bash
uv run --locked malweave data inspect --dataset rands \
  --summary reports/rands/2026-09-02/inspection.json
```

The audit checks the expected full release: 256 shards, 215,404 available files, class counts,
metadata schema, path layout, metadata/file coverage, and file sizes. It is read-only. Add
`--verify-hashes all` only when you deliberately want a separate full-byte integrity pass; normal
EXE extraction re-hashes each source immediately before static parsing.

## Optional Independent PE Assessment

This optional, reusable annotation job uses the same three Detect-It-Easy (DiE) scans as RawByteClf
(`recursive`, `deep`, and `heuristic`) plus the local `file` utility. Use it for a corpus without
architecture/packing metadata, or later to validate the RanDS annotations. It is not a prerequisite
for the time-sensitive RanDS Ghidra job below. Both tools must be installed on the isolated analysis
worker; `diec` is not a Python dependency and MalWeave does not download it automatically.

```bash
uv run --locked malweave data assess-pe \
  --dataset rands \
  --state-db data/processed/rands/pe-assessment.sqlite \
  --manifest data/processed/rands/pe-assessment.csv \
  --summary reports/rands/2026-09-19/pe-assessment.json \
  --file-command file \
  --die-command /absolute/path/to/diec \
  --workers 8 \
  --die-timeout-seconds 10
```

The job first checks the release contract, then SHA-256-verifies each source before the static tool
calls. SQLite commits every completed row, so an interrupted job resumes safely with the identical
command plus `--resume`. Progress and the terminal JSON report contain aggregate counts only; the
CSV is a private local manifest with source identities.

This is an annotation pass, not a filter: every verified source receives its `file` result, derived
architecture, the per-mode DiE status, DiE detection types, and metadata values. `die_obfuscated` is
`true` when any successful scan detects an upstream obfuscation type, `false` only when all three
scans succeed with no detection, and `unknown` when a scan is incomplete and there is no detection.
`i386_unobfuscated_eligible` records the later RawByteClf-style condition without removing files:
`true` requires derived `i386` plus `die_obfuscated=false`; `false` means a known contrary result;
`unknown` means it cannot yet be established. Future experiment configs select this annotation as a
cohort policy and record it.

## Extract The Full EXE Representation

Start one durable job. All paths below are ignored local artifacts; the state database is the source
of truth while the job is running.

```bash
uv run --locked malweave data extract-exe \
  --dataset rands \
  --representation-dir data/processed/rands/exe \
  --state-db data/processed/rands/exe/extraction.sqlite \
  --manifest data/processed/rands/exe/manifest.csv \
  --summary reports/rands/2026-09-02/exe-extraction.json
```

The command first reruns the release audit and refuses an incomplete or malformed corpus. It then
enumerates every available metadata-backed source in SHA-256 order. For every source it:

1. Reads and re-hashes the raw bytes against its canonical source SHA-256.
2. Statically extracts executable PE sections with the existing RawByteClf-compatible rules.
3. Stores successful bytes at `exe/<first-two-sha-characters>/<source-sha>.bin`.
4. Commits the source result, failure status, byte count, representation digest, and runtime to
   SQLite before moving on.

Failures are data results, not silent drops: read errors, source-hash mismatches, malformed PEs,
and sources with no executable section remain in `exe-manifest.csv`. The JSON report carries only
aggregate counts and never individual source identities.

Use a bounded local check if desired, without defining a special cohort:

```bash
uv run --locked malweave data extract-exe \
  --dataset rands \
  --representation-dir data/processed/rands/exe \
  --state-db data/processed/rands/exe/extraction.sqlite \
  --manifest data/processed/rands/exe/manifest.csv \
  --summary reports/rands/2026-09-02/exe-extraction.json \
  --limit 100
```

Continue that exact job with the same output locations:

```bash
uv run --locked malweave data extract-exe \
  --dataset rands \
  --representation-dir data/processed/rands/exe \
  --state-db data/processed/rands/exe/extraction.sqlite \
  --manifest data/processed/rands/exe/manifest.csv \
  --summary reports/rands/2026-09-02/exe-extraction.json \
  --resume
```

`--resume` validates the snapshot and complete source-list digest before it skips completed rows.
It will not accidentally merge two different releases. An existing state database without
`--resume` is rejected. If a representation file already exists after an interruption, it is reused
only when its digest matches newly extracted bytes; a conflicting file stops the job.

The command writes one aggregate terminal progress line to `stderr` after every 100 sources, while
leaving final JSON on `stdout` for automation. Include `--progress-every 1000` to reduce terminal
updates or a smaller positive number for more frequent updates.

## Extract DIS And DEC With Ghidra

For the RanDS Ghidra workstream, selection is deliberately fast and explicit: metadata
`Arch == I386` selects the source set, while **both** metadata values of `Packed` run. The manifest
retains `metadata_packed`, so an experiment can later compare packed and unpacked groups. This is a
RanDS metadata-based extension, not the paper's separately verified `file` plus DiE cohort.

The versioned scripts in `ghidra_scripts/` are an attributed RawByteClf-compatible port. One
unified source job produces both views and persists their terminal statuses separately. DIS and DEC
use separate headless invocations inside that job because RawByteClf applies different analysis
options to DIS; they share the source partition, state database, output contract, and resume point.
The workflow only performs static analysis; still run it in the approved isolated environment.

Start with a ten-source, one-worker pilot. Replace the Ghidra launcher path with the one installed
on the analysis worker:

```bash
uv run --locked malweave data extract-ghidra \
  --dataset rands \
  --representations dis dec \
  --analyze-headless /absolute/path/to/ghidra/support/analyzeHeadless \
  --dis-representation-dir data/processed/rands/dis \
  --dec-representation-dir data/processed/rands/dec \
  --state-db data/processed/rands/ghidra/extraction.sqlite \
  --work-dir data/processed/rands/ghidra-work \
  --dis-manifest data/processed/rands/ghidra/dis-manifest.csv \
  --dec-manifest data/processed/rands/ghidra/dec-manifest.csv \
  --summary reports/rands/2026-09-21/ghidra-extraction.json \
  --workers 1 \
  --limit 10
```

Each source is SHA-256-verified before Ghidra starts. Temporary Ghidra projects live under
`--work-dir` and are removed after every invocation. The durable SQLite state stores the cohort,
both script digests, launcher path and digest, per-view timeouts, output digests, statuses, and
runtimes. To continue, rerun the exact command with `--resume`; a completed DIS is retained while a
pending DEC resumes, and vice versa. Changing an extraction-contract input requires a new state
database. Defaults match RawByteClf (`DIS=60/30`, `DEC=300/60`); the outer timeout covers both
headless invocations and cleanup.

## Freeze Representation Products

Once EXE extraction is complete, build representation products. RAW remains a verified reference to
the canonical source bytes; no second RAW copy is created. This pass re-hashes the full source
corpus and validates all successful EXE files before writing product and exact-duplicate manifests.

```bash
uv run --locked malweave data build-products \
  --dataset rands \
  --exe-manifest data/processed/rands/exe/manifest.csv \
  --exe-dir data/processed/rands/exe \
  --manifest data/processed/rands/products-manifest.csv \
  --duplicate-groups data/processed/rands/exe-duplicate-groups.csv \
  --summary reports/rands/2026-09-02/products.json
```

Now the data workstream is complete for RAW and EXE: it has full-corpus availability, failures,
representation identities, and duplicate groups. Add future representations (strings or APIs) with
their own extractors and manifests; do not make them depend on a model run.

## Start An Experiment Later

When the model components are ready, create an experiment configuration that selects products,
architectures, tokenization, loss, optimizer, schedule, epochs, seeds, and evaluation policy. For a
comparative claim, the config first freezes a leakage-safe split, then fits tokenizers only on its
training partition. Each training run records the resolved config, input digests, checkpoint,
metrics, and environment in a private artifact directory.
