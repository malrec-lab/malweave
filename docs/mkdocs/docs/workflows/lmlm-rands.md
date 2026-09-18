# RanDS Data Preparation

This workflow prepares full-corpus data representations. It does not choose a model, a split, a
tokenizer, or hyperparameters. Those choices belong to a later experiment configuration.

Raw RanDS files are live malware. Run this only in the approved isolated storage environment; the
commands statically read bytes and never execute, upload, or modify the source files.

## Locate And Audit The Corpus

Create a local `.env` from the template and set the raw and metadata locations:

```dotenv
MALWEAVE_RANDS_DIR=/path/to/rands/raw
MALWEAVE_RANDS_METADATA_DIR=/path/to/rands/metadata
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
representation identities, and duplicate groups. Add other representations (DIS, DEC, strings, or
APIs) with their own full-corpus extractors and manifests; do not make them depend on a model run.

## Start An Experiment Later

When the model components are ready, create an experiment configuration that selects products,
architectures, tokenization, loss, optimizer, schedule, epochs, seeds, and evaluation policy. For a
comparative claim, the config first freezes a leakage-safe split, then fits tokenizers only on its
training partition. Each training run records the resolved config, input digests, checkpoint,
metrics, and environment in a private artifact directory.
