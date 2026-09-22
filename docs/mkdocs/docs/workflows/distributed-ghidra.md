# Distributed Ghidra Extraction

Use this workflow only from an approved isolated malware-analysis environment. Raw PE files remain
read-only, private, and outside Git. Run the ten-source pilot in the RanDS workflow before creating
any distributed plan.

Each section uses one SQLite state database. For every source, the unified job creates both DIS and
DEC terminal results. A section is complete only after both representations have a recorded result
(success or a reported failure), so `--resume` never reruns a completed representation.

## Create One Plan

Create the representation-agnostic plan once, from the audited corpus. Copy the same plan directory
to every worker without modification.

```bash
uv run --locked malweave data plan-ghidra-shards \
  --dataset rands \
  --sections 5 \
  --output-dir /private/ghidra-plan
```

The directory contains `plan.json` and `section-1.csv` through `section-5.csv`. These files contain
private sample identities: do not commit or publish them.

## Bootstrap A Worker

Run the repository's bootstrap script from an existing checkout. It installs the selected JDK and
Ghidra outside the repository, installs the locked Python environment, and copies `.env.example`
to a usable local `.env` if one does not already exist.

```bash
GHIDRA_SHA256=<official-archive-sha256> \
MALWEAVE_REPO_DIR=/srv/malweave \
./scripts/setup-ghidra-worker.sh
```

The generated `.env` already uses the following checkout-local defaults. Edit it only when the
corpus or fast local disk is mounted elsewhere:

```dotenv
GHIDRA_ROOT=${HOME}/ghidra/ghidra_11.2.1_PUBLIC
MALWEAVE_RANDS_DIR=data/raw/rands
MALWEAVE_RANDS_METADATA_DIR=data/raw/rands
MALWEAVE_OUTPUT_DIR=data/processed/rands
MALWEAVE_STATE_DIR=data/processed/rands/ghidra-state
MALWEAVE_WORK_DIR=data/interim/rands/ghidra-work
MALWEAVE_SHARD_PLAN_DIR=data/interim/rands/ghidra-plan
MALWEAVE_WORKERS=1
```

`GHIDRA_SHA256` is optional only when the worker's private run record captures the verified archive
digest by another approved mechanism. Ghidra and the JDK are external system tools, not `uv.lock`
dependencies. DiE is not required for the metadata-I386 RanDS workstream.

## Run And Resume A Section

From the checkout, run one section per worker:

```bash
./scripts/run-ghidra-section.sh 1
```

The script writes `section-1.sqlite`, `section-1.json`, `dis-section-1.csv`, and
`dec-section-1.csv` under `MALWEAVE_STATE_DIR`, while DIS and DEC text outputs go to separate output
directories. A rerun automatically adds `--resume` for the same state database.

Do not put multiple workers on the same section/state database. Choose `MALWEAVE_WORKERS` from the
machine's measured CPU and RAM budget; each logical worker can invoke Ghidra twice per source.

## Collect And Merge

After every section summary reports `job.complete: true`, copy both output trees and state artifacts
to the isolated coordinator. Then merge each representation independently:

```bash
./scripts/merge-ghidra-sections.sh dis /private/merged/dis /private/worker-state
./scripts/merge-ghidra-sections.sh dec /private/merged/dec /private/worker-state
```

The merger rejects incomplete sections and duplicate source identities, writes a deterministic
private `manifest.csv`, and produces an aggregate `summary.json`. It cannot infer omitted shard
directories, so compare the merged source count with the original `plan.json` before treating the
corpus job as complete.
