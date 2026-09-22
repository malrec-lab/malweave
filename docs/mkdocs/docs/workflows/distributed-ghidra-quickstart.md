# Distributed Ghidra Quick Start

This is the smallest safe sequence for a distributed DIS+DEC run. Read [Distributed Ghidra
Extraction](distributed-ghidra.md) for the safety constraints and merge rules.

```bash
# Coordinator: create one private plan after the read-only RanDS audit and a local 10-source pilot.
uv run --locked malweave data plan-ghidra-shards \
  --dataset rands \
  --sections 5 \
  --output-dir /private/ghidra-plan

# Each worker: bootstrap external JDK/Ghidra tools and the locked Python environment.
GHIDRA_SHA256=<official-archive-sha256> \
MALWEAVE_REPO_DIR=/srv/malweave \
./scripts/setup-ghidra-worker.sh

# Configure private local paths in /srv/malweave/.env, then run one unique section.
cd /srv/malweave
./scripts/run-ghidra-section.sh 1

# Resume the same section after an interruption; the wrapper detects its state database.
./scripts/run-ghidra-section.sh 1

# Coordinator: collect all section state files and merge each view.
./scripts/merge-ghidra-sections.sh dis /private/merged/dis /private/worker-state
./scripts/merge-ghidra-sections.sh dec /private/merged/dec /private/worker-state
```

The unified job records DIS and DEC independently for each source. It may retain a successful DIS
when DEC fails or times out; inspect each representation's private manifest and aggregate summary
before selecting a downstream cohort.
