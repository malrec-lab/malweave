#!/usr/bin/env bash
set -euo pipefail

# This intentionally invokes the production bootstrap before using the synthetic fixture.
export MALWEAVE_REPO_DIR=/workspace
export GHIDRA_DIR=/opt/ghidra

bash scripts/setup-ghidra-worker.sh

UV_BIN="${UV_BIN:-/root/.local/bin/uv}"
if [[ ! -x "$UV_BIN" ]]; then
    UV_BIN="$(command -v uv)"
fi
FIXTURE_ROOT=/tmp/malweave-benign-e2e

"$UV_BIN" run --locked python examples/benign-ghidra/create_fixture.py "$FIXTURE_ROOT"

"$UV_BIN" run --locked malweave data extract-exe \
    --dataset rands \
    --config "$FIXTURE_ROOT/dataset.yaml" \
    --root "$FIXTURE_ROOT/corpus" \
    --representation-dir "$FIXTURE_ROOT/output/exe" \
    --state-db "$FIXTURE_ROOT/state/exe.sqlite" \
    --manifest "$FIXTURE_ROOT/state/exe-manifest.csv" \
    --summary "$FIXTURE_ROOT/reports/exe.json"

"$UV_BIN" run --locked malweave data extract-ghidra \
    --dataset rands \
    --config "$FIXTURE_ROOT/dataset.yaml" \
    --root "$FIXTURE_ROOT/corpus" \
    --representations dis dec \
    --analyze-headless "$GHIDRA_DIR/ghidra_11.2.1_PUBLIC/support/analyzeHeadless" \
    --dis-representation-dir "$FIXTURE_ROOT/output/dis" \
    --dec-representation-dir "$FIXTURE_ROOT/output/dec" \
    --state-db "$FIXTURE_ROOT/state/ghidra.sqlite" \
    --work-dir "$FIXTURE_ROOT/work" \
    --dis-manifest "$FIXTURE_ROOT/state/dis-manifest.csv" \
    --dec-manifest "$FIXTURE_ROOT/state/dec-manifest.csv" \
    --summary "$FIXTURE_ROOT/reports/ghidra.json" \
    --workers 1

"$UV_BIN" run --locked python examples/benign-ghidra/assert_e2e.py "$FIXTURE_ROOT"
