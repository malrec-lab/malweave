#!/usr/bin/env bash
set -euo pipefail

# Run unified DIS+DEC Ghidra extraction for one shard section.
# Usage: ./run-ghidra-section.sh <section-number>

SECTION="${1:-}"
if [[ -z "$SECTION" ]]; then
    echo "Usage: $0 <section-number>"
    exit 1
fi

if [[ -f .env ]]; then
    set -a
    source .env
    set +a
fi

REQUIRED_VARS=(GHIDRA_ROOT MALWEAVE_RANDS_DIR MALWEAVE_OUTPUT_DIR MALWEAVE_STATE_DIR MALWEAVE_WORK_DIR MALWEAVE_SHARD_PLAN_DIR)
for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo "Error: $var is not set" >&2
        exit 1
    fi
done

MALWEAVE_CONFIG="${MALWEAVE_CONFIG:-configs/datasets/rands-raw-2026.yaml}"
MALWEAVE_RANDS_METADATA_DIR="${MALWEAVE_RANDS_METADATA_DIR:-$MALWEAVE_RANDS_DIR}"
if [[ -z "${MALWEAVE_WORKERS:-}" ]]; then
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then CPU_COUNT=$(nproc)
    elif [[ "$OSTYPE" == "darwin"* ]]; then CPU_COUNT=$(sysctl -n hw.ncpu)
    else CPU_COUNT=4
    fi
    MALWEAVE_WORKERS=$(( CPU_COUNT * 9 / 10 ))
    [[ $MALWEAVE_WORKERS -lt 1 ]] && MALWEAVE_WORKERS=1
fi

DIS_DIR="$MALWEAVE_OUTPUT_DIR/dis"
DEC_DIR="$MALWEAVE_OUTPUT_DIR/dec"
STATE_DB="$MALWEAVE_STATE_DIR/section-${SECTION}.sqlite"
DIS_MANIFEST="$MALWEAVE_STATE_DIR/dis-section-${SECTION}.csv"
DEC_MANIFEST="$MALWEAVE_STATE_DIR/dec-section-${SECTION}.csv"
SUMMARY="$MALWEAVE_STATE_DIR/section-${SECTION}.json"
ANALYZE_HEADLESS="$GHIDRA_ROOT/support/analyzeHeadless"
mkdir -p "$DIS_DIR" "$DEC_DIR" "$MALWEAVE_STATE_DIR" "$MALWEAVE_WORK_DIR"
[[ -x "$ANALYZE_HEADLESS" ]] || { echo "Error: analyzeHeadless is not executable: $ANALYZE_HEADLESS" >&2; exit 1; }

RESUME_FLAG=()
[[ -f "$STATE_DB" ]] && RESUME_FLAG=(--resume)
uv run --locked malweave data extract-ghidra \
    --dataset rands \
    --config "$MALWEAVE_CONFIG" \
    --root "$MALWEAVE_RANDS_DIR" \
    --metadata-root "$MALWEAVE_RANDS_METADATA_DIR" \
    --representations dis dec \
    --analyze-headless "$ANALYZE_HEADLESS" \
    --dis-representation-dir "$DIS_DIR" \
    --dec-representation-dir "$DEC_DIR" \
    --state-db "$STATE_DB" \
    --dis-manifest "$DIS_MANIFEST" \
    --dec-manifest "$DEC_MANIFEST" \
    --summary "$SUMMARY" \
    --work-dir "$MALWEAVE_WORK_DIR" \
    --workers "$MALWEAVE_WORKERS" \
    --shard-plan "$MALWEAVE_SHARD_PLAN_DIR" \
    --section "$SECTION" \
    --progress-every 50 \
    "${RESUME_FLAG[@]}"

echo "Extraction complete: section $SECTION"
 echo "State: $STATE_DB"
 echo "DIS: $DIS_DIR"
 echo "DEC: $DEC_DIR"
