#!/usr/bin/env bash
#
# Train one frozen MalWeave experiment on a Runpod Pod, then stop the Pod so a
# finished (or crashed) run cannot keep billing.
#
# Stop:      POST   https://rest.runpod.io/v1/pods/{podId}/stop
# Terminate: DELETE https://rest.runpod.io/v1/pods/{podId}
# Auth:      Authorization: Bearer $RUNPOD_API_KEY
#
# Run this INSIDE the Pod. Runpod injects RUNPOD_POD_ID into the container; if you
# use plain SSH and it is empty, pass --pod-id explicitly.
#
# The Pod is stopped on ANY exit (success, failure, or Ctrl-C). Pass
# --keep-alive-on-failure to leave it running after a failure for debugging, or
# --no-stop to disable auto-stop entirely.
#
# Example:
#   RUNPOD_API_KEY=... scripts/train-and-stop-runpod.sh \
#     --experiment configs/experiments/malconv-raw.yaml \
#     --preset pilot --track malconvgct --run-id rands-raw-pilot-001 \
#     --artifact-root /workspace/malweave/work/runs \
#     --staging-report /workspace/malweave/work/staged/rands-malconv-raw/pilot/staging-summary.json
#
set -euo pipefail

REST_URL="${RUNPOD_REST_URL:-https://rest.runpod.io/v1}"
POD_ID="${RUNPOD_POD_ID:-}"
STOP_ACTION="stop"
STOP_RETRIES="${STOP_RETRIES:-3}"
KEEP_ALIVE_ON_FAILURE=0
NO_STOP=0
MALWEAVE_BIN="${MALWEAVE_BIN:-}"
declare -a TRAIN_ARGS=()

die() {
  printf 'error: %s\n' "$1" >&2
  exit 2
}

usage() {
  awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --experiment|--preset|--split-manifest|--track|--run-id|--artifact-root|--raw-root|--exe-root|--staging-report|--device|--raw-samples-dir)
      [[ $# -ge 2 ]] || die "$1 needs a value"
      TRAIN_ARGS+=("$1" "$2")
      shift 2
      ;;
    --seed|--gradient-accumulation-steps)
      [[ $# -ge 2 ]] || die "$1 needs a value"
      TRAIN_ARGS+=("$1" "$2")
      shift 2
      ;;
    --pod-id)
      [[ $# -ge 2 ]] || die "--pod-id needs a value"
      POD_ID="$2"
      shift 2
      ;;
    --terminate)
      STOP_ACTION="terminate"
      shift
      ;;
    --keep-alive-on-failure)
      KEEP_ALIVE_ON_FAILURE=1
      shift
      ;;
    --no-stop)
      NO_STOP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      TRAIN_ARGS+=("$@")
      break
      ;;
    *)
      die "unknown argument: $1 (pass extra malweave flags after --)"
      ;;
  esac
done

joined=" ${TRAIN_ARGS[*]-} "
[[ "$joined" == *" --experiment "* ]] || die "--experiment is required"
[[ "$joined" == *" --run-id "* ]] || die "--run-id is required"

stop_pod() {
  local action="$1" method="POST" path="/stop" attempt body http
  if [[ "$action" == "terminate" ]]; then
    method="DELETE"
    path=""
  fi
  for ((attempt = 1; attempt <= STOP_RETRIES; attempt++)); do
    body="$(mktemp)"
    http="$(curl -sS -X "$method" \
      -H "Authorization: Bearer ${RUNPOD_API_KEY}" \
      -H "Accept: application/json" \
      -o "$body" -w '%{http_code}' \
      "${REST_URL}/pods/${POD_ID}${path}" 2>/dev/null || true)"
    if [[ "$http" =~ ^2 ]]; then
      printf '[runpod] %s requested for Pod %s (HTTP %s, attempt %s/%s).\n' \
        "$action" "$POD_ID" "$http" "$attempt" "$STOP_RETRIES" >&2
      rm -f "$body"
      return 0
    fi
    printf '[runpod] WARNING: %s attempt %s/%s returned HTTP %s.\n' \
      "$action" "$attempt" "$STOP_RETRIES" "${http:-000}" >&2
    [[ -s "$body" ]] && cat "$body" >&2
    rm -f "$body"
    [[ "$attempt" -lt "$STOP_RETRIES" ]] && sleep 5
  done
  return 1
}

on_exit() {
  local status=$?
  trap - EXIT
  if [[ "$NO_STOP" -eq 1 ]]; then
    printf '[runpod] --no-stop set; leaving Pod %s running.\n' "${POD_ID:-unknown}" >&2
    exit "$status"
  fi
  if [[ -z "$POD_ID" ]]; then
    printf '[runpod] WARNING: no Pod id (set RUNPOD_POD_ID or --pod-id); cannot %s.\n' \
      "$STOP_ACTION" >&2
    exit "$status"
  fi
  if [[ "$KEEP_ALIVE_ON_FAILURE" -eq 1 && "$status" -ne 0 ]]; then
    printf '[runpod] training failed (exit %s); leaving Pod %s running for debugging.\n' \
      "$status" "$POD_ID" >&2
    exit "$status"
  fi
  printf '[runpod] training finished (exit %s); requesting %s.\n' "$status" "$STOP_ACTION" >&2
  stop_pod "$STOP_ACTION" || true
  exit "$status"
}

if [[ "$NO_STOP" -eq 0 ]]; then
  [[ -n "${RUNPOD_API_KEY:-}" ]] || die "set RUNPOD_API_KEY or pass --no-stop"
  [[ -n "$POD_ID" ]] || printf '[runpod] WARNING: RUNPOD_POD_ID is empty; pass --pod-id to enable auto-stop.\n' >&2
fi
command -v curl >/dev/null || die "curl is required"
if [[ -z "$MALWEAVE_BIN" ]]; then
  command -v uv >/dev/null || die "uv is required (or set MALWEAVE_BIN)"
fi

trap on_exit EXIT

if [[ -n "$MALWEAVE_BIN" ]]; then
  read -r -a RUNNER <<< "$MALWEAVE_BIN"
else
  RUNNER=(uv run --locked malweave)
fi
printf '[runpod] Pod %s | action %s | retries %s | starting: %s experiment train %s\n' \
  "${POD_ID:-unknown}" "$STOP_ACTION" "$STOP_RETRIES" "${RUNNER[*]}" "${TRAIN_ARGS[*]}" >&2
"${RUNNER[@]}" experiment train "${TRAIN_ARGS[@]}"
