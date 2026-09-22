#!/usr/bin/env bash
set -euo pipefail

# Merge one representation's completed unified Ghidra sections.
# Usage: ./merge-ghidra-sections.sh <dis|dec> <output-dir> <state-dir> [state-dir...]

REPRESENTATION="${1:-}"
OUTPUT_DIR="${2:-}"
if [[ "$REPRESENTATION" != "dis" && "$REPRESENTATION" != "dec" ]] || [[ -z "$OUTPUT_DIR" ]] || [[ $# -lt 3 ]]; then
    echo "Usage: $0 <dis|dec> <output-dir> <state-dir> [state-dir...]" >&2
    exit 1
fi
shift 2

mkdir -p "$OUTPUT_DIR"
MANIFESTS=()
SUMMARIES=()
for state_dir in "$@"; do
    if [[ ! -d "$state_dir" ]]; then
        echo "Error: state directory not found: $state_dir" >&2
        exit 1
    fi
    for manifest in "$state_dir"/"${REPRESENTATION}"-section-*.csv; do
        [[ -f "$manifest" ]] && MANIFESTS+=("$manifest")
    done
    for summary in "$state_dir"/section-*.json; do
        [[ -f "$summary" ]] && SUMMARIES+=("$summary")
    done
done

if [[ ${#MANIFESTS[@]} -eq 0 ]] || [[ ${#SUMMARIES[@]} -eq 0 ]]; then
    echo "Error: expected ${REPRESENTATION} manifests and unified section summaries." >&2
    exit 1
fi

python3 - "$REPRESENTATION" "$OUTPUT_DIR" "${MANIFESTS[@]}" -- "${SUMMARIES[@]}" <<'PYTHON'
import csv
import json
import sys
from collections import Counter
from pathlib import Path

representation = sys.argv[1]
output_dir = Path(sys.argv[2])
separator = sys.argv.index("--")
manifest_paths = [Path(path) for path in sys.argv[3:separator]]
summary_paths = [Path(path) for path in sys.argv[separator + 1 :]]

rows_by_sha = {}
for path in manifest_paths:
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            source_sha256 = row["source_sha256"]
            if source_sha256 in rows_by_sha:
                raise SystemExit(f"duplicate source in section manifests: {source_sha256}")
            rows_by_sha[source_sha256] = row

for path in summary_paths:
    summary = json.loads(path.read_text(encoding="utf-8"))
    job = summary.get("job", {})
    if not job.get("complete") or representation not in job.get("representations", []):
        raise SystemExit(f"section is incomplete or lacks {representation}: {path}")

rows = [rows_by_sha[source_sha256] for source_sha256 in sorted(rows_by_sha)]
with (output_dir / "manifest.csv").open("w", encoding="utf-8", newline="") as handle:
    if not rows:
        raise SystemExit("no manifest rows to merge")
    writer = csv.DictWriter(handle, fieldnames=rows[0].keys(), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)

statuses = Counter(row["extraction_status"] for row in rows)
labels = {
    label: dict(sorted(Counter(row["extraction_status"] for row in rows if row["label"] == label).items()))
    for label in ("benign", "ransomware")
}
packing = {
    name: dict(
        sorted(
            Counter(row["extraction_status"] for row in rows if row["metadata_packed"] == value).items()
        )
    )
    for name, value in (("unpacked", "0"), ("packed", "1"))
}
summary = {
    "job": {"sources_total": len(rows), "sources_completed": len(rows), "complete": True},
    "representation": representation,
    "extraction": {
        "statuses": dict(sorted(statuses.items())),
        "successful": statuses["success"],
        "failed": len(rows) - statuses["success"],
    },
    "labels": labels,
    "packing": packing,
    "sections_merged": len(summary_paths),
}
(output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PYTHON

echo "Merged ${#MANIFESTS[@]} ${REPRESENTATION} section manifests into $OUTPUT_DIR"
