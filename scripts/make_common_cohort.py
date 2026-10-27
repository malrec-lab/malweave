#!/usr/bin/env python3
"""Build a common RAW cohort matching an EXE cohort, with a derived staging report.

The EXE cohort is expected to be a subset of the RAW cohort with identical
split/label assignments. This script filters the RAW split manifest to the EXE
source identities and derives a staging report that points at the already staged
RAW root (no bytes are copied or reverified).

Usage:
    uv run --locked python scripts/make_common_cohort.py \
      --raw-manifest reports/runpod-reports/staged/raw-full-train-balanced/split-manifest.csv \
      --exe-manifest reports/runpod-reports/staged/exe-full-train-balanced-dedup/split-manifest.csv \
      --raw-staging  reports/runpod-reports/staged/raw-full-train-balanced/staging-summary.json \
      --output-manifest reports/runpod-reports/staged/raw-common/split-manifest.csv \
      --output-staging  reports/runpod-reports/staged/raw-common/staging-summary.json
"""

from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import io
import json
from pathlib import Path


def _read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or ())
        rows = list(reader)
    return fields, rows


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    payload = buffer.getvalue().encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-manifest", type=Path, required=True)
    parser.add_argument("--exe-manifest", type=Path, required=True)
    parser.add_argument("--raw-staging", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    parser.add_argument("--output-staging", type=Path, required=True)
    args = parser.parse_args()

    raw_fields, raw_rows = _read_rows(args.raw_manifest)
    _, exe_rows = _read_rows(args.exe_manifest)
    exe_sources = {row["source_sha256"] for row in exe_rows}
    raw_by_source = {row["source_sha256"]: row for row in raw_rows}
    missing = exe_sources - set(raw_by_source)
    if missing:
        raise SystemExit(f"{len(missing)} EXE sources are absent from the RAW manifest.")

    common = [raw_by_source[source] for source in exe_sources]
    mismatched = 0
    exe_split_label = {row["source_sha256"]: (row["split"], row["label"]) for row in exe_rows}
    for row in common:
        if (row["split"], row["label"]) != exe_split_label[row["source_sha256"]]:
            mismatched += 1
    if mismatched:
        raise SystemExit(f"{mismatched} common sources disagree on split/label.")

    payload = _write_csv(args.output_manifest, raw_fields, common)
    by_label: dict[str, int] = {}
    by_split: dict[str, int] = {}
    total_bytes = 0
    for row in common:
        by_label[row["label"]] = by_label.get(row["label"], 0) + 1
        by_split[row["split"]] = by_split.get(row["split"], 0) + 1
        total_bytes += int(row["object_size"])

    staging = json.loads(args.raw_staging.read_text(encoding="utf-8"))
    staging.update(
        {
            "manifest_sha256": sha256(payload).hexdigest(),
            "output_bytes": total_bytes,
            "selected": len(common),
            "success_by_label": dict(sorted(by_label.items())),
            "failure_by_label": {},
            "failure_reasons": {},
            "passed": True,
        }
    )
    staging["common_cohort_note"] = (
        "Derived subset of an already verified RAW staging report; every selected "
        "object is contained in the verified full cohort and was not re-downloaded."
    )
    args.output_staging.parent.mkdir(parents=True, exist_ok=True)
    args.output_staging.write_text(
        json.dumps(staging, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "common_sources": len(common),
                "by_split": dict(sorted(by_split.items())),
                "by_label": dict(sorted(by_label.items())),
                "output_bytes": total_bytes,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
