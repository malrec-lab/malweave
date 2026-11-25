"""Select one dataset's audit pilot from its current inventory."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import gzip
import json
from pathlib import Path
import random

from malweave.data.dataset_audit import DATASETS, load_sources_csv
from malweave.data.sorel_io import atomic_bytes
from malweave.training.contracts import _private_path


def _size_bucket(size: int) -> str:
    if size < 1024**2:
        return "<1 MiB"
    if size <= 8 * 1024**2:
        return "1–8 MiB"
    return ">8 MiB"


def _rands_markers() -> dict[str, str]:
    path = Path(DATASETS["rands"]["inventory_csv"]).with_name("file-descriptions.csv.gz")
    if not path.is_file():
        return {}
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        return {
            row["sha256"]: "clr"
            if "mono/.net assembly" in row["file_description"].lower()
            else "no-clr"
            for row in csv.DictReader(stream)
            if row["file_description"]
        }


def _select(rows: list[dict], markers: dict[str, str], limit: int) -> list[tuple[dict, tuple]]:
    strata = defaultdict(list)
    for row in rows:
        clr = {"0": "no-clr", "1": "clr"}.get(row["extra"].get("clr_present"))
        stratum = (
            _size_bucket(row["size"]),
            clr or markers.get(row["sha256"], "clr-unknown"),
            row["label"] or "label-unknown",
        )
        strata[stratum].append(row)

    keys = sorted(strata)
    # Cover each stratum with at least one file when the sample size allows it.
    allocation = {key: int(limit >= len(keys)) for key in keys}
    for _ in range(limit - sum(allocation.values())):
        key = max(
            (key for key in keys if allocation[key] < len(strata[key])),
            key=lambda key: limit * len(strata[key]) - allocation[key] * len(rows),
        )
        allocation[key] += 1

    rng = random.Random(0)
    return [
        (row, key)
        for key in keys
        for row in rng.sample(sorted(strata[key], key=lambda row: row["sha256"]), allocation[key])
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=sorted(DATASETS), required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="New .txt file of selected hashes."
    )
    parser.add_argument("--limit", type=int, default=250, help="Number of sources to sample.")
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")
    if args.output.suffix != ".txt" or args.output.exists():
        parser.error("--output must be a new .txt file")
    _private_path(args.output, "audit pilot sample")

    inventory, _ = load_sources_csv(args.dataset)
    rows = [row for row in inventory if row["etag"]]
    if len(rows) < args.limit:
        parser.error(f"only {len(rows)} inventory rows have an ETag")
    markers = _rands_markers() if args.dataset == "rands" else {}
    selected = _select(rows, markers, args.limit)
    atomic_bytes(args.output, "".join(row["sha256"] + "\n" for row, _ in selected).encode())
    print(
        json.dumps(
            {
                "dataset": args.dataset,
                "seed": 0,
                "inventory_files": len(inventory),
                "missing_etag": len(inventory) - len(rows),
                "selected": len(selected),
                "strata": dict(Counter(" / ".join(key) for _, key in selected)),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
