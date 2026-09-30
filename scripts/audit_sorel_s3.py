#!/usr/bin/env python3
"""Inventory the public SOREL-20M binary prefix without downloading samples.

Run from the repository root:

    uv run python scripts/audit_sorel_s3.py

If interrupted, resume with the same options and --resume. The CSV inventory,
SQLite scan state, and summary are private local research artifacts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from malweave.data.s3.sorel import (
    SOREL_BINARIES_PREFIX,
    SOREL_BUCKET,
    audit_sorel_binary_prefix,
    make_unsigned_s3_client,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "List SOREL-20M S3 binary object metadata. This does not download or inspect "
            "binary contents and does not provide labels."
        )
    )
    parser.add_argument("--bucket", default=SOREL_BUCKET)
    parser.add_argument("--prefix", default=SOREL_BINARIES_PREFIX)
    parser.add_argument("--region", default=None, help="S3 region; defaults to AWS config.")
    parser.add_argument(
        "--state-db", type=Path, default=Path("data/processed/sorel-20m/binaries.sqlite")
    )
    parser.add_argument(
        "--manifest", type=Path, default=Path("data/processed/sorel-20m/binaries.csv")
    )
    parser.add_argument(
        "--summary", type=Path, default=Path("reports/sorel-20m/binaries-inventory.json")
    )
    parser.add_argument("--progress-every", type=int, default=100)
    parser.add_argument("--workers", type=int, default=1, help="Number of parallel workers")
    parser.add_argument("--resume", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    client = make_unsigned_s3_client(
        region_name=args.region, max_pool_connections=max(10, args.workers)
    )
    summary = audit_sorel_binary_prefix(
        bucket=args.bucket,
        prefix=args.prefix,
        state_path=args.state_db,
        manifest_path=args.manifest,
        summary_path=args.summary,
        client=client,
        resume=args.resume,
        progress_every=args.progress_every,
        workers=args.workers,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
