"""Deterministic bounded-memory pilot selection from frozen SOREL metadata."""

from __future__ import annotations

import csv
from hashlib import sha256
import heapq
import io
import json
from pathlib import Path

from malweave.data.s3.inventory import OBJECT_FIELDS, S3InventoryError, validate_private_path
from malweave.data.s3.sorel import (
    SOREL_BINARIES_PREFIX,
    SOREL_BUCKET,
    SOREL_SHA256_PATTERN,
    write_json_atomic,
)


def select_sorel_pilot(
    sources: Path,
    snapshot: Path,
    manifest: Path,
    summary: Path,
    *,
    count: int = 10_000,
    seed: str = "sorel-exe-pilot-v1",
) -> dict:
    """Select the lowest seeded SHA-256 ranks, without size or label filtering."""
    validate_private_path(manifest)
    validate_private_path(summary, summary=True)
    if count < 1 or not seed:
        raise S3InventoryError("Positive count and nonempty seed required.")
    if len({p.resolve() for p in (sources, snapshot, manifest, summary)}) != 4:
        raise S3InventoryError("Input and output paths must differ.")
    if manifest.exists() or summary.exists():
        raise S3InventoryError("Pilot outputs already exist; refusing to overwrite.")
    frozen = json.loads(snapshot.read_text(encoding="utf-8"))
    expected = frozen["manifest"]
    if (
        frozen["bucket"] != SOREL_BUCKET
        or frozen["prefix"] != SOREL_BINARIES_PREFIX
        or frozen["snapshot_id"] != expected["sha256"]
        or count > expected["rows"]
    ):
        raise S3InventoryError("Invalid SOREL snapshot or insufficient sources.")
    digest = sha256()
    with sources.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != expected["sha256"] or sources.stat().st_size != expected["bytes"]:
        raise S3InventoryError("Source manifest differs from frozen snapshot.")
    seed_bytes = seed.encode("utf-8")
    selected: list[tuple[int, str, dict]] = []
    previous = ""
    rows = total = 0
    with sources.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != OBJECT_FIELDS:
            raise S3InventoryError("Unexpected source schema.")
        for row in reader:
            key = row["object_key"]
            if (
                None in row
                or any(value is None for value in row.values())
                or key <= previous
                or not key.startswith(SOREL_BINARIES_PREFIX)
                or not SOREL_SHA256_PATTERN.fullmatch(key[len(SOREL_BINARIES_PREFIX) :])
            ):
                raise S3InventoryError("Invalid or unordered source row.")
            size = int(row["object_size"])
            if size < 0:
                raise S3InventoryError("Negative object size.")
            previous = key
            rows += 1
            total += size
            rank = int.from_bytes(sha256(seed_bytes + b"\0" + key.encode()).digest(), "big")
            entry = (-rank, key, row)
            if len(selected) < count:
                heapq.heappush(selected, entry)
            elif rank < -selected[0][0]:
                heapq.heapreplace(selected, entry)
    if rows != expected["rows"] or total != frozen["total_object_bytes"]:
        raise S3InventoryError("Source aggregates differ from snapshot.")
    ordered = sorted(selected, key=lambda entry: (-entry[0], entry[1]))
    output = io.StringIO(newline="")
    fields = ("selection_order", "source_sha256", "bucket", *OBJECT_FIELDS, "snapshot_id")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for index, (_, key, row) in enumerate(ordered, 1):
        writer.writerow(
            {
                "selection_order": index,
                "source_sha256": key[len(SOREL_BINARIES_PREFIX) :],
                "bucket": SOREL_BUCKET,
                **row,
                "snapshot_id": frozen["snapshot_id"],
            }
        )
    payload = output.getvalue().encode("utf-8")
    result = {
        "schema_version": 1,
        "dataset": "SOREL-20M",
        "release": frozen["release"],
        "source_snapshot_id": frozen["snapshot_id"],
        "source_rows": rows,
        "selected_rows": count,
        "seed": seed,
        "selection_algorithm": "sha256(seed_utf8 + NUL + object_key_utf8), lowest ranks first",
        "filters": "None; no size, architecture, packing, or label filtering",
        "selected_compressed_bytes": sum(int(entry[2]["object_size"]) for entry in ordered),
        "manifest": {"rows": count, "bytes": len(payload), "sha256": sha256(payload).hexdigest()},
        "sample_bytes_read": False,
        "eligibility_verified": False,
        "remote_versions_pinned": False,
        "failure_policy": "Retain selected sources and record failures; do not replace failed samples",
    }
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("xb") as handle:
        handle.write(payload)
    write_json_atomic(summary, result)
    return result
