"""Deterministic RAW and EXE product manifests for the full audited RanDS corpus."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from hashlib import sha256
import io
import json
from pathlib import Path
import time
from typing import Any

from malweave.config import PROJECT_ROOT
from malweave.data.dataset_config import RandsDatasetConfig, RandsDatasetLocations
from malweave.data.rands import SHA256_PATTERN
from malweave.data.rands_exe import enumerate_rands_sources

EXE_REQUIRED_FIELDS = {
    "source_sha256",
    "label",
    "family",
    "extraction_status",
    "representation_sha256",
    "representation_relative_path",
    "extracted_size",
    "runtime_ms",
    "snapshot",
}
PRODUCT_FIELDS = (
    "representation",
    "source_sha256",
    "label",
    "family",
    "representation_sha256",
    "leakage_group_sha256",
    "representation_relative_path",
    "representation_size",
    "snapshot",
)
DUPLICATE_GROUP_FIELDS = (
    "representation",
    "leakage_group_sha256",
    "group_member_count",
    "source_sha256",
    "label",
    "family",
    "representation_relative_path",
    "snapshot",
)


class RandsProductError(ValueError):
    """Raised when RAW/EXE inputs cannot form a safe, reproducible product."""


@dataclass(frozen=True)
class ExeInput:
    source_sha256: str
    label: str
    family: str
    status: str
    representation_sha256: str | None
    relative_path: str | None
    size: int
    runtime_ms: float
    snapshot: str


@dataclass(frozen=True)
class ProductRow:
    representation: str
    source_sha256: str
    label: str
    family: str
    representation_sha256: str
    relative_path: str
    size: int
    snapshot: str


def _validate_product_path(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if tuple(relative.parts[:2]) != ("data", "processed"):
        raise RandsProductError(
            "Product manifests inside the repository must be under data/processed."
        )


def _validate_summary_path(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] != "reports":
        raise RandsProductError("Product summaries inside the repository must be under reports/.")


def load_exe_inputs(path: Path) -> dict[str, ExeInput]:
    """Load one complete EXE manifest without accepting duplicate source identities."""
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as error:
        raise RandsProductError(f"Could not read EXE manifest: {path}") from error
    with handle:
        reader = csv.DictReader(handle)
        missing = sorted(EXE_REQUIRED_FIELDS - set(reader.fieldnames or ()))
        if missing:
            raise RandsProductError(
                f"EXE manifest is missing required fields: {', '.join(missing)}."
            )
        inputs: dict[str, ExeInput] = {}
        for row_number, row in enumerate(reader, start=2):
            source = (row["source_sha256"] or "").lower()
            digest = (row["representation_sha256"] or "").lower()
            if not SHA256_PATTERN.fullmatch(source) or source in inputs:
                raise RandsProductError(
                    f"Invalid or duplicate source SHA-256 in EXE manifest row {row_number}."
                )
            if row["extraction_status"] == "success" and not SHA256_PATTERN.fullmatch(digest):
                raise RandsProductError(
                    f"Successful EXE row {row_number} has no valid representation SHA-256."
                )
            try:
                size = int(row["extracted_size"])
            except ValueError as error:
                raise RandsProductError(
                    f"Invalid extracted size in EXE manifest row {row_number}."
                ) from error
            try:
                runtime_ms = float(row["runtime_ms"])
            except ValueError as error:
                raise RandsProductError(
                    f"Invalid runtime in EXE manifest row {row_number}."
                ) from error
            inputs[source] = ExeInput(
                source,
                row["label"],
                row["family"] or "",
                row["extraction_status"],
                digest or None,
                row["representation_relative_path"] or None,
                size,
                runtime_ms,
                row["snapshot"],
            )
    return inputs


def _groups(rows: list[ProductRow]) -> dict[str, int]:
    groups: dict[str, list[ProductRow]] = defaultdict(list)
    for row in rows:
        groups[row.representation_sha256].append(row)
    duplicates = [group for group in groups.values() if len(group) > 1]
    return {
        "groups": len(groups),
        "duplicate_groups": len(duplicates),
        "extra_sources": sum(len(group) - 1 for group in duplicates),
        "cross_label_groups": sum(len({row.label for row in group}) > 1 for group in duplicates),
    }


def build_rands_products(
    dataset_config: RandsDatasetConfig,
    root: Path | RandsDatasetLocations,
    exe_inputs: dict[str, ExeInput],
    exe_root: Path,
) -> tuple[list[ProductRow], dict[str, Any]]:
    """Verify RAW identities and freeze RAW/EXE rows without copying raw malware bytes."""
    locations = (
        root
        if isinstance(root, RandsDatasetLocations)
        else RandsDatasetLocations(raw_root=root, metadata_root=root)
    )
    sources = enumerate_rands_sources(dataset_config, locations)
    if set(exe_inputs) != {source.source_sha256 for source in sources}:
        raise RandsProductError(
            "EXE manifest sources must exactly match the full audited RanDS corpus."
        )
    started = time.perf_counter()
    raw_rows: list[ProductRow] = []
    exe_rows: list[ProductRow] = []
    raw_bytes = 0
    for source in sources:
        source_path = locations.raw_root / dataset_config.samples_dir / source.relative_path
        try:
            content = source_path.read_bytes()
        except OSError as error:
            raise RandsProductError(
                f"Could not read verified RAW source {source.source_sha256}."
            ) from error
        if sha256(content).hexdigest() != source.source_sha256:
            raise RandsProductError(f"RAW source hash changed for {source.source_sha256}.")
        raw_bytes += len(content)
        raw_rows.append(
            ProductRow(
                "raw",
                source.source_sha256,
                source.label,
                source.family,
                source.source_sha256,
                "source",
                len(content),
                source.snapshot,
            )
        )
        exe = exe_inputs[source.source_sha256]
        if exe.status != "success":
            continue
        assert exe.representation_sha256 is not None and exe.relative_path is not None
        representation_path = exe_root / exe.relative_path
        try:
            extracted = representation_path.read_bytes()
        except OSError as error:
            raise RandsProductError(
                f"Could not read EXE representation for {source.source_sha256}."
            ) from error
        if (
            sha256(extracted).hexdigest() != exe.representation_sha256
            or len(extracted) != exe.size
        ):
            raise RandsProductError(
                f"EXE representation integrity failed for {source.source_sha256}."
            )
        exe_rows.append(
            ProductRow(
                "exe",
                source.source_sha256,
                source.label,
                source.family,
                exe.representation_sha256,
                exe.relative_path,
                exe.size,
                source.snapshot,
            )
        )
    rows = [*raw_rows, *exe_rows]
    exe_bytes = sum(row.size for row in exe_rows)
    return rows, {
        "operation": "build_rands_products",
        "source_cohort": {
            "total": len(sources),
            "raw_available": len(raw_rows),
            "exe_available": len(exe_rows),
            "exe_excluded": dict(
                sorted(
                    Counter(
                        item.status for item in exe_inputs.values() if item.status != "success"
                    ).items()
                )
            ),
        },
        "products": {
            "raw": {
                "serialization": "source_reference",
                "padding": "none",
                "truncation": "none",
                "bytes": raw_bytes,
                "leakage_groups": _groups(raw_rows),
            },
            "exe": {
                "serialization": "executable_sections",
                "padding": "none",
                "truncation": "none",
                "bytes": exe_bytes,
                "leakage_groups": _groups(exe_rows),
            },
        },
        "runtime_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def write_rands_product_outputs(
    rows: list[ProductRow],
    summary: dict[str, Any],
    manifest_path: Path,
    duplicate_groups_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    """Persist local product provenance, duplicate membership, and an aggregate report."""
    _validate_product_path(manifest_path)
    _validate_product_path(duplicate_groups_path)
    _validate_summary_path(summary_path)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=PRODUCT_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "representation": row.representation,
                "source_sha256": row.source_sha256,
                "label": row.label,
                "family": row.family,
                "representation_sha256": row.representation_sha256,
                "leakage_group_sha256": row.representation_sha256,
                "representation_relative_path": row.relative_path,
                "representation_size": row.size,
                "snapshot": row.snapshot,
            }
        )
    payload = output.getvalue().encode()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(payload)
    exe_groups: dict[str, list[ProductRow]] = defaultdict(list)
    for row in rows:
        if row.representation == "exe":
            exe_groups[row.representation_sha256].append(row)
    duplicates = [group for group in exe_groups.values() if len(group) > 1]
    duplicate_output = io.StringIO(newline="")
    duplicate_writer = csv.DictWriter(
        duplicate_output, fieldnames=DUPLICATE_GROUP_FIELDS, lineterminator="\n"
    )
    duplicate_writer.writeheader()
    for group in sorted(duplicates, key=lambda group: group[0].representation_sha256):
        for row in sorted(group, key=lambda item: item.source_sha256):
            duplicate_writer.writerow(
                {
                    "representation": row.representation,
                    "leakage_group_sha256": row.representation_sha256,
                    "group_member_count": len(group),
                    "source_sha256": row.source_sha256,
                    "label": row.label,
                    "family": row.family,
                    "representation_relative_path": row.relative_path,
                    "snapshot": row.snapshot,
                }
            )
    duplicate_payload = duplicate_output.getvalue().encode()
    duplicate_groups_path.parent.mkdir(parents=True, exist_ok=True)
    duplicate_groups_path.write_bytes(duplicate_payload)
    completed = {
        **summary,
        "manifest": {"rows": len(rows), "sha256": sha256(payload).hexdigest()},
        "duplicate_groups_manifest": {
            "groups": len(duplicates),
            "rows": sum(len(group) for group in duplicates),
            "sha256": sha256(duplicate_payload).hexdigest(),
        },
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(completed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return completed
