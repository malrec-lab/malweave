"""Read-only inspection and manifest construction for the RanDS raw PE corpus."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import csv
from dataclasses import dataclass
import hashlib
from itertools import chain
from pathlib import Path
import re
from typing import Any, Literal

from malweave.config import PROJECT_ROOT
from malweave.data.dataset_config import RandsDatasetConfig, RandsDatasetLocations, RandsProtocol

BENIGN_HEADER = (
    "SHA256",
    "SHA1",
    "MD5",
    "Size in bytes",
    "File extension",
    "Arch",
    "Packed",
    "Entropy",
    "Year",
    "Filepath",
)
RANSOMWARE_DOCUMENTED_HEADER = (
    "SHA256",
    "SHA1",
    "MD5",
    "Size in bytes",
    "File extension",
    "Arch",
    "Family",
    "Packed",
    "Entropy",
    "Year",
    "Filepath",
)
RANSOMWARE_ACTUAL_HEADER = (
    "SHA256",
    "SHA1",
    "MD5",
    "Size in bytes",
    "File extension",
    "Arch",
    "Packed",
    "Entropy",
    "Family",
    "Year",
    "Filepath",
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SHARD_PATTERN = re.compile(r"^[0-9a-f]{2}$")
HashMode = Literal["none", "sample", "all"]


class RandsDataError(ValueError):
    """Raised when the local RanDS release violates its data contract."""


@dataclass(frozen=True)
class RandsRecord:
    """Canonical metadata for one advertised RanDS sample."""

    sha256: str
    sha1: str
    md5: str
    size_bytes: int
    extension: str
    arch: str
    packed: bool
    entropy: float
    family: str | None
    year: int
    label: str

    @property
    def relative_path(self) -> Path:
        return Path(self.sha256[:2]) / self.sha256


@dataclass(frozen=True)
class LoadedRandsMetadata:
    records: dict[str, RandsRecord]
    rows_by_label: Counter[str]
    duplicate_rows: int
    class_overlap: int
    schema_corrections: tuple[str, ...]


def _require_header(actual: list[str], expected: tuple[str, ...], csv_path: Path) -> None:
    if tuple(actual) != expected:
        raise RandsDataError(
            f"Unexpected header in {csv_path.name}: expected {expected}, got {tuple(actual)}"
        )


def _parse_bool(value: str, csv_name: str, row_number: int) -> bool:
    if value == "0":
        return False
    if value == "1":
        return True
    raise RandsDataError(f"Invalid packed flag in {csv_name} row {row_number}: {value!r}")


def _parse_record(
    row: list[str],
    *,
    label: str,
    csv_name: str,
    row_number: int,
    ransomware_layout: Literal["documented_order", "actual_order"] | None = None,
) -> RandsRecord:
    expected_length = 10 if label == "benign" else 11
    if len(row) != expected_length:
        raise RandsDataError(
            f"Expected {expected_length} columns in {csv_name} row {row_number}, got {len(row)}."
        )

    sha256 = row[0].strip().lower()
    if not SHA256_PATTERN.fullmatch(sha256):
        raise RandsDataError(f"Invalid SHA-256 in {csv_name} row {row_number}.")

    if label == "benign":
        packed_index, entropy_index, family, year_index = 6, 7, None, 8
    elif ransomware_layout == "actual_order":
        packed_index, entropy_index, family, year_index = 6, 7, row[8].strip(), 9
    elif ransomware_layout == "documented_order":
        packed_index, entropy_index, family, year_index = 7, 8, row[6].strip(), 9
    else:
        raise RandsDataError("Ransomware metadata layout was not detected.")

    try:
        size_bytes = int(row[3])
        entropy = float(row[entropy_index])
        year = int(row[year_index])
    except ValueError as error:
        raise RandsDataError(f"Invalid numeric value in {csv_name} row {row_number}.") from error

    return RandsRecord(
        sha256=sha256,
        sha1=row[1].strip().lower(),
        md5=row[2].strip().lower(),
        size_bytes=size_bytes,
        extension=row[4].strip().lower(),
        arch=row[5].strip(),
        packed=_parse_bool(row[packed_index].strip(), csv_name, row_number),
        entropy=entropy,
        family=family or None,
        year=year,
        label=label,
    )


def _is_packed_flag(value: str) -> bool:
    return value in {"0", "1"}


def _is_float(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def _detect_ransomware_layout(header: list[str], row: list[str], csv_path: Path) -> str:
    if len(row) != 11:
        raise RandsDataError(f"Expected 11 columns in the first row of {csv_path.name}.")
    if tuple(header) == RANSOMWARE_ACTUAL_HEADER:
        if _is_packed_flag(row[6]) and _is_float(row[7]):
            return "actual_order"
    elif tuple(header) == RANSOMWARE_DOCUMENTED_HEADER:
        if _is_packed_flag(row[7]) and _is_float(row[8]):
            return "documented_order"
        if _is_packed_flag(row[6]) and _is_float(row[7]):
            return "actual_order"
    raise RandsDataError(
        f"Could not identify the Family/Packed/Entropy layout in {csv_path.name}."
    )


def _iter_csv_rows(csv_path: Path) -> tuple[list[str], Iterable[tuple[int, list[str]]]]:
    handle = csv_path.open(newline="", encoding="utf-8-sig")
    reader = csv.reader(handle)
    try:
        header = next(reader)
    except StopIteration as error:
        handle.close()
        raise RandsDataError(f"Metadata file is empty: {csv_path}") from error

    def rows() -> Iterable[tuple[int, list[str]]]:
        try:
            yield from enumerate(reader, start=2)
        finally:
            handle.close()

    return header, rows()


def load_rands_metadata(config: RandsDatasetConfig, root: Path) -> LoadedRandsMetadata:
    """Normalize both metadata files, including the published ransomware header mismatch."""
    records: dict[str, RandsRecord] = {}
    rows_by_label: Counter[str] = Counter()
    duplicate_rows = 0
    class_overlap_shas: set[str] = set()
    corrections: list[str] = []

    benign_path = root / config.benign_csv
    header, rows = _iter_csv_rows(benign_path)
    _require_header(header, BENIGN_HEADER, benign_path)
    for row_number, row in rows:
        record = _parse_record(
            row, label="benign", csv_name=benign_path.name, row_number=row_number
        )
        rows_by_label[record.label] += 1
        previous = records.get(record.sha256)
        if previous is not None:
            duplicate_rows += 1
            if previous.label != record.label:
                class_overlap_shas.add(record.sha256)
            continue
        records[record.sha256] = record

    ransomware_path = root / config.ransomware_csv
    header, rows = _iter_csv_rows(ransomware_path)
    if tuple(header) not in {RANSOMWARE_DOCUMENTED_HEADER, RANSOMWARE_ACTUAL_HEADER}:
        raise RandsDataError(f"Unexpected header in {ransomware_path.name}: {tuple(header)}")

    rows_iterator = iter(rows)
    try:
        first_row_number, first_row = next(rows_iterator)
    except StopIteration as error:
        raise RandsDataError(f"Metadata file has no records: {ransomware_path}") from error
    layout = _detect_ransomware_layout(header, first_row, ransomware_path)
    if tuple(header) == RANSOMWARE_DOCUMENTED_HEADER and layout == "actual_order":
        corrections.append(
            "Ransomware.csv header says Family/Packed/Entropy, but rows contain "
            "Packed/Entropy/Family; normalized by position."
        )

    for row_number, row in chain(((first_row_number, first_row),), rows_iterator):
        record = _parse_record(
            row,
            label="ransomware",
            csv_name=ransomware_path.name,
            row_number=row_number,
            ransomware_layout=layout,
        )
        rows_by_label[record.label] += 1
        previous = records.get(record.sha256)
        if previous is not None:
            duplicate_rows += 1
            if previous.label != record.label:
                class_overlap_shas.add(record.sha256)
            continue
        records[record.sha256] = record

    return LoadedRandsMetadata(
        records=records,
        rows_by_label=rows_by_label,
        duplicate_rows=duplicate_rows,
        class_overlap=len(class_overlap_shas),
        schema_corrections=tuple(corrections),
    )


def _matches_protocol(record: RandsRecord, protocol: RandsProtocol) -> bool:
    if protocol.arch is not None and record.arch != protocol.arch:
        return False
    return protocol.packed is None or record.packed == protocol.packed


def _counter_dict(counter: Counter[Any]) -> dict[str, int]:
    return {str(key): counter[key] for key in sorted(counter, key=str)}


def _distribution(records: list[RandsRecord]) -> dict[str, Any]:
    years = [record.year for record in records]
    families = Counter(record.family for record in records if record.family)
    return {
        "files": len(records),
        "architectures": _counter_dict(Counter(record.arch for record in records)),
        "extensions": _counter_dict(Counter(record.extension for record in records)),
        "packed": {
            "false": sum(not record.packed for record in records),
            "true": sum(record.packed for record in records),
        },
        "year_min": min(years) if years else None,
        "year_max": max(years) if years else None,
        "families": len(families),
        "families_support_1": sum(count == 1 for count in families.values()),
        "families_support_lt_10": sum(count < 10 for count in families.values()),
    }


def hash_file_sha256(path: Path) -> tuple[str, int]:
    """Return a file's SHA-256 and byte count without interpreting its contents."""
    digest = hashlib.sha256()
    bytes_read = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            bytes_read += len(chunk)
    return digest.hexdigest(), bytes_read


def _verify_content_hashes(paths: list[Path]) -> dict[str, int]:
    mismatches = 0
    bytes_read = 0
    for path in paths:
        digest, sample_bytes = hash_file_sha256(path)
        bytes_read += sample_bytes
        if digest != path.name.lower():
            mismatches += 1
    return {"checked": len(paths), "mismatches": mismatches, "bytes_read": bytes_read}


def _locations(root: Path | RandsDatasetLocations) -> RandsDatasetLocations:
    """Accept legacy combined roots while allowing metadata to live separately."""
    if isinstance(root, RandsDatasetLocations):
        return root
    return RandsDatasetLocations(raw_root=root, metadata_root=root)


def inspect_rands(
    config: RandsDatasetConfig,
    root: Path | RandsDatasetLocations,
    *,
    hash_mode: HashMode = "none",
) -> tuple[dict[str, Any], LoadedRandsMetadata, set[str]]:
    """Audit paths, metadata, distributions, release counts, and optional content hashes."""
    locations = _locations(root)
    if not locations.raw_root.is_dir():
        raise RandsDataError(f"RanDS raw root is not a directory: {locations.raw_root}")
    if not locations.metadata_root.is_dir():
        raise RandsDataError(f"RanDS metadata root is not a directory: {locations.metadata_root}")

    samples_root = locations.raw_root / config.samples_dir
    if not samples_root.is_dir():
        raise RandsDataError(f"RanDS samples directory does not exist: {samples_root}")

    metadata = load_rands_metadata(config, locations.metadata_root)
    present_shas: set[str] = set()
    present_by_label: dict[str, list[RandsRecord]] = {"benign": [], "ransomware": []}
    first_path_by_shard: dict[str, Path] = {}
    all_paths: list[Path] = []
    invalid_filenames = 0
    misplaced_files = 0
    orphan_files = 0
    size_mismatches = 0
    ignored_files = 0
    unexpected_root_files = 0
    total_bytes = 0

    shard_dirs = sorted(path for path in samples_root.iterdir() if path.is_dir())
    valid_shards = [path for path in shard_dirs if SHARD_PATTERN.fullmatch(path.name.lower())]
    invalid_shard_dirs = len(shard_dirs) - len(valid_shards)

    for path in samples_root.iterdir():
        if not path.is_file():
            continue
        if path.name == ".DS_Store":
            ignored_files += 1
        else:
            unexpected_root_files += 1

    for shard in valid_shards:
        for path in sorted(shard.iterdir(), key=lambda item: item.name):
            if not path.is_file():
                continue
            if path.name == ".DS_Store":
                ignored_files += 1
                continue

            sha256 = path.name.lower()
            if not SHA256_PATTERN.fullmatch(sha256):
                invalid_filenames += 1
                continue
            if shard.name.lower() != sha256[:2]:
                misplaced_files += 1

            all_paths.append(path)
            first_path_by_shard.setdefault(shard.name.lower(), path)
            present_shas.add(sha256)
            actual_size = path.stat().st_size
            total_bytes += actual_size

            record = metadata.records.get(sha256)
            if record is None:
                orphan_files += 1
                continue
            if actual_size != record.size_bytes:
                size_mismatches += 1
            present_by_label[record.label].append(record)

    protocol_summary: dict[str, Any] = {}
    for name, protocol in config.protocols.items():
        matching = [
            record
            for records in present_by_label.values()
            for record in records
            if _matches_protocol(record, protocol)
        ]
        labels = Counter(record.label for record in matching)
        ransomware_families = Counter(
            record.family for record in matching if record.label == "ransomware" and record.family
        )
        protocol_summary[name] = {
            "files": len(matching),
            "labels": _counter_dict(labels),
            "ransomware_families": len(ransomware_families),
            "ransomware_families_support_1": sum(
                count == 1 for count in ransomware_families.values()
            ),
            "ransomware_families_support_lt_10": sum(
                count < 10 for count in ransomware_families.values()
            ),
        }

    metadata_without_file = {
        label: metadata.rows_by_label[label] - len(present_by_label[label])
        for label in ("benign", "ransomware")
    }
    contract_mismatches: list[str] = []
    if len(valid_shards) != config.expected.shards:
        contract_mismatches.append(
            f"expected {config.expected.shards} shards, found {len(valid_shards)}"
        )
    if len(all_paths) != config.expected.files:
        contract_mismatches.append(
            f"expected {config.expected.files} files, found {len(all_paths)}"
        )
    for label, expected_count in config.expected.labels.items():
        actual_count = len(present_by_label[label])
        if actual_count != expected_count:
            contract_mismatches.append(
                f"expected {expected_count} {label} files, found {actual_count}"
            )

    integrity_failures = {
        "duplicate metadata rows": metadata.duplicate_rows,
        "cross-class SHA-256 values": metadata.class_overlap,
        "invalid shard directories": invalid_shard_dirs,
        "unexpected files at the samples root": unexpected_root_files,
        "invalid sample filenames": invalid_filenames,
        "misplaced sample files": misplaced_files,
        "orphan sample files": orphan_files,
        "file size mismatches": size_mismatches,
    }
    contract_mismatches.extend(
        f"found {count} {description}"
        for description, count in integrity_failures.items()
        if count
    )

    if hash_mode == "sample":
        hash_paths = [first_path_by_shard[name] for name in sorted(first_path_by_shard)]
    elif hash_mode == "all":
        hash_paths = all_paths
    elif hash_mode == "none":
        hash_paths = []
    else:
        raise RandsDataError(f"Unsupported hash mode: {hash_mode}")

    content_hashes = _verify_content_hashes(hash_paths)
    if content_hashes["mismatches"]:
        contract_mismatches.append(
            f"found {content_hashes['mismatches']} content SHA-256 mismatches"
        )

    summary = {
        "dataset": {"name": config.name, "snapshot": config.snapshot},
        "schema": {"corrections": list(metadata.schema_corrections)},
        "metadata": {
            "rows": _counter_dict(metadata.rows_by_label),
            "unique_sha256": len(metadata.records),
            "duplicate_rows": metadata.duplicate_rows,
            "class_overlap": metadata.class_overlap,
            "without_file": metadata_without_file,
        },
        "files": {
            "shards": len(valid_shards),
            "invalid_shard_dirs": invalid_shard_dirs,
            "files": len(all_paths),
            "ignored_files": ignored_files,
            "unexpected_root_files": unexpected_root_files,
            "invalid_filenames": invalid_filenames,
            "misplaced_files": misplaced_files,
            "orphan_files": orphan_files,
            "size_mismatches": size_mismatches,
            "total_bytes": total_bytes,
        },
        "present": {
            label: _distribution(present_by_label[label]) for label in ("benign", "ransomware")
        },
        "protocols": protocol_summary,
        "content_hashes": content_hashes,
        "contract": {"passed": not contract_mismatches, "mismatches": contract_mismatches},
    }
    return summary, metadata, present_shas


def _validate_manifest_path(path: Path) -> None:
    """Refuse to write sample inventories into versioned source locations."""
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return

    allowed_prefixes = (("data", "interim"), ("data", "processed"))
    if tuple(relative.parts[:2]) not in allowed_prefixes:
        raise RandsDataError(
            "Manifest paths inside the repository must be under data/interim or data/processed."
        )


def write_rands_manifest(
    path: Path,
    config: RandsDatasetConfig,
    metadata: LoadedRandsMetadata,
    present_shas: set[str],
) -> None:
    """Write a deterministic local inventory without provider machine paths."""
    _validate_manifest_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = (
        "sha256",
        "label",
        "label_id",
        "size_bytes",
        "extension",
        "arch",
        "packed",
        "entropy",
        "family",
        "year",
        "available",
        "relative_path",
        "snapshot",
    )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for sha256 in sorted(metadata.records):
            record = metadata.records[sha256]
            writer.writerow(
                {
                    "sha256": record.sha256,
                    "label": record.label,
                    "label_id": 0 if record.label == "benign" else 1,
                    "size_bytes": record.size_bytes,
                    "extension": record.extension,
                    "arch": record.arch,
                    "packed": int(record.packed),
                    "entropy": record.entropy,
                    "family": record.family or "",
                    "year": record.year,
                    "available": int(record.sha256 in present_shas),
                    "relative_path": (Path(config.samples_dir) / record.relative_path).as_posix(),
                    "snapshot": config.snapshot,
                }
            )
