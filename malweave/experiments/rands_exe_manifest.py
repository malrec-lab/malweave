"""Freeze independent EXE cohorts from S3 and RanDS metadata, without RAW manifests."""

from collections import Counter, defaultdict
import csv
from decimal import Decimal
from hashlib import sha256
import io
import json
from pathlib import Path
import time
from typing import Any

from malweave.data.dataset_config import RandsDatasetConfig
from malweave.data.rands import load_rands_metadata
from malweave.data.s3.client import make_s3_client, read_s3_object
from malweave.data.s3.inventory import inventory_s3_prefix, validate_private_path
from malweave.data.s3.manifest import ManifestOptions, ManifestSelectionError, select_labeled_rows
from malweave.experiments.rands_exe_inputs import RandsExeInputError
from malweave.training.manifest import SHA256_PATTERN
from malweave.training.stage import _staging_lock, _write_new_verified_file

FIELDS = (
    "source_sha256",
    "split",
    "label",
    "group_id",
    "representation",
    "representation_sha256",
    "relative_path",
    "object_key",
    "object_size",
    "object_etag",
    "snapshot",
    "year",
    "arch",
    "metadata_packed",
)


def freeze_exe_s3_manifest(
    metadata_root: Path,
    dataset_config: RandsDatasetConfig,
    manifest: Path,
    summary: Path,
    state_root: Path,
    *,
    bucket: str,
    prefix: str,
    metadata_key: str,
    snapshot: str,
    seed: str,
    year_ranges: dict[str, dict[str, int]],
    metadata_filters: dict[str, Any],
    fractions: dict[str, float] | None = None,
    total: int | None = None,
    resume: bool = False,
    client: Any = None,
) -> dict[str, Any]:
    """Freeze a S3-compatible EXE split for either common staging backend.

    A durable prefix inventory supplies ETags/sizes; the extraction metadata supplies
    expected content digests. Actual bytes are verified later by the shared stager.
    Cross-split or cross-label identical representations fail closed, like training.
    Only train is balanced, after availability filtering; evaluation is not sampled.
    """
    for path in (manifest, state_root):
        validate_private_path(path)
    validate_private_path(summary, summary=True)
    with _staging_lock(state_root):
        return _freeze(
            metadata_root,
            dataset_config,
            manifest,
            summary,
            state_root,
            bucket=bucket,
            prefix=prefix,
            metadata_key=metadata_key,
            snapshot=snapshot,
            seed=seed,
            year_ranges=year_ranges,
            metadata_filters=metadata_filters,
            fractions=fractions or {"train": 0.7, "validation": 0.15, "test": 0.15},
            total=total,
            resume=resume,
            client=client,
        )


def _freeze(metadata_root, dataset_config, manifest, summary, state_root, **options):
    started = time.monotonic()
    if (manifest.exists() or summary.exists()) and not options["resume"]:
        raise RandsExeInputError("EXE outputs exist; use new paths for a new frozen cohort.")
    if not options["bucket"] or not options["prefix"].endswith("/"):
        raise RandsExeInputError("EXE requires a bucket and slash-terminated prefix.")
    metadata = load_rands_metadata(dataset_config, metadata_root)
    if metadata.class_overlap or dataset_config.snapshot != options["snapshot"]:
        raise RandsExeInputError("RanDS metadata labels overlap or snapshot differs.")
    metadata_digests = {
        name: sha256((metadata_root / name).read_bytes()).hexdigest()
        for name in (dataset_config.benign_csv, dataset_config.ransomware_csv)
    }
    ranges = options["year_ranges"]
    filters = options["metadata_filters"]
    if (
        set(ranges) != {"train", "validation", "test"}
        or not isinstance(filters.get("arch"), str)
        or not isinstance(filters.get("packed"), bool)
        or set(filters) != {"arch", "packed"}
        or any(
            not isinstance(v, int) or isinstance(v, bool)
            for bounds in ranges.values()
            for v in bounds.values()
        )
    ):
        raise RandsExeInputError("Unsupported EXE temporal ranges or metadata filters.")
    if not (
        set(ranges["train"]) == {"max"}
        and set(ranges["validation"]) == {"min", "max"}
        and set(ranges["test"]) == {"min"}
        and ranges["train"]["max"]
        < ranges["validation"]["min"]
        <= ranges["validation"]["max"]
        < ranges["test"]["min"]
    ):
        raise RandsExeInputError("EXE year ranges must be disjoint and chronological.")
    state_root.mkdir(parents=True, exist_ok=True)
    contract = {
        "schema": 2,
        "metadata_sha256": metadata_digests,
        "expected_sources": dataset_config.expected.files,
        "expected_labels": dataset_config.expected.labels,
        "year_ranges": ranges,
        "metadata_filters": filters,
        "total": options["total"],
        "fractions": options["fractions"],
        **{k: options[k] for k in ("bucket", "prefix", "metadata_key", "snapshot", "seed")},
        "manifest": str(manifest.resolve()),
        "summary": str(summary.resolve()),
    }
    contract_path = state_root / "contract.json"
    if options["resume"]:
        if not contract_path.is_file() or json.loads(contract_path.read_text()) != contract:
            raise RandsExeInputError("EXE metadata settings changed or state missing.")
    else:
        if any(state_root.iterdir()):
            raise RandsExeInputError("Existing EXE metadata state needs --resume.")
        _write_new_verified_file(contract_path, json.dumps(contract, sort_keys=True).encode())
    client = options["client"] or make_s3_client()
    cache = state_root / "extraction-metadata.json"
    if not cache.exists():
        payload, provenance = read_s3_object(
            client, options["bucket"], options["metadata_key"], max_bytes=256 * 1024 * 1024
        )
        _write_new_verified_file(
            cache,
            json.dumps(
                {
                    "csv": payload.decode("utf-8"),
                    "provenance": provenance,
                }
            ).encode(),
        )
    saved = json.loads(cache.read_text())
    text = saved["csv"]
    provenance = saved["provenance"]
    if sha256(text.encode()).hexdigest() != provenance["sha256"]:
        raise RandsExeInputError("EXE metadata cache digest changed.")
    inventory = state_root / "objects.csv"
    inventory_report = summary.with_name(summary.stem + "-objects.json")
    if not inventory.exists():
        inventory_s3_prefix(
            bucket=options["bucket"],
            prefix=options["prefix"],
            state_path=state_root / "objects.sqlite",
            manifest_path=inventory,
            summary_path=inventory_report,
            resume=(state_root / "objects.sqlite").exists(),
            client=client,
        )
    audit = json.loads(inventory_report.read_text())
    inventory_payload = inventory.read_bytes()
    if sha256(inventory_payload).hexdigest() != audit["manifest"]["sha256"]:
        raise RandsExeInputError("EXE object inventory digest changed.")
    objects = {r["object_key"]: r for r in csv.DictReader(io.StringIO(inventory_payload.decode()))}
    extracted = {}
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    required = {
        "source_sha256",
        "source_hash_status",
        "extraction_status",
        "label",
        "representation_sha256",
        "extracted_size",
        "snapshot",
    }
    if not required.issubset(reader.fieldnames or ()):
        raise RandsExeInputError("EXE extraction metadata schema is incomplete.")
    for row in reader:
        identity = row["source_sha256"]
        if not SHA256_PATTERN.fullmatch(identity) or identity in extracted:
            raise RandsExeInputError("Invalid or duplicate EXE source metadata.")
        extracted[identity] = row
    release_counts = Counter(row["label"] for row in extracted.values())
    if (
        len(extracted) != dataset_config.expected.files
        or dict(release_counts) != dataset_config.expected.labels
    ):
        raise RandsExeInputError("EXE extraction metadata does not match the full release counts.")
    for identity, row in extracted.items():
        record = metadata.records.get(identity)
        if (
            record is None
            or record.label != row["label"]
            or row["snapshot"] != options["snapshot"]
        ):
            raise RandsExeInputError("EXE metadata source, label or snapshot differs from RanDS.")
    expected_keys = {f"{options['prefix']}{s[:2]}/{s}.bin" for s in extracted}
    if any(key.endswith(".bin") and key not in expected_keys for key in objects):
        raise RandsExeInputError("EXE S3 objects lack extraction metadata or have invalid keys.")
    candidates = []
    exclusions = Counter()
    excluded_coverage = Counter()
    for identity, record in sorted(metadata.records.items()):
        label = record.label
        split = next(
            (
                name
                for name, bounds in ranges.items()
                if bounds.get("min", record.year) <= record.year <= bounds.get("max", record.year)
            ),
            None,
        )
        row = extracted.get(identity)
        key = f"{options['prefix']}{identity[:2]}/{identity}.bin"
        obj = objects.get(key)
        reason = None
        if record.arch != filters["arch"] or record.packed != filters["packed"]:
            reason = "metadata_filter"
        elif split is None:
            reason = "outside_year_ranges"
        elif row is None:
            reason = "missing_extraction_metadata"
        elif row["source_hash_status"] != "verified" or row["extraction_status"] != "success":
            reason = "extraction_not_successful"
        elif obj is None:
            reason = "missing_s3_object"
        if reason:
            exclusions[reason] += 1
            excluded_coverage[f"{split or 'unassigned'}/{label}/{reason}"] += 1
            continue
        digest = row["representation_sha256"]
        if (
            not SHA256_PATTERN.fullmatch(digest)
            or not obj["object_etag"]
            or int(obj["object_size"]) <= 0
            or int(obj["object_size"]) != int(row["extracted_size"])
        ):
            raise RandsExeInputError(
                "EXE object size or expected representation digest is invalid."
            )
        candidates.append(
            {
                "source_sha256": identity,
                "split": split,
                "label": label,
                "group_id": digest,
                "representation": "exe",
                "representation_sha256": digest,
                "relative_path": f"exe/{identity[:2]}/{identity}.bin",
                "object_key": key,
                "object_size": obj["object_size"],
                "object_etag": obj["object_etag"],
                "snapshot": options["snapshot"],
                "year": str(record.year),
                "arch": record.arch,
                "metadata_packed": str(int(record.packed)),
            }
        )
    fractions = {k: Decimal(str(v)) for k, v in options["fractions"].items()}
    cohort = candidates
    if options["total"] is not None:
        try:
            cohort, _ = select_labeled_rows(
                candidates,
                splits=("train", "validation", "test"),
                labels=("benign", "ransomware"),
                fractions=fractions,
                options=ManifestOptions(total=options["total"], seed=options["seed"]),
            )
        except ManifestSelectionError as error:
            raise RandsExeInputError(str(error)) from error
    groups = defaultdict(list)
    for row in cohort:
        groups[row["group_id"]].append(row)
    crossing = sum(len({r["split"] for r in g}) > 1 for g in groups.values())
    conflicts = sum(len({r["label"] for r in g}) > 1 for g in groups.values())
    report = {
        "passed": False,
        "inventory_audit_passed": True,
        "release_audit": {
            "passed": True,
            "extraction_rows": len(extracted),
            "by_label": dict(release_counts),
            "metadata_rows": len(metadata.records),
        },
        "metadata_sha256": metadata_digests,
        "year_ranges": ranges,
        "metadata_filters": filters,
        "metadata_provenance": provenance,
        "object_inventory_sha256": audit["manifest"]["sha256"],
        "selected_sources": len(cohort),
        "pilot_excluded": len(candidates) - len(cohort),
        "eligible": len(candidates),
        "exclusions": dict(exclusions),
        "exclusions_by_split_label_reason": dict(excluded_coverage),
        "cross_split_duplicate_groups": crossing,
        "cross_label_duplicate_groups": conflicts,
        "same_split_duplicates": "retain",
        "cross_split_policy": "fail",
        "verification": "metadata_only; staging must verify all representation bytes",
    }
    summary.parent.mkdir(parents=True, exist_ok=True)
    if crossing or conflicts:
        report["runtime_seconds"] = time.monotonic() - started
        summary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        raise RandsExeInputError("EXE duplicate groups cross splits or labels; see summary.")
    try:
        selected, selection = select_labeled_rows(
            cohort,
            splits=("train", "validation", "test"),
            labels=("benign", "ransomware"),
            fractions=fractions,
            options=ManifestOptions(balance_splits=("train",), seed=options["seed"]),
        )
        if any(
            not any(r["split"] == split and r["label"] == label for r in selected)
            for split in ("train", "validation", "test")
            for label in ("benign", "ransomware")
        ):
            raise ManifestSelectionError("EXE split lacks at least one class; cannot publish.")
    except ManifestSelectionError as error:
        report["selection_error"] = str(error)
        report["runtime_seconds"] = time.monotonic() - started
        summary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        raise RandsExeInputError(str(error)) from error
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(selected)
    payload = output.getvalue().encode()
    manifest.parent.mkdir(parents=True, exist_ok=True)
    if manifest.exists():
        if manifest.read_bytes() != payload:
            raise RandsExeInputError("Existing EXE manifest differs; refusing to overwrite it.")
    else:
        _write_new_verified_file(manifest, payload)
    report.update(
        {
            "passed": True,
            "selection": selection,
            "balance_excluded": len(cohort) - len(selected),
            "manifest": {"rows": len(selected), "sha256": sha256(payload).hexdigest()},
            "representation_bytes": sum(int(r["object_size"]) for r in selected),
            "runtime_seconds": time.monotonic() - started,
        }
    )
    summary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report
