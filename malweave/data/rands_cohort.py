"""Freeze the approved first RanDS round using curator metadata, without DiE gates."""

from collections import Counter, defaultdict
import csv
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import random
import sqlite3
from typing import Any

import yaml

from malweave.config import CONFIGS_DIR
from malweave.data.dataset_config import load_rands_dataset_config
from malweave.data.rands import SHA256_PATTERN, load_rands_metadata
from malweave.data.s3_layout import EXE_PREFIX, RAW_PREFIX, sharded_key
from malweave.experiments.rands_comparison import SPLIT_FIELDS
from malweave.training.contracts import SupervisedTrainingError, _private_path


def _load_model_input_audit(
    root: Path | None, config: dict, products: dict, candidates: list[str], metadata
) -> tuple[dict[str, str], dict]:
    """Require complete, immutable audit evidence for the pre-sampling EXE pool."""
    if root is None:
        raise SupervisedTrainingError("Exact model-input deduplication requires --input-audit.")
    try:
        identity_path = root / "identity.json"
        database = root / "audit.sqlite3"
        identity = json.loads(identity_path.read_text())
        summary = json.loads((root / "summary.json").read_text())
        limits = config["inputs"]["exe"]["truncation"]
        if (
            identity["max_bytes"] != limits["max_bytes"]
            or identity["max_tokens_including_bos_eos"] != limits["max_tokens"]
            or identity["token_digest_encoding"]
            != "SHA256(uint64_le length + uint32_le token IDs)"
            or identity["production_adapter_sha256"]
            != sha256((Path(__file__).parent / "lmlm_inputs.py").read_bytes()).hexdigest()
            or any(
                not SHA256_PATTERN.fullmatch(identity[key])
                for key in ("tokenizer_sha256", "checkpoint_config_sha256", "audit_script_sha256")
            )
        ):
            raise SupervisedTrainingError("Model-input audit preprocessing identity mismatch.")
        if (
            summary["status"] != "complete"
            or summary["rows_expected"] != len(candidates)
            or summary["rows_verified"] != len(candidates)
            or summary["errors"] != 0
            or summary["audit_database_sha256"] != sha256(database.read_bytes()).hexdigest()
            or (root / "audit.sqlite3-wal").exists()
        ):
            raise SupervisedTrainingError("Model-input audit is incomplete or its digest changed.")
        with sqlite3.connect(database.resolve().as_uri() + "?mode=ro&immutable=1", uri=True) as db:
            if db.execute("pragma integrity_check").fetchone()[0] != "ok":
                raise SupervisedTrainingError("Model-input audit database integrity failed.")
            rows = db.execute(
                "select source,label,status,full_exe_sha,full_bytes,prefix_bytes,tokens,token_sha "
                "from samples"
            ).fetchall()
        if len(rows) != len(candidates) or {r[0] for r in rows} != set(candidates):
            raise SupervisedTrainingError("Model-input audit candidate coverage mismatch.")
        tokens = {}
        for source, label, status, exe_sha, size, prefix_size, length, digest in rows:
            product = products[source]
            if (
                label != metadata.records[source].label
                or status != "ok"
                or exe_sha != product["representation_sha256"]
                or size != int(product["extracted_size"])
                or prefix_size != min(size, limits["max_bytes"])
                or type(length) is not int
                or not 2 <= length <= limits["max_tokens"]
                or not isinstance(digest, str)
                or not SHA256_PATTERN.fullmatch(digest)
            ):
                raise SupervisedTrainingError("Stale or malformed model-input audit row.")
            tokens[source] = digest
        return tokens, {
            "identity": identity,
            "identity_sha256": sha256(identity_path.read_bytes()).hexdigest(),
            "database_sha256": summary["audit_database_sha256"],
            "summary_sha256": sha256((root / "summary.json").read_bytes()).hexdigest(),
            "candidates_verified": len(rows),
        }
    except (OSError, KeyError, TypeError, ValueError, sqlite3.Error) as error:
        raise SupervisedTrainingError(
            "Could not validate complete model-input audit evidence."
        ) from error


def freeze_metadata_cohort(
    metadata_root: Path,
    exe_manifest: Path,
    config_path: Path,
    output: Path,
    *,
    input_audit: Path | None = None,
) -> dict[str, Any]:
    """Filter, deduplicate before temporal split, then undersample train once.

    The EXE manifest and model-input audit are evidence; no payloads or DiE state are read.
    Every metadata source appears once in either split.csv or excluded.csv.
    """
    _private_path(output, "cohort output")
    if output.exists():
        raise SupervisedTrainingError(
            "Cohort output already exists; frozen cohorts are immutable."
        )
    config = yaml.safe_load(config_path.read_text())
    policy = config["cohort"]
    if policy != {
        "eligibility": "rands_metadata",
        "arch": "I386",
        "packed": False,
        "train_years": [2006, 2023],
        "validation_years": [2024, 2024],
        "test_years": [2025, 2025],
        "train_balance": "fixed_random_undersampling",
        "deduplication": "exact_model_tokens_after_full_exe",
        "seed": 0,
    }:
        raise SupervisedTrainingError(
            "Unsupported cohort policy; use the approved metadata round."
        )
    dataset = load_rands_dataset_config(CONFIGS_DIR / "datasets/rands-raw-2026.yaml")
    metadata = load_rands_metadata(dataset, metadata_root)
    if metadata.class_overlap:
        raise SupervisedTrainingError("Metadata has conflicting source labels; no cohort frozen.")
    products = {}
    with exe_manifest.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "source_sha256",
            "label",
            "extraction_status",
            "source_hash_status",
            "representation_sha256",
            "representation_relative_path",
            "extracted_size",
            "snapshot",
        }
        if not required <= set(reader.fieldnames or ()):
            raise SupervisedTrainingError("Incomplete EXE conversion manifest schema.")
        published_fields = {"source_key", "status", "exe_sha256", "exe_key", "exe_bytes"}
        published = bool(published_fields & set(reader.fieldnames))
        if published and not published_fields <= set(reader.fieldnames):
            raise SupervisedTrainingError("Incomplete published EXE mapping.")
        for row in reader:
            source = row["source_sha256"]
            if source in products or source not in metadata.records:
                raise SupervisedTrainingError("Duplicate or unknown source in EXE manifest.")
            if (
                row["label"] != metadata.records[source].label
                or row["snapshot"] != dataset.snapshot
            ):
                raise SupervisedTrainingError(
                    "EXE manifest label/snapshot disagrees with metadata."
                )
            if published and (
                row["source_key"] != sharded_key(RAW_PREFIX, source)
                or row["status"] != row["extraction_status"]
                or (
                    row["status"] == "success"
                    and (
                        row["exe_sha256"] != row["representation_sha256"]
                        or row["exe_key"] != sharded_key(EXE_PREFIX, row["representation_sha256"])
                        or row["exe_bytes"] != row["extracted_size"]
                    )
                )
            ):
                raise SupervisedTrainingError(
                    "Published EXE mapping disagrees with extraction evidence."
                )
            if row["extraction_status"] == "success":
                relative = PurePosixPath(row["representation_relative_path"])
                if (
                    row["source_hash_status"] != "verified"
                    or not SHA256_PATTERN.fullmatch(row["representation_sha256"])
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or not relative.parts
                    or int(row["extracted_size"]) <= 0
                ):
                    raise SupervisedTrainingError("Invalid successful EXE conversion evidence.")
            products[source] = row
    exclusions = []
    groups = defaultdict(list)

    def exclude(source: str, reason: str) -> None:
        record = metadata.records[source]
        exclusions.append(
            {
                "source_sha256": source,
                "label": record.label,
                "family": record.family or "",
                "year": record.year,
                "reason": reason,
            }
        )

    for source, record in sorted(metadata.records.items()):
        row = products.get(source)
        if record.arch.upper() != policy["arch"]:
            exclude(source, "metadata_architecture")
        elif record.packed:
            exclude(source, "metadata_packed")
        elif row is None:
            exclude(source, "metadata_without_exe_manifest")
        elif row["extraction_status"] != "success":
            exclude(source, "extraction_" + row["extraction_status"])
        else:
            groups[row["representation_sha256"]].append(source)
    candidates = []
    for digest, sources in sorted(groups.items()):
        if len({metadata.records[source].label for source in sources}) > 1:
            for source in sources:
                exclude(source, "conflicting_exe_labels")
            continue
        chosen = min(sources, key=lambda source: (metadata.records[source].year, source))
        for source in sources:
            if source != chosen:
                exclude(source, "same_label_exe_duplicate")
        candidates.append(chosen)
    token_digests, audit_evidence = _load_model_input_audit(
        input_audit, config, products, candidates, metadata
    )
    token_groups = defaultdict(list)
    for source in candidates:
        token_groups[token_digests[source]].append(source)
    cohort = []
    for digest, sources in sorted(token_groups.items()):
        if len({metadata.records[source].label for source in sources}) > 1:
            for source in sources:
                exclude(source, "conflicting_model_input_labels")
            continue
        chosen = min(sources, key=lambda source: (metadata.records[source].year, source))
        for source in sources:
            if source != chosen:
                exclude(source, "same_label_model_input_duplicate")
        record = metadata.records[chosen]
        split = next(
            (
                name
                for name in ("train", "validation", "test")
                if policy[name + "_years"][0] <= record.year <= policy[name + "_years"][1]
            ),
            None,
        )
        if split is None:
            exclude(chosen, "year_outside_protocol")
            continue
        product = products[chosen]
        row = dict.fromkeys(SPLIT_FIELDS, "")
        row.update(
            split=split,
            source_sha256=chosen,
            label=record.label,
            family=record.family or "",
            snapshot=dataset.snapshot,
            raw_representation_sha256=chosen,
            raw_relative_path=record.relative_path.as_posix(),
            raw_size=record.size_bytes,
            exe_representation_sha256=product["representation_sha256"],
            exe_relative_path=product["representation_relative_path"],
            exe_size=int(product["extracted_size"]),
            active_leakage_group_sha256=digest,
            year=record.year,
            arch=record.arch,
            packed=int(record.packed),
            eligibility_source="rands_metadata",
        )
        cohort.append(row)
    before = Counter((row["split"], row["label"]) for row in cohort)
    if any(
        before[name, label] == 0
        for name in ("train", "validation", "test")
        for label in ("benign", "ransomware")
    ):
        raise SupervisedTrainingError("Temporal partitions must each contain both classes.")
    target = min(before["train", label] for label in ("benign", "ransomware"))
    rng = random.Random(policy["seed"])
    keep = set()
    for label in ("benign", "ransomware"):
        candidates = sorted(
            row["source_sha256"]
            for row in cohort
            if row["split"] == "train" and row["label"] == label
        )
        # The current audited cohort has benign as majority. Do not silently introduce
        # non-stratified ransomware downsampling if a future release reverses that.
        if label == "ransomware" and len(candidates) > target:
            raise SupervisedTrainingError(
                "Ransomware is majority; family-stratified sampling needs review."
            )
        keep.update(rng.sample(candidates, target) if len(candidates) > target else candidates)
    selected = []
    for row in cohort:
        if row["split"] == "train" and row["source_sha256"] not in keep:
            exclude(row["source_sha256"], "train_undersampling")
        else:
            selected.append(row)
    selected.sort(key=lambda row: (row["split"], row["source_sha256"]))
    if len(selected) + len(exclusions) != len(metadata.records):
        raise SupervisedTrainingError("Cohort source accounting mismatch.")
    output.mkdir(parents=True, exist_ok=False)
    files = {
        "split.csv": (selected, (*SPLIT_FIELDS, "year", "arch", "packed", "eligibility_source")),
        "excluded.csv": (
            sorted(exclusions, key=lambda row: row["source_sha256"]),
            ("source_sha256", "label", "family", "year", "reason"),
        ),
    }
    for name, (rows, fields) in files.items():
        with (output / name).open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def counts(rows):
        return {
            name: dict(
                sorted(Counter(row["label"] for row in rows if row["split"] == name).items())
            )
            for name in ("train", "validation", "test")
        }

    summary = {
        "eligibility_source": "rands_metadata",
        "die_verified": False,
        "model_input_audit": audit_evidence,
        "model_input_groups": len(token_groups),
        "policy": policy,
        "metadata_sources": len(metadata.records),
        "exe_manifest_sources": len(products),
        "before_undersampling": counts(cohort),
        "split_counts": counts(selected),
        "excluded_by_reason_label": dict(
            sorted(Counter(row["reason"] + "/" + row["label"] for row in exclusions).items())
        ),
        "family_counts": {
            name: dict(
                sorted(
                    Counter(
                        row["family"]
                        for row in selected
                        if row["split"] == name and row["label"] == "ransomware"
                    ).items()
                )
            )
            for name in ("train", "validation", "test")
        },
        "selected_exe_bytes": sum(row["exe_size"] for row in selected),
        "schema_corrections": metadata.schema_corrections,
        "input_sha256": {
            name: sha256(path.read_bytes()).hexdigest()
            for name, path in {
                "Benign.csv": metadata_root / "Benign.csv",
                "Ransomware.csv": metadata_root / "Ransomware.csv",
                "exe_manifest": exe_manifest,
                "experiment": config_path,
            }.items()
        },
        "output_sha256": {
            name: sha256((output / name).read_bytes()).hexdigest() for name in files
        },
        "sampling": "Python random.Random(0).sample over lexically sorted source IDs; saved once",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def stage_cohort_exe(split_manifest: Path, exe_root: Path, s3_prefix: str, workers: int = 8):
    """Download only frozen EXE rows, verify full digests and reuse verified local files."""
    with split_manifest.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    return _stage_exe_rows(rows, exe_root, s3_prefix, workers)


def _stage_exe_rows(rows, exe_root: Path, s3_prefix: str, workers: int):
    from concurrent.futures import ThreadPoolExecutor
    import os
    import shutil
    import sys
    import time
    from urllib.parse import urlsplit

    import boto3
    from botocore.config import Config

    _private_path(exe_root, "EXE download root")
    location = urlsplit(s3_prefix)
    if location.scheme != "s3" or not location.netloc or location.query or location.fragment:
        raise SupervisedTrainingError("An explicit private s3:// EXE prefix is required.")
    if workers < 1:
        raise SupervisedTrainingError("Download workers must be positive.")
    if location.path.strip("/") != EXE_PREFIX:
        raise SupervisedTrainingError(
            "Expected the representations/exe prefix at the bucket root."
        )
    if not rows:
        raise SupervisedTrainingError("The frozen cohort is empty.")
    paths = [row["exe_relative_path"] for row in rows]
    if len(set(paths)) != len(paths):
        raise SupervisedTrainingError("Duplicate EXE paths in frozen cohort.")
    for row in rows:
        relative = PurePosixPath(row["exe_relative_path"])
        if (
            not relative.parts
            or relative.is_absolute()
            or ".." in relative.parts
            or not SHA256_PATTERN.fullmatch(row["exe_representation_sha256"])
            or int(row["exe_size"]) < 1
        ):
            raise SupervisedTrainingError("Invalid frozen EXE path/digest/size.")
        if not (exe_root / relative).resolve().is_relative_to(exe_root.resolve()):
            raise SupervisedTrainingError("EXE download path escapes its root.")
    exe_root.mkdir(parents=True, exist_ok=True)
    needed = sum(
        int(row["exe_size"]) for row in rows if not (exe_root / row["exe_relative_path"]).exists()
    )
    if shutil.disk_usage(exe_root).free < needed + 1024**3:
        raise SupervisedTrainingError(
            "Not enough free disk for the selected EXEs plus 1 GiB reserve."
        )
    client = boto3.client(
        "s3",
        config=Config(
            max_pool_connections=workers,
            connect_timeout=10,
            read_timeout=30,
            retries={"mode": "standard", "total_max_attempts": 3},
        ),
    )

    def download(row):
        path = exe_root / row["exe_relative_path"]
        expected = row["exe_representation_sha256"]
        if path.exists():
            digest = sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            if path.stat().st_size != int(row["exe_size"]) or digest.hexdigest() != expected:
                raise SupervisedTrainingError(
                    "Existing EXE digest/size mismatch; source paths omitted."
                )
            return "reused", 0
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".download")
        key = sharded_key(EXE_PREFIX, expected)
        response = client.get_object(Bucket=location.netloc, Key=key)
        size = 0
        digest = sha256()
        body = response["Body"]
        try:
            with temporary.open("wb") as output:
                for block in body.iter_chunks(chunk_size=1024 * 1024):
                    size += len(block)
                    digest.update(block)
                    output.write(block)
            if size != int(row["exe_size"]) or digest.hexdigest() != expected:
                raise SupervisedTrainingError(
                    "Downloaded EXE digest/size mismatch; source paths omitted."
                )
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        finally:
            body.close()
        return "downloaded", size

    started = last_log = time.monotonic()
    counts = Counter()
    transferred = 0
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for start in range(0, len(rows), workers * 4):
                for status, size in pool.map(download, rows[start : start + workers * 4]):
                    counts[status] += 1
                    transferred += size
                    if time.monotonic() - last_log >= 5:
                        print(
                            json.dumps(
                                {
                                    "phase": "download_exe",
                                    "completed": sum(counts.values()),
                                    "total": len(rows),
                                    "downloaded_bytes": transferred,
                                    "elapsed_seconds": time.monotonic() - started,
                                }
                            ),
                            file=sys.stderr,
                            flush=True,
                        )
                        last_log = time.monotonic()
    except Exception as error:
        raise SupervisedTrainingError(
            "EXE staging failed; verified completed files are reusable. "
            "Private provider/sample details omitted."
        ) from error
    return {
        "completed": sum(counts.values()),
        "counts": dict(counts),
        "downloaded_bytes": transferred,
        "elapsed_seconds": time.monotonic() - started,
    }
