"""EXE-only RanDS acquisition, resumable hashing, quarantine and frozen splits.

No raw PE is fetched or opened. S3 names identify sources; EXE digests are computed
from downloaded bytes and are not inferred from multipart ETags.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import csv
import fcntl
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import yaml

from malweave.config import CONFIGS_DIR
from malweave.data.dataset_config import load_rands_dataset_config
from malweave.data.rands import SHA256_PATTERN, load_rands_metadata
from malweave.data.s3_layout import (
    DATASET_RECEIPT,
    EXE_MANIFEST,
    EXE_PREFIX,
    EXPERIMENTS_PREFIX,
    METADATA_PREFIX,
    sharded_key,
)
from malweave.training.contracts import _private_path


class RandsTrainingError(ValueError):
    """An EXE-only preparation/training contract could not be satisfied."""


def file_digest(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


class Progress:
    """Flushed JSON lines and heartbeat, including while downloads/checkpoints block."""

    def __init__(self, seconds: float = 5) -> None:
        self.seconds = max(0.1, seconds)
        self.started = time.monotonic()
        self.state: dict[str, Any] = {"phase": "starting"}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._heartbeat, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def _heartbeat(self) -> None:
        while not self.stop.wait(self.seconds):
            self.emit()

    def emit(self, **values: Any) -> None:
        with self.lock:
            if values.get("phase", self.state.get("phase")) != self.state.get("phase"):
                self.state = {}
            self.state.update(values)
            elapsed = time.monotonic() - self.started
            print(
                json.dumps({**self.state, "elapsed_seconds": round(elapsed, 2)}),
                file=sys.stderr,
                flush=True,
            )

    def __exit__(self, *args: object) -> None:
        self.stop.set()
        self.thread.join()


def load_config(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text())
    except yaml.YAMLError as error:
        raise RandsTrainingError("Invalid scratch YAML config.") from error
    if not isinstance(value, dict) or value.get("experiment", {}).get("kind") != "scratch":
        raise RandsTrainingError("Expected an EXE scratch experiment config.")
    required = {
        "experiment": ["kind", "snapshot", "seed"],
        "data": ["expected_exe_files", "conflict_policy", "duplicate_policy", "split_fractions"],
        "tokenizer": ["vocab_size", "max_train_files", "max_bytes_per_file", "full_byte_coverage"],
        "model": ["name", "max_tokens", "architecture"],
        "training": [
            "epochs",
            "batch_size",
            "gradient_accumulation_steps",
            "learning_rate",
            "weight_decay",
            "warmup_ratio",
            "max_grad_norm",
            "precision",
            "gradient_checkpointing",
        ],
        "runtime": [
            "dataloader_workers",
            "cpu_threads",
            "progress_seconds",
            "checkpoint_updates",
            "deterministic",
        ],
    }
    for section, keys in required.items():
        if not isinstance(value.get(section), dict) or not set(keys) <= value[section].keys():
            raise RandsTrainingError(f"Missing scratch config fields in {section}.")
    data = value["data"]
    if (
        data["conflict_policy"] != "quarantine_all"
        or data["duplicate_policy"] != "one_representative"
    ):
        raise RandsTrainingError(
            "Only explicit quarantine_all / one_representative policies supported."
        )
    fractions = data["split_fractions"]
    if set(fractions) != {"train", "validation", "test"} or any(
        v <= 0 for v in fractions.values()
    ):
        raise RandsTrainingError("Three positive split fractions required.")
    if not math.isclose(sum(fractions.values()), 1):
        raise RandsTrainingError("Split fractions must sum to one.")
    return value


def validate_s3(uri: str) -> str:
    parsed = urlsplit(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
        raise RandsTrainingError("Expected an S3 URI with bucket and nonempty prefix.")
    if parsed.query or parsed.fragment or any(p in {".", ".."} for p in parsed.path.split("/")):
        raise RandsTrainingError("Invalid S3 prefix.")
    return uri.rstrip("/")


def aws(*arguments: str) -> None:
    # AWS CLI performs bounded SDK retries. Output is retained by the caller's terminal.
    try:
        subprocess.run(["aws", *arguments, "--no-cli-pager"], check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise RandsTrainingError(
            "AWS CLI failed; check profile, permissions and network; rerun to resume."
        ) from error


def _fetch_manifest_exe(root: Path, exe_prefix: str, progress: Progress) -> dict[str, str]:
    from malweave.data.rands_cohort import _stage_exe_rows

    with TemporaryDirectory(prefix=".exe-manifest-", dir=root) as temp:
        manifest = Path(temp) / "manifest.csv"
        receipt_path = Path(temp) / DATASET_RECEIPT
        bucket = urlsplit(exe_prefix).netloc
        aws(
            "s3", "cp", f"s3://{bucket}/{DATASET_RECEIPT}", str(receipt_path), "--only-show-errors"
        )
        aws("s3", "cp", exe_prefix + "/manifest.csv", str(manifest), "--only-show-errors")
        manifest_hash = file_digest(manifest)
        try:
            receipt = json.loads(receipt_path.read_text())
            approved = (
                receipt["dataset"] == "rands"
                and receipt["phase"] == "verified"
                and receipt["digests"][EXE_MANIFEST] == manifest_hash
            )
        except (KeyError, TypeError, ValueError):
            approved = False
        if not approved:
            raise RandsTrainingError("EXE manifest does not match the published RanDS receipt.")
        provenance = {
            "dataset_receipt_sha256": file_digest(receipt_path),
            "exe_manifest_sha256": manifest_hash,
        }
        with manifest.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            required = {"source_sha256", "status", "exe_sha256", "exe_bytes", "exe_key"}
            if not required.issubset(reader.fieldnames or ()):
                raise RandsTrainingError("Invalid canonical EXE manifest columns.")
            rows = []
            for row in reader:
                if row["status"] != "success":
                    continue
                source, digest = row["source_sha256"], row["exe_sha256"]
                size = row["exe_bytes"] or ""
                if (
                    not SHA256_PATTERN.fullmatch(source or "")
                    or not SHA256_PATTERN.fullmatch(digest or "")
                    or row["exe_key"] != sharded_key(EXE_PREFIX, digest)
                    or not size.isdecimal()
                    or int(size) < 1
                ):
                    raise RandsTrainingError("Invalid source or object identity in EXE manifest.")
                rows.append(
                    {
                        "exe_relative_path": f"{source[:2]}/{source}.bin",
                        "exe_representation_sha256": digest,
                        "exe_size": size,
                    }
                )
    progress.emit(phase="download_exe", total=len(rows))
    _stage_exe_rows(rows, root / "exe", exe_prefix, workers=8)
    return provenance


def _input_prefixes(exe_prefix: str, metadata_prefix: str) -> None:
    exe, metadata = urlsplit(exe_prefix), urlsplit(metadata_prefix)
    if exe.path.strip("/") != EXE_PREFIX:
        raise RandsTrainingError("Expected the representations/exe prefix at the bucket root.")
    if metadata.path.strip("/") != METADATA_PREFIX or metadata.netloc != exe.netloc:
        raise RandsTrainingError("Expected the metadata prefix in the same RanDS bucket.")


def fetch_exe(root: Path, exe_prefix: str, metadata_prefix: str, progress: Progress) -> None:
    _private_path(root, "RanDS EXE work root")
    exe_prefix, metadata_prefix = validate_s3(exe_prefix), validate_s3(metadata_prefix)
    _input_prefixes(exe_prefix, metadata_prefix)
    root.mkdir(parents=True, exist_ok=True)
    (root / "metadata").mkdir(exist_ok=True)
    progress.emit(phase="download_metadata")
    for name in ["Benign.csv", "Ransomware.csv"]:
        temporary = root / "metadata" / (name + ".download")
        aws("s3", "cp", metadata_prefix + "/" + name, str(temporary), "--only-show-errors")
        os.replace(temporary, root / "metadata" / name)
    provenance = _fetch_manifest_exe(root, exe_prefix, progress)
    atomic_json(
        root / "storage.json",
        {
            "exe_prefix": exe_prefix,
            "metadata_prefix": metadata_prefix,
            "checksum_provenance": "verified_against_canonical_exe_manifest",
            **provenance,
        },
    )


def validate_experiment_prefix(prefix: str) -> str:
    prefix = validate_s3(prefix)
    if urlsplit(prefix).path != f"/{EXPERIMENTS_PREFIX}":
        raise RandsTrainingError("RanDS training output must use experiments/ at the bucket root.")
    return prefix


def _aws_json(*arguments: str) -> dict:
    try:
        result = subprocess.run(
            ["aws", *arguments, "--output", "json", "--no-cli-pager"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RandsTrainingError(
            "Cannot check S3; verify the AWS CLI, credentials and network."
        ) from error
    if result.returncode:
        raise RandsTrainingError(f"S3 preflight failed: {result.stderr[-1200:]}")
    try:
        return json.loads(result.stdout)
    except ValueError as error:
        raise RandsTrainingError("AWS CLI returned an invalid preflight response.") from error


def _check_experiment_storage(prefix: str, *, write_test: bool) -> dict:
    location = urlsplit(prefix)
    bucket = location.netloc
    prefix_key = location.path.lstrip("/")
    identity = _aws_json("sts", "get-caller-identity")
    region = (
        _aws_json("s3api", "get-bucket-location", "--bucket", bucket).get("LocationConstraint")
        or "us-east-1"
    )
    listing = _aws_json(
        "s3api",
        "list-objects-v2",
        "--bucket",
        bucket,
        "--prefix",
        prefix_key + "/",
        "--max-keys",
        "1",
    )
    checks = {
        "identity": "passed",
        "list_destination": "passed",
        "destination_has_objects": listing.get("KeyCount", 0) > 0,
        "put_get_checksum_delete": "not_tested",
    }
    if write_test:
        probe_key = f"{prefix_key}/checks/{uuid4().hex}/probe.txt"
        uri = f"s3://{bucket}/{probe_key}"
        with TemporaryDirectory(prefix="rands-s3-check-") as temporary:
            source = Path(temporary) / "probe.txt"
            destination = Path(temporary) / "download.txt"
            source.write_bytes(b"MalWeave RanDS S3 permission and checksum test.\n")
            try:
                aws("s3", "cp", str(source), uri, "--only-show-errors")
                aws("s3", "cp", uri, str(destination), "--only-show-errors")
                if file_digest(source) != file_digest(destination):
                    raise RandsTrainingError("S3 preflight round-trip checksum mismatch.")
            finally:
                aws("s3", "rm", uri, "--only-show-errors")
            remaining = _aws_json(
                "s3api",
                "list-objects-v2",
                "--bucket",
                bucket,
                "--prefix",
                probe_key,
                "--max-keys",
                "1",
            )
            if remaining.get("KeyCount", 0):
                raise RandsTrainingError("S3 preflight probe still exists after deletion.")
        checks["put_get_checksum_delete"] = "passed"
    return {
        "prefix": prefix,
        "region": "eu-west-1" if region == "EU" else region,
        "caller": {key: identity[key] for key in ("Account", "Arn")},
        "checks": checks,
    }


def check_storage(
    exe_prefix: str, metadata_prefix: str, result_prefix: str, *, write_test: bool = False
) -> dict[str, Any]:
    """Check input read permissions and optionally a tiny text output round trip."""
    exe_prefix, metadata_prefix = validate_s3(exe_prefix), validate_s3(metadata_prefix)
    _input_prefixes(exe_prefix, metadata_prefix)
    result_prefix = validate_experiment_prefix(result_prefix)
    parsed = urlsplit(exe_prefix)
    if urlsplit(result_prefix).netloc != parsed.netloc:
        raise RandsTrainingError("RanDS experiment output must use the same bucket as its inputs.")
    listing = _aws_json(
        "s3api",
        "list-objects-v2",
        "--bucket",
        parsed.netloc,
        "--prefix",
        parsed.path.lstrip("/") + "/",
        "--max-keys",
        "1",
    )
    if not listing.get("KeyCount"):
        raise RandsTrainingError("EXE prefix is empty.")
    for key in (DATASET_RECEIPT, EXE_MANIFEST):
        _aws_json("s3api", "head-object", "--bucket", parsed.netloc, "--key", key)
    metadata = urlsplit(metadata_prefix)
    sizes = {}
    for name in ["Benign.csv", "Ransomware.csv"]:
        head = _aws_json(
            "s3api",
            "head-object",
            "--bucket",
            metadata.netloc,
            "--key",
            metadata.path.strip("/") + "/" + name,
        )
        sizes[name] = head["ContentLength"]
    return {
        "input_list": "passed",
        "metadata_head_bytes": sizes,
        "output": _check_experiment_storage(result_prefix, write_test=write_test),
    }


FIELDS = (
    "split",
    "source_sha256",
    "exe_sha256",
    "relative_path",
    "size",
    "label",
    "family",
    "arch",
    "packed",
    "snapshot",
)


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: tuple[str, ...]) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def _prepare_exe(
    root: Path, config_path: Path, *, hash_workers: int = 4, progress: Progress | None = None
) -> dict[str, Any]:
    """Freeze one representative per non-conflicting exact EXE group; all exclusions retained."""
    _private_path(root, "RanDS EXE work root")
    config = load_config(config_path)
    root.mkdir(parents=True, exist_ok=True)
    metadata = root / "metadata"
    identity = {
        "config": file_digest(config_path),
        "metadata": {
            name: file_digest(metadata / name) for name in ["Benign.csv", "Ransomware.csv"]
        },
    }
    if (root / "prepared.json").exists():
        previous = json.loads((root / "prepared.json").read_text())
        if previous["identity"] != identity:
            raise RandsTrainingError(
                "Prepared config/metadata changed; choose a new data directory."
            )
        for name in ["split.csv", "excluded.csv"]:
            if file_digest(root / name) != previous["digests"][name]:
                raise RandsTrainingError("Frozen preparation artifact changed.")
        return previous
    metadata_config = load_rands_dataset_config(CONFIGS_DIR / "datasets/rands-raw-2026.yaml")
    loaded = load_rands_metadata(metadata_config, metadata)
    if loaded.class_overlap:
        raise RandsTrainingError(
            "Source IDs have conflicting class labels; resolve before preparation."
        )
    files = sorted((root / "exe").glob("*/*.bin"))
    if len(files) != config["data"]["expected_exe_files"]:
        raise RandsTrainingError(
            f"Expected {config['data']['expected_exe_files']} EXE files, found {len(files)}; finish download first."
        )
    if progress:
        progress.emit(phase="hash_exe", completed=0, total=len(files))
    connection = sqlite3.connect(root / "hashes.sqlite")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS hashes (path TEXT PRIMARY KEY, size INT, mtime INT, ctime INT, digest TEXT)"
    )
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[str] = set()
    cache = {row[0]: row[1:] for row in connection.execute("SELECT * FROM hashes")}

    def inspect(path: Path) -> tuple[dict[str, Any], tuple[Any, ...]]:
        source = path.stem
        if (
            not SHA256_PATTERN.fullmatch(source)
            or path.parent.name != source[:2]
            or path.is_symlink()
            or path.parent.is_symlink()
            or (root / "exe").is_symlink()
        ):
            raise RandsTrainingError("Invalid EXE source filename/shard or symlink.")
        if source not in loaded.records:
            raise RandsTrainingError("EXE source absent from metadata.")
        relative = path.relative_to(root / "exe").as_posix()
        stat = path.stat()
        if stat.st_size <= 0:
            raise RandsTrainingError("Empty EXE file; no split written.")
        fingerprint = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        saved = cache.get(relative)
        digest = saved[3] if saved and tuple(saved[:3]) == fingerprint else file_digest(path)
        after = path.stat()
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_ino) != (
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
            stat.st_ino,
        ):
            raise RandsTrainingError("EXE changed during hashing.")
        record = loaded.records[source]
        row = dict(
            zip(
                FIELDS,
                [
                    "",
                    source,
                    digest,
                    relative,
                    stat.st_size,
                    record.label,
                    record.family or "",
                    record.arch,
                    int(record.packed),
                    config["experiment"]["snapshot"],
                ],
            )
        )
        return row, (relative, *fingerprint, digest)

    try:
        # Bounded map chunks avoid queuing hundreds of thousands of futures.
        with ThreadPoolExecutor(max_workers=max(1, hash_workers)) as pool:
            for start in range(0, len(files), 128):
                for row, receipt in pool.map(inspect, files[start : start + 128]):
                    groups[row["exe_sha256"]].append(row)
                    seen.add(row["source_sha256"])
                    connection.execute("INSERT OR REPLACE INTO hashes VALUES (?,?,?,?,?)", receipt)
                connection.commit()
                if progress:
                    progress.emit(
                        phase="hash_exe", completed=min(start + 128, len(files)), total=len(files)
                    )
    finally:
        connection.close()
    excluded: list[dict[str, Any]] = []
    representatives: dict[str, list[dict[str, Any]]] = defaultdict(list)
    conflict_groups = 0
    for digest, rows in sorted(groups.items()):
        if len({row["label"] for row in rows}) > 1:
            conflict_groups += 1
            excluded.extend(
                {"source_sha256": row["source_sha256"], "reason": "conflicting_exe_labels"}
                for row in rows
            )
        else:
            chosen = min(rows, key=lambda row: row["source_sha256"])
            representatives[chosen["label"]].append(chosen)
            excluded.extend(
                {"source_sha256": row["source_sha256"], "reason": "same_label_exe_duplicate"}
                for row in rows
                if row is not chosen
            )
    excluded.extend(
        {"source_sha256": source, "reason": "metadata_without_exe"}
        for source in sorted(loaded.records.keys() - seen)
    )
    split: list[dict[str, Any]] = []
    fractions = config["data"]["split_fractions"]
    for label in ["benign", "ransomware"]:
        rows = sorted(
            representatives[label],
            key=lambda row: sha256(
                f"{config['experiment']['seed']}:{row['exe_sha256']}".encode()
            ).hexdigest(),
        )
        counts = {name: math.floor(len(rows) * value) for name, value in fractions.items()}
        for name in sorted(
            counts, key=lambda name: (-(len(rows) * fractions[name] - counts[name]), name)
        )[: len(rows) - sum(counts.values())]:
            counts[name] += 1
        if any(count < 1 for count in counts.values()):
            raise RandsTrainingError(
                "Too few non-conflicting groups for both labels in all splits."
            )
        offset = 0
        for name, count in counts.items():
            split.extend({**row, "split": name} for row in rows[offset : offset + count])
            offset += count
    split.sort(key=lambda row: (row["split"], row["source_sha256"]))
    for row in excluded:
        row["label"] = loaded.records[row["source_sha256"]].label
    _write_csv(root / "split.csv", split, FIELDS)
    _write_csv(root / "excluded.csv", excluded, ("source_sha256", "reason", "label"))
    result = {
        "identity": identity,
        "digests": {name: file_digest(root / name) for name in ["split.csv", "excluded.csv"]},
        "metadata_sources": len(loaded.records),
        "exe_sources": len(seen),
        "conflicting_exe_groups": conflict_groups,
        "excluded_by_reason": dict(Counter(row["reason"] for row in excluded)),
        "excluded_by_reason_label": dict(
            Counter(f"{row['reason']}/{row['label']}" for row in excluded)
        ),
        "split_counts": dict(Counter(row["split"] for row in split)),
        "split_labels": {
            name: dict(Counter(row["label"] for row in split if row["split"] == name))
            for name in fractions
        },
        "arch_by_split_label": dict(
            Counter(f"{r['split']}/{r['label']}/{r['arch']}" for r in split)
        ),
        "packed_by_split_label": dict(
            Counter(f"{r['split']}/{r['label']}/{r['packed']}" for r in split)
        ),
        "schema_corrections": loaded.schema_corrections,
        "checksum_provenance": "local SHA256 of EXE bytes; source-ID filenames are not EXE digests",
        "missing_exe_note": "Metadata-only sources include unreleased binaries and failed extraction; reasons not reconstructed.",
    }
    if len(split) + len(excluded) != len(loaded.records):
        raise RandsTrainingError("Source accounting mismatch.")
    atomic_json(root / "prepared.json", result)
    if progress:
        progress.emit(
            phase="prepared",
            **{k: result[k] for k in ["exe_sources", "conflicting_exe_groups", "split_counts"]},
        )
    return result


def load_split(root: Path, config_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    prepared = json.loads((root / "prepared.json").read_text())
    if prepared["identity"]["config"] != file_digest(config_path):
        raise RandsTrainingError("Training config differs from the frozen preparation config.")
    if prepared["digests"]["split.csv"] != file_digest(root / "split.csv"):
        raise RandsTrainingError("Frozen split digest changed.")
    with (root / "split.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    sources: set[str] = set()
    groups: set[str] = set()
    for row in rows:
        source, digest = row["source_sha256"], row["exe_sha256"]
        relative = Path(row["relative_path"])
        if (
            not SHA256_PATTERN.fullmatch(source)
            or not SHA256_PATTERN.fullmatch(digest)
            or source in sources
            or digest in groups
            or row["split"] not in {"train", "validation", "test"}
            or row["label"] not in {"benign", "ransomware"}
            or relative.as_posix() != f"{source[:2]}/{source}.bin"
            or int(row["size"]) <= 0
        ):
            raise RandsTrainingError("Malformed or leaking frozen split.")
        sources.add(source)
        groups.add(digest)
    for name in ["train", "validation", "test"]:
        if {row["label"] for row in rows if row["split"] == name} != {"benign", "ransomware"}:
            raise RandsTrainingError("Every split must contain both labels.")
    return rows, prepared


@contextmanager
def exclusive(path: Path):
    """Lock one local training run by ID."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RandsTrainingError("Another local writer is using this job.") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def prepare_exe(
    root: Path, config_path: Path, *, hash_workers: int = 4, progress: Progress | None = None
) -> dict[str, Any]:
    _private_path(root, "EXE preparation root")
    with exclusive(root / "preparation.lock"):
        return _prepare_exe(root, config_path, hash_workers=hash_workers, progress=progress)
