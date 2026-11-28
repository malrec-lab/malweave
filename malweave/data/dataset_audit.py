"""Native/.NET audit. Download one PE, inspect it locally, and remove the copy."""

from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import closing, contextmanager
import csv
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import struct
from tempfile import NamedTemporaryFile
from typing import Any

import dnfile
import pefile

from ..training.contracts import _private_path
from .audit_reporting import METHOD, canonical_job_identity, summarize
from .dataset_storage import dataset_input_dir, require_published_inventory
from .rands_die import DiskProgress, _stop_signals
from .s3_layout import (
    DATASET_SLUGS,
    INVENTORY,
    RAW_PREFIX,
    account_id,
    dataset_bucket,
    sharded_key,
)
from .storage_io import DataError, job_lock, json_write

DEFAULT_WORKERS = 16

LABEL_NATIVE = "native"
LABEL_DOTNET = "dotnet"
LABEL_DOTNET_INVALID = "dotnet_invalid"
LABEL_UNKNOWN = "unknown"

REASON_CLR_ABSENT = "clr_directory_absent"
REASON_METADATA_VALIDATED = "metadata_validated"
REASON_MALFORMED_METADATA = "malformed_metadata"
REASON_TRUNCATED_METADATA = "truncated_metadata"
REASON_INVALID_CLR_HEADER = "invalid_clr_header"
REASON_INVALID_PE_HEADER = "invalid_pe_header"
REASON_INSUFFICIENT_HEADER = "insufficient_header_data"
REASON_INCOMPLETE_DATA_DIRECTORIES = "incomplete_pe_data_directories"
REASON_INCOMPLETE_SECTION_TABLE = "incomplete_pe_section_table"
REASON_INCONSISTENT_CLR_DIRECTORY = "inconsistent_clr_directory"
REASON_DOWNLOAD_FAILED = "download_failed"
REASON_VERSION_MISMATCH = "object_version_mismatch"
REASON_SHA256_MISMATCH = "source_sha256_mismatch"
REASON_PARSER_ERROR = "parser_error"

STATUS_SUCCESS = "success"
STATUS_TRANSPORT_ERROR = "transport_error"
STATUS_VERSION_MISMATCH = "version_mismatch"


class TransportError(OSError):
    """Retryable network/object-storage failure (never a metadata verdict)."""


class ObjectVersionMismatch(DataError):
    """The source no longer matches the pinned inventory."""


class SourceDigestMismatch(ObjectVersionMismatch):
    """The downloaded content does not match the source inventory hash."""


def _s3_client(profile: str | None = None):
    import boto3
    from botocore.config import Config

    session = boto3.session.Session(profile_name=profile) if profile else boto3.session.Session()
    return session.client(
        "s3",
        config=Config(
            connect_timeout=5,
            read_timeout=60,
            retries={"total_max_attempts": 3},
            max_pool_connections=16,
        ),
    )


@contextmanager
def _object_body(client, bucket, key, etag):
    try:
        response = client.get_object(
            Bucket=bucket, Key=key, IfMatch=etag, ExpectedBucketOwner=account_id()
        )
    except Exception as exc:
        if _is_precondition_failed(exc):
            raise ObjectVersionMismatch(str(exc)) from exc
        raise TransportError(f"S3 get failed: {exc}") from exc
    with closing(response["Body"]) as body:
        status = response["ResponseMetadata"]["HTTPStatusCode"]
        if status != 200:
            raise TransportError(f"expected HTTP 200, got {status}")
        if response.get("ETag") != etag:
            raise ObjectVersionMismatch("response ETag differs from pinned ETag")
        yield response, body


def _read_body(body, size: int) -> bytes:
    try:
        return body.read(size)
    except Exception as exc:  # boto3 can return headers before the body fails
        raise TransportError(f"S3 response body read failed: {exc}") from exc


def _stream_full_file(client, row: dict, stream) -> str:
    """Write exactly one pinned source to disk and verify its complete digest."""
    expected_size = row["size"]
    received = 0
    digest = hashlib.sha256()
    with _object_body(client, row["bucket"], row["key"], row["etag"]) as (response, body):
        if response.get("ContentLength", expected_size) != expected_size:
            raise TransportError("object length differs from inventory size")
        while chunk := _read_body(body, 1024**2):
            received += len(chunk)
            if received > expected_size:
                raise TransportError("download exceeded inventory size")
            stream.write(chunk)
            digest.update(chunk)
    if received != expected_size:
        raise TransportError("object length differs from inventory size")
    actual = digest.hexdigest()
    if actual != row["sha256"]:
        raise SourceDigestMismatch("downloaded SHA-256 differs from the source inventory")
    return actual


def _is_precondition_failed(exc: Exception) -> bool:
    name = type(exc).__name__
    text = str(exc)
    return name in {"ClientError", "PreconditionFailed"} and (
        "412" in text or "PreconditionFailed" in text
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Source inventory adapters. Each loader returns a list of uniform source rows
# (dicts) and a dict of excluded-format counts. Rows are frozen into the job
# identity via ``sources_digest``.
# ---------------------------------------------------------------------------


def _sha_pattern_ok(value: str) -> bool:
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def _digest_rows(rows: Iterable[dict]) -> str:
    canonical = json.dumps(sorted(rows, key=lambda r: r["sha256"]), sort_keys=True)
    return _sha256(canonical.encode())


DATASETS = {dataset: dataset_input_dir(dataset) / INVENTORY for dataset in DATASET_SLUGS}


def load_sources_csv(
    dataset: str, inventory: Path | None = None
) -> tuple[list[dict], dict[str, int]]:
    """Load the dataset's flat sources CSV (the single per-dataset inventory file).

    Required columns: ``sha256, s3_key, size, etag``; optional: ``label``,
    ``clr_present``. Everything else the audit needs is derived here.
    """
    path = inventory if inventory is not None else DATASETS[dataset]
    if not path.exists():
        raise DataError(f"missing sources CSV for {dataset!r}: {path}")
    rows: list[dict] = []
    excluded: dict[str, int] = {}
    seen: set[str] = set()
    bucket = dataset_bucket(dataset, account_id())
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not {"sha256", "s3_key", "size", "etag"}.issubset(reader.fieldnames or ()):
            raise DataError("Inventory requires sha256, s3_key, size and etag columns.")
        for row in reader:
            sha = row["sha256"]
            if not _sha_pattern_ok(sha):
                raise DataError(f"{dataset} source with invalid sha256: {sha!r}")
            if sha in seen:
                raise DataError(f"duplicate {dataset} sha256: {sha}")
            key, size, etag = row["s3_key"], row["size"], row["etag"]
            if key != sharded_key(RAW_PREFIX, sha):
                raise DataError("Use the published S3 inventory with canonical RAW keys.")
            if (
                not size
                or not size.isascii()
                or not size.isdecimal()
                or int(size) < 1
                or not etag
                or not etag.strip()
            ):
                raise DataError("Inventory rows require a positive size and pinned ETag.")
            seen.add(sha)
            rows.append(
                {
                    "dataset": dataset,
                    "sha256": sha,
                    "bucket": bucket,
                    "key": key,
                    "size": int(size),
                    "etag": etag,
                    "label": row.get("label") or None,
                    "extra": {
                        k: v
                        for k, v in row.items()
                        if k not in {"sha256", "s3_key", "size", "etag", "label"}
                    },
                }
            )
    if not rows:
        raise DataError("The S3 inventory is empty.")
    if dataset == "rawmal":
        # Only PE rows are listed in rawmal/inventory.csv; non-PE formats were
        # excluded during conversion and are counted from the frozen inventory
        excluded = {"non_pe_formats": 110017}
    return rows, excluded


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _inspect_header(path: Path, prefix: bytes, size: int, evidence: dict) -> dict:
    result = {
        "status": STATUS_SUCCESS,
        "label": LABEL_UNKNOWN,
        "stage_a": evidence,
        "stage_b": None,
        "bytes": size,
        "error": None,
    }
    if len(prefix) < 0x40 or struct.unpack_from("<I", prefix, 0x3C)[0] + 24 > size:
        return {**result, "reason": REASON_INSUFFICIENT_HEADER}
    try:
        pe = pefile.PE(name=str(path), fast_load=True)
    except pefile.PEFormatError as exc:
        return {**result, "reason": REASON_INVALID_PE_HEADER, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - unexpected parser behaviour
        return {**result, "reason": REASON_PARSER_ERROR, "error": f"pefile: {exc}"}

    with closing(pe):
        optional = pe.OPTIONAL_HEADER
        coff = pe.FILE_HEADER
        directories = optional.DATA_DIRECTORY
        directory_count = optional.NumberOfRvaAndSizes
        section_count = coff.NumberOfSections
        evidence.update(
            machine=coff.Machine,
            optional_header_magic=optional.Magic,
            pe32_plus=optional.Magic == 0x20B,
            warnings=pe.get_warnings()[:8],
            declared_directory_count=directory_count,
            parsed_directory_count=len(directories),
            declared_section_count=section_count,
            parsed_section_count=len(pe.sections),
        )
        if optional.Magic not in {0x10B, 0x20B}:
            return {**result, "reason": REASON_INVALID_PE_HEADER}
        optional_end = optional.get_file_offset() + coff.SizeOfOptionalHeader
        directory_end = optional.get_file_offset() + optional.sizeof() + 8 * directory_count
        if directory_end > min(optional_end, size) or len(directories) < min(directory_count, 16):
            return {**result, "reason": REASON_INCOMPLETE_DATA_DIRECTORIES}
        if optional_end + 40 * section_count > size or len(pe.sections) != section_count:
            return {**result, "reason": REASON_INCOMPLETE_SECTION_TABLE}
        # Interpret an omitted CLR entry only after checking the declared header layout.
        declared = directory_count > 14
        entry = directories[14] if declared else None
        clr_rva, clr_size = (entry.VirtualAddress, entry.Size) if entry is not None else (0, 0)

    evidence.update(clr_directory_declared=declared, dir14_va=clr_rva, dir14_size=clr_size)
    if bool(clr_rva) != bool(clr_size):
        return {**result, "reason": REASON_INCONSISTENT_CLR_DIRECTORY}
    if not clr_rva:
        return {
            **result,
            "label": LABEL_NATIVE,
            "reason": REASON_CLR_ABSENT,
            "clr_present": False,
        }
    return {
        **result,
        "label": None,
        "reason": None,
        "clr_present": True,
        "error": "clr_present",
    }


def _inspect_metadata(path: Path, stage_b: dict) -> dict:
    size = stage_b["bytes"]
    try:
        dn = dnfile.dnPE(name=str(path))
    except pefile.PEFormatError as exc:
        # dnfile surfaces unreadable CLR structures as PEFormatError from pefile's
        # get_data (verified on 0.18.0: "data at RVA can't be fetched. Corrupt header?").
        stage_b["exception"] = f"PEFormatError: {exc}"
        text = str(exc)
        if "can't be fetched" in text:
            reason = REASON_INVALID_CLR_HEADER
        elif "less than expected" in text:
            reason = REASON_TRUNCATED_METADATA
        else:
            return {
                "status": STATUS_SUCCESS,
                "label": LABEL_UNKNOWN,
                "reason": REASON_PARSER_ERROR,
                "stage_b": stage_b,
                "bytes": size,
                "error": str(exc),
            }
        return {
            "status": STATUS_SUCCESS,
            "label": LABEL_DOTNET_INVALID,
            "reason": reason,
            "stage_b": stage_b,
            "bytes": size,
            "error": None,
        }
    except dnfile.errors.dnFormatError as exc:
        # Rare escape path: dnfile 0.18.0 usually catches dnFormatError internally
        # and logs it instead; treat any escaped one as a malformed CLR structure.
        stage_b["exception"] = f"dnFormatError: {exc}"
        return {
            "status": STATUS_SUCCESS,
            "label": LABEL_DOTNET_INVALID,
            "reason": REASON_INVALID_CLR_HEADER,
            "stage_b": stage_b,
            "bytes": size,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - unexpected parser behaviour
        stage_b["exception"] = f"{type(exc).__name__}: {exc}"
        return {
            "status": STATUS_SUCCESS,
            "label": LABEL_UNKNOWN,
            "reason": REASON_PARSER_ERROR,
            "stage_b": stage_b,
            "bytes": size,
            "error": str(exc),
        }
    with closing(dn):
        net = getattr(dn, "net", None)
        metadata = getattr(net, "metadata", None)
        mdtables = getattr(net, "mdtables", None)
        stage_b["net_state"] = {
            "net": net is not None,
            "metadata": metadata is not None,
            "mdtables": mdtables is not None,
        }
        stage_b["streams"] = (
            [s.struct.Name.decode("latin1", "replace") for s in metadata.streams_list or []]
            if metadata
            else []
        )
        stage_b["flags_raw"] = net.struct.Flags if net else None
        stage_b["warnings"] = [str(w) for w in dn.get_warnings()][:8]
        ok = net is not None and metadata is not None and mdtables is not None
        if ok:
            label, reason = LABEL_DOTNET, REASON_METADATA_VALIDATED
        elif net is None:
            # "failed to parse CLR data: ..." logged internally by dnfile
            label, reason = LABEL_DOTNET_INVALID, REASON_INVALID_CLR_HEADER
        else:
            # CLR header parsed but metadata root/tables failed ("failed to parse
            # .NET metadata: ..." logged internally by dnfile)
            label, reason = LABEL_DOTNET_INVALID, REASON_MALFORMED_METADATA
    return {
        "status": STATUS_SUCCESS,
        "label": label,
        "reason": reason,
        "stage_b": stage_b,
        "bytes": size,
        "error": None,
    }


def classify_full_file(client, row: dict, job_dir: Path) -> dict:
    """Download one PE per worker and classify it locally from the same bytes."""
    with NamedTemporaryFile(dir=job_dir, prefix=".audit-pe-", suffix=".tmp") as temporary:
        try:
            digest = _stream_full_file(client, row, temporary)
        except (ObjectVersionMismatch, TransportError) as exc:
            mismatch = isinstance(exc, ObjectVersionMismatch)
            return {
                "status": STATUS_VERSION_MISMATCH if mismatch else STATUS_TRANSPORT_ERROR,
                "label": None if mismatch else LABEL_UNKNOWN,
                "reason": (
                    REASON_SHA256_MISMATCH
                    if isinstance(exc, SourceDigestMismatch)
                    else REASON_VERSION_MISMATCH
                    if mismatch
                    else REASON_DOWNLOAD_FAILED
                ),
                "stage_a": None,
                "stage_b": None,
                "bytes": temporary.tell(),
                "error": str(exc),
            }

        temporary.flush()
        path = Path(temporary.name)
        size = row["size"]
        with path.open("rb") as stream:
            prefix = stream.read(64)
        header = _inspect_header(
            path,
            prefix,
            size,
            {"fetched_bytes": size, "object_sha256": digest},
        )
        if not header.get("clr_present"):
            return header
        metadata = _inspect_metadata(path, {"bytes": size, "object_sha256": digest})
        return {**metadata, "stage_a": header["stage_a"], "clr_present": True}


# ---------------------------------------------------------------------------
# Job storage and runner
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS job (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS source (
    sha256 TEXT PRIMARY KEY,
    dataset TEXT,
    key TEXT,
    size INTEGER,
    etag TEXT,
    label TEXT,
    extra TEXT
);
CREATE TABLE IF NOT EXISTS result (
    sha256 TEXT PRIMARY KEY REFERENCES source(sha256),
    status TEXT,
    label TEXT,
    reason TEXT,
    clr_present INTEGER,
    stage_a TEXT,
    stage_b TEXT,
    bytes_downloaded INTEGER,
    error TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);
"""


def _identity(dataset: str, rows: list[dict], excluded: dict[str, int], config: dict) -> dict:
    """Pin the source snapshot and classification policy for resume."""
    return {
        "schema": 1,
        "method": METHOD,
        "dataset": dataset,
        "sources_count": len(rows),
        "sources_sha256": _digest_rows(rows),
        "excluded": excluded,
        "config": config,
        "pefile_version": pefile.__version__,
        "dnfile_version": dnfile.__version__,
        "python_version": platform.python_version(),
        "classification_policy": (
            "CLR absence requires a complete declared PE header and section table "
            "and an omitted CLR entry or a zero RVA and size"
        ),
    }


def _open_state(job_dir: Path) -> sqlite3.Connection:
    """A job directory belongs to exactly one dataset: fixed file names throughout."""
    # check_same_thread=False: workers only compute; the main thread owns all commits.
    db = sqlite3.connect(job_dir / "state.sqlite3", check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript(_SCHEMA)
    return db


def run_dataset_audit(
    job_dir: Path,
    dataset: str,
    *,
    sha_list: str | None = None,
    inventory: Path | None = None,
    workers: int = DEFAULT_WORKERS,
    limit: int | None = None,
    retry_errors: bool = False,
    profile: str | None = None,
) -> dict:
    """Audit one dataset with one full download per source.

    ``sha_list`` restricts the job to the listed sha256 values (one per line) —
    used by the stratified pilot so the full run gets its own job directory.
    """
    if workers < 1 or (limit is not None and limit < 1):
        raise DataError("workers and limit must be positive")
    if dataset not in DATASETS:
        raise DataError(f"unknown dataset {dataset!r}; expected one of {sorted(DATASETS)}")
    job_dir = Path(job_dir)
    _private_path(job_dir, "dataset audit job directory")

    rows, excluded = (
        load_sources_csv(dataset, inventory)
        if inventory is not None
        else load_sources_csv(dataset)
    )
    require_published_inventory(dataset, inventory or DATASETS[dataset], profile=profile)
    if sha_list:
        wanted = {
            line.strip()
            for line in Path(sha_list).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }
        by_sha = {r["sha256"]: r for r in rows}
        missing = sorted(wanted - set(by_sha))
        if missing:
            raise DataError(
                f"{len(missing)} sha256 not found in {dataset} inventory, e.g. {missing[:3]}"
            )
        rows = [by_sha[sha] for sha in sorted(wanted)]
        excluded = {}
    config: dict[str, Any] = {}
    if sha_list:
        config["sha_list_sha256"] = _sha256(Path(sha_list).read_bytes())
    identity = _identity(dataset, rows, excluded, config)
    identity_json = json.dumps(identity, sort_keys=True)

    job_dir.mkdir(parents=True, exist_ok=True)
    with job_lock(job_dir), _stop_signals(), closing(_open_state(job_dir)) as db:
        saved = db.execute("SELECT value FROM job WHERE key='identity'").fetchone()
        if saved is None:
            db.execute("INSERT INTO job(key, value) VALUES('identity', ?)", (identity_json,))
            db.executemany(
                "INSERT INTO source(sha256, dataset, key, size, etag, label, extra) "
                "VALUES(?,?,?,?,?,?,?)",
                [
                    (
                        r["sha256"],
                        r["dataset"],
                        r["key"],
                        r["size"],
                        r["etag"],
                        r["label"],
                        json.dumps(r["extra"]),
                    )
                    for r in rows
                ],
            )
            db.commit()
        elif canonical_job_identity(json.loads(saved[0])) != identity:
            raise DataError("Audit inputs/identity changed. Use a new job directory.")
        # Resume removes temporary files left by a hard stop under the writer lock.
        for temporary in job_dir.glob(".audit-pe-*.tmp"):
            temporary.unlink(missing_ok=True)
        progress = DiskProgress(job_dir / "progress")

        query = (
            "SELECT s.sha256, s.key, s.size, s.etag FROM source s "
            "LEFT JOIN result r ON s.sha256 = r.sha256 "
            "WHERE r.sha256 IS NULL OR r.status = ?"
        )
        params = [STATUS_VERSION_MISMATCH]
        if retry_errors:
            query += " OR r.status = ?"
            params.append(STATUS_TRANSPORT_ERROR)
        query += " ORDER BY s.rowid"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        pending = db.execute(query, params).fetchall()
        bucket = rows[0]["bucket"] if rows else None

        client = _s3_client(profile)
        total = len(pending)
        counts = {"completed": 0, "failed": 0, "pending": total, "bytes_downloaded": 0}
        progress.emit(phase="running", dataset=dataset, workers=workers, **counts)

        def work(item):
            sha, key, size, etag = item
            row = {"sha256": sha, "bucket": bucket, "key": key, "size": size, "etag": etag}
            return sha, classify_full_file(client, row, job_dir)

        active: dict[Any, None] = {}
        iterator = iter(pending)
        done = 0

        def submit_more():
            while len(active) < workers:
                try:
                    item = next(iterator)
                except StopIteration:
                    return
                future = executor.submit(work, item)
                active[future] = None

        with progress, ThreadPoolExecutor(max_workers=workers) as executor:
            submit_more()
            while active:
                done_set, _ = wait(list(active), timeout=5, return_when=FIRST_COMPLETED)
                for future in done_set:
                    del active[future]
                    sha, result = future.result()
                    db.execute(
                        "INSERT INTO result(sha256, status, label, reason, clr_present, "
                        "stage_a, stage_b, bytes_downloaded, error, updated_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,datetime('now')) "
                        "ON CONFLICT(sha256) DO UPDATE SET "
                        "status=excluded.status, label=excluded.label, "
                        "reason=excluded.reason, "
                        "clr_present=excluded.clr_present, "
                        "stage_a=excluded.stage_a, stage_b=excluded.stage_b, "
                        "bytes_downloaded=excluded.bytes_downloaded, "
                        "error=excluded.error, updated_at=excluded.updated_at",
                        (
                            sha,
                            result["status"],
                            result["label"],
                            result["reason"],
                            result.get("clr_present"),
                            json.dumps(result["stage_a"]) if result.get("stage_a") else None,
                            json.dumps(result["stage_b"]) if result.get("stage_b") else None,
                            result.get("bytes", 0),
                            result.get("error"),
                        ),
                    )
                    db.commit()
                    done += 1
                    counts["bytes_downloaded"] += result.get("bytes", 0)
                    if result["status"] == STATUS_SUCCESS:
                        counts["completed"] += 1
                    else:
                        counts["failed"] += 1
                    counts["pending"] = total - done
                    progress.emit(phase="running", dataset=dataset, **counts)
                submit_more()
        progress.emit(
            phase="complete" if counts["pending"] == 0 else "limited",
            dataset=dataset,
            workers=workers,
            **counts,
        )
        summary = summarize(job_dir)
        json_write(job_dir / "summary.json", summary)
        # Fold the WAL back into the main database so the file is self-contained:
        # moving/copying a finished job must never depend on -wal/-shm files.
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return summary
