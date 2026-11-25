"""Bounded, audited per-source downloads with explicit attempts and reusable receipts."""

from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from malweave.data.sorel_io import SourceFailure, digest, durable_replace, json_write

BASE_URL = "https://sorel-20m.s3.amazonaws.com/09-DEC-2020/binaries/"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _curl(url: str, path: Path, config: Any, executable: str) -> dict[str, Any]:
    command = [
        executable,
        "-sS",
        "--fail",
        "--location",
        "--connect-timeout",
        "20",
        "--max-time",
        str(config.request_timeout_seconds),
        "--max-filesize",
        str(config.max_compressed_bytes),
        "--output",
        str(path),
        "--write-out",
        "%{json}",
        "--url",
        url,
    ]
    record: dict[str, Any] = {"command": command}
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=config.request_timeout_seconds + 5,
            check=False,
        )
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        try:
            metrics = json.loads(result.stdout)
        except (ValueError, TypeError):
            metrics = {}
        record["metrics"] = metrics
        try:
            record["http_status"] = (
                int(metrics.get("http_code", metrics.get("response_code", 0))) or None
            )
        except (AttributeError, TypeError, ValueError):
            record["http_status"] = None
        record["status"] = (
            "success"
            if result.returncode == 0
            else ("compressed_size_limit" if result.returncode == 63 else "download_error")
        )
        if record["http_status"] and record["http_status"] >= 400:
            record["status"] = f"http_{record['http_status']}"
        # Without an HTTP receipt a zero exit alone is not a verified S3 response.
        if record["status"] == "success" and record["http_status"] != 200:
            record["status"] = "download_invalid_receipt"
    except subprocess.TimeoutExpired as error:
        record.update(status="download_timeout", error=str(error), http_status=None)
        for key, value in (("stdout", error.stdout), ("stderr", error.stderr)):
            record[key] = (
                value.decode("utf-8", "replace") if isinstance(value, bytes) else value or ""
            )
    except OSError as error:
        record.update(status="download_error", error=str(error), http_status=None)
    return record


def _urllib(url: str, path: Path, config: Any) -> dict[str, Any]:
    started = time.monotonic()
    record: dict[str, Any] = {"http_status": None}
    try:
        with (
            urlopen(url, timeout=config.request_timeout_seconds) as response,
            path.open("wb") as output,
        ):
            record["http_status"] = response.status
            record["response_headers"] = dict(response.headers.items())
            size = 0
            while chunk := response.read(min(1024**2, config.max_compressed_bytes + 1 - size)):
                output.write(chunk)
                size += len(chunk)
                if size > config.max_compressed_bytes:
                    raise SourceFailure("compressed_size_limit")
                if time.monotonic() - started > config.request_timeout_seconds:
                    raise TimeoutError("Transfer deadline exceeded")
            output.flush()
            os.fsync(output.fileno())
        record["status"] = (
            "success" if record["http_status"] == 200 else "download_invalid_receipt"
        )
    except HTTPError as error:
        record.update(http_status=error.code, status=f"http_{error.code}", error=str(error))
    except SourceFailure as error:
        record.update(status=str(error), error=str(error))
    except (URLError, OSError, TimeoutError) as error:
        record.update(status="download_error", error=str(error))
        if isinstance(error, OSError) and error.errno in (
            errno.ENOSPC,
            errno.EDQUOT,
            errno.EACCES,
            errno.EROFS,
        ):
            record["status"] = "download_write_error"
    return record


def download_source(
    job: Path, identifier: str, config: Any, executable: str = "curl"
) -> tuple[Path, Path]:
    """Reuse a verified completed transfer, otherwise record every bounded attempt."""
    spool = job / "spool"
    spool.mkdir(exist_ok=True)
    output = spool / f"{identifier}.zlib"
    directory = job / "downloads" / identifier[:2] / identifier
    directory.mkdir(parents=True, exist_ok=True)
    receipt = directory / "receipt.json"
    active = directory / "active.json"
    # Persist the start before launching transport, so a killed parent leaves evidence.
    if active.is_file():
        interrupted = json.loads(active.read_text())
        saved = directory / f"attempt-{interrupted['attempt']:06d}.json"
        part = spool / f"{identifier}.{interrupted['attempt']:06d}.part"
        if not saved.is_file():
            observed = part.stat().st_size if part.is_file() else 0
            interrupted.update(
                status="download_interrupted",
                finished_at_utc=None,
                recovered_at_utc=_now(),
                wall_seconds=0,
                timing_complete=False,
                history_complete=False,
                received_bytes=observed,
                received_bytes_complete=False,
                total_received_bytes=interrupted["total_received_bytes"] + observed,
                note="Interrupted transfer: observed bytes are a lower bound; duration is unknown.",
            )
            json_write(saved, interrupted)
        # A surviving curl child can only write its old, unlinked attempt file.
        part.unlink(missing_ok=True)
        active.unlink()
    attempts = sorted(directory.glob("attempt-*.json"))
    # Recover interruption between the durable attempt and receipt writes.
    if attempts and (not receipt.is_file() or digest(attempts[-1]) != digest(receipt)):
        json_write(receipt, json.loads(attempts[-1].read_text()))
    if receipt.is_file():
        previous = json.loads(receipt.read_text())
        if previous["status"] == "success" and output.is_file():
            if digest(output) != previous["compressed_sha256"]:
                raise SourceFailure("download_corrupt_spool")
            return output, receipt
        if previous["status"] in ("http_403", "http_404", "compressed_size_limit"):
            raise SourceFailure(previous["status"])
    else:
        previous = {}
    sequence = max(
        (int(path.stem.split("-")[-1]) for path in directory.glob("attempt-*.json")), default=0
    )
    for retry in range(config.request_attempts):
        number = sequence + retry + 1
        part = spool / f"{identifier}.{number:06d}.part"
        part.unlink(missing_ok=True)
        started = time.monotonic()
        started_at = _now()
        json_write(
            active,
            {
                "schema": 1,
                "original_sha256": identifier,
                "url": BASE_URL + identifier,
                "backend": config.download_backend,
                "attempt": number,
                "started_at_utc": started_at,
                "http_status": None,
                "previous_attempt_sha256": digest(receipt) if receipt.is_file() else None,
                "total_wall_seconds": previous.get("total_wall_seconds", 0),
                "total_received_bytes": previous.get("total_received_bytes", 0),
                "history_complete": previous.get("history_complete", True),
            },
        )
        record = (
            _curl(BASE_URL + identifier, part, config, executable)
            if config.download_backend == "curl"
            else _urllib(BASE_URL + identifier, part, config)
        )
        size = part.stat().st_size if part.exists() else 0
        if size > config.max_compressed_bytes:
            record["status"] = "compressed_size_limit"
        if record.get("returncode") == 23:
            record["status"] = "download_write_error"
        if record["status"] == "success" and not part.is_file():
            record["status"] = "download_missing"
        record.update(
            schema=1,
            original_sha256=identifier,
            url=BASE_URL + identifier,
            backend=config.download_backend,
            attempt=sequence + retry + 1,
            started_at_utc=started_at,
            finished_at_utc=_now(),
            wall_seconds=round(time.monotonic() - started, 6),
            previous_attempt_sha256=digest(receipt) if receipt.is_file() else None,
            received_bytes=size,
            timing_complete=True,
            received_bytes_complete=True,
            history_complete=previous.get("history_complete", True),
        )
        record["total_wall_seconds"] = (
            previous.get("total_wall_seconds", 0) + record["wall_seconds"]
        )
        record["total_received_bytes"] = previous.get("total_received_bytes", 0) + size
        if record["status"] == "success":
            record["compressed_sha256"] = digest(part)
            with part.open("rb") as stream:
                os.fsync(stream.fileno())
            durable_replace(part, output)
        json_write(directory / f"attempt-{record['attempt']:06d}.json", record)
        json_write(receipt, record)
        active.unlink()
        previous = record
        if record["status"] == "download_write_error":
            raise OSError(
                "Cannot write downloaded input; source remains pending. See its receipt."
            )
        if record["status"] == "success":
            return output, receipt
        part.unlink(missing_ok=True)
        http = record.get("http_status")
        if record["status"] == "compressed_size_limit" or (
            http and 400 <= http < 500 and http not in (408, 429)
        ):
            break
        if retry + 1 < config.request_attempts:
            time.sleep(min(2**retry, 4))
    raise SourceFailure(record["status"])
