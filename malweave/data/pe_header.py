"""Static raw PE-header extraction and a bounded private S3 batch pilot."""

from __future__ import annotations

from collections import Counter
import csv
from hashlib import sha256
import json
from pathlib import Path
import struct
import tempfile
import time

import lief

from malweave.data.pe_sections import _preflight_status


def extract_header(content: bytes) -> tuple[bytes | None, dict]:
    """Preserve original bytes, including padding; never rebuild a PE with LIEF."""
    audit = {"lief_version": lief.__version__, "input_bytes": len(content)}
    status = _preflight_status(content)
    if status:
        return None, {**audit, "status": status}
    pe = struct.unpack_from("<I", content, 0x3C)[0]
    optional = pe + 24
    optional_size = struct.unpack_from("<H", content, pe + 20)[0]
    sections = struct.unpack_from("<H", content, pe + 6)[0]
    if optional_size < 64:
        return None, {**audit, "status": "invalid_optional_header"}
    magic = struct.unpack_from("<H", content, optional)[0]
    if magic not in (0x10B, 0x20B):
        return None, {**audit, "status": "invalid_optional_magic"}
    size = struct.unpack_from("<I", content, optional + 60)[0]
    table_end = optional + optional_size + 40 * sections
    audit.update(size_of_headers=size, section_table_end=table_end, offset=0)
    if not table_end <= size <= len(content):
        return None, {**audit, "status": "invalid_size_of_headers"}
    lief.logging.disable()
    try:
        binary = lief.PE.parse(list(content))
        if not isinstance(binary, lief.PE.Binary):
            return None, {**audit, "status": "lief_parse_failed"}
        audit["pe"] = json.loads(lief.to_json(binary))
        if binary.optional_header.sizeof_headers != size:
            return None, {**audit, "status": "header_size_mismatch"}
    except (RuntimeError, ValueError, TypeError) as error:
        return None, {**audit, "status": "lief_error", "error": str(error)}
    header = content[:size]
    return header, {**audit, "status": "success", "header_sha256": sha256(header).hexdigest()}


def header_batch(
    *, manifest: Path, bucket: str, output_prefix: str, job_dir: Path, per_group: int = 2
) -> dict:
    """Run only a small balanced pilot. Source SHA is inherited, never recomputed.

    RAW GETs are pinned to inventory ETags and lengths, not claimed SHA verification.
    A unique job directory and destination prefix are required; no existing object is overwritten.
    """
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    if not 1 <= per_group <= 10:
        raise ValueError("Pilot per-group count must be between 1 and 10")
    if job_dir.exists():
        raise ValueError("Use a fresh pilot job directory")
    output_prefix = output_prefix.strip("/")
    if not output_prefix.startswith("rands/representations/pe-header/pilots/"):
        raise ValueError("Destination must be a dedicated PE-header pilot prefix")
    manifest_bytes = manifest.read_bytes()
    selected = []
    counts: Counter = Counter()
    with manifest.open(newline="") as handle:
        for row in csv.DictReader(handle):
            group = (row["split"], row["label"])
            if row["availability"] == "available" and counts[group] < per_group:
                selected.append(row)
                counts[group] += 1
    if len(counts) != 6 or any(count != per_group for count in counts.values()):
        raise ValueError("Pilot requires both labels in all three splits")
    for row in selected:
        source = row["source_sha256"]
        if len(source) != 64 or any(c not in "0123456789abcdef" for c in source):
            raise ValueError("Invalid source identity")
        if not row["object_etag"] or int(row["object_size"]) <= 0:
            raise ValueError("Missing pinned source object identity")
    job_dir.mkdir(parents=True, mode=0o700)
    s3 = boto3.client("s3")
    started = time.monotonic()
    results = []

    def publish(key: str, body: bytes) -> None:
        s3.put_object(
            Bucket=bucket, Key=key, Body=body, ServerSideEncryption="AES256", IfNoneMatch="*"
        )
        received = s3.get_object(Bucket=bucket, Key=key)["Body"]
        try:
            if sha256(received.read()).digest() != sha256(body).digest():
                raise RuntimeError("Uploaded object checksum mismatch")
        finally:
            received.close()

    for row in selected:
        source = row["source_sha256"]
        evidence = {
            "source": row,
            "source_digest_verification": "inherited; ETag-pinned GET and size check",
        }
        try:
            response = s3.get_object(
                Bucket=bucket, Key=row["object_key"], IfMatch=row["object_etag"]
            )
            with tempfile.TemporaryDirectory(prefix="pe-header-", dir=job_dir) as temporary:
                raw = Path(temporary) / "input.pe"
                try:
                    with raw.open("xb") as handle:
                        raw.chmod(0o600)
                        for block in response["Body"].iter_chunks(1024 * 1024):
                            handle.write(block)
                finally:
                    response["Body"].close()
                if raw.stat().st_size != int(row["object_size"]):
                    raise ValueError("RAW size mismatch")
                header, audit = extract_header(raw.read_bytes())
            evidence.update(audit)
        except (OSError, ValueError, RuntimeError, BotoCoreError, ClientError) as error:
            header = None
            evidence.update(status="failed", error_type=type(error).__name__, error=str(error))
        if header is not None:
            key = f"{output_prefix}/headers/{source[:2]}/{source}.bin"
            publish(key, header)
            evidence["header_key"] = key
        body = json.dumps(evidence, sort_keys=True).encode()
        publish(f"{output_prefix}/records/{source}.json", body)
        local = job_dir / f"{source}.json"
        local.write_bytes(body)
        local.chmod(0o600)
        results.append(evidence)
        print(json.dumps({"processed": len(results), "status": evidence["status"]}), flush=True)
    groups: dict[str, set[str]] = {}
    for result in results:
        if result["status"] == "success":
            groups.setdefault(result["header_sha256"], set()).add(result["source"]["split"])
    summary = {
        "pilot_only": True,
        "manifest_sha256": sha256(manifest_bytes).hexdigest(),
        "split_identity": "inherited from supplied manifest; baseline equivalence not yet verified",
        "sources": len(results),
        "statuses": dict(Counter(r["status"] for r in results)),
        "coverage": {f"{s}/{label}": n for (s, label), n in counts.items()},
        "header_bytes": sum(
            r.get("size_of_headers", 0) for r in results if r["status"] == "success"
        ),
        "cross_split_header_groups": sum(len(splits) > 1 for splits in groups.values()),
        "elapsed_seconds": time.monotonic() - started,
    }
    for name, value in [("manifest.json", results), ("summary.json", summary)]:
        body = json.dumps(value, sort_keys=True).encode()
        publish(f"{output_prefix}/{name}", body)
        (job_dir / name).write_bytes(body)
        (job_dir / name).chmod(0o600)
    return summary
