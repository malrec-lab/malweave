"""Check the selected AWS identity and SOREL destination before corpus work."""

import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from malweave.data import sorel_archive as archive
from malweave.data.sorel_io import SorelError, digest


def _query(*arguments: str) -> Any:
    try:
        result = subprocess.run(
            ["aws", *arguments, "--output", "json", "--no-cli-pager"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SorelError("Cannot check S3; verify AWS CLI, credentials and network.") from error
    if result.returncode:
        raise SorelError(f"S3 preflight failed: {result.stderr[-1200:]}")
    try:
        return json.loads(result.stdout)
    except ValueError as error:
        raise SorelError("AWS CLI returned an invalid preflight response.") from error


def check_sorel_s3(prefix: str, *, write_test: bool = False) -> dict[str, Any]:
    """Default is read-only; opt-in test writes and deletes one tiny text object."""
    prefix = archive.validate_prefix(prefix)
    parsed = urlsplit(prefix)
    bucket = parsed.netloc
    identity = _query("sts", "get-caller-identity")
    location = _query("s3api", "get-bucket-location", "--bucket", bucket)
    listing = _query(
        "s3api",
        "list-objects-v2",
        "--bucket",
        bucket,
        "--prefix",
        parsed.path.lstrip("/") + "/",
        "--max-keys",
        "1",
    )
    region = location.get("LocationConstraint") or "us-east-1"
    if region == "EU":
        region = "eu-west-1"
    result: dict[str, Any] = {
        "prefix": prefix,
        "region": region,
        "caller": {key: identity[key] for key in ("Account", "Arn")},
        "checks": {
            "identity": "passed",
            "list_destination": "passed",
            "destination_has_objects": listing.get("KeyCount", 0) > 0,
            "put_get_checksum_delete": "not_tested",
        },
    }
    if write_test:
        uri = prefix + "/checks/" + uuid4().hex + "/probe.txt"
        with tempfile.TemporaryDirectory(prefix="sorel-s3-check-") as temporary:
            source = Path(temporary) / "probe.txt"
            target = Path(temporary) / "download.txt"
            source.write_bytes(b"MalWeave SOREL S3 permission and checksum test.\n")
            try:
                archive._upload(source, uri)
                archive._download(uri, target)
                if digest(source) != digest(target):
                    raise SorelError("S3 preflight round-trip checksum mismatch.")
            finally:
                # A failed multipart/PUT response can still have created the object.
                archive._aws("s3", "rm", uri, "--only-show-errors")
            if archive._download(uri, target, missing_ok=True):
                raise SorelError("S3 preflight probe still exists after deletion.")
        result["checks"]["put_get_checksum_delete"] = "passed"
    return result
