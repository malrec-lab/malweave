"""Fetch only the two RanDS metadata CSVs into a private, immutable cache."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
from typing import Any

from malweave.data.dataset_config import RandsDatasetConfig
from malweave.data.rands import load_rands_metadata
from malweave.data.s3.client import make_s3_client, read_s3_object
from malweave.data.s3.inventory import validate_private_path
from malweave.data.s3.rands import RandsS3Error


def prepare_rands_metadata(
    config: RandsDatasetConfig,
    root: Path,
    *,
    bucket: str,
    prefix: str,
    client: Any = None,
) -> Path:
    """Reuse a verified snapshot or publish a complete schema-validated CSV pair.

    Only explicit metadata keys are read. Partial downloads never become the active
    cache; changing the source or cached content requires a new cache directory.
    """
    validate_private_path(root)
    root = root.expanduser().resolve()
    names = (config.benign_csv, config.ransomware_csv)
    if not bucket or not prefix.endswith("/"):
        raise RandsS3Error("Metadata needs a bucket and slash-terminated S3 prefix.")
    if len(set(names)) != 2 or any(
        Path(name).name != name or not name.endswith(".csv") for name in names
    ):
        raise RandsS3Error("Metadata filenames must be two distinct CSV basenames.")
    settings = {"bucket": bucket, "prefix": prefix, "snapshot": config.snapshot}
    if root.exists():
        try:
            receipt = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
            if receipt["source"] != settings or set(receipt["files"]) != set(names):
                raise ValueError("Metadata cache source changed.")
            for name in names:
                content = (root / name).read_bytes()
                recorded = receipt["files"][name]
                if (
                    recorded["key"] != prefix + name
                    or len(content) != recorded["size"]
                    or sha256(content).hexdigest() != recorded["sha256"]
                ):
                    raise ValueError("Metadata cache bytes changed.")
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise RandsS3Error(
                "Metadata cache is incomplete, changed, or belongs to another source; "
                "use a new --metadata-cache or supply --metadata-root."
            ) from error
        load_rands_metadata(config, root)
        return root

    if client is None:
        client = make_s3_client()
    root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".metadata-", dir=root.parent) as temporary:
        pending = Path(temporary) / "snapshot"
        pending.mkdir(mode=0o700)
        files = {}
        for name in names:
            content, provenance = read_s3_object(
                client, bucket, prefix + name, max_bytes=128 * 1024 * 1024
            )
            (pending / name).write_bytes(content)
            files[name] = provenance
        load_rands_metadata(config, pending)
        (pending / "provenance.json").write_text(
            json.dumps({"source": settings, "files": files}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if root.exists():
            raise RandsS3Error(
                "Metadata cache appeared during download; retry without overwriting."
            )
        pending.rename(root)
    return root
