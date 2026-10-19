"""Synthetic metadata tests for SOREL source freezing."""

from hashlib import sha256
import json

import pytest

from malweave.data.s3.inventory import S3InventoryError
from malweave.data.s3.sorel import SOREL_BINARIES_PREFIX, SOREL_BUCKET
from malweave.data.s3.sorel_sources import freeze_sorel_sources


def test_freeze_and_reject_tampered_inventory(tmp_path):
    inventory = tmp_path / "inventory.csv"
    audit = tmp_path / "audit.json"
    output = tmp_path / "sources.csv"
    summary = tmp_path / "sources.json"
    content = (
        "object_key,object_size,object_etag,object_last_modified\n"
        f"{SOREL_BINARIES_PREFIX}{'a' * 64},12,etag,2020-12-09\n"
    ).encode()
    inventory.write_bytes(content)
    audit.write_text(
        json.dumps(
            {
                "inventory_complete": True,
                "bucket": SOREL_BUCKET,
                "prefix": SOREL_BINARIES_PREFIX,
                "excluded_objects": 0,
                "listed_objects": 1,
                "object_sizes": {"total_bytes": 12},
                "manifest": {
                    "bytes": len(content),
                    "sha256": sha256(content).hexdigest(),
                    "rows": 1,
                },
            }
        )
    )
    result = freeze_sorel_sources(inventory, audit, output, summary)
    assert output.read_bytes() == content
    assert result["snapshot_id"] == sha256(content).hexdigest()
    assert result["remote_versions_pinned"] is False
    with pytest.raises(S3InventoryError, match="never overwrite"):
        freeze_sorel_sources(inventory, audit, output, summary)
    inventory.write_bytes(content + b"tampered")
    with pytest.raises(S3InventoryError, match="do not match"):
        freeze_sorel_sources(inventory, audit, tmp_path / "other.csv", tmp_path / "other.json")
    assert not (tmp_path / "other.csv").exists()
