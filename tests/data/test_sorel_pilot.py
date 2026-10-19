"""Pilot selection checks using synthetic object metadata only."""

import csv
from hashlib import sha256
import json

import pytest

from malweave.data.s3.inventory import S3InventoryError
from malweave.data.s3.sorel import SOREL_BINARIES_PREFIX, SOREL_BUCKET
from malweave.data.s3.sorel_pilot import select_sorel_pilot


def test_seeded_selection_matches_full_ranking_and_extends(tmp_path):
    sources = tmp_path / "sources.csv"
    snapshot = tmp_path / "snapshot.json"
    keys = [SOREL_BINARIES_PREFIX + f"{i:064x}" for i in range(30)]
    content = "object_key,object_size,object_etag,object_last_modified\n" + "".join(
        f"{key},{i + 1},etag,date\n" for i, key in enumerate(keys)
    )
    payload = content.encode()
    sources.write_bytes(payload)
    digest = sha256(payload).hexdigest()
    snapshot.write_text(
        json.dumps(
            {
                "bucket": SOREL_BUCKET,
                "prefix": SOREL_BINARIES_PREFIX,
                "release": "09-DEC-2020",
                "snapshot_id": digest,
                "manifest": {"rows": 30, "bytes": len(payload), "sha256": digest},
                "total_object_bytes": sum(range(1, 31)),
            }
        )
    )
    expected = sorted(keys, key=lambda key: sha256(b"test\0" + key.encode()).digest())
    for count in (5, 10):
        manifest = tmp_path / f"pilot-{count}.csv"
        summary = tmp_path / f"pilot-{count}.json"
        result = select_sorel_pilot(sources, snapshot, manifest, summary, count=count, seed="test")
        with manifest.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert [row["object_key"] for row in rows] == expected[:count]
        assert result["manifest"]["sha256"] == sha256(manifest.read_bytes()).hexdigest()
        assert result["sample_bytes_read"] is False
    with pytest.raises(S3InventoryError, match="overwrite"):
        select_sorel_pilot(sources, snapshot, manifest, summary, count=10, seed="test")
    sources.write_bytes(payload + b"changed")
    with pytest.raises(S3InventoryError, match="differs"):
        select_sorel_pilot(sources, snapshot, tmp_path / "bad.csv", tmp_path / "bad.json", count=5)
    assert not (tmp_path / "bad.csv").exists()
