"""Synthetic tests for full-corpus SOREL metadata preselection."""

import csv
from hashlib import sha256
import io
import json
from pathlib import Path
import sqlite3
import zlib

import pytest

from malweave.data.s3.sorel import SOREL_BINARIES_PREFIX, SOREL_BUCKET
from malweave.data.s3.sorel_full_filter import (
    _assess_candidate,
    _read_candidate_with_retries,
    prepare_sorel_packed_candidates,
)


@pytest.mark.parametrize(
    ("packed", "description", "file_status", "expected", "downloads", "scans"),
    [
        ("2", "", "success", "excluded_packed", 0, 0),
        ("0", "PE32+ executable", "success", "excluded_not_pe32", 1, 0),
        ("0", "data", "success", "excluded_not_pe32", 1, 0),
        ("0", "PE32 executable", "failed", "partial", 1, 0),
        ("0", "PE32 executable", "success", "complete", 1, 1),
    ],
)
def test_prefilters_skip_unnecessary_downloads_and_die(
    monkeypatch, packed, description, file_status, expected, downloads, scans
) -> None:
    from unittest.mock import Mock

    read = Mock(return_value=(12, 20, "success", "synthetic-digest", ""))
    die = Mock(return_value=("success", "false", "", {}, ""))
    monkeypatch.setattr("malweave.data.s3.sorel_full_filter._read_candidate_with_retries", read)
    monkeypatch.setattr(
        "malweave.data.s3.sorel_full_filter._run_file",
        lambda *_: (file_status, description, "unknown", ""),
    )
    monkeypatch.setattr("malweave.data.s3.sorel_full_filter._run_diec", die)
    result = _assess_candidate(
        {"packed": packed, "object_size": "12"},
        client=None,
        max_compressed=1024,
        max_decompressed=1024,
        timeout=1,
    )
    assert result["assessment_status"] == expected
    assert read.call_count == downloads
    assert die.call_count == scans
    assert result["runtime_seconds"] >= 0
    if not scans:
        assert result["die_status"] == "not_run"
        assert result["die_obfuscated"] == "unknown"


def _file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path, *, missing_metadata: bool = False) -> tuple[Path, ...]:
    source_path = tmp_path / "sources.csv"
    keys = ["a" * 64, "b" * 64]
    source_rows = [
        {
            "object_key": SOREL_BINARIES_PREFIX + identity,
            "object_size": "12",
            "object_etag": f'"etag-{identity[0]}"',
            "object_last_modified": "2020-12-09T00:00:00+00:00",
        }
        for identity in keys
    ]
    with source_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=("object_key", "object_size", "object_etag", "object_last_modified"),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(source_rows)
    source_hash = _file_digest(source_path)
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "dataset": "SOREL-20M",
                "release": "09-DEC-2020",
                "bucket": SOREL_BUCKET,
                "prefix": SOREL_BINARIES_PREFIX,
                "snapshot_id": source_hash,
                "manifest": {
                    "sha256": source_hash,
                    "bytes": source_path.stat().st_size,
                    "rows": 2,
                },
                "total_object_bytes": 24,
            }
        ),
        encoding="utf-8",
    )
    db_path = tmp_path / "meta.db"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE meta(sha256 TEXT PRIMARY KEY, is_malware INTEGER, "
            "packed INTEGER, rl_fs_t REAL)"
        )
        records = [(keys[0], 1, 0, 1.0), (keys[1], 1, 2, 2.0)]
        if missing_metadata:
            records.pop()
        db.executemany("INSERT INTO meta VALUES (?, ?, ?, ?)", records)
    pilot_path = tmp_path / "pilot.csv"
    pilot_path.write_text("synthetic-pilot\n", encoding="utf-8")
    pilot_summary_path = tmp_path / "pilot.json"
    pilot_summary_path.write_text(
        json.dumps(
            {
                "scope": "bounded static pilot; no sample execution",
                "selected_rows": 1,
                "statuses": {
                    "zlib_status": {"success": 1},
                    "file_status": {"success": 1},
                    "die_status": {"success": 1},
                    "assessment_status": {"complete": 1},
                },
                "output_sha256": _file_digest(pilot_path),
            }
        ),
        encoding="utf-8",
    )
    return source_path, snapshot_path, db_path, pilot_path, pilot_summary_path


def test_preparation_retains_only_packed_zero_sources(tmp_path: Path) -> None:
    source, snapshot, metadata, pilot, pilot_summary = _fixture(tmp_path)
    output = tmp_path / "candidates.csv"
    summary = tmp_path / "candidates.json"

    report = prepare_sorel_packed_candidates(
        source, snapshot, metadata, pilot, pilot_summary, output, summary
    )

    assert report["release_audit_passed"] is True
    assert report["counts"]["source_objects"] == 2
    assert report["counts"]["packed_zero_candidates"] == 1
    with output.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 1
    assert rows[0]["source_sha256"] == "a" * 64
    assert rows[0]["packed"] == "0"


def test_preparation_fails_when_a_source_has_no_metadata(tmp_path: Path) -> None:
    source, snapshot, metadata, pilot, pilot_summary = _fixture(tmp_path, missing_metadata=True)

    with pytest.raises(ValueError, match="Release audit failed"):
        prepare_sorel_packed_candidates(
            source,
            snapshot,
            metadata,
            pilot,
            pilot_summary,
            tmp_path / "candidates.csv",
            tmp_path / "candidates.json",
        )


def test_sorel_short_s3_read_is_retried_and_decompressed(tmp_path: Path, monkeypatch) -> None:
    payload = b"synthetic PE-like bytes"
    compressed = zlib.compress(payload)

    class Client:
        calls = 0

        def get_object(self, **kwargs):
            self.calls += 1
            content = compressed[:5] if self.calls == 1 else compressed
            return {"ETag": '"synthetic-etag"', "Body": io.BytesIO(content)}

    monkeypatch.setattr("malweave.data.s3.sorel_full_filter.time.sleep", lambda _: None)
    row = {
        "object_size": str(len(compressed)),
        "object_key": "synthetic/key",
        "object_etag": '"synthetic-etag"',
    }
    client = Client()
    sample = tmp_path / "sample.pe"

    received, size, status, digest, error = _read_candidate_with_retries(
        row,
        client=client,
        path=sample,
        max_compressed=1024,
        max_output=1024,
    )

    assert client.calls == 2
    assert received == len(compressed)
    assert size == len(payload)
    assert status == "success"
    assert digest == sha256(payload).hexdigest()
    assert not error
    assert sample.read_bytes() == payload
