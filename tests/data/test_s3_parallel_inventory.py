"""Synthetic-only coverage for parallel sharded S3 inventory scanning."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from malweave.data.s3.inventory import (
    S3InventoryError,
    inventory_s3_prefix,
    shard_prefixes,
)

PREFIX = "sorel-20m/09-DEC-2020/binaries/"


def _keys(count: int) -> list[str]:
    return [PREFIX + sha256(f"synthetic-{index}".encode()).hexdigest() for index in range(count)]


class ShardedFakeS3:
    """Serve sorted synthetic keys under any prefix shard in 500-key pages."""

    def __init__(self, keys: list[str], *, fail_after: int | None = None) -> None:
        self.keys = sorted(keys)
        self.calls = 0
        self.fail_after = fail_after

    def list_objects_v2(self, **request: object) -> dict[str, object]:
        self.calls += 1
        if self.fail_after is not None and self.calls > self.fail_after:
            raise RuntimeError("synthetic listing outage")
        prefix = str(request["Prefix"])
        token = request.get("ContinuationToken")
        matching = [key for key in self.keys if key.startswith(prefix)]
        start = int(str(token)) if token else 0
        page = matching[start : start + 500]
        truncated = start + 500 < len(matching)
        response: dict[str, object] = {
            "Contents": [
                {
                    "Key": key,
                    "Size": 16,
                    "ETag": f'"{key}"',
                    "LastModified": "2020-12-09T00:00:00Z",
                }
                for key in page
            ],
            "IsTruncated": truncated,
        }
        if truncated:
            response["NextContinuationToken"] = str(start + 500)
        return response


def _inventory_kwargs(tmp_path: Path) -> dict[str, object]:
    return {
        "bucket": "synthetic",
        "prefix": PREFIX,
        "state_path": tmp_path / "state.sqlite",
        "manifest_path": tmp_path / "objects.csv",
        "summary_path": tmp_path / "summary.json",
        "progress_every": 1000,
    }


def test_parallel_inventory_covers_hex_marker_short_and_nonhex_keys(tmp_path: Path) -> None:
    keys = _keys(3000)
    keys.append(PREFIX)  # directory marker equal to the prefix
    keys.append(PREFIX + "a")  # single hex-character key
    keys.append(PREFIX + "README.txt")  # non-hex ASCII first byte
    summary = inventory_s3_prefix(
        **_inventory_kwargs(tmp_path),  # type: ignore[arg-type]
        client=ShardedFakeS3(keys),
        workers=4,
        shard_by_ascii=True,
    )
    assert summary["listed_objects"] == len(keys)
    assert summary["manifest"]["rows"] == len(keys)
    assert summary["excluded_objects"] == 0
    assert summary["scan_mode"] == f"sharded-ascii:{len(shard_prefixes())}"


def test_parallel_inventory_resumes_from_durable_shard_state(tmp_path: Path) -> None:
    keys = _keys(3000)
    kwargs = _inventory_kwargs(tmp_path)
    with pytest.raises(S3InventoryError, match="preserved"):
        inventory_s3_prefix(
            **kwargs,  # type: ignore[arg-type]
            client=ShardedFakeS3(keys, fail_after=40),
            workers=4,
            shard_by_ascii=True,
        )
    assert Path(kwargs["state_path"]).exists()  # type: ignore[arg-type]
    assert not Path(kwargs["manifest_path"]).exists()  # type: ignore[arg-type]
    summary = inventory_s3_prefix(
        **kwargs,  # type: ignore[arg-type]
        client=ShardedFakeS3(keys),
        workers=4,
        shard_by_ascii=True,
        resume=True,
    )
    assert summary["listed_objects"] == len(keys)
    assert summary["scan_mode"] == f"sharded-ascii:{len(shard_prefixes())}"


def test_parallel_inventory_requires_declared_ascii_key_contract(tmp_path: Path) -> None:
    with pytest.raises(S3InventoryError, match="ASCII key-shard"):
        inventory_s3_prefix(
            **_inventory_kwargs(tmp_path),  # type: ignore[arg-type]
            client=ShardedFakeS3(_keys(10)),
            workers=4,
        )


def test_sequential_resume_of_parallel_state_is_rejected(tmp_path: Path) -> None:
    inventory_s3_prefix(
        **_inventory_kwargs(tmp_path),  # type: ignore[arg-type]
        client=ShardedFakeS3(_keys(50)),
        workers=4,
        shard_by_ascii=True,
    )
    Path(_inventory_kwargs(tmp_path)["manifest_path"]).unlink()  # type: ignore[arg-type]
    with pytest.raises(S3InventoryError, match="parallel mode"):
        inventory_s3_prefix(
            **_inventory_kwargs(tmp_path),  # type: ignore[arg-type]
            client=ShardedFakeS3(_keys(50)),
            resume=True,
        )
