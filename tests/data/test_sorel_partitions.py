"""Fixed partitions cover synthetic metadata exactly once across independent jobs."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest
import yaml

from malweave.cli import main
from malweave.data import sorel
from malweave.data.sorel_partitions import part_status
from tests.data.test_sorel import _job, _scanners
from tests.data.test_sorel_runner import _curl_fixture


def test_five_parts_are_disjoint_balanced_and_cover_all_malware(tmp_path):
    _, base, metadata = _job(tmp_path, count=17)
    groups = []
    for part in range(1, 6):
        config = replace(base, samples=0, partition_count=5, partition_index=part)
        job = tmp_path / f"part-{part}"
        audit = sorel.prepare_sorel(metadata, job, config)
        with sqlite3.connect(job / "state.sqlite") as db:
            group = {row[0] for row in db.execute("SELECT id FROM sources")}
        assert audit["selected"] == (17 + 5 - part) // 5
        assert group == {f"{i:064x}" for i in range(part - 1, 17, 5)}
        assert all(not group.intersection(previous) for previous in groups)
        assert part_status(job)["pending"] == len(group)
        groups.append(group)
    assert set.union(*groups) == {f"{i:064x}" for i in range(17)}


def test_full_part_cli_resumes_without_reselecting_other_parts(tmp_path, monkeypatch):
    _, base, metadata = _job(tmp_path, count=15)
    config = replace(base, samples=0, partition_count=5)
    path = tmp_path / "full.yaml"
    path.write_text(yaml.safe_dump(asdict(config)))
    job = tmp_path / "part-2"
    _scanners(monkeypatch)
    calls = _curl_fixture(monkeypatch)
    args = [
        "data",
        "sorel-run",
        "--part",
        "2",
        "--config",
        str(path),
        "--job-dir",
        str(job),
        "--metadata",
        str(metadata),
    ]
    assert main([*args, "--limit", "1"]) == 0
    assert part_status(job)["completed"] == 1
    assert part_status(job)["selected"] == 3
    assert main(args) == 0
    assert len(calls) == len(set(calls)) == 3
    assert part_status(job)["pending"] == 0
    assert sorel.verify_sorel(job)["verified_sources"] == 3
    with pytest.raises(sorel.SorelError, match="config"):
        sorel.run_sorel(job, replace(config, partition_index=3))
    assert main(["data", "sorel-status", "--job-dir", str(job)]) == 0


@pytest.mark.parametrize(
    "values",
    [
        {"partition_index": 6, "partition_count": 5, "samples": 0},
        {"partition_index": 0},
        {"partition_count": 0},
        {"partition_count": 5, "samples": 10},
        {"samples": -1},
    ],
)
def test_invalid_partition_config_rejected(tmp_path, values):
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(values))
    with pytest.raises(sorel.SorelError):
        sorel.load_sorel_config(path)


def test_full_selection_order_independent_of_metadata_insertion(tmp_path):
    _, base, metadata = _job(tmp_path, count=13)
    config = replace(base, samples=0, partition_count=5, partition_index=4)
    alternate = tmp_path / "reverse.db"
    with sqlite3.connect(metadata) as source, sqlite3.connect(alternate) as target:
        target.execute("CREATE TABLE meta (sha256 TEXT, is_malware INT, rl_fs_t REAL)")
        target.executemany(
            "INSERT INTO meta VALUES (?,?,?)",
            source.execute("SELECT * FROM meta ORDER BY sha256 DESC"),
        )
    for name, data in [("a", metadata), ("b", alternate)]:
        sorel.prepare_sorel(data, tmp_path / name, config)
    selections = [
        json.loads((tmp_path / name / "selection.json").read_text()) for name in ("a", "b")
    ]
    assert selections[0]["sources_sha256"] == selections[1]["sources_sha256"]
