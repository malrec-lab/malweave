"""Synthetic EXE-only data preparation and scoped download regression tests."""

import csv
import json
from pathlib import Path

import pytest
import yaml

from malweave.data.rands_training import RandsTrainingError, load_split, prepare_exe
from tests.training.scratch_fixtures import fixture


def test_preparation_accounts_for_conflicts_duplicates_and_missing(tmp_path: Path):
    data, config = fixture(tmp_path)
    with (data / "metadata/Benign.csv").open() as handle:
        benign = list(csv.DictReader(handle))
    with (data / "metadata/Ransomware.csv").open() as handle:
        ransomware = list(csv.DictReader(handle))

    def path(row):
        source = row["SHA256"]
        return data / "exe" / source[:2] / (source + ".bin")

    # One cross-label group, one same-label group. No majority voting.
    path(ransomware[0]).write_bytes(path(benign[0]).read_bytes())
    path(benign[2]).write_bytes(path(benign[1]).read_bytes())
    path(ransomware[-1]).unlink()
    settings = yaml.safe_load(config.read_text())
    settings["data"]["expected_exe_files"] -= 1
    config.write_text(yaml.safe_dump(settings))
    result = prepare_exe(data, config)
    assert result["conflicting_exe_groups"] == 1
    assert result["excluded_by_reason"] == {
        "conflicting_exe_labels": 2,
        "same_label_exe_duplicate": 1,
        "metadata_without_exe": 1,
    }
    rows, _ = load_split(data, config)
    assert len(rows) == 12
    assert len({r["exe_sha256"] for r in rows}) == len(rows)
    assert {r["source_sha256"] for r in rows}.isdisjoint(
        {benign[0]["SHA256"], ransomware[0]["SHA256"]}
    )
    assert prepare_exe(data, config) == json.loads((data / "prepared.json").read_text())
    (data / "split.csv").write_text("changed")
    with pytest.raises(RandsTrainingError, match="changed"):
        load_split(data, config)


@pytest.mark.parametrize(
    ("prefix", "metadata"),
    (
        ("rands/representations/exe", "synthetic/metadata"),
        ("raw", "synthetic/metadata"),
        ("representations/exe", "other/metadata"),
    ),
)
def test_download_rejects_old_or_mixed_prefixes(tmp_path, prefix, metadata):
    from malweave.data import rands_training as module

    with module.Progress() as progress, pytest.raises(RandsTrainingError):
        module.fetch_exe(tmp_path, f"s3://synthetic/{prefix}", f"s3://{metadata}", progress)


def test_canonical_scratch_fetch_uses_manifest_and_preserves_local_names(tmp_path, monkeypatch):
    from hashlib import sha256
    import io

    import boto3
    from botocore.response import StreamingBody

    from malweave.data import rands_training as module

    content = b"synthetic EXE bytes"
    digest = sha256(content).hexdigest()
    source = "a" * 64
    key = f"representations/exe/{digest[:2]}/{digest}"
    manifest = (
        "source_sha256,status,exe_sha256,exe_bytes,exe_key\n"
        f"{source},success,{digest},{len(content)},{key}\n"
        f"{'b' * 64},no_executable_sections,,,\n"
    )

    published = {
        "dataset": "rands",
        "phase": "verified",
        "digests": {"representations/exe/manifest.csv": sha256(manifest.encode()).hexdigest()},
    }

    def fake_aws(*args):
        assert args[1] == "cp"
        contents = {
            "manifest.csv": manifest,
            "dataset.json": json.dumps(published),
        }.get(args[2].rsplit("/", 1)[-1], "labels")
        Path(args[3]).write_text(contents)

    class Client:
        def get_object(self, *, Bucket, Key):
            assert Bucket == "synthetic" and Key == key
            return {"Body": StreamingBody(io.BytesIO(content), len(content))}

    monkeypatch.setattr(module, "aws", fake_aws)
    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: Client())
    with module.Progress() as progress:
        module.fetch_exe(
            tmp_path, "s3://synthetic/representations/exe", "s3://synthetic/metadata", progress
        )
    assert (tmp_path / "exe" / "aa" / f"{source}.bin").read_bytes() == content
    assert not (tmp_path / "exe" / "bb").exists()
    stored = json.loads((tmp_path / "storage.json").read_text())
    assert stored["exe_manifest_sha256"] == sha256(manifest.encode()).hexdigest()
    assert stored["dataset_receipt_sha256"] == sha256(json.dumps(published).encode()).hexdigest()
    published["phase"] = "copy"
    with module.Progress() as progress, pytest.raises(RandsTrainingError, match="receipt"):
        module.fetch_exe(
            tmp_path, "s3://synthetic/representations/exe", "s3://synthetic/metadata", progress
        )


def test_experiment_storage_rejects_unapproved_output_namespace():
    from malweave.data.rands_training import validate_experiment_prefix

    assert (
        validate_experiment_prefix("s3://synthetic/experiments/") == "s3://synthetic/experiments"
    )
    with pytest.raises(RandsTrainingError, match="experiments/"):
        validate_experiment_prefix("s3://synthetic/results")


@pytest.mark.parametrize("write_test", [False, True])
def test_storage_preflight_uses_canonical_paths_and_cleans_its_probe(monkeypatch, write_test):
    from malweave.data import rands_training as module

    queries = []
    writes = []
    objects = {}

    def aws_json(*args):
        queries.append(args)
        if args[0] == "sts":
            return {"Account": "123456789012", "Arn": "fixture"}
        if args[1] == "head-object":
            return {"ContentLength": 20}
        if args[1] == "get-bucket-location":
            return {"LocationConstraint": "ap-southeast-1"}
        assert args[1] == "list-objects-v2"
        prefix = args[args.index("--prefix") + 1]
        return {"KeyCount": 0 if prefix.startswith("experiments/checks/") else 1}

    def aws(*args):
        writes.append(args)
        if args[1] == "rm":
            del objects[args[2]]
        elif args[2].startswith("s3://"):
            Path(args[3]).write_bytes(objects[args[2]])
        else:
            objects[args[3]] = Path(args[2]).read_bytes()

    monkeypatch.setattr(module, "_aws_json", aws_json)
    monkeypatch.setattr(module, "aws", aws)
    outcome = module.check_storage(
        "s3://synthetic/representations/exe",
        "s3://synthetic/metadata",
        "s3://synthetic/experiments",
        write_test=write_test,
    )
    assert outcome["output"]["checks"]["put_get_checksum_delete"] == (
        "passed" if write_test else "not_tested"
    )
    assert not objects
    assert len(writes) == (3 if write_test else 0)
    assert {args[-1] for args in queries if args[1] == "head-object"} == {
        "dataset.json",
        "representations/exe/manifest.csv",
        "metadata/Benign.csv",
        "metadata/Ransomware.csv",
    }
