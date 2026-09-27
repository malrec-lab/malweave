"""EXE metadata selection feeds both shared staging backends using synthetic bytes."""

from collections import Counter
import csv
from hashlib import sha256
import io
import json

from botocore.exceptions import ClientError
import pytest

from malweave.data.dataset_config import RandsDatasetConfig, RandsExpectedCounts
from malweave.data.rands import BENIGN_HEADER, RANSOMWARE_ACTUAL_HEADER, RandsDataError
from malweave.experiments.rands_exe_inputs import RandsExeInputError
from malweave.experiments.rands_exe_manifest import freeze_exe_s3_manifest
from malweave.training.manifest import load_training_manifest
from malweave.training.stage import stage_manifest_from_s3
from malweave.training.stage_network import stage_network


def csv_bytes(rows):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=rows[0])
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode()


class S3:
    def __init__(self, objects=None):
        self.objects = objects or {}
        self.reads = []
        self.fail_listing = False

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {"ContentLength": len(self.objects[Key]), "ETag": '"synthetic"'}

    def get_object(self, Bucket, Key, **kwargs):
        assert kwargs["IfMatch"] == '"synthetic"'
        self.reads.append(Key)
        return {"Body": io.BytesIO(self.objects[Key]), "ETag": '"synthetic"'}

    def list_objects_v2(self, **kwargs):
        if self.fail_listing:
            raise OSError("synthetic interruption")
        return {
            "Contents": [
                {"Key": key, "Size": len(value), "ETag": '"synthetic"'}
                for key, value in self.objects.items()
                if key.startswith(kwargs["Prefix"])
            ]
        }

    def put_object(self, Bucket, Key, Body):
        self.objects[Key] = bytes(Body)


def fixture(tmp_path, *, duplicate=None, missing=False):
    rows, metadata, objects = [], [], {}
    choices = [("train", "benign")] * 3 + [("train", "ransomware")] * 2
    choices += [(s, label) for s in ("validation", "test") for label in ("benign", "ransomware")]
    for i, (split, label) in enumerate(choices):
        source = sha256(f"source-{i}".encode()).hexdigest()
        content = f"safe-exe-{i}".encode()
        if duplicate == "cross_split" and i == 7:
            content = b"safe-exe-0"
        if duplicate == "cross_label" and i == 3:
            content = b"safe-exe-0"
        if duplicate == "same_split" and i == 1:
            content = b"safe-exe-0"
        rows.append(
            {
                "source_sha256": source,
                "split": split,
                "label": label,
                "group_id": source,
                "object_key": f"raw/{source}",
                "object_size": 10,
                "object_etag": '"synthetic"',
            }
        )
        metadata.append(
            {
                "source_sha256": source,
                "label": label,
                "source_hash_status": "verified",
                "extraction_status": "success",
                "representation_sha256": sha256(content).hexdigest(),
                "extracted_size": len(content),
                "snapshot": "synthetic",
            }
        )
        if not (missing and i == 0):
            objects[f"exe/{source[:2]}/{source}.bin"] = content
    objects["exe/manifest.csv"] = csv_bytes(metadata)
    metadata_root = tmp_path / "rands-metadata"
    metadata_root.mkdir()
    for label, name, header in (
        ("benign", "Benign.csv", BENIGN_HEADER),
        ("ransomware", "Ransomware.csv", RANSOMWARE_ACTUAL_HEADER),
    ):
        with (metadata_root / name).open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            for row in rows:
                if row["label"] != label:
                    continue
                values = [
                    row["source_sha256"],
                    "1" * 40,
                    "2" * 32,
                    "99999",
                    "EXE",
                    "I386",
                    "0",
                    "5.0",
                ]
                if label == "ransomware":
                    values.append("synthetic-family")
                values.extend(
                    [
                        str({"train": 2022, "validation": 2023, "test": 2024}[row["split"]]),
                        "ignored",
                    ]
                )
                writer.writerow(values)
    dataset_config = RandsDatasetConfig(
        name="rands",
        snapshot="synthetic",
        root_env="UNUSED_RAW_ROOT",
        benign_csv="Benign.csv",
        ransomware_csv="Ransomware.csv",
        samples_dir="dataset",
        expected=RandsExpectedCounts(shards=256, files=9, labels={"benign": 5, "ransomware": 4}),
        protocols={},
    )
    return {
        "metadata_root": metadata_root,
        "dataset_config": dataset_config,
        "manifest": tmp_path / "exe.csv",
        "summary": tmp_path / "exe.json",
        "state_root": tmp_path / "metadata",
        "bucket": "source",
        "prefix": "exe/",
        "metadata_key": "exe/manifest.csv",
        "snapshot": "synthetic",
        "seed": "synthetic",
        "year_ranges": {
            "train": {"max": 2022},
            "validation": {"min": 2023, "max": 2023},
            "test": {"min": 2024},
        },
        "metadata_filters": {"arch": "I386", "packed": False},
        "client": S3(objects),
    }


def test_metadata_only_then_shared_local_and_network_staging(tmp_path):
    args = fixture(tmp_path)
    result = freeze_exe_s3_manifest(**args)
    assert args["client"].reads == ["exe/manifest.csv"]
    assert result["balance_excluded"] == 1
    assert not (tmp_path / "source.csv").exists()
    assert "source_manifest_sha256" not in result
    assert result["release_audit"]["passed"]
    rows = load_training_manifest(args["manifest"], "exe")
    counts = Counter((r.split, r.label) for r in rows)
    assert counts == {
        ("train", 0): 2,
        ("train", 1): 2,
        ("validation", 0): 1,
        ("validation", 1): 1,
        ("test", 0): 1,
        ("test", 1): 1,
    }
    assert stage_manifest_from_s3(
        args["manifest"],
        args["summary"],
        tmp_path / "local",
        bucket="source",
        representation="exe",
        workers=2,
        client=args["client"],
    )["passed"]
    target = S3()
    report = stage_network(
        args["manifest"],
        args["summary"],
        tmp_path / "network-state",
        source_bucket="source",
        destination_bucket="target",
        destination_prefix="malweave/full-exe",
        destination_endpoint="https://s3api-test.runpod.io",
        destination_region="test",
        representation="exe",
        source_client=args["client"],
        destination_client=target,
    )
    assert report["publication_complete"]
    assert report["selected"] == len(rows)
    assert "malweave/full-exe/staging-summary.json" in target.objects
    reads = len(args["client"].reads)
    with pytest.raises(RandsExeInputError, match="outputs exist"):
        freeze_exe_s3_manifest(**args)
    assert len(args["client"].reads) == reads


@pytest.mark.parametrize("field,value", [("Arch", "AMD64"), ("Packed", "1")])
def test_exe_filters_shared_metadata_without_raw_availability(tmp_path, field, value):
    args = fixture(tmp_path)
    path = args["metadata_root"] / "Benign.csv"
    rows = list(csv.DictReader(io.StringIO(path.read_text())))
    rows[0][field] = value
    path.write_bytes(csv_bytes(rows))
    result = freeze_exe_s3_manifest(**args)
    assert result["exclusions"] == {"metadata_filter": 1}
    assert result["manifest"]["rows"] == 8
    assert result["selection"]["selected_by_split_and_label"]["train"] == {
        "benign": 2,
        "ransomware": 2,
    }


def test_incomplete_extraction_release_fails_before_staging(tmp_path):
    args = fixture(tmp_path)
    rows = list(csv.DictReader(io.StringIO(args["client"].objects["exe/manifest.csv"].decode())))
    args["client"].objects["exe/manifest.csv"] = csv_bytes(rows[1:])
    with pytest.raises(RandsExeInputError, match="release counts"):
        freeze_exe_s3_manifest(**args)
    assert not args["manifest"].exists()
    assert args["client"].reads == ["exe/manifest.csv"]


@pytest.mark.parametrize("duplicate", ["cross_split", "cross_label"])
def test_duplicate_conflicts_fail_without_dropping_or_reassigning(tmp_path, duplicate):
    args = fixture(tmp_path, duplicate=duplicate)
    with pytest.raises(RandsExeInputError, match="duplicate groups"):
        freeze_exe_s3_manifest(**args)
    assert not args["manifest"].exists()
    report = json.loads(args["summary"].read_text())
    assert report[duplicate + "_duplicate_groups"] == 1
    assert not report["passed"]


def test_missing_objects_accounted_before_train_only_balance(tmp_path):
    args = fixture(tmp_path, missing=True)
    result = freeze_exe_s3_manifest(**args)
    assert result["exclusions"] == {"missing_s3_object": 1}
    assert result["balance_excluded"] == 0
    assert result["manifest"]["rows"] == 8


def test_same_split_duplicates_retained(tmp_path):
    args = fixture(tmp_path, duplicate="same_split")
    assert freeze_exe_s3_manifest(**args)["eligible"] == 9


def test_metadata_resume_reuses_snapshot_and_validates_contract(tmp_path):
    from malweave.data.s3.inventory import S3InventoryError

    args = fixture(tmp_path)
    args["client"].fail_listing = True
    with pytest.raises(S3InventoryError):
        freeze_exe_s3_manifest(**args)
    args["client"].fail_listing = False
    assert freeze_exe_s3_manifest(**args, resume=True)["passed"]
    assert args["client"].reads == ["exe/manifest.csv"]


def test_bad_rands_metadata_never_contacts_s3(tmp_path):
    args = fixture(tmp_path)
    (args["metadata_root"] / "Benign.csv").write_text("invalid header")
    with pytest.raises(RandsDataError):
        freeze_exe_s3_manifest(**args)
    assert args["client"].reads == []


def test_resume_completes_summary_without_overwriting_manifest(tmp_path):
    args = fixture(tmp_path)
    freeze_exe_s3_manifest(**args)
    frozen = args["manifest"].read_bytes()
    args["summary"].unlink()
    assert freeze_exe_s3_manifest(**args, resume=True)["passed"]
    assert args["manifest"].read_bytes() == frozen
    assert args["client"].reads == ["exe/manifest.csv"]


def test_changed_contract_or_metadata_refuses_resume(tmp_path):
    args = fixture(tmp_path)
    freeze_exe_s3_manifest(**args)
    with pytest.raises(RandsExeInputError, match="settings changed"):
        freeze_exe_s3_manifest(**{**args, "seed": "changed"}, resume=True)
    cache = args["state_root"] / "extraction-metadata.json"
    saved = json.loads(cache.read_text())
    saved["csv"] += "corrupted"
    cache.write_text(json.dumps(saved))
    with pytest.raises(RandsExeInputError, match="cache digest"):
        freeze_exe_s3_manifest(**args, resume=True)


def test_bom_metadata_preserves_source_digest(tmp_path):
    args = fixture(tmp_path)
    args["client"].objects["exe/manifest.csv"] = (
        b"\xef\xbb\xbf" + args["client"].objects["exe/manifest.csv"]
    )
    assert freeze_exe_s3_manifest(**args)["passed"]


def test_bad_representation_bytes_fail_shared_stage(tmp_path):
    from malweave.training.stage import StageError

    args = fixture(tmp_path)
    freeze_exe_s3_manifest(**args)
    row = load_training_manifest(args["manifest"], "exe")[0]
    args["client"].objects[row.object_key] = b"x" * row.object_size
    with pytest.raises(StageError):
        stage_manifest_from_s3(
            args["manifest"],
            args["summary"],
            tmp_path / "local",
            bucket="source",
            representation="exe",
            client=args["client"],
        )
    report = json.loads((tmp_path / "local/staging-summary.json").read_text())
    assert not report["passed"]
    assert report["failure_reasons"]["digest_mismatch"] == 1
