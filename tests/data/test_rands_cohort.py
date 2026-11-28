"""Synthetic regression coverage for first-round metadata filtering and frozen splits."""

from collections import Counter
import csv
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

import pytest
import yaml

from malweave.config import CONFIGS_DIR
from malweave.data.rands import LoadedRandsMetadata, RandsRecord
from malweave.data.rands_cohort import freeze_metadata_cohort
from malweave.training.contracts import SupervisedTrainingError


def metadata_fixture(tmp_path, monkeypatch, extra=()):
    records = {}
    products = []
    metadata_root = tmp_path / "metadata"
    metadata_root.mkdir()
    for name in ("Benign.csv", "Ransomware.csv"):
        (metadata_root / name).write_text("synthetic metadata digest input")
    definitions = [
        (1, "benign", 2020, 1),
        (2, "benign", 2021, 2),
        (3, "benign", 2022, 3),
        (4, "ransomware", 2020, 4),
        (5, "benign", 2024, 5),
        (6, "ransomware", 2024, 6),
        (7, "benign", 2025, 7),
        (8, "ransomware", 2025, 8),
        (9, "benign", 2010, 1),
        (10, "benign", 2024, 10),
        (11, "ransomware", 2025, 10),
        (12, "benign", 2020, 12),
        (13, "ransomware", 2020, 13),
        (14, "benign", 2020, 14),
        (15, "ransomware", 2020, 15),
    ]
    for index, label, year, group in [*definitions, *extra]:
        source = f"{index:064x}"
        record = RandsRecord(
            source,
            "a" * 40,
            "b" * 32,
            10,
            "EXE",
            "ARM" if index == 13 else "I386",
            index == 12,
            6.0,
            "synthetic-family" if label == "ransomware" else None,
            year,
            label,
        )
        records[source] = record
        if index != 14:
            products.append(
                {
                    "source_sha256": source,
                    "label": label,
                    "extraction_status": "no_sections" if index == 15 else "success",
                    "source_hash_status": "verified",
                    "representation_sha256": sha256(str(group).encode()).hexdigest(),
                    "representation_relative_path": source[:2] + "/" + source + ".bin",
                    "extracted_size": 10,
                    "snapshot": "2026-09-02",
                }
            )
    loaded = LoadedRandsMetadata(
        records, Counter(record.label for record in records.values()), 0, 0, ()
    )
    monkeypatch.setattr("malweave.data.rands_cohort.load_rands_metadata", lambda *args: loaded)
    manifest = tmp_path / "exe.csv"
    with manifest.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=products[0])
        writer.writeheader()
        writer.writerows(products)
    config = CONFIGS_DIR / "experiments/rands-lmlm-c.yaml"
    audit = tmp_path / "audit"
    audit.mkdir()
    groups = {}
    for product in products:
        record = records[product["source_sha256"]]
        if (
            record.arch == "I386"
            and not record.packed
            and product["extraction_status"] == "success"
        ):
            groups.setdefault(product["representation_sha256"], []).append(record)
    with sqlite3.connect(audit / "audit.sqlite3") as db:
        db.execute(
            "create table samples (source text primary key,label text,status text,"
            "full_exe_sha text,full_bytes integer,prefix_bytes integer,tokens integer,token_sha text)"
        )
        for digest, group in groups.items():
            if len({r.label for r in group}) > 1:
                continue
            record = min(group, key=lambda r: (r.year, r.sha256))
            db.execute(
                "insert into samples values (?,?,?,?,?,?,?,?)",
                (
                    record.sha256,
                    record.label,
                    "ok",
                    digest,
                    10,
                    10,
                    12,
                    sha256(("tokens-" + record.sha256).encode()).hexdigest(),
                ),
            )
        count = db.execute("select count(*) from samples").fetchone()[0]
    identity = {
        "max_bytes": 65536,
        "max_tokens_including_bos_eos": 65536,
        "token_digest_encoding": "SHA256(uint64_le length + uint32_le token IDs)",
        "production_adapter_sha256": sha256(
            (Path(__file__).parents[2] / "malweave/data/lmlm_inputs.py").read_bytes()
        ).hexdigest(),
        "tokenizer_sha256": "a" * 64,
        "checkpoint_config_sha256": "b" * 64,
        "audit_script_sha256": "c" * 64,
    }
    (audit / "identity.json").write_text(json.dumps(identity))
    (audit / "summary.json").write_text(
        json.dumps(
            {"status": "complete", "rows_expected": count, "rows_verified": count, "errors": 0}
        )
    )
    seal_audit(audit)
    return metadata_root, manifest, config, audit


def seal_audit(audit):
    path = audit / "summary.json"
    summary = json.loads(path.read_text())
    summary["audit_database_sha256"] = sha256((audit / "audit.sqlite3").read_bytes()).hexdigest()
    path.write_text(json.dumps(summary))


def test_metadata_filter_dedup_temporal_split_and_fixed_train_undersampling(tmp_path, monkeypatch):
    inputs = metadata_fixture(tmp_path, monkeypatch)
    first = tmp_path / "first"
    summary = freeze_metadata_cohort(*inputs[:3], first, input_audit=inputs[3])
    freeze_metadata_cohort(*inputs[:3], tmp_path / "second", input_audit=inputs[3])
    assert (first / "split.csv").read_bytes() == (tmp_path / "second/split.csv").read_bytes()
    assert summary["die_verified"] is False
    assert summary["before_undersampling"]["train"] == {"benign": 3, "ransomware": 1}
    assert summary["split_counts"]["train"] == {"benign": 1, "ransomware": 1}
    assert summary["split_counts"]["validation"] == {"benign": 1, "ransomware": 1}
    assert summary["split_counts"]["test"] == {"benign": 1, "ransomware": 1}
    with (first / "excluded.csv").open() as handle:
        excluded = {row["source_sha256"]: row["reason"] for row in csv.DictReader(handle)}
    assert (
        excluded[f"{1:064x}"] == "same_label_exe_duplicate"
    )  # Earlier year wins over smaller hash.
    assert excluded[f"{10:064x}"] == excluded[f"{11:064x}"] == "conflicting_exe_labels"
    assert excluded[f"{12:064x}"] == "metadata_packed"
    assert excluded[f"{13:064x}"] == "metadata_architecture"
    assert excluded[f"{14:064x}"] == "metadata_without_exe_manifest"
    assert excluded[f"{15:064x}"] == "extraction_no_sections"
    assert (
        len(excluded) + sum(sum(labels.values()) for labels in summary["split_counts"].values())
        == 15
    )
    with pytest.raises(SupervisedTrainingError, match="immutable"):
        freeze_metadata_cohort(*inputs[:3], first, input_audit=inputs[3])


def test_manifest_label_mismatch_stops_before_output(tmp_path, monkeypatch):
    inputs = metadata_fixture(tmp_path, monkeypatch)
    manifest = inputs[1]
    manifest.write_text(manifest.read_text().replace(f"{1:064x},benign", f"{1:064x},ransomware"))
    output = tmp_path / "invalid"
    with pytest.raises(SupervisedTrainingError, match="label/snapshot"):
        freeze_metadata_cohort(*inputs[:3], output, input_audit=inputs[3])
    assert not output.exists()


def test_stage_downloads_only_selected_exe_and_reuses_verified_files(tmp_path, monkeypatch):
    import io

    import boto3
    from botocore.response import StreamingBody

    from malweave.data.rands_cohort import stage_cohort_exe

    content = b"synthetic EXE representation; never an executable"
    digest = sha256(content).hexdigest()
    split = tmp_path / "split.csv"
    with split.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=("exe_relative_path", "exe_representation_sha256", "exe_size")
        )
        writer.writeheader()
        writer.writerow(
            {
                "exe_relative_path": "ab/synthetic.bin",
                "exe_representation_sha256": digest,
                "exe_size": len(content),
            }
        )
    requests = []

    class FakeClient:
        def get_object(self, **kwargs):
            requests.append(kwargs)
            return {"Body": StreamingBody(io.BytesIO(content), len(content))}

    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: FakeClient())
    root = tmp_path / "exe"
    prefix = "representations/exe"
    location = f"s3://synthetic-bucket/{prefix}"
    with pytest.raises(SupervisedTrainingError, match="bucket root"):
        stage_cohort_exe(split, root, "s3://synthetic-bucket/exe", workers=1)
    first = stage_cohort_exe(split, root, location, workers=1)
    second = stage_cohort_exe(split, root, location, workers=1)
    relative = f"{digest[:2]}/{digest}"
    assert requests == [{"Bucket": "synthetic-bucket", "Key": f"{prefix}/{relative}"}]
    assert first["counts"] == {"downloaded": 1}
    assert second["counts"] == {"reused": 1}
    assert (root / "ab/synthetic.bin").read_bytes() == content
    (root / "ab/synthetic.bin").write_bytes(b"corrupt")
    with pytest.raises(SupervisedTrainingError, match="staging failed"):
        stage_cohort_exe(split, root, location, workers=1)


def test_metadata_cohort_cli_writes_same_frozen_outputs(tmp_path, monkeypatch, capsys):
    from malweave import cli

    metadata, manifest, config, audit = metadata_fixture(tmp_path, monkeypatch)
    output = tmp_path / "cli-cohort"
    assert (
        cli.main(
            [
                "experiment",
                "freeze-rands-metadata",
                "--metadata-dir",
                str(metadata),
                "--exe-manifest",
                str(manifest),
                "--experiment",
                str(config),
                "--output-dir",
                str(output),
                "--input-audit",
                str(audit),
            ]
        )
        == 0
    )
    assert '"die_verified": false' in capsys.readouterr().out
    assert (output / "split.csv").exists()


def test_model_input_groups_are_resolved_before_split_and_sampling(tmp_path, monkeypatch):
    inputs = metadata_fixture(
        tmp_path,
        monkeypatch,
        extra=(
            (16, "benign", 2024, 16),
            (17, "benign", 2009, 17),
            (18, "benign", 2024, 18),
            (19, "ransomware", 2025, 19),
            (20, "benign", 2024, 20),
            (21, "benign", 2024, 21),
        ),
    )
    audit = inputs[3]
    with sqlite3.connect(audit / "audit.sqlite3") as db:
        for left, right in [(16, 2), (17, 9), (18, 19), (21, 20)]:
            digest = db.execute(
                "select token_sha from samples where source=?", (f"{right:064x}",)
            ).fetchone()[0]
            db.execute("update samples set token_sha=? where source=?", (digest, f"{left:064x}"))
    seal_audit(audit)
    output = tmp_path / "clean"
    summary = freeze_metadata_cohort(*inputs[:3], output, input_audit=audit)
    with (output / "excluded.csv").open() as handle:
        excluded = {int(r["source_sha256"], 16): r["reason"] for r in csv.DictReader(handle)}
    assert excluded[16] == excluded[9] == excluded[21] == "same_label_model_input_duplicate"
    assert excluded[18] == excluded[19] == "conflicting_model_input_labels"
    assert summary["before_undersampling"]["train"] == {"benign": 3, "ransomware": 1}
    assert summary["split_counts"]["validation"] == {"benign": 2, "ransomware": 1}
    with (output / "split.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert len({r["active_leakage_group_sha256"] for r in rows}) == len(rows)
    assert all(r["active_leakage_group_sha256"] != r["exe_representation_sha256"] for r in rows)
    assert summary["metadata_sources"] == 21


@pytest.mark.parametrize("change", ["missing", "stale", "identity", "digest", "limits"])
def test_incomplete_or_changed_audit_cannot_freeze(tmp_path, monkeypatch, change):
    inputs = metadata_fixture(tmp_path, monkeypatch)
    audit = inputs[3]
    if change in {"missing", "stale"}:
        with sqlite3.connect(audit / "audit.sqlite3") as db:
            if change == "missing":
                db.execute("delete from samples where source=?", (f"{2:064x}",))
            else:
                db.execute("update samples set full_bytes=11 where source=?", (f"{2:064x}",))
        seal_audit(audit)
    elif change == "identity":
        path = audit / "identity.json"
        value = json.loads(path.read_text())
        value["production_adapter_sha256"] = "0" * 64
        path.write_text(json.dumps(value))
    elif change == "limits":
        config = yaml.safe_load(inputs[2].read_text())
        config["inputs"]["exe"]["truncation"]["max_bytes"] = 70000
        path = tmp_path / "changed.yaml"
        path.write_text(yaml.safe_dump(config))
        inputs = (*inputs[:2], path, audit)
    else:
        path = audit / "summary.json"
        value = json.loads(path.read_text())
        value["audit_database_sha256"] = "0" * 64
        path.write_text(json.dumps(value))
    output = tmp_path / "must-not-exist"
    with pytest.raises(SupervisedTrainingError, match="audit"):
        freeze_metadata_cohort(*inputs[:3], output, input_audit=audit)
    assert not output.exists()


def test_approved_config_requires_complete_input_audit(tmp_path, monkeypatch):
    inputs = metadata_fixture(tmp_path, monkeypatch)
    with pytest.raises(SupervisedTrainingError, match="requires --input-audit"):
        freeze_metadata_cohort(*inputs[:3], tmp_path / "missing-audit")


def test_published_manifest_preserves_cohort_and_checks_mapping(tmp_path, monkeypatch):
    from malweave.data.s3_layout import EXE_PREFIX, RAW_PREFIX, sharded_key

    metadata, manifest, config, audit = metadata_fixture(tmp_path, monkeypatch)
    with manifest.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        source = row["source_sha256"]
        ok = row["extraction_status"] == "success"
        digest = row["representation_sha256"]
        row.update(
            source_key=sharded_key(RAW_PREFIX, source),
            status=row["extraction_status"],
            exe_sha256=digest if ok else "",
            exe_key=sharded_key(EXE_PREFIX, digest) if ok else "",
            exe_bytes=row["extracted_size"] if ok else "",
        )

    def save():
        with manifest.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    save()
    assert freeze_metadata_cohort(
        metadata, manifest, config, tmp_path / "published", input_audit=audit
    )
    rows[0]["exe_key"] = "representations/exe/wrong-key"
    save()
    with pytest.raises(SupervisedTrainingError, match="mapping disagrees"):
        freeze_metadata_cohort(metadata, manifest, config, tmp_path / "invalid", input_audit=audit)
