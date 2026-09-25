"""Synthetic end-to-end coverage for the private supervised-training runner."""

from __future__ import annotations

import csv
from hashlib import sha256
import io
import json
from pathlib import Path

import pytest

from malweave.experiments.rands_comparison import SPLIT_FIELDS
from malweave.training.stage import StageError, stage_manifest_from_s3
from malweave.training.supervised import (
    SupervisedRunRequest,
    SupervisedTrainingError,
    run_supervised_training,
)


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _write_config(path: Path) -> None:
    path.write_text(
        """
experiment: {dataset: rands, kind: feasibility}
inputs:
  raw: {truncation: {max_bytes: 1024}}
  exe: {truncation: {max_tokens: 8}, tokenizer: {vocab_size: 32}}
runtime: {gradient_checkpointing: false}
tracks:
  malconvgct:
    architecture:
      vocab_size: 257
      embedding_size: 2
      channels: 2
      stride: 1
      kernel_size: 2
      layers: 1
      pad_token_id: 0
      num_labels: 2
    training:
      epochs: 2
      precision: fp32
      optimizer: {learning_rate: 0.01, weight_decay: 0.0}
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_private_split(path: Path, raw_root: Path) -> None:
    rows: list[dict[str, str | int]] = []
    for split in ("train", "validation", "test"):
        for label in ("benign", "ransomware"):
            content = (f"{split}-{label}".encode() * 128)[:1024]
            source = sha256(content).hexdigest()
            sample_path = raw_root / "dataset" / source[:2]
            sample_path.mkdir(parents=True, exist_ok=True)
            (sample_path / source).write_bytes(content)
            rows.append(
                {
                    "split": split,
                    "source_sha256": source,
                    "label": label,
                    "family": "",
                    "snapshot": "test",
                    "raw_representation_sha256": source,
                    "raw_relative_path": "source",
                    "raw_size": 1024,
                    "exe_representation_sha256": _digest(f"exe-{source}"),
                    "exe_relative_path": f"exe/{source}.bin",
                    "exe_size": 1,
                    "active_leakage_group_sha256": _digest(f"exe-{source}"),
                }
            )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SPLIT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def test_supervised_runner_writes_private_checkpoint_metrics_and_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path = tmp_path / "supervised.yaml"
    split_path = tmp_path / "split.csv"
    raw_root = tmp_path / "raw"
    artifact_root = tmp_path / "artifacts"
    _write_config(config_path)
    _write_private_split(split_path, raw_root)

    result = run_supervised_training(
        SupervisedRunRequest(
            track="malconvgct",
            config_path=config_path,
            split_manifest_path=split_path,
            raw_root=raw_root,
            exe_root=tmp_path / "exe",
            artifact_root=artifact_root,
            run_id="synthetic-run",
            device="cpu",
            gradient_accumulation_steps=1,
            seed=17,
        )
    )

    run_dir = artifact_root / "synthetic-run"
    assert (run_dir / "best.pt").exists()
    assert (run_dir / "metrics.json").exists()
    assert (run_dir / "run-manifest.json").exists()
    assert (run_dir / "test-predictions.csv").exists()
    assert result["metrics"]["test"]["roc_auc"] is not None
    assert result["manifest"]["tokenizer_sha256"] is None
    assert result["manifest"]["seed"] == 17
    progress = capsys.readouterr().err
    assert "train: preparing track=malconvgct device=cpu train=2 validation=2 test=2" in progress
    assert "epoch=1/2 phase=train batches=2/2" in progress
    assert "epoch=2/2 phase=validation" in progress
    assert "train: phase=test" in progress
    assert sha256((b"train-benign" * 128)[:1024]).hexdigest() not in progress


class FakeS3:
    def __init__(self, objects: dict[str, bytes]) -> None:
        self.objects = objects

    def get_object(self, **request: str) -> dict[str, io.BytesIO]:
        return {"Body": io.BytesIO(self.objects[request["Key"]])}


def test_raw_s3_split_is_fully_staged_before_local_training(tmp_path: Path) -> None:
    config_path = tmp_path / "malconv-raw.yaml"
    manifest = tmp_path / "raw-split.csv"
    audit = tmp_path / "raw-split.json"
    stage_root = tmp_path / "staged"
    _write_config(config_path)
    objects: dict[str, bytes] = {}
    rows = []
    for split in ("train", "validation", "test"):
        for label in ("benign", "ransomware"):
            content = (f"synthetic-{split}-{label}".encode() * 100)[:1024]
            source = sha256(content).hexdigest()
            key = f"synthetic/{source}"
            objects[key] = content
            rows.append(
                {
                    "source_sha256": source,
                    "label": label,
                    "split": split,
                    "group_id": source,
                    "availability": "available",
                    "object_key": key,
                    "object_size": len(content),
                    "object_etag": '"synthetic"',
                }
            )
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    audit.write_text(
        json.dumps(
            {
                "inventory_audit_passed": True,
                "manifest": {"sha256": sha256(manifest.read_bytes()).hexdigest()},
            }
        ),
        encoding="utf-8",
    )
    request = SupervisedRunRequest(
        track="malconvgct",
        config_path=config_path,
        split_manifest_path=manifest,
        raw_root=None,
        exe_root=None,
        artifact_root=tmp_path / "artifacts",
        run_id="synthetic-staged",
        device="cpu",
        gradient_accumulation_steps=1,
        seed=17,
        staging_report=stage_root / "staging-summary.json",
    )
    with pytest.raises(SupervisedTrainingError, match="staging report"):
        run_supervised_training(request)
    staged = stage_manifest_from_s3(
        manifest, audit, stage_root, bucket="synthetic", client=FakeS3(objects)
    )
    assert staged["passed"] is True
    assert staged["selected"] == 6
    result = run_supervised_training(request)
    assert result["manifest"]["source_kind"] == "local"
    assert result["manifest"]["staging_report_sha256"] is not None
    assert result["metrics"]["source"]["failures_by_label"] == {}


def test_staging_records_failure_and_resumes_without_rewriting_success(tmp_path: Path) -> None:
    manifest = tmp_path / "split.csv"
    audit = tmp_path / "audit.json"
    root = tmp_path / "staged"
    objects = {"synthetic/first": b"first"}
    rows = [
        {
            "source_sha256": sha256(content).hexdigest(),
            "label": label,
            "split": split,
            "group_id": sha256(content).hexdigest(),
            "availability": "available",
            "object_key": key,
            "object_size": len(content),
            "object_etag": '"synthetic"',
        }
        for key, content, label, split in (
            ("synthetic/first", b"first", "benign", "train"),
            ("synthetic/second", b"second", "ransomware", "test"),
        )
    ]
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    audit.write_text(
        json.dumps(
            {
                "inventory_audit_passed": True,
                "manifest": {"sha256": sha256(manifest.read_bytes()).hexdigest()},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(StageError, match="incomplete"):
        stage_manifest_from_s3(manifest, audit, root, bucket="synthetic", client=FakeS3(objects))
    failed = json.loads((root / "staging-summary.json").read_text(encoding="utf-8"))
    assert failed["success_by_label"] == {"benign": 1}
    assert failed["failure_by_label"] == {"ransomware": 1}
    assert failed["downloaded_bytes_this_run"] == len(b"first")
    objects["synthetic/second"] = b"second"
    passed = stage_manifest_from_s3(
        manifest, audit, root, bucket="synthetic", client=FakeS3(objects), resume=True
    )
    assert passed["passed"] is True
    assert passed["downloaded_bytes_this_run"] == len(b"second")
    assert passed["output_bytes"] == len(b"firstsecond")
