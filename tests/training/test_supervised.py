"""Synthetic end-to-end coverage for the private supervised-training runner."""

from __future__ import annotations

import csv
from hashlib import sha256
from pathlib import Path

from malweave.experiments.rands_comparison import SPLIT_FIELDS
from malweave.training.supervised import SupervisedRunRequest, run_supervised_training


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


def test_supervised_runner_writes_private_checkpoint_metrics_and_manifest(tmp_path: Path) -> None:
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
