"""Strict released-checkpoint loading and EXE-only transfer on synthetic data."""

import csv
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import pytest
from safetensors.torch import load_file, save_file
from tests.lmlm_fixtures import released_checkpoint
import torch
import yaml

from malweave import cli
from malweave.config import PROJECT_ROOT
from malweave.experiments.rands_comparison import SPLIT_FIELDS
from malweave.training.contracts import SupervisedTrainingError
from malweave.training.lmlm_checkpoint import load_finetuned_bimamba, load_released_bimamba
from malweave.training.supervised import (
    SupervisedRunRequest,
    _pr_auc,
    _validate_audited_cohort,
    _validate_transfer_config,
    load_supervised_split,
    run_supervised_training,
)


@pytest.fixture(autouse=True)
def one_cpu_thread():
    previous = torch.get_num_threads()
    torch.set_num_threads(1)
    yield
    torch.set_num_threads(previous)


def load(root: Path):
    return load_released_bimamba(
        root,
        representation="exe",
        max_tokens=12,
        source_context=64,
        gradient_checkpointing=False,
        head_initialization="upstream_normal",
    )


def test_backbone_load_is_exact_and_new_head_can_finetune(tmp_path: Path):
    root = tmp_path / "checkpoint"
    original = released_checkpoint(root)
    loaded = load(root)
    for name, value in original.state_dict().items():
        if not name.startswith("classifier."):
            torch.testing.assert_close(loaded.model.state_dict()[name], value, rtol=0, atol=0)
    assert loaded.model.config.num_hidden_layers == 2
    assert loaded.model.config.hidden_size == 8
    assert loaded.model.config.vocab_size == 264
    assert len(loaded.provenance["source_files_sha256"]) == 5
    assert torch.count_nonzero(loaded.model.classifier.bias) == 0
    assert not torch.equal(loaded.model.classifier.weight, original.classifier.weight)
    before = loaded.model.embeddings.weight.detach().clone()
    inputs = torch.stack(
        [
            loaded.inputs.encode_bytes(bytes(range(10))),
            loaded.inputs.encode_bytes(bytes(range(10, 20))),
        ]
    )
    optimizer = torch.optim.AdamW(loaded.model.parameters(), lr=0.001)
    loss = loaded.model(inputs, labels=torch.tensor([0, 1])).loss
    assert torch.isfinite(loss)
    loss.backward()
    optimizer.step()
    assert not torch.equal(before, loaded.model.embeddings.weight)


@pytest.mark.parametrize("fault", ["missing", "extra", "shape", "nan", "truncated"])
def test_loader_refuses_incomplete_or_incompatible_weights(tmp_path: Path, fault: str):
    root = tmp_path / "checkpoint"
    released_checkpoint(root)
    path = root / "model.safetensors"
    if fault == "truncated":
        path.write_bytes(path.read_bytes()[:-16])
    else:
        tensors = load_file(str(path))
        if fault == "missing":
            tensors.pop("backbone.embeddings.weight")
        elif fault == "extra":
            tensors["backbone.unknown.weight"] = torch.zeros(1)
        elif fault == "shape":
            tensors["backbone.embeddings.weight"] = torch.zeros(1, 8)
        elif fault == "nan":
            tensors["backbone.embeddings.weight"][0, 0] = float("nan")
        save_file(tensors, str(path))
    with pytest.raises(SupervisedTrainingError, match="checkpoint rejected"):
        load(root)


@pytest.mark.parametrize(
    "override",
    [
        {"is_decoder": True},
        {"bi_mix_directions": True},
        {"architectures": ["MambaForSequenceClassification"]},
    ],
)
def test_loader_rejects_unsupported_model_modes(tmp_path: Path, override: dict):
    root = tmp_path / "checkpoint"
    released_checkpoint(root)
    path = root / "config.json"
    path.write_text(json.dumps({**json.loads(path.read_text()), **override}))
    with pytest.raises(SupervisedTrainingError):
        load(root)


def experiment(tmp_path: Path, mode: str = "full") -> SupervisedRunRequest:
    checkpoint = tmp_path / "checkpoint"
    released_checkpoint(checkpoint, "Unigram")
    exe = tmp_path / "exe"
    exe.mkdir()
    rows = []
    for index, split in enumerate(("train", "validation", "test")):
        for label in ("benign", "ransomware"):
            content = bytes([index + 7, int(label == "ransomware"), 32, 255])
            digest = sha256(content).hexdigest()
            relative = digest + ".bin"
            (exe / relative).write_bytes(content)
            row = dict.fromkeys(SPLIT_FIELDS, "")
            row.update(
                split=split,
                source_sha256=sha256(b"PE" + content).hexdigest(),
                label=label,
                family="synthetic-family" if label == "ransomware" else "",
                exe_representation_sha256=digest,
                active_leakage_group_sha256=digest,
                exe_relative_path=relative,
            )
            rows.append(row)
    split_path = tmp_path / "split.csv"
    with split_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SPLIT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    config = {
        "experiment": {"dataset": "rands", "kind": "feasibility"},
        "inputs": {
            "exe": {"truncation": {"max_bytes": 64, "max_tokens": 12}, "checkpoint_context": 64}
        },
        "runtime": {"gradient_checkpointing": False, "mamba_fast_path_required": False},
        "finetuning": {
            "representation": "exe",
            "mode": mode,
            "early_stopping": {"patience": 3, "min_delta": 0},
            "bootstrap": {"replicates": 20, "confidence": 0.95, "seed": 0},
            "head": {"type": "linear", "initialization": "upstream_normal"},
            "selection": {
                "checkpoint": "validation_roc_auc",
                "threshold": "argmax",
            },
        },
        "tracks": {
            "mamba": {
                "training": {
                    "epochs": 1,
                    "batch_size": 1,
                    "precision": "fp32",
                    "optimizer": {"learning_rate": 0.001, "weight_decay": 0.0},
                    "scheduler": {"type": "linear", "warmup_ratio": 0.0, "max_grad_norm": 1.0},
                }
            }
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))
    return SupervisedRunRequest(
        track="mamba",
        config_path=config_path,
        split_manifest_path=split_path,
        raw_root=tmp_path / "RAW_MUST_NOT_BE_READ",
        exe_root=exe,
        artifact_root=tmp_path / "runs",
        run_id="synthetic",
        device="cpu",
        gradient_accumulation_steps=3,
        seed=17,
        checkpoint_path=checkpoint,
    )


@pytest.mark.parametrize("mode", ["full", "head_only"])
def test_exe_only_finetune_uses_saved_tokenizer_and_preserves_initialization(
    tmp_path: Path,
    monkeypatch,
    mode: str,
):
    request = experiment(tmp_path, mode)

    def no_fitting(*args, **kwargs):
        pytest.fail("A released checkpoint must never fit a RanDS tokenizer")

    monkeypatch.setattr("malweave.training.supervised.train_exe_bpe_tokenizer", no_fitting)
    initial = load(request.checkpoint_path).model.state_dict()
    result = run_supervised_training(request)
    run = request.artifact_root / request.run_id
    assert json.loads((run / "run-manifest.json").read_text())["status"] == "completed"
    saved = load_file(str(run / "model.safetensors"))
    changed = [
        name
        for name in initial
        if not name.startswith("classifier.") and not torch.equal(initial[name], saved[name])
    ]
    assert bool(changed) == (mode == "full")
    assert result["manifest"]["initialization"]["source_files_sha256"]
    assert result["manifest"]["finetuning"]["mode"] == mode
    assert result["metrics"]["test"]["average_precision"] is not None
    assert (run / "test-predictions.csv").is_file()
    reloaded = load_finetuned_bimamba(run)
    inputs = reloaded.inputs.encode_bytes(b"synthetic").unsqueeze(0)
    with torch.no_grad():
        assert torch.isfinite(reloaded.model(inputs).logits).all()
    for key, value in saved.items():
        torch.testing.assert_close(reloaded.model.state_dict()[key], value, rtol=0, atol=0)
    (run / "tokenizer.json").write_text("{}")
    with pytest.raises(SupervisedTrainingError, match="digest mismatch"):
        load_finetuned_bimamba(run)
    with pytest.raises(SupervisedTrainingError, match="overwrite"):
        run_supervised_training(request)


def test_cli_checkpoint_path_does_not_require_raw_pe(tmp_path: Path):
    request = experiment(tmp_path)
    assert (
        cli.main(
            [
                "experiment",
                "train",
                "--track",
                "mamba",
                "--checkpoint",
                str(request.checkpoint_path),
                "--experiment",
                str(request.config_path),
                "--split-manifest",
                str(request.split_manifest_path),
                "--exe-root",
                str(request.exe_root),
                "--artifact-root",
                str(request.artifact_root),
                "--run-id",
                "cli",
                "--device",
                "cpu",
                "--gradient-accumulation-steps",
                "1",
                "--seed",
                "17",
            ]
        )
        == 0
    )


def test_explicit_transfer_config_is_required(tmp_path: Path):
    request = experiment(tmp_path)
    config = yaml.safe_load(request.config_path.read_text())
    del config["finetuning"]
    request.config_path.write_text(yaml.safe_dump(config))
    with pytest.raises(SupervisedTrainingError, match="explicit fine-tuning config"):
        run_supervised_training(request)
    assert not request.artifact_root.exists()
    with pytest.raises(SupervisedTrainingError, match="simple name"):
        run_supervised_training(replace(request, run_id="../escape"))


def test_frozen_manifest_rejects_exe_leakage(tmp_path: Path):
    request = experiment(tmp_path)
    rows = list(csv.DictReader(request.split_manifest_path.open()))
    rows[-1]["exe_representation_sha256"] = rows[0]["exe_representation_sha256"]
    with request.split_manifest_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SPLIT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(SupervisedTrainingError, match="EXE leakage"):
        load_supervised_split(request.split_manifest_path)


def test_average_precision_groups_tied_scores():
    assert _pr_auc([0.5, 0.5], [0, 1]) == 0.5
    assert _pr_auc([0.5, 0.5], [1, 0]) == 0.5


def test_finetune_config_cannot_fall_back_to_random_weights(tmp_path: Path):
    request = experiment(tmp_path)
    with pytest.raises(SupervisedTrainingError, match="random fallback is forbidden"):
        run_supervised_training(replace(request, checkpoint_path=None))


def test_partial_accumulation_matches_a_single_combined_batch(tmp_path: Path):
    request = experiment(tmp_path)
    run_supervised_training(request)  # Two single-example batches in a partial group of three.
    config = yaml.safe_load(request.config_path.read_text())
    config["tracks"]["mamba"]["training"]["batch_size"] = 2
    request.config_path.write_text(yaml.safe_dump(config))
    second = replace(request, run_id="combined", gradient_accumulation_steps=1)
    run_supervised_training(second)
    first_weights = load_file(str(request.artifact_root / "synthetic/model.safetensors"))
    second_weights = load_file(str(request.artifact_root / "combined/model.safetensors"))
    torch.testing.assert_close(
        first_weights["classifier.weight"],
        second_weights["classifier.weight"],
        rtol=1e-4,
        atol=1e-6,
    )


@pytest.mark.parametrize("filename,payload", [("config.json", "[]"), ("tokenizer.json", "{}")])
def test_malformed_artifacts_have_actionable_validation_errors(
    tmp_path: Path,
    filename: str,
    payload: str,
):
    root = tmp_path / "checkpoint"
    released_checkpoint(root)
    (root / filename).write_text(payload)
    with pytest.raises(SupervisedTrainingError, match="Released checkpoint rejected"):
        load(root)


def test_pause_resume_matches_uninterrupted_training_with_dropout(tmp_path):
    request = experiment(tmp_path)
    source_config = request.checkpoint_path / "config.json"
    source = json.loads(source_config.read_text())
    source["hidden_dropout_prob"] = 0.2
    source_config.write_text(json.dumps(source))
    config = yaml.safe_load(request.config_path.read_text())
    config["tracks"]["mamba"]["training"]["epochs"] = 3
    request.config_path.write_text(yaml.safe_dump(config))
    with request.split_manifest_path.open() as handle:
        rows = list(csv.DictReader(handle))
    for index in range(4):
        content = f"synthetic extra training input {index}".encode()
        digest = sha256(content).hexdigest()
        (request.exe_root / (digest + ".bin")).write_bytes(content)
        row = dict.fromkeys(SPLIT_FIELDS, "")
        row.update(
            split="train",
            source_sha256=sha256(b"PE" + content).hexdigest(),
            label="ransomware" if index % 2 else "benign",
            exe_representation_sha256=digest,
            active_leakage_group_sha256=digest,
            exe_relative_path=digest + ".bin",
        )
        rows.append(row)
    with request.split_manifest_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SPLIT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    paused = run_supervised_training(replace(request, max_updates=1))
    run = request.artifact_root / request.run_id
    assert paused["manifest"]["status"] == "paused"
    assert paused["metrics"]["test_evaluated"] is False
    assert not (run / "test-predictions.csv").exists()
    resumed = run_supervised_training(replace(request, resume=True))
    uninterrupted = run_supervised_training(replace(request, run_id="continuous"))
    for name, value in load_file(str(run / "model.safetensors")).items():
        torch.testing.assert_close(
            value,
            load_file(str(request.artifact_root / "continuous/model.safetensors"))[name],
            rtol=0,
            atol=0,
        )
    assert resumed["metrics"]["history"] == uninterrupted["metrics"]["history"]
    first = torch.load(run / "last.pt", weights_only=True)
    second = torch.load(request.artifact_root / "continuous/last.pt", weights_only=True)
    assert first["scheduler"] == second["scheduler"]
    assert first["update"] == second["update"] == 6


def test_early_stopping_keeps_first_equal_checkpoint_and_source_argmax(tmp_path, monkeypatch):
    request = experiment(tmp_path)
    config = yaml.safe_load(request.config_path.read_text())
    config["tracks"]["mamba"]["training"]["epochs"] = 10
    request.config_path.write_text(yaml.safe_dump(config))

    def fixed_evaluation(*args, predictions=None):
        if predictions is not None:
            predictions.extend([0, 0])  # Source argmax selects class 0 for tied logits.
        return 0.5, [0.5, 0.5], [0, 1]

    monkeypatch.setattr("malweave.training.supervised._evaluate", fixed_evaluation)
    result = run_supervised_training(request)
    assert len(result["metrics"]["history"]) == 4
    assert result["metrics"]["selection"]["checkpoint_epoch"] == 1
    assert result["metrics"]["stopped_early"] is True
    assert result["metrics"]["test"]["tp"] == 0
    assert result["metrics"]["test"]["tn"] == 1
    assert result["metrics"]["test"]["families"]["synthetic-family"] == {
        "support": 1,
        "detected": 0,
        "recall": 0.0,
        "present_in_rands_train": True,
    }
    assert "balanced_accuracy" not in result["metrics"]["test"]
    assert result["metrics"]["test"]["roc_auc_ci"]["lower"] == 0.5


def test_committed_c_config_uses_approved_five_epoch_schedule():
    config = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-c.yaml").read_text())
    assert config["tracks"]["mamba"]["training"]["epochs"] == 5
    assert _validate_transfer_config(config) == config["finetuning"]
    config["tracks"]["mamba"]["training"]["epochs"] = 15
    with pytest.raises(SupervisedTrainingError, match="approved 5-epoch budget"):
        _validate_transfer_config(config)


@pytest.mark.parametrize("conflicting_label", [False, True])
def test_frozen_manifest_rejects_model_input_leakage(tmp_path: Path, conflicting_label):
    request = experiment(tmp_path)
    with request.split_manifest_path.open() as handle:
        rows = list(csv.DictReader(handle))
    if conflicting_label:
        rows[1]["active_leakage_group_sha256"] = rows[0]["active_leakage_group_sha256"]
        assert rows[1]["label"] != rows[0]["label"]
    else:
        rows[-1]["active_leakage_group_sha256"] = rows[0]["active_leakage_group_sha256"]
    with request.split_manifest_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SPLIT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(SupervisedTrainingError, match="model-input leakage"):
        load_supervised_split(request.split_manifest_path)


@pytest.mark.parametrize("fault", [None, "missing", "tokenizer", "limits", "split"])
def test_audited_cohort_is_bound_to_checkpoint_and_preprocessing(tmp_path: Path, fault):
    request = experiment(tmp_path)
    config = yaml.safe_load(request.config_path.read_text())
    config["cohort"] = {"deduplication": "exact_model_tokens_after_full_exe"}
    identity = {
        "tokenizer_sha256": sha256(
            (request.checkpoint_path / "tokenizer.json").read_bytes()
        ).hexdigest(),
        "checkpoint_config_sha256": sha256(
            (request.checkpoint_path / "config.json").read_bytes()
        ).hexdigest(),
        "production_adapter_sha256": sha256(
            (PROJECT_ROOT / "malweave/data/lmlm_inputs.py").read_bytes()
        ).hexdigest(),
        "max_bytes": 64,
        "max_tokens_including_bos_eos": 12,
    }
    summary = {
        "policy": config["cohort"],
        "output_sha256": {
            "split.csv": sha256(request.split_manifest_path.read_bytes()).hexdigest()
        },
        "model_input_audit": {"identity": identity},
    }
    if fault == "tokenizer":
        identity["tokenizer_sha256"] = "0" * 64
    if fault == "limits":
        identity["max_bytes"] = 65
    if fault == "split":
        summary["output_sha256"]["split.csv"] = "0" * 64
    if fault != "missing":
        (request.split_manifest_path.parent / "summary.json").write_text(json.dumps(summary))
    if fault:
        with pytest.raises(SupervisedTrainingError, match="audited cohort"):
            _validate_audited_cohort(request, config)
    else:
        assert _validate_audited_cohort(request, config)["identity"] == identity
