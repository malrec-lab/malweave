"""Synthetic E2 protocol, recovery and input-integrity regression coverage."""

from dataclasses import replace
import json

import pytest
from safetensors.torch import load_file
import torch
import yaml

from malweave.cli import main
from malweave.config import PROJECT_ROOT
from malweave.training.contracts import SupervisedTrainingError
from malweave.training.e2_smoke import prepare_e2_smoke
from malweave.training.malconv_e2 import validate_e2_cohort, validate_e2_config
from malweave.training.supervised import SupervisedRunRequest, run_supervised_training


@pytest.fixture(autouse=True)
def single_cpu_thread():
    previous = torch.get_num_threads()
    torch.set_num_threads(1)
    yield
    torch.set_num_threads(previous)


def request(tmp_path):
    root = tmp_path / "synthetic"
    prepare_e2_smoke(root, max_tokens=130, tiny_model=True)
    return SupervisedRunRequest(
        track="malconvgct",
        config_path=root / "config.yaml",
        split_manifest_path=root / "split.csv",
        raw_root=root / "raw",
        exe_root=root / "NO_EXE_ACCESS",
        artifact_root=tmp_path / "runs",
        run_id="resumed",
        device="cpu",
        gradient_accumulation_steps=4,
        seed=0,
    )


def assert_state_equal(first, second):
    if isinstance(first, torch.Tensor):
        torch.testing.assert_close(first, second, rtol=0, atol=0)
    elif isinstance(first, dict):
        assert first.keys() == second.keys()
        for key in first:
            assert_state_equal(first[key], second[key])
    elif isinstance(first, (list, tuple)):
        assert len(first) == len(second)
        for left, right in zip(first, second, strict=True):
            assert_state_equal(left, right)
    else:
        assert first == second


@pytest.mark.parametrize("pause_update", [1, 2, 3, 6])
def test_e2_resume_matches_continuous_including_partial_batch_and_epoch_boundary(
    tmp_path, pause_update
):
    run_request = request(tmp_path)
    paused = run_supervised_training(replace(run_request, max_updates=pause_update))
    directory = run_request.artifact_root / run_request.run_id
    assert paused["manifest"]["status"] == "paused"
    assert paused["metrics"]["test_evaluated"] is False
    assert not (directory / "test-predictions.csv").exists()
    assert not (directory / "tokenizer.json").exists()
    assert (directory / "progress.jsonl").is_file()
    resumed = run_supervised_training(replace(run_request, resume=True))
    continuous = run_supervised_training(replace(run_request, run_id="continuous"))
    assert resumed["metrics"]["history"] == continuous["metrics"]["history"]
    assert resumed["metrics"]["test"] == continuous["metrics"]["test"]
    expected = run_request.artifact_root / "continuous"
    assert_state_equal(
        load_file(str(directory / "model.safetensors")),
        load_file(str(expected / "model.safetensors")),
    )
    first = torch.load(directory / "last.pt", weights_only=True)
    second = torch.load(expected / "last.pt", weights_only=True)
    for key in (
        "model",
        "optimizer",
        "scheduler",
        "update",
        "torch_rng",
        "python_rng",
        "epoch_generator_state",
        "stale_epochs",
        "best_auc",
        "best_epoch",
    ):
        assert_state_equal(first[key], second[key])
    assert first["update"] == 6
    assert (
        resumed["metrics"]["selection"]["decision_rule"] == "softmax_argmax; ties select class 0"
    )
    assert (directory / "history.csv").exists()


def test_e2_session_time_limit_pauses_at_committed_update_and_rejects_identity_change(tmp_path):
    run_request = request(tmp_path)
    result = run_supervised_training(replace(run_request, max_seconds=1e-9))
    assert result["metrics"]["updates"] == 1
    assert result["metrics"]["session_samples"] == 4
    with pytest.raises(SupervisedTrainingError, match="seed"):
        run_supervised_training(replace(run_request, resume=True, seed=1))
    run_supervised_training(replace(run_request, resume=True))
    with pytest.raises(SupervisedTrainingError, match="completed"):
        run_supervised_training(replace(run_request, resume=True))


def test_physical_batch64_uses_full_batches_and_resumes_exactly(tmp_path):
    root = tmp_path / "batch64"
    fixture = prepare_e2_smoke(root, max_tokens=130, full_length=True)
    assert fixture["batch_size"] == 64 and fixture["gradient_accumulation_steps"] == 1
    assert fixture["rows"] == 132
    config_path = root / "config.yaml"
    config = yaml.safe_load(config_path.read_text())
    # Retain the real batch/input path but use small channels for a fast CPU test.
    config["tracks"]["malconvgct"]["architecture"].update(
        embedding_size=2, channels=4, chunk_size=256, min_chunk_size=64
    )
    config_path.write_text(yaml.safe_dump(config))
    run_request = SupervisedRunRequest(
        track="malconvgct",
        config_path=config_path,
        split_manifest_path=root / "split.csv",
        raw_root=root / "raw",
        exe_root=root / "NO_EXE_ACCESS",
        artifact_root=tmp_path / "runs",
        run_id="batch64",
        device="cpu",
        gradient_accumulation_steps=1,
        seed=0,
    )
    paused = run_supervised_training(replace(run_request, max_updates=1))
    assert paused["metrics"]["session_samples"] == 64
    assert paused["manifest"]["batch_size"] == 64
    resumed = run_supervised_training(replace(run_request, resume=True, max_updates=3))
    assert resumed["metrics"]["session_samples"] == 128
    run_supervised_training(replace(run_request, run_id="continuous", max_updates=3))
    first = torch.load(tmp_path / "runs/batch64/last.pt", weights_only=True)
    second = torch.load(tmp_path / "runs/continuous/last.pt", weights_only=True)
    for key in ("model", "optimizer", "scheduler", "torch_rng", "epoch_generator_state"):
        assert_state_equal(first[key], second[key])
    assert first["update"] == 3
    assert not resumed["metrics"]["test_evaluated"]


@pytest.mark.parametrize("change", ["precision", "epochs", "encoding", "batch", "checkpoint"])
def test_e2_rejects_incompatible_protocol(tmp_path, change):
    run_request = request(tmp_path)
    config = yaml.safe_load(run_request.config_path.read_text())
    if change == "precision":
        config["tracks"]["malconvgct"]["training"]["precision"] = "fp16"
    elif change == "epochs":
        config["tracks"]["malconvgct"]["training"]["epochs"] = 16
    elif change == "encoding":
        config["inputs"]["raw"]["encoding"]["byte_offset"] = 1
    elif change == "batch":
        run_request = replace(run_request, gradient_accumulation_steps=1)
    else:
        run_request = replace(run_request, checkpoint_path=tmp_path / "checkpoint")
    with pytest.raises(SupervisedTrainingError):
        validate_e2_config(config, run_request)


def test_e2_committed_config_uses_batch64_and_keeps_c_budget_separate(tmp_path):
    run_request = replace(request(tmp_path), gradient_accumulation_steps=1)
    config = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-e2.yaml").read_text())
    validate_e2_config(config, run_request)
    assert config["tracks"]["malconvgct"]["architecture"]["kernel_size"] == 64
    assert config["tracks"]["malconvgct"]["training"]["epochs"] == 15
    # E2 uses a physical batch of 64, not merely the same effective batch.
    accumulated = yaml.safe_load(yaml.safe_dump(config))
    accumulated["tracks"]["malconvgct"]["training"]["batch_size"] = 1
    with pytest.raises(SupervisedTrainingError, match="batch 64, accumulation 1"):
        validate_e2_config(accumulated, replace(run_request, gradient_accumulation_steps=64))
    c_config = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-c.yaml").read_text())
    assert c_config["tracks"]["mamba"]["training"]["epochs"] == 5
    assert config["cohort"] == c_config["cohort"]
    with pytest.raises(SupervisedTrainingError, match="summary"):
        validate_e2_cohort(run_request, config)


def test_e2_cli_can_resume_without_any_tokenizer(tmp_path, capsys):
    root = tmp_path / "smoke"
    assert (
        main(
            [
                "experiment",
                "prepare-e2-smoke",
                "--output-dir",
                str(root),
                "--tiny-model",
                "--max-tokens",
                "130",
            ]
        )
        == 0
    )
    args = [
        "experiment",
        "train",
        "--track",
        "malconvgct",
        "--experiment",
        str(root / "config.yaml"),
        "--split-manifest",
        str(root / "split.csv"),
        "--raw-root",
        str(root / "raw"),
        "--exe-root",
        str(root / "NO_EXE_ACCESS"),
        "--artifact-root",
        str(root / "runs"),
        "--run-id",
        "cli",
        "--device",
        "cpu",
        "--gradient-accumulation-steps",
        "4",
        "--seed",
        "0",
    ]
    assert main([*args, "--max-seconds", "0.000001"]) == 0
    assert main([*args, "--resume", "--max-updates", "2"]) == 0
    manifest = json.loads((root / "runs/cli/run-manifest.json").read_text())
    assert manifest["status"] == "paused"
    assert manifest["updates"] == 2
