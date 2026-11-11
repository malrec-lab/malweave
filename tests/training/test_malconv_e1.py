"""Original/LMLM baseline isolation and E1 whole-input/resume regressions."""

from dataclasses import replace
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest
from tests.training.test_malconv_e2 import assert_state_equal
import torch
import yaml

from malweave.config import PROJECT_ROOT
from malweave.data.malconv_inputs import audit_malconv_inputs, encode_e1_bytes
from malweave.models import MalConvGCTConfig, MalConvGCTForSequenceClassification
from malweave.training.contracts import SupervisedTrainingError
from malweave.training.e2_smoke import prepare_e2_smoke
from malweave.training.malconv_e1 import validate_e1_config
from malweave.training.malconv_e2 import validate_e2_config
from malweave.training.supervised import (
    SplitExample,
    SupervisedRunRequest,
    _SupervisedDataset,
    run_supervised_training,
)


@pytest.fixture(autouse=True)
def single_thread():
    previous = torch.get_num_threads()
    torch.set_num_threads(1)
    yield
    torch.set_num_threads(previous)


def e1_request(tmp_path):
    root = tmp_path / "e1-inputs"
    prepare_e2_smoke(root, tiny_model=True, max_tokens=130)
    config = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-e1.yaml").read_text())
    config["experiment"].update(kind="feasibility")
    config.pop("cohort")
    config["tracks"]["malconvgct"]["architecture"].update(
        channels=4, embedding_size=2, chunk_size=1024, min_chunk_size=256
    )
    config["tracks"]["malconvgct"]["training"].update(
        epochs=3, batch_size=2, effective_batch_size=4
    )
    config["supervision"]["bootstrap"]["replicates"] = 20
    (root / "config.yaml").write_text(yaml.safe_dump(config))
    return SupervisedRunRequest(
        track="malconvgct",
        config_path=root / "config.yaml",
        split_manifest_path=root / "split.csv",
        raw_root=root / "raw",
        exe_root=root / "NO_EXE",
        artifact_root=tmp_path / "runs",
        run_id="e1",
        device="cpu",
        gradient_accumulation_steps=2,
        seed=0,
    )


@pytest.mark.parametrize("pause_update", [1, 2, 3])
def test_e1_constant_lr_full_resume_and_separate_identity(tmp_path, pause_update):
    request = e1_request(tmp_path)
    paused = run_supervised_training(replace(request, max_updates=pause_update))
    assert not paused["metrics"]["test_evaluated"]
    resumed = run_supervised_training(replace(request, resume=True))
    continuous = run_supervised_training(replace(request, run_id="continuous"))
    assert resumed["metrics"]["history"] == continuous["metrics"]["history"]
    assert resumed["metrics"]["test"] == continuous["metrics"]["test"]
    first = torch.load(tmp_path / "runs/e1/last.pt", weights_only=True)
    second = torch.load(tmp_path / "runs/continuous/last.pt", weights_only=True)
    for key in ("model", "optimizer", "scheduler", "torch_rng", "epoch_generator_state"):
        assert_state_equal(first[key], second[key])
    events = [
        json.loads(line) for line in (tmp_path / "runs/e1/progress.jsonl").read_text().splitlines()
    ]
    assert all(row["learning_rate"] == 0.001 for row in events)
    manifest = resumed["manifest"]
    assert "e1_input_audit" in manifest and "e2_input_audit" not in manifest
    assert manifest["input_encoding"]["max_bytes"] is None
    assert manifest["malconv_source_behavior"] == {
        "implementation": "original",
        "context_receives_gradients": True,
        "embedding_padding_idx": 0,
        "batch_pad_to_multiple_of": 1,
        "protocol": "malconvgct_e1",
        "upstream_commit": "b5a865420e984b22a2474834bd1748318e84b553",
    }


def test_full_e1_encoding_and_reader_do_not_apply_e2_prefix_limit(tmp_path):
    assert encode_e1_bytes(bytes(range(256))).tolist() == list(range(1, 257))
    assert encode_e1_bytes(b"").numel() == 0
    content = b"synthetic-full-input" + bytes(range(256)) * 4097
    source = sha256(content).hexdigest()
    path = tmp_path / "raw/dataset" / source[:2] / source
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    row = SplitExample("train", source, 0, "", "", source)
    e1 = _SupervisedDataset(
        [row], "malconvgct", tmp_path / "raw", "dataset", tmp_path, None, None, e1=True
    )
    e2 = _SupervisedDataset(
        [row], "malconvgct", tmp_path / "raw", "dataset", tmp_path, None, 1048576, e2=True
    )
    first, _ = e1[0]
    second, _ = e2[0]
    assert first.numel() == len(content) > 1048576
    assert first[-1].item() == content[-1] + 1
    assert second.numel() == 1048576
    path.write_bytes(content[:-1] + b"!")
    for dataset in (e1, e2):
        with pytest.raises(SupervisedTrainingError, match="digest changed"):
            dataset[0]


def test_e1_audit_uses_full_input_not_the_e2_prefix(tmp_path):
    rows = []
    for index in range(2):
        content = b"same-prefix" * 16 + bytes([index])
        source = sha256(content).hexdigest()
        path = tmp_path / "raw/dataset" / source[:2] / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        rows.append(
            SimpleNamespace(source_sha256=source, split="train" if index else "test", label=index)
        )
    summary = audit_malconv_inputs(
        rows,
        tmp_path / "raw",
        "dataset",
        None,
        "synthetic",
        tmp_path / "audit",
        protocol="malconvgct_e1",
    )
    assert summary["statuses"] == {"success": 2}
    assert summary["cross_split_or_conflicting_label_groups"] == 0
    assert summary["retained_bytes"] == summary["raw_bytes"]
    assert summary["identity"]["encoding"]["byte_offset"] == 1


def test_committed_baselines_cannot_silently_exchange_source_behavior(tmp_path):
    request = e1_request(tmp_path)
    e1 = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-e1.yaml").read_text())
    e2 = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-e2.yaml").read_text())
    training = e1["tracks"]["malconvgct"]["training"]
    accumulation = training["effective_batch_size"] // training["batch_size"]
    validate_e1_config(e1, replace(request, gradient_accumulation_steps=accumulation))
    validate_e2_config(e2, replace(request, gradient_accumulation_steps=1))
    assert e1["cohort"] == e2["cohort"]
    assert e1["supervision"] == e2["supervision"]
    assert e1["tracks"]["malconvgct"]["training"]["epochs"] == 15
    for config, validator, wrong in (
        (e1, validate_e1_config, "lmlm"),
        (e2, validate_e2_config, "original"),
    ):
        config["tracks"]["malconvgct"]["architecture"]["implementation"] = wrong
        with pytest.raises(SupervisedTrainingError, match="implementation|behavior"):
            validator(config, request)


def test_model_profiles_preserve_distinct_context_and_pad_behavior():
    for profile in ("original", "lmlm"):
        model = MalConvGCTForSequenceClassification(
            MalConvGCTConfig(
                vocab_size=264,
                channels=4,
                embedding_size=2,
                kernel_size=64,
                stride=64,
                implementation=profile,
            )
        )
        model(torch.tensor([[3, 12, 13, 4, 0, 0, 0, 0]]), labels=torch.tensor([1])).loss.backward()
        assert (model.malconv.context_net.embedding.weight.grad is not None) == (
            profile == "original"
        )
        assert model.malconv.embedding.padding_idx == (0 if profile == "original" else None)


def test_resume_rejects_switching_e1_to_lmlm_without_overwriting_state(tmp_path):
    request = e1_request(tmp_path)
    run_supervised_training(replace(request, max_updates=1))
    state_path = tmp_path / "runs/e1/last.pt"
    original_digest = sha256(state_path.read_bytes()).hexdigest()
    e2_root = tmp_path / "e2-inputs"
    prepare_e2_smoke(e2_root, tiny_model=True, max_tokens=130)
    with pytest.raises(SupervisedTrainingError, match="config_sha256"):
        run_supervised_training(
            replace(
                request,
                config_path=e2_root / "config.yaml",
                resume=True,
                gradient_accumulation_steps=4,
                max_updates=2,
            )
        )
    assert sha256(state_path.read_bytes()).hexdigest() == original_digest


def test_e1_synthetic_cli_can_train_and_resume_without_exe_or_tokenizer(tmp_path, capsys):
    from malweave.cli import main

    root = tmp_path / "cli-fixture"
    assert (
        main(
            [
                "experiment",
                "prepare-e1-smoke",
                "--output-dir",
                str(root),
                "--sample-bytes",
                "130",
                "--tiny-model",
            ]
        )
        == 0
    )
    config = yaml.safe_load((root / "config.yaml").read_text())
    assert config["experiment"]["protocol"] == "malconvgct_e1"
    assert config["inputs"]["raw"]["max_bytes"] is None
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
        str(root / "NO_EXE"),
        "--artifact-root",
        str(tmp_path / "runs"),
        "--run-id",
        "cli-e1",
        "--device",
        "cpu",
        "--gradient-accumulation-steps",
        "4",
        "--seed",
        "0",
    ]
    assert main([*args, "--max-updates", "1"]) == 0
    assert main([*args, "--resume", "--max-updates", "2"]) == 0
    state = torch.load(tmp_path / "runs/cli-e1/last.pt", weights_only=True)
    assert state["update"] == 2
    assert not (tmp_path / "runs/cli-e1/tokenizer.json").exists()
