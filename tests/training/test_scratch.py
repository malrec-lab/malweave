"""Synthetic training, metrics, graceful stop and complete local/remote resume."""

from dataclasses import replace
import json
from pathlib import Path
import shutil

import pytest
from tests.training.scratch_fixtures import fixture
import torch
import yaml

from malweave.data.byte_inputs import SPECIAL_TOKENS, train_exe_bpe_tokenizer
from malweave.data.rands_training import RandsTrainingError, load_split, prepare_exe
from malweave.models import HRRFormerConfig, HRRFormerForSequenceClassification
from malweave.training import scratch_storage
from malweave.training.scratch import ExeDataset, ScratchRequest, _rank_metrics, run_scratch


@pytest.mark.parametrize("backbone", ["hrrformer", "mamba"])
def test_interrupted_training_matches_uninterrupted_and_rejects_changed_config(
    tmp_path: Path, backbone: str
):
    data, config = fixture(tmp_path)
    if backbone == "mamba":
        settings = yaml.safe_load(config.read_text())
        settings["model"].update(
            name="mamba",
            architecture={
                "hidden_size": 8,
                "num_hidden_layers": 1,
                "state_size": 4,
                "expand": 2,
                "conv_kernel": 4,
                "hidden_dropout_prob": 0.1,
                "residual_in_fp32": True,
                "is_decoder": False,
                "bi_tie_directions": False,
                "bi_add_directions": True,
            },
        )
        settings["training"]["gradient_checkpointing"] = True
        config.write_text(yaml.safe_dump(settings, sort_keys=False))
    prepare_exe(data, config)
    request = ScratchRequest(config, data, tmp_path / "runs", "continuous", device="cpu")
    full = run_scratch(request)
    interrupted = replace(request, run_id="resumed", max_steps=1)
    stopped = run_scratch(interrupted)
    assert stopped["status"] == "stopped"
    resumed = run_scratch(replace(interrupted, resume=True, max_steps=None))
    assert resumed["status"] == full["status"] == "complete"
    left = torch.load(request.runs / "continuous/last.pt", weights_only=True)
    right = torch.load(request.runs / "resumed/last.pt", weights_only=True)
    assert left["state"]["samples"] == right["state"]["samples"] == 24
    assert left["state"]["history"] == right["state"]["history"]
    for name, tensor in left["model"].items():
        torch.testing.assert_close(tensor, right["model"][name], rtol=0, atol=0)
    assert left["scheduler"] == right["scheduler"]
    assert full["test"] == resumed["test"]
    assert run_scratch(replace(interrupted, resume=True))["status"] == "complete"
    config.write_text(config.read_text() + "\n# changed\n")
    with pytest.raises(RandsTrainingError, match="config"):
        run_scratch(replace(interrupted, resume=True))


def test_exe_dataset_detects_changed_bytes_and_full_alphabet_handles_unseen_bytes(tmp_path: Path):
    data, config = fixture(tmp_path)
    prepare_exe(data, config)
    rows, _ = load_split(data, config)
    tokenizer = train_exe_bpe_tokenizer([b"ABC"], 272, full_byte_coverage=True)
    assert (
        tokenizer.token_to_id(SPECIAL_TOKENS["unk"]) not in tokenizer.encode(chr(10752 + 255)).ids
    )
    dataset = ExeDataset(data / "exe", rows, tokenizer, 16)
    path = data / "exe" / rows[0]["relative_path"]
    path.write_bytes(b"X" * int(rows[0]["size"]))
    with pytest.raises(RandsTrainingError, match="digest changed"):
        dataset[0]


def test_masked_hrr_logits_ignore_batch_padding():
    torch.manual_seed(0)
    model = HRRFormerForSequenceClassification(
        HRRFormerConfig(
            vocab_size=20,
            hidden_size=8,
            num_hidden_layers=2,
            num_attention_heads=2,
            max_position_embeddings=16,
            mask_padding=True,
        )
    ).eval()
    with torch.no_grad():
        plain = model(torch.tensor([[3, 8, 4]]), attention_mask=torch.ones(1, 3)).logits
        padded = model(
            torch.tensor([[3, 8, 4, 0, 0]]), attention_mask=torch.tensor([[1, 1, 1, 0, 0]])
        ).logits
    torch.testing.assert_close(plain, padded, atol=1e-6, rtol=1e-5)


def test_tied_score_metrics_do_not_depend_on_label_order():
    assert _rank_metrics([0.5, 0.5], [0, 1]) == _rank_metrics([0.5, 0.5], [1, 0]) == (0.5, 0.5)


def test_remote_snapshot_restore_and_failed_upload_keep_previous_pointer(
    tmp_path: Path, monkeypatch
):
    remote = tmp_path / "remote"

    def fake_aws(*args):
        assert args[:2] == ("s3", "cp")

        def path(value):
            return (
                remote / value.removeprefix("s3://") if value.startswith("s3://") else Path(value)
            )

        src, dst = path(args[2]), path(args[3])
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

    monkeypatch.setattr(scratch_storage, "aws", fake_aws)
    run = tmp_path / "local/trial"
    run.mkdir(parents=True)
    for name in ["last.pt", "tokenizer.json", "run-manifest.json"]:
        (run / name).write_bytes(b"synthetic checkpoint " + name.encode())
    prefix = "s3://synthetic-bucket/experiments"
    scratch_storage.publish(run, prefix)
    pointer = remote / "synthetic-bucket/experiments/trial/latest.json"
    previous = pointer.read_bytes()

    def fail_upload(*args):
        raise RandsTrainingError("synthetic upload failure")

    monkeypatch.setattr(scratch_storage, "aws", fail_upload)
    (run / "last.pt").write_bytes(b"new checkpoint")
    with pytest.raises(RandsTrainingError):
        scratch_storage.publish(run, prefix)
    assert pointer.read_bytes() == previous
    monkeypatch.setattr(scratch_storage, "aws", fake_aws)
    restored = tmp_path / "another/trial"
    scratch_storage.restore(restored, prefix)
    assert (restored / "last.pt").read_bytes() == b"synthetic checkpoint last.pt"
    assert (restored / "run-manifest.json").read_bytes() == (
        run / "run-manifest.json"
    ).read_bytes()


def test_remote_training_resume_rebuilds_cache_and_completes(tmp_path: Path, monkeypatch):
    data, config = fixture(tmp_path)
    prepare_exe(data, config)
    remote = tmp_path / "fake-s3"

    def fake_aws(*args):
        def path(value):
            return (
                remote / value.removeprefix("s3://") if value.startswith("s3://") else Path(value)
            )

        source, destination = path(args[2]), path(args[3])
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)

    monkeypatch.setattr(scratch_storage, "aws", fake_aws)
    request = ScratchRequest(
        config,
        data,
        tmp_path / "machine-a",
        "remote-run",
        device="cpu",
        max_steps=1,
        s3_prefix="s3://synthetic/experiments",
    )
    assert run_scratch(request)["status"] == "stopped"
    restored = replace(request, runs=tmp_path / "machine-b", resume=True, max_steps=None)
    assert run_scratch(restored)["status"] == "complete"
    assert (restored.runs / "remote-run/cache/train.tokens").is_file()
    pointer = json.loads((remote / "synthetic/experiments/remote-run/latest.json").read_text())
    assert "completed.json" in pointer["files"]
    assert not any("cache" in name for name in pointer["files"])


def test_sigterm_stops_at_optimizer_boundary_and_cache_corruption_rejected(
    tmp_path: Path, monkeypatch
):
    import signal

    from malweave.training import scratch as module

    data, config = fixture(tmp_path)
    prepare_exe(data, config)
    original = module._model

    def model_with_signal(*args):
        model = original(*args)
        forward = model.forward
        sent = False

        def wrapped(*args, **kwargs):
            nonlocal sent
            if not sent:
                sent = True
                signal.raise_signal(signal.SIGTERM)
            return forward(*args, **kwargs)

        model.forward = wrapped
        return model

    monkeypatch.setattr(module, "_model", model_with_signal)
    request = ScratchRequest(config, data, tmp_path / "runs", "signal", device="cpu")
    result = run_scratch(request)
    assert result["status"] == "stopped"
    assert result["samples"] == 9
    checkpoint = torch.load(request.runs / "signal/last.pt", weights_only=True)
    assert checkpoint["state"]["next_batch"] == 3
    cache = request.runs / "signal/cache/train.tokens"
    payload = cache.read_bytes()
    cache.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
    monkeypatch.setattr(module, "_model", original)
    with pytest.raises(RandsTrainingError, match="Token cache changed"):
        run_scratch(replace(request, resume=True))
