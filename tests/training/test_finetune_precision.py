"""Synthetic AMP step/resume tests; CPU scaling exercises overflow bookkeeping."""

import pytest
import torch
import yaml

from malweave.config import PROJECT_ROOT
from malweave.training.contracts import SupervisedTrainingError
from malweave.training.finetune_state import (
    mixed_precision_context,
    save_training_state,
    scaled_optimizer_step,
    state_recalls,
)
from malweave.training.supervised import _validate_transfer_config


def ratio_config():
    config = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-c.yaml").read_text())
    config["experiment"].update(dataset="vera_assemblage", protocol="vera_active_latent_ratios")
    config["finetuning"]["initialization"] = "original_mlm"
    config["finetuning"]["bootstrap"]["seed"] = 2026
    config["tracks"]["mamba"]["training"].update(precision="fp16", effective_batch_size=64)
    config["cohort"] = {
        "deduplication": "exact_model_tokens_after_full_exe",
        "split_method": "stratified_group_disjoint_non_temporal",
        "active_percentage": 30,
        "approval_status": "approved_frozen",
        "final_training_authorized": False,
    }
    return config


def test_ratio_benchmark_requires_final_authorization():
    config = ratio_config()
    with pytest.raises(SupervisedTrainingError, match="final training authorization"):
        _validate_transfer_config(config)
    config["cohort"]["final_training_authorized"] = True
    assert _validate_transfer_config(config)["initialization"] == "original_mlm"


def test_ratio_requires_approved_bootstrap_seed():
    config = ratio_config()
    config["experiment"]["kind"] = "feasibility"
    config["finetuning"]["bootstrap"]["seed"] = 0
    with pytest.raises(SupervisedTrainingError, match="seed 2026"):
        _validate_transfer_config(config)


@pytest.mark.parametrize("fault", ["parent", "precision", "ratio", "epochs"])
def test_ratio_protocol_rejects_obsolete_settings(fault):
    config = ratio_config()
    config["experiment"]["kind"] = "feasibility"
    if fault == "parent":
        config["finetuning"]["initialization"] = "completed_finetuning_run"
    elif fault == "precision":
        config["tracks"]["mamba"]["training"]["precision"] = "bf16"
    elif fault == "ratio":
        config["cohort"]["active_percentage"] = 20
    else:
        config["tracks"]["mamba"]["training"]["epochs"] = 6
    with pytest.raises(SupervisedTrainingError, match="Ratio study"):
        _validate_transfer_config(config)


def setup_step():
    model = torch.nn.Linear(2, 1)
    optimizer = torch.optim.SGD(model.parameters(), lr=0.1)
    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lambda step: 1 / (step + 1))
    scaler = torch.amp.GradScaler("cpu", init_scale=16, growth_interval=2)
    return model, optimizer, scheduler, scaler


def test_explicit_active_latent_recalls_and_class_validation():
    metrics = state_recalls(["Active", "Active", "Latent", "benign"], [1, 1, 1, 0], [1, 0, 1, 0])
    assert metrics["Active"] == {"support": 2, "detected": 1, "recall": 0.5}
    assert metrics["Latent"]["recall"] == 1.0
    assert state_recalls(["benign"], [0], [0])["Active"]["recall"] is None
    with pytest.raises(SupervisedTrainingError, match="class/state"):
        state_recalls(["Active"], [0], [0])
    with pytest.raises(SupervisedTrainingError, match="lengths"):
        state_recalls(["Active"], [], [])


def test_fp16_rejects_cpu_and_unknown_precision():
    with pytest.raises(SupervisedTrainingError, match="CUDA"):
        mixed_precision_context(torch.device("cpu"), "fp16")
    with pytest.raises(SupervisedTrainingError, match="Unsupported precision"):
        mixed_precision_context(torch.device("cpu"), "int8")


def test_overflow_skips_optimizer_and_scheduler_then_recovers():
    model, optimizer, scheduler, scaler = setup_step()
    before = model.weight.detach().clone()
    scaler.scale(model(torch.ones(1, 2)).sum()).backward()
    model.weight.grad.fill_(float("inf"))
    epoch = scheduler.last_epoch
    assert not scaled_optimizer_step(model, optimizer, scheduler, scaler, 1.0)
    assert scaler.get_scale() == 8
    assert scheduler.last_epoch == epoch
    torch.testing.assert_close(model.weight, before, rtol=0, atol=0)
    assert all(p.grad is None for p in model.parameters())
    scaler.scale(model(torch.ones(1, 2)).sum()).backward()
    assert scaled_optimizer_step(model, optimizer, scheduler, scaler, 1.0)
    assert scheduler.last_epoch == epoch + 1
    assert not torch.equal(model.weight, before)


def test_scaler_resume_matches_uninterrupted_step(tmp_path):
    model, optimizer, scheduler, scaler = setup_step()
    scaler.scale(model(torch.ones(1, 2)).sum()).backward()
    scaled_optimizer_step(model, optimizer, scheduler, scaler, 0.5)
    path = tmp_path / "last.pt"
    save_training_state(path, model, optimizer, scheduler, {"grad_scaler": scaler.state_dict()})
    restored = torch.load(path, weights_only=True)
    m2, o2, s2, g2 = setup_step()
    m2.load_state_dict(restored["model"])
    o2.load_state_dict(restored["optimizer"])
    s2.load_state_dict(restored["scheduler"])
    g2.load_state_dict(restored["grad_scaler"])
    for m, o, s, g in ((model, optimizer, scheduler, scaler), (m2, o2, s2, g2)):
        g.scale(m(torch.ones(1, 2)).sum()).backward()
        assert scaled_optimizer_step(m, o, s, g, 0.5)
    torch.testing.assert_close(model.weight, m2.weight, rtol=0, atol=0)
    assert scaler.state_dict() == g2.state_dict()
    assert scheduler.state_dict() == s2.state_dict()


def test_unscaled_nonfinite_gradients_fail_closed():
    model, optimizer, scheduler, _ = setup_step()
    model(torch.ones(1, 2)).sum().backward()
    model.weight.grad.fill_(float("nan"))
    with pytest.raises(SupervisedTrainingError, match="Nonfinite gradients"):
        scaled_optimizer_step(
            model, optimizer, scheduler, torch.amp.GradScaler("cpu", enabled=False), 1.0
        )


@pytest.mark.skipif(not torch.cuda.is_available(), reason="Requires CUDA FP16 hardware")
def test_cuda_fp16_autocast_and_scaled_step():
    device = torch.device("cuda")
    model = torch.nn.Linear(2, 1).to(device)
    optimizer = torch.optim.SGD(model.parameters(), lr=0.1)
    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lambda _: 1.0)
    scaler = torch.amp.GradScaler("cuda", init_scale=16)
    before = model.weight.detach().clone()
    with mixed_precision_context(device, "fp16"):
        output = model(torch.ones(2, 2, device=device))
        assert output.dtype == torch.float16
        loss = output.float().square().mean()
    scaler.scale(loss).backward()
    assert scaled_optimizer_step(model, optimizer, scheduler, scaler, 1.0)
    assert not torch.equal(model.weight, before)
