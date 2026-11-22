"""Atomic local training state and the approved class-stratified ROC-AUC interval."""

import json
from pathlib import Path
import random

import torch

from malweave.training.contracts import SupervisedTrainingError


def mixed_precision_context(device, precision):
    """FP16 is CUDA-only; do not silently fall back to full precision."""
    if precision not in {"fp32", "bf16", "fp16"}:
        raise SupervisedTrainingError(f"Unsupported precision: {precision}.")
    if precision == "fp16" and device.type != "cuda":
        raise SupervisedTrainingError("fp16 requires a CUDA device.")
    return torch.autocast(
        device_type=device.type,
        dtype=torch.float16 if precision == "fp16" else torch.bfloat16,
        enabled=precision != "fp32",
    )


def scaled_optimizer_step(model, optimizer, scheduler, scaler, max_grad_norm):
    """Unscale before clipping; overflow consumes a batch but not an LR update."""
    scaler.unscale_(optimizer)
    finite = all(
        parameter.grad is None or torch.isfinite(parameter.grad).all().item()
        for parameter in model.parameters()
    )
    if not finite and not scaler.is_enabled():
        raise SupervisedTrainingError("Nonfinite gradients; aborting run.")
    if finite and max_grad_norm is not None:
        norm = torch.nn.utils.clip_grad_norm_(model.parameters(), float(max_grad_norm))
        if not torch.isfinite(norm).item():
            raise SupervisedTrainingError("Nonfinite gradient norm; aborting run.")
    previous_scale = scaler.get_scale()
    scaler.step(optimizer)
    scaler.update()
    stepped = scaler.get_scale() >= previous_scale
    if stepped:
        scheduler.step()
    optimizer.zero_grad()
    return stepped


def write_json(path: Path, value) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def save_training_state(path, model, optimizer, scheduler, state) -> None:
    state = {
        **state,
        "model": model.state_dict(),
        "optimizer": optimizer.state_dict(),
        "scheduler": scheduler.state_dict(),
        "torch_rng": torch.get_rng_state(),
        "python_rng": random.getstate(),
        "cuda_rng": torch.cuda.get_rng_state_all() if torch.cuda.is_available() else [],
    }
    temporary = path.with_suffix(".tmp")
    torch.save(state, temporary)
    temporary.replace(path)


def restore_rng(state) -> None:
    torch.set_rng_state(state["torch_rng"])
    random.setstate(state["python_rng"])
    if state["cuda_rng"]:
        torch.cuda.set_rng_state_all(state["cuda_rng"])


def state_recalls(states, labels, predictions):
    """Report explicit ransomware strata with support; never infer state from family."""
    if not len(states) == len(labels) == len(predictions):
        raise SupervisedTrainingError("State evaluation lengths do not match.")
    counts = {state: {"support": 0, "detected": 0} for state in ("Active", "Latent")}
    for state, label, prediction in zip(states, labels, predictions, strict=True):
        if state not in {"Active", "Latent", "benign"} or label != int(state != "benign"):
            raise SupervisedTrainingError("Invalid class/state evaluation membership.")
        if state != "benign":
            counts[state]["support"] += 1
            counts[state]["detected"] += int(prediction == 1)
    return {
        state: {**row, "recall": row["detected"] / row["support"] if row["support"] else None}
        for state, row in counts.items()
    }


def test_statistics(probabilities, labels, policy):
    import numpy as np
    from sklearn.metrics import average_precision_score, roc_auc_score

    labels = np.asarray(labels)
    probabilities = np.asarray(probabilities)
    positive = np.flatnonzero(labels == 1)
    negative = np.flatnonzero(labels == 0)
    rng = np.random.default_rng(policy["seed"])
    values = []
    for _ in range(policy["replicates"]):
        indices = np.concatenate(
            (
                rng.choice(negative, len(negative), replace=True),
                rng.choice(positive, len(positive), replace=True),
            )
        )
        values.append(roc_auc_score(labels[indices], probabilities[indices]))
    low, high = np.percentile(values, [2.5, 97.5])
    return {
        "average_precision": float(average_precision_score(labels, probabilities)),
        "roc_auc_ci": {
            "confidence": policy["confidence"],
            "lower": float(low),
            "upper": float(high),
            "replicates": policy["replicates"],
            "seed": policy["seed"],
            "method": "class-stratified percentile bootstrap",
        },
    }
