"""Atomic local training state and the approved class-stratified ROC-AUC interval."""

import json
from pathlib import Path
import random

import torch


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
