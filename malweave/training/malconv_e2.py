"""Explicit E2 protocol validation; separate from the active C configuration."""

from __future__ import annotations

from hashlib import sha256
import json
import math

from malweave.data.malconv_inputs import E2_ENCODING
from malweave.training.contracts import SupervisedTrainingError


def e2_optimizer_groups(model, weight_decay):
    """Match Transformers 4.47 Trainer: exclude bias and LayerNorm from decay.

    The pinned MalConvGCT architecture contains no LayerNorm modules. Its only
    no-decay parameters are biases; embeddings and convolution/linear weights decay.
    """
    return [
        {
            "params": [
                p
                for name, p in model.named_parameters()
                if p.requires_grad and ("bias" in name) == no_decay
            ],
            "weight_decay": 0.0 if no_decay else weight_decay,
        }
        for no_decay in (False, True)
    ]


def validate_e2_config(config, request):
    try:
        raw = config["inputs"]["raw"]
        training = config["tracks"]["malconvgct"]["training"]
        architecture = config["tracks"]["malconvgct"]["architecture"]
        policy = config["supervision"]
        if request.track != "malconvgct" or request.checkpoint_path is not None:
            raise ValueError("E2 requires random-init malconvgct without --checkpoint.")
        if "finetuning" in config or config["experiment"]["dataset"] != "rands":
            raise ValueError("E2 is a RanDS supervised baseline, not fine-tuning.")
        if raw["encoding"] != E2_ENCODING or architecture["vocab_size"] != 264:
            raise ValueError("E2 requires byte+7, BOS=3, EOS=4, PAD=0 and 264 embedding rows.")
        if architecture["pad_token_id"] != 0 or architecture["num_labels"] != 2:
            raise ValueError("E2 requires PAD=0 and two labels.")
        if architecture["implementation"] != "lmlm":
            raise ValueError("E2 requires the lmlm source implementation.")
        if policy["selection"] != {"checkpoint": "validation_roc_auc", "threshold": "argmax"}:
            raise ValueError("E2 requires validation ROC-AUC and source argmax decisions.")
        if policy["early_stopping"] != {"patience": 3, "min_delta": 0}:
            raise ValueError("E2 requires early stopping patience=3, min_delta=0.")
        bootstrap = policy["bootstrap"]
        if bootstrap["confidence"] != 0.95 or bootstrap["seed"] != 0:
            raise ValueError("Require 95% stratified bootstrap, seed 0.")
        for value in (
            training["epochs"],
            training["batch_size"],
            training["effective_batch_size"],
            bootstrap["replicates"],
        ):
            if type(value) is not int or value < 1:
                raise ValueError("Epoch, batch and bootstrap settings must be positive integers.")
        if type(raw["max_tokens"]) is not int or raw["max_tokens"] < 2:
            raise ValueError("E2 max_tokens includes BOS/EOS and must be at least two.")
        if training["epochs"] > 15 or training["precision"] != "fp32":
            raise ValueError("E2 requires FP32 and at most 15 epochs.")
        if (
            training["batch_size"] * request.gradient_accumulation_steps
            != training["effective_batch_size"]
        ):
            raise ValueError("microbatch × accumulation must match effective_batch_size.")
        optimizer, scheduler = training["optimizer"], training["scheduler"]
        numbers = [
            float(optimizer["learning_rate"]),
            float(optimizer["weight_decay"]),
            float(scheduler["warmup_ratio"]),
            float(scheduler["max_grad_norm"]),
        ]
        if (
            not all(math.isfinite(v) for v in numbers)
            or numbers[0] <= 0
            or numbers[1] < 0
            or not 0 <= numbers[2] < 1
            or numbers[3] <= 0
            or scheduler["type"] != "linear"
        ):
            raise ValueError("Invalid E2 optimizer/scheduler settings.")
        if config["experiment"]["kind"] == "benchmark":
            expected = {
                "implementation": "lmlm",
                "embedding_size": 8,
                "channels": 256,
                "kernel_size": 64,
                "stride": 64,
                "layers": 1,
                "vocab_size": 264,
                "pad_token_id": 0,
                "num_labels": 2,
                "chunk_size": 65536,
                "min_chunk_size": 1024,
            }
            if architecture != expected or raw["max_tokens"] != 1048576:
                raise ValueError(
                    "Benchmark requires the approved E2 architecture and 1 Mi token limit."
                )
            if (
                training["epochs"] != 15
                or training["batch_size"] != 64
                or training["effective_batch_size"] != 64
                or request.gradient_accumulation_steps != 1
                or request.seed != 0
            ):
                raise ValueError(
                    "Benchmark requires 15 planned epochs, batch 64, accumulation 1 and seed 0."
                )
            if (
                numbers != [0.001, 0.01, 0.05, 1.0]
                or optimizer["betas"] != [0.9, 0.999]
                or optimizer["epsilon"] != 1e-8
                or bootstrap["replicates"] != 2000
            ):
                raise ValueError(
                    "Benchmark optimizer, scheduler or bootstrap differs from approved E2."
                )
        return policy
    except (KeyError, TypeError, ValueError) as error:
        raise SupervisedTrainingError(f"Invalid explicit E2 config: {error}") from error


def validate_e2_cohort(request, config):
    return validate_malconv_cohort(request, config)


def validate_malconv_cohort(request, config):
    """Bind both baselines to the frozen C cohort, independently of their RAW encoding."""
    if config["experiment"]["kind"] == "feasibility":
        return None
    try:
        path = request.split_manifest_path.parent / "summary.json"
        payload = path.read_bytes()
        summary = json.loads(payload)
        if (
            summary["policy"] != config["cohort"]
            or summary["policy"]["deduplication"] != "exact_model_tokens_after_full_exe"
            or summary["output_sha256"]["split.csv"]
            != sha256(request.split_manifest_path.read_bytes()).hexdigest()
            or not summary["model_input_audit"]["identity"]
        ):
            raise ValueError("Frozen round-02 summary/split identity mismatch.")
        return {
            "summary_sha256": sha256(payload).hexdigest(),
            "c_model_input_audit": summary["model_input_audit"],
        }
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise SupervisedTrainingError(
            "MalConv baselines require the unchanged frozen C cohort summary."
        ) from error
