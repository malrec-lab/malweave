"""Original MalConvGCT implementation under the approved RanDS E1 protocol.

The original training script uses low_mem=False and a fixed PAD embedding.
AdamW/weight decay, the 15-epoch cap and ROC-AUC selection are explicit RanDS
adaptations; this is not a claim to reproduce every original paper setting.
"""

import math

from malweave.data.malconv_inputs import E1_ENCODING
from malweave.training.contracts import SupervisedTrainingError


def validate_e1_config(config, request):
    try:
        architecture = config["tracks"]["malconvgct"]["architecture"]
        training = config["tracks"]["malconvgct"]["training"]
        raw = config["inputs"]["raw"]
        policy = config["supervision"]
        if (
            request.track != "malconvgct"
            or request.checkpoint_path is not None
            or "finetuning" in config
            or config["experiment"]["dataset"] != "rands"
        ):
            raise ValueError("E1 requires random-init RanDS MalConvGCT without a checkpoint.")
        if raw != {"max_bytes": None, "encoding": E1_ENCODING}:
            raise ValueError("E1 requires the entire original input, byte+1, no BOS/EOS.")
        if (
            architecture["implementation"] != "original"
            or architecture["vocab_size"] != 257
            or architecture["pad_token_id"] != 0
            or architecture["num_labels"] != 2
        ):
            raise ValueError("E1 requires original context/PAD behavior and 257 embeddings.")
        if policy["selection"] != {"checkpoint": "validation_roc_auc", "threshold": "argmax"}:
            raise ValueError("E1 requires the shared RanDS validation ROC-AUC/argmax policy.")
        if policy["early_stopping"] != {"patience": 3, "min_delta": 0}:
            raise ValueError("E1 requires patience=3, min_delta=0.")
        bootstrap = policy["bootstrap"]
        if bootstrap["confidence"] != 0.95 or bootstrap["seed"] != 0:
            raise ValueError("E1 requires 95% stratified bootstrap, seed 0.")
        for value in (
            training["epochs"],
            training["batch_size"],
            training["effective_batch_size"],
            bootstrap["replicates"],
        ):
            if type(value) is not int or value < 1:
                raise ValueError("Epoch, batch and bootstrap settings must be positive integers.")
        if training["epochs"] > 15 or training["precision"] != "fp32":
            raise ValueError("E1 requires FP32 and at most 15 epochs.")
        if (
            training["batch_size"] * request.gradient_accumulation_steps
            != training["effective_batch_size"]
        ):
            raise ValueError("microbatch × accumulation must match effective_batch_size.")
        optimizer = training["optimizer"]
        scheduler = training["scheduler"]
        if scheduler != {"type": "constant", "warmup_ratio": 0.0, "max_grad_norm": None}:
            raise ValueError("E1 requires fixed LR without warmup, decay or gradient clipping.")
        lr, wd = float(optimizer["learning_rate"]), float(optimizer["weight_decay"])
        if not math.isfinite(lr) or not math.isfinite(wd) or lr <= 0 or wd < 0:
            raise ValueError("Invalid E1 optimizer.")
        if config["experiment"]["kind"] == "benchmark":
            expected = {
                "implementation": "original",
                "vocab_size": 257,
                "embedding_size": 8,
                "channels": 256,
                "kernel_size": 256,
                "stride": 64,
                "layers": 1,
                "pad_token_id": 0,
                "num_labels": 2,
                "chunk_size": 65536,
                "min_chunk_size": 1024,
            }
            if architecture != expected:
                raise ValueError("E1 benchmark requires the approved original architecture.")
            if (
                training["epochs"] != 15
                or training["effective_batch_size"] != 128
                or request.seed != 0
                or lr != 0.001
                or wd != 0.01
                or optimizer["betas"] != [0.9, 0.999]
                or optimizer["epsilon"] != 1e-8
                or bootstrap["replicates"] != 2000
            ):
                raise ValueError("E1 benchmark differs from the approved RanDS protocol.")
        return policy
    except (KeyError, TypeError, ValueError) as error:
        raise SupervisedTrainingError(f"Invalid explicit E1 config: {error}") from error
