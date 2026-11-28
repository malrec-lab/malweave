"""Load the released EXE detector intact for A; no head initialization or training.

Tensor aliases, linear head and last pooling follow RawByteClf revision
2502450e40ac00363e168106662aac29821d4a93, architectures/mamba_hf.py and head_utils.py.
"""

from dataclasses import fields
import json
from pathlib import Path

from safetensors import SafetensorError, safe_open
import torch

from malweave.data.lmlm_inputs import ReleasedExeTokenizer
from malweave.models.mamba import MambaConfig, MambaForSequenceClassification
from malweave.training.contracts import SupervisedTrainingError
from malweave.training.lmlm_checkpoint import SOURCE_FILES, ReleasedBiMamba, file_sha256


def load_released_detector(
    root: Path, *, max_bytes: int = 65536, max_tokens: int = 65536
) -> ReleasedBiMamba:
    """Strictly preserve every backbone/head tensor; reject scratch and MLM artifacts."""
    try:
        root = root.expanduser().resolve()
        config = json.loads((root / "config.json").read_text())
        if not isinstance(config, dict):
            raise TypeError("Detector config must be a JSON object.")
        if (
            config.get("architectures") != ["MambaForSequenceClassification"]
            or config.get("model_type") != "mamba"
            or config.get("is_decoder", False)
            or config.get("bi_mix_directions", False)
            or config.get("bi_tie_directions", False)
            or not config.get("bi_add_directions", True)
            or config.get("head_num_hidden_layers", 0) != 0
            or config.get("head_hidden_size", 0) != 0
            or config.get("label2id") != {"ben": 0, "mal": 1}
            or config.get("id2label") != {"0": "ben", "1": "mal"}
        ):
            raise ValueError("Require the released untied BiMamba detector with ben=0, mal=1.")
        lineage = Path(config.get("_name_or_path") or "").parts
        if "checkpoint-799" not in lineage or "task--mlm" not in lineage:
            raise ValueError("Detector must declare initialization from the selected MLM-799.")
        for part in root.parts:
            if part.startswith("lift_level--") and part != "lift_level--raw":
                raise ValueError("Detector must use EXE, not a different representation.")
            if part.startswith("max_length--") and part != "max_length--65536":
                raise ValueError("Detector source context must be 65536.")
        if (
            type(max_tokens) is not int
            or type(max_bytes) is not int
            or not 2 <= max_tokens <= 65536
            or not 1 <= max_bytes <= 65536
        ):
            raise ValueError("A input limits cannot exceed the released 65536-byte/token context.")
        inputs = ReleasedExeTokenizer(root, config, max_tokens, max_bytes)
        accepted = {f.name for f in fields(MambaConfig)}
        values = {k: v for k, v in config.items() if k in accepted}
        values.update(num_labels=2, gradient_checkpointing=False)
        # Constructor RNG use must not leak to callers; all initialized tensors are overwritten.
        with torch.random.fork_rng(devices=[]):
            model = MambaForSequenceClassification(MambaConfig(**values))
        expected = model.state_dict()
        tensors = {}
        with safe_open(str(root / "model.safetensors"), framework="pt", device="cpu") as saved:
            keys = list(saved.keys())
            for key in keys:
                if key.startswith("backbone."):
                    name = key.removeprefix("backbone.")
                    if name == "embedding.weight":
                        name = "embeddings.weight"
                elif key in {"head_clf.final_layer.weight", "head_clf.final_layer.bias"}:
                    name = "classifier." + key.rsplit(".", 1)[1]
                else:
                    raise ValueError(f"Unexpected detector tensor namespace: {key}.")
                tensor = saved.get_tensor(key)
                if (
                    name not in expected
                    or name in tensors
                    or tensor.shape != expected[name].shape
                    or tensor.dtype != torch.float32
                    or not torch.isfinite(tensor).all().item()
                ):
                    raise ValueError(f"Invalid, duplicate, non-FP32 or nonfinite tensor: {key}.")
                tensors[name] = tensor
        if set(tensors) != set(expected):
            raise ValueError("Detector is incomplete; every backbone and head tensor is required.")
        model.load_state_dict(tensors, strict=True)
        model.requires_grad_(False)
        model.eval()
        trainer = root / "trainer_state.json"
        state = json.loads(trainer.read_text()) if trainer.exists() else {}
        provenance = {
            "initialization": "released EXE detector; original backbone and classification head",
            "source_config": config,
            "source_files_sha256": {name: file_sha256(root / name) for name in SOURCE_FILES},
            "backbone_tensors_loaded": sum(not k.startswith("classifier.") for k in tensors),
            "head_tensors_loaded": 2,
            "source_label2id": config["label2id"],
            "evaluation_label2id": {"benign": 0, "ransomware": 1},
            "max_bytes": max_bytes,
            "max_tokens": max_tokens,
            "source_best_checkpoint": Path(state.get("best_model_checkpoint") or "").name,
            "source_global_step": state.get("global_step"),
            "source_trainer_state_sha256": file_sha256(trainer) if trainer.exists() else None,
            "limitation": "Published detector 1923; not a claim to recover missing best 768.",
        }
        return ReleasedBiMamba(model, inputs, provenance)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, SafetensorError) as error:
        raise SupervisedTrainingError(f"Released detector rejected: {error}") from error
