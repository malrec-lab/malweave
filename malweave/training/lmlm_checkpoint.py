"""Strict EXE BiMamba MLM transfer loader; never executes checkpoint code or pickle.

Backbone naming and head initialization follow RawByteClf revision
2502450e40ac00363e168106662aac29821d4a93 (MIT), src/architectures/mamba_hf.py
and src/learn/train.py. This is an explicit adapter, not AutoModel remote code.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from hashlib import sha256
import json
import math
from pathlib import Path
from typing import Any

from safetensors import SafetensorError, safe_open
import torch

from malweave.data.lmlm_inputs import ReleasedExeTokenizer
from malweave.models.mamba import MambaConfig, MambaForSequenceClassification
from malweave.training.contracts import SupervisedTrainingError

SOURCE_FILES = (
    "config.json",
    "model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
)


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass
class ReleasedBiMamba:
    model: MambaForSequenceClassification
    inputs: ReleasedExeTokenizer
    provenance: dict[str, Any]


def load_released_bimamba(
    root: Path,
    *,
    representation: str,
    max_tokens: int,
    source_context: int,
    gradient_checkpointing: bool,
    head_initialization: str,
    max_bytes: int = 65536,
) -> ReleasedBiMamba:
    """Load every backbone tensor, discard only the MLM head, initialize two-class head.

    Architecture dimensions come from the checkpoint, including its padded vocabulary.
    Context and representation are explicit researcher assertions, checked against path
    metadata when available. No missing-backbone or unsupported-mode fallback is allowed.
    """
    try:
        if representation != "exe":
            raise ValueError("This loader supports EXE checkpoints only.")
        if type(source_context) is not int or not 2 <= max_tokens <= source_context:
            raise ValueError("Require 2 <= max_tokens <= declared source_context.")
        if type(gradient_checkpointing) is not bool:
            raise ValueError("gradient_checkpointing must be explicitly true or false.")
        if head_initialization != "upstream_normal":
            raise ValueError("Supported head initialization: upstream_normal.")
        root = root.expanduser().resolve()
        for name in SOURCE_FILES:
            if not (root / name).is_file():
                raise ValueError(f"Checkpoint is incomplete: missing {name}.")
        for part in root.parts:
            if part.startswith("lift_level--") and part != "lift_level--raw":
                raise ValueError("Checkpoint path is not EXE (lift_level--raw).")
            if part.startswith("task--") and part != "task--mlm":
                raise ValueError("Expected an MLM checkpoint, not a classifier or CLM.")
            if part.startswith("max_length--") and part != f"max_length--{source_context}":
                raise ValueError("Declared source_context disagrees with checkpoint path.")
        config = json.loads((root / "config.json").read_text())
        if not isinstance(config, dict):
            raise TypeError("Checkpoint config must be a JSON object.")
        if (
            config.get("model_type") != "mamba"
            or config.get("architectures") != ["MambaForMaskedLM"]
            or config.get("is_decoder", False)
        ):
            raise ValueError("Only released bidirectional MambaForMaskedLM is supported.")
        if config.get("bi_mix_directions") or config.get("bi_tie_directions"):
            raise ValueError(
                "Mixed or tied directional checkpoints are not supported by this loader."
            )
        required = {"vocab_size", "hidden_size", "num_hidden_layers", "initializer_range"}
        if not required <= config.keys():
            raise ValueError("Checkpoint config lacks required architecture fields.")
        for name in ("vocab_size", "hidden_size", "num_hidden_layers"):
            if type(config[name]) is not int or config[name] <= 0:
                raise ValueError(f"Invalid checkpoint dimension: {name}.")
        std = float(config["initializer_range"])
        if not math.isfinite(std) or std <= 0:
            raise ValueError("Checkpoint initializer_range must be finite and positive.")
        inputs = ReleasedExeTokenizer(root, config, max_tokens, max_bytes)
        accepted = {field.name for field in fields(MambaConfig)}
        values = {key: value for key, value in config.items() if key in accepted}
        values.update(num_labels=2, gradient_checkpointing=gradient_checkpointing)
        with safe_open(str(root / "model.safetensors"), framework="pt", device="cpu") as saved:
            keys = list(saved.keys())
            if not any(key.startswith("head_mlm.") for key in keys):
                raise ValueError(
                    "Checkpoint has no MLM head; initialization lineage is ambiguous."
                )
            if any(not key.startswith(("backbone.", "head_mlm.")) for key in keys):
                raise ValueError("Unexpected tensor namespace in released MLM checkpoint.")
            model = MambaForSequenceClassification(MambaConfig(**values))
            expected = {
                key: value
                for key, value in model.state_dict().items()
                if not key.startswith("classifier.")
            }
            mapping = {}
            for key in keys:
                if key.startswith("backbone."):
                    name = key.removeprefix("backbone.")
                    if name == "embedding.weight":
                        name = "embeddings.weight"  # RawByteClf's legacy load hook.
                    if name in mapping:
                        raise ValueError("Duplicate backbone tensor alias.")
                    mapping[name] = key
            if set(mapping) != set(expected):
                missing = sorted(set(expected) - set(mapping))
                unexpected = sorted(set(mapping) - set(expected))
                raise ValueError(
                    f"Backbone keys mismatch: missing={missing}, unexpected={unexpected}."
                )
            tensors = {}
            inverse_mapping = {source: name for name, source in mapping.items()}
            for key in keys:
                tensor = saved.get_tensor(key)
                if not torch.isfinite(tensor).all().item():
                    raise ValueError(f"Nonfinite checkpoint tensor: {key}.")
                if key.startswith("backbone."):
                    name = inverse_mapping[key]
                    if tensor.shape != expected[name].shape:
                        raise ValueError(f"Backbone tensor shape mismatch: {name}.")
                    tensors[name] = tensor
            incompatible = model.load_state_dict(tensors, strict=False)
            if (
                set(incompatible.missing_keys) != {"classifier.weight", "classifier.bias"}
                or incompatible.unexpected_keys
            ):
                raise ValueError(
                    "Incomplete backbone load; refusing to train random backbone weights."
                )
        with torch.no_grad():
            model.classifier.weight.normal_(mean=0.0, std=std)
            model.classifier.bias.zero_()
        provenance = {
            "initialization": "released EXE BiMamba MLM backbone; fresh binary classification head",
            "source_files_sha256": {name: file_sha256(root / name) for name in SOURCE_FILES},
            "source_config": config,
            "source_context": source_context,
            "max_tokens": max_tokens,
            "max_bytes": max_bytes,
            "byte_mapping": "contiguous chr(byte + 10752); released tokenizer postprocessor",
            "backbone_tensors_loaded": len(tensors),
            "discarded_mlm_head_tensors": sum(key.startswith("head_mlm.") for key in keys),
            "head": {"type": "linear", "initialization": head_initialization, "std": std},
            "label2id": {"benign": 0, "ransomware": 1},
        }
        return ReleasedBiMamba(model, inputs, provenance)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, SafetensorError) as error:
        raise SupervisedTrainingError(f"Released checkpoint rejected: {error}") from error


def load_finetuned_bimamba_for_transfer(
    root: Path,
    *,
    max_bytes: int,
    max_tokens: int,
    source_context: int,
    gradient_checkpointing: bool,
) -> ReleasedBiMamba:
    """Initialize a new run from a verified classifier, never its optimizer state."""
    loaded = load_finetuned_bimamba(root)
    config = loaded.provenance["source_config"]
    if (
        max_bytes != loaded.inputs.max_bytes
        or max_tokens != loaded.inputs.max_tokens
        or source_context != loaded.provenance["source_context"]
        or config.get("is_decoder", False)
        or config.get("bi_mix_directions", False)
    ):
        raise SupervisedTrainingError("Parent input/architecture contract must be preserved.")
    parent = json.loads((root / "run-manifest.json").read_text())
    loaded.model.config.gradient_checkpointing = gradient_checkpointing
    loaded.model.train()
    loaded.provenance = {
        **loaded.provenance,
        "initialization_kind": "completed_finetuning_run",
        "parent_run_manifest_sha256": file_sha256(root / "run-manifest.json"),
        "parent_artifact_files_sha256": parent["artifact_files_sha256"],
        "parent_run_id": parent["run_id"],
        "classification_head": "preserved_parent",
        "optimizer_state": "fresh",
    }
    return loaded


def load_finetuned_bimamba(root: Path) -> ReleasedBiMamba:
    """Reload a completed MalWeave run without the author's original artifact folder."""
    try:
        manifest = json.loads((root / "run-manifest.json").read_text())
        if manifest["status"] != "completed" or not manifest["finetuning"]:
            raise ValueError("Expected a completed released-checkpoint fine-tuning run.")
        expected_names = {
            "model.safetensors",
            "tokenizer.json",
            "tokenizer_config.json",
            "special_tokens_map.json",
        }
        digests = manifest["artifact_files_sha256"]
        if set(digests) != expected_names or any(
            file_sha256(root / name) != digests[name] for name in expected_names
        ):
            raise ValueError("Fine-tuned artifact digest mismatch.")
        provenance = manifest["initialization"]
        config = provenance["source_config"]
        accepted = {field.name for field in fields(MambaConfig)}
        values = {key: value for key, value in config.items() if key in accepted}
        values.update(num_labels=2, gradient_checkpointing=False)
        model = MambaForSequenceClassification(MambaConfig(**values))
        from safetensors.torch import load_file

        saved = load_file(str(root / "model.safetensors"))
        if any(not torch.isfinite(tensor).all().item() for tensor in saved.values()):
            raise ValueError("Nonfinite fine-tuned weights.")
        model.load_state_dict(saved, strict=True)
        model.eval()
        return ReleasedBiMamba(
            model,
            ReleasedExeTokenizer(root, config, provenance["max_tokens"], provenance["max_bytes"]),
            provenance,
        )
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as error:
        raise SupervisedTrainingError(f"Fine-tuned run rejected: {error}") from error
