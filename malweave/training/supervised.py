"""Private, reproducible supervised-training orchestration."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import csv
from dataclasses import dataclass
from functools import partial
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import random
import re
import shutil
import subprocess
import sys
import time
from typing import Any

import torch
from torch import Tensor, nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import LambdaLR
from torch.utils.data import DataLoader, Dataset
import yaml

from malweave.config import PROJECT_ROOT
from malweave.data.byte_inputs import (
    SPECIAL_TOKENS,
    LmlmInputError,
    collate_exe_tokens,
    collate_raw_byte_ids,
    encode_exe_tokens,
    raw_bytes_to_ids,
    train_exe_bpe_tokenizer,
    write_private_tokenizer,
)
from malweave.data.rands import SHA256_PATTERN
from malweave.experiments.rands_comparison import SPLIT_FIELDS
from malweave.models import (
    HRRFormerConfig,
    HRRFormerForSequenceClassification,
    MalConvGCTConfig,
    MalConvGCTForSequenceClassification,
    MambaConfig,
    MambaForSequenceClassification,
)
from malweave.training.contracts import SupervisedTrainingError, _private_path


@dataclass(frozen=True)
class SplitExample:
    split: str
    source_sha256: str
    label: int
    raw_relative_path: str
    exe_relative_path: str
    exe_representation_sha256: str
    family: str = ""
    year: int | None = None
    state: str = ""


@dataclass(frozen=True)
class SupervisedRunRequest:
    track: str
    config_path: Path
    split_manifest_path: Path
    raw_root: Path
    exe_root: Path
    artifact_root: Path
    run_id: str
    device: str
    gradient_accumulation_steps: int
    seed: int
    command: str | None = None
    raw_samples_dir: str = "dataset"
    checkpoint_path: Path | None = None
    resume: bool = False
    max_updates: int | None = None
    max_seconds: float | None = None


def _load_mapping(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise SupervisedTrainingError(f"Could not read experiment config: {path}") from error
    except yaml.YAMLError as error:
        raise SupervisedTrainingError(f"Invalid experiment YAML: {path}") from error
    if not isinstance(loaded, dict):
        raise SupervisedTrainingError("Experiment config must be a mapping.")
    return loaded


def _sha256_file(path: Path) -> str:
    try:
        return sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise SupervisedTrainingError(
            f"Could not read required private artifact: {path}"
        ) from error


def _validate_audited_cohort(request: SupervisedRunRequest, config: dict) -> dict | None:
    """Bind a token-deduplicated split to the actual checkpoint and preprocessing."""
    if (
        config.get("experiment", {}).get("dataset") == "vera_assemblage"
        and config.get("cohort", {}).get("deduplication") != "exact_model_tokens_after_full_exe"
    ):
        raise SupervisedTrainingError("VERA transfer requires a frozen exact-input cohort audit.")
    if config.get("cohort", {}).get("deduplication") != "exact_model_tokens_after_full_exe":
        return None
    try:
        summary_path = request.split_manifest_path.parent / "summary.json"
        summary = json.loads(summary_path.read_text())
        evidence = summary["model_input_audit"]
        identity = evidence["identity"]
        if (
            summary["policy"] != config["cohort"]
            or summary["output_sha256"]["split.csv"] != _sha256_file(request.split_manifest_path)
            or request.checkpoint_path is None
            or identity["tokenizer_sha256"]
            != _sha256_file(request.checkpoint_path / "tokenizer.json")
            or identity["checkpoint_config_sha256"]
            != _sha256_file(
                request.checkpoint_path
                / (
                    "run-manifest.json"
                    if config.get("finetuning", {}).get("initialization")
                    == "completed_finetuning_run"
                    else "config.json"
                )
            )
            or identity["production_adapter_sha256"]
            != _sha256_file(PROJECT_ROOT / "malweave/data/lmlm_inputs.py")
            or identity["max_bytes"] != config["inputs"]["exe"]["truncation"]["max_bytes"]
            or identity["max_tokens_including_bos_eos"]
            != config["inputs"]["exe"]["truncation"]["max_tokens"]
        ):
            raise SupervisedTrainingError(
                "Audited cohort does not match split/checkpoint/preprocessing."
            )
        return {"summary_sha256": _sha256_file(summary_path), **evidence}
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise SupervisedTrainingError("A matching audited cohort summary is required.") from error


def load_supervised_split(path: Path) -> list[SplitExample]:
    """Load the private split and reject malformed or duplicate source rows."""
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as error:
        raise SupervisedTrainingError(f"Could not read supervised split: {path}") from error
    labels = {"benign": 0, "ransomware": 1}
    with handle:
        reader = csv.DictReader(handle)
        missing = sorted(set(SPLIT_FIELDS) - set(reader.fieldnames or ()))
        if missing:
            raise SupervisedTrainingError(
                f"Split manifest is missing required fields: {', '.join(missing)}."
            )
        examples: list[SplitExample] = []
        sources: set[str] = set()
        representations: dict[str, tuple[str, str]] = {}
        input_groups: dict[str, tuple[str, str]] = {}
        for row_number, row in enumerate(reader, start=2):
            source = (row["source_sha256"] or "").lower()
            exe_digest = (row["exe_representation_sha256"] or "").lower()
            if (
                not SHA256_PATTERN.fullmatch(source)
                or not SHA256_PATTERN.fullmatch(exe_digest)
                or source in sources
            ):
                raise SupervisedTrainingError(
                    f"Invalid or duplicate source in split row {row_number}."
                )
            if row["split"] not in {"train", "validation", "test"} or row["label"] not in labels:
                raise SupervisedTrainingError(f"Invalid split or label in row {row_number}.")
            previous = representations.get(exe_digest)
            if previous is not None and previous != (row["split"], row["label"]):
                raise SupervisedTrainingError(
                    "The frozen split has EXE leakage across partitions or conflicting labels."
                )
            representations[exe_digest] = (row["split"], row["label"])
            group = (row["active_leakage_group_sha256"] or "").lower()
            if not SHA256_PATTERN.fullmatch(group):
                raise SupervisedTrainingError(f"Invalid active input group in row {row_number}.")
            if group in input_groups and input_groups[group] != (row["split"], row["label"]):
                raise SupervisedTrainingError(
                    "The frozen split has model-input leakage or conflicting labels."
                )
            input_groups[group] = (row["split"], row["label"])
            sources.add(source)
            examples.append(
                SplitExample(
                    split=row["split"],
                    source_sha256=source,
                    label=labels[row["label"]],
                    raw_relative_path=row["raw_relative_path"],
                    exe_relative_path=row["exe_relative_path"],
                    exe_representation_sha256=exe_digest,
                    family=row.get("family") or "",
                    year=int(row["year"]) if row.get("year") else None,
                    state=row.get("state") or "",
                )
            )
    return examples


def _binary_auc(probabilities: list[float], labels: list[int]) -> float | None:
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return None
    ranked = sorted(zip(probabilities, labels), key=lambda item: item[0])
    rank_sum = 0.0
    index = 0
    while index < len(ranked):
        end = index + 1
        while end < len(ranked) and ranked[end][0] == ranked[index][0]:
            end += 1
        mean_rank = (index + 1 + end) / 2
        rank_sum += mean_rank * sum(label for _, label in ranked[index:end])
        index = end
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def _pr_auc(probabilities: list[float], labels: list[int]) -> float | None:
    positives = sum(labels)
    if positives == 0:
        return None
    ordered = sorted(zip(probabilities, labels), key=lambda item: item[0], reverse=True)
    found = 0
    area = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        added = sum(label for _, label in ordered[index:end])
        found += added
        area += (added / positives) * found / end
        index = end
    return area


def _threshold_metrics(
    probabilities: list[float],
    labels: list[int],
    threshold: float,
    predictions: list[int] | None = None,
) -> dict[str, Any]:
    if predictions is None:
        predictions = [int(value >= threshold) for value in probabilities]
    true_positive = sum(prediction == label == 1 for prediction, label in zip(predictions, labels))
    true_negative = sum(prediction == label == 0 for prediction, label in zip(predictions, labels))
    false_positive = sum(
        prediction == 1 and label == 0 for prediction, label in zip(predictions, labels)
    )
    false_negative = sum(
        prediction == 0 and label == 1 for prediction, label in zip(predictions, labels)
    )
    total = len(labels)
    precision = (
        true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    )
    specificity = (
        true_negative / (true_negative + false_positive) if true_negative + false_positive else 0.0
    )
    return {
        "accuracy": (true_positive + true_negative) / total if total else None,
        "balanced_accuracy": (recall + specificity) / 2,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "confusion_matrix": [[true_negative, false_positive], [false_negative, true_positive]],
        "per_class": {
            "benign": {"support": true_negative + false_positive, "recall": specificity},
            "ransomware": {"support": true_positive + false_negative, "recall": recall},
        },
    }


def _select_threshold(probabilities: list[float], labels: list[int]) -> float:
    candidates = sorted({0.0, math.nextafter(max(probabilities), math.inf), *probabilities})
    return max(
        candidates,
        key=lambda value: (
            _threshold_metrics(probabilities, labels, value)["balanced_accuracy"],
            -value,
        ),
    )


class _SupervisedDataset(Dataset[tuple[Tensor, int]]):
    def __init__(
        self,
        examples: list[SplitExample],
        track: str,
        raw_root: Path,
        raw_samples_dir: str,
        exe_root: Path,
        tokenizer: Any | None,
        max_length: int | None,
        e2: bool = False,
        e1: bool = False,
    ) -> None:
        self.examples = examples
        self.track = track
        self.raw_root = raw_root
        self.raw_samples_dir = raw_samples_dir
        self.exe_root = exe_root
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.e2 = e2
        self.e1 = e1

    def __len__(self) -> int:
        return len(self.examples)

    def _content(self, example: SplitExample) -> bytes:
        if self.e2 or self.e1:
            from malweave.data.malconv_inputs import raw_sample_path, verified_prefix

            path = raw_sample_path(self.raw_root, self.raw_samples_dir, example.source_sha256)
            limit = None if self.e1 else self.max_length - 2
            return verified_prefix(path, example.source_sha256, limit)[0]
        if self.track == "malconvgct":
            path = (
                self.raw_root
                / self.raw_samples_dir
                / example.source_sha256[:2]
                / example.source_sha256
            )
        else:
            path = self.exe_root / example.exe_relative_path
            if not path.resolve().is_relative_to(self.exe_root.resolve()):
                raise SupervisedTrainingError("EXE path escapes its declared root.")
        try:
            if self.track != "malconvgct" and hasattr(self.tokenizer, "max_bytes"):
                digest = sha256()
                prefix = bytearray()
                with path.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                        remaining = self.tokenizer.max_bytes - len(prefix)
                        if remaining > 0:
                            prefix.extend(block[:remaining])
                content = bytes(prefix)
                actual_digest = digest.hexdigest()
            else:
                content = path.read_bytes()
                actual_digest = sha256(content).hexdigest()
        except OSError as error:
            raise SupervisedTrainingError(
                f"Could not read required representation for {self.track}."
            ) from error
        expected_digest = (
            example.source_sha256
            if self.track == "malconvgct"
            else example.exe_representation_sha256
        )
        if actual_digest != expected_digest:
            raise SupervisedTrainingError(
                f"Representation digest changed for {self.track}; aborting run."
            )
        return content

    def __getitem__(self, index: int) -> tuple[Tensor, int]:
        example = self.examples[index]
        content = self._content(example)
        if self.e1:
            from malweave.data.malconv_inputs import encode_e1_bytes

            return encode_e1_bytes(content), example.label
        if self.e2:
            from malweave.data.malconv_inputs import encode_e2_bytes

            return encode_e2_bytes(content, self.max_length), example.label
        if self.track == "malconvgct":
            return raw_bytes_to_ids(content, self.max_length), example.label
        assert self.tokenizer is not None
        if hasattr(self.tokenizer, "encode_bytes"):
            try:
                return self.tokenizer.encode_bytes(content), example.label
            except LmlmInputError as error:
                raise SupervisedTrainingError(f"Released EXE encoding failed: {error}") from error
        return encode_exe_tokens(self.tokenizer, content, self.max_length), example.label


def _partition(examples: Iterable[SplitExample], name: str) -> list[SplitExample]:
    selected = [example for example in examples if example.split == name]
    if not selected:
        raise SupervisedTrainingError(f"The frozen split has no {name} rows.")
    return selected


def _track_config(config: dict[str, Any], track: str) -> dict[str, Any]:
    try:
        track_config = config["tracks"][track]
    except (KeyError, TypeError) as error:
        raise SupervisedTrainingError(f"Unknown supervised track: {track}.") from error
    if not isinstance(track_config, dict):
        raise SupervisedTrainingError(f"tracks.{track} must be a mapping.")
    return track_config


def _build_model(
    config: dict[str, Any], track: str, tokenizer: Any | None
) -> tuple[nn.Module, int | None, bool]:
    track_config = _track_config(config, track)
    architecture = track_config.get("architecture")
    if not isinstance(architecture, dict):
        raise SupervisedTrainingError(f"tracks.{track}.architecture must be a mapping.")
    if track == "malconvgct":
        raw = config["inputs"]["raw"]
        model_config = {
            **architecture,
            "chunk_size": int(architecture.get("chunk_size", 65_536)),
            "min_chunk_size": int(architecture.get("min_chunk_size", 1_024)),
        }
        model = MalConvGCTForSequenceClassification(MalConvGCTConfig(**model_config))
        protocol = config.get("experiment", {}).get("protocol")
        if protocol == "malconvgct_e1":
            return model, None, False
        limit = raw["max_tokens"] if protocol == "lmlm_e2" else raw["truncation"]["max_bytes"]
        return model, int(limit), False
    if tokenizer is None:
        raise SupervisedTrainingError("EXE tracks require a train-partition tokenizer.")
    exe = config["inputs"]["exe"]
    vocab_size = tokenizer.get_vocab_size()
    if track == "hrrformer":
        return (
            HRRFormerForSequenceClassification(
                HRRFormerConfig(
                    vocab_size=vocab_size,
                    max_position_embeddings=int(exe["truncation"]["max_tokens"]),
                    **architecture,
                    gradient_checkpointing=bool(config["runtime"]["gradient_checkpointing"]),
                )
            ),
            int(exe["truncation"]["max_tokens"]),
            True,
        )
    if track == "mamba":
        return (
            MambaForSequenceClassification(
                MambaConfig(
                    vocab_size=vocab_size,
                    pad_token_id=tokenizer.token_to_id(SPECIAL_TOKENS["pad"]),
                    bos_token_id=tokenizer.token_to_id(SPECIAL_TOKENS["bos"]),
                    eos_token_id=tokenizer.token_to_id(SPECIAL_TOKENS["eos"]),
                    **architecture,
                    gradient_checkpointing=bool(config["runtime"]["gradient_checkpointing"]),
                )
            ),
            int(exe["truncation"]["max_tokens"]),
            False,
        )
    raise SupervisedTrainingError(f"Unsupported supervised track: {track}.")


def _evaluate(
    model: nn.Module,
    loader: DataLoader[tuple[Tensor, Tensor]],
    device: torch.device,
    use_attention_mask: bool,
    precision: str = "fp32",
    predictions: list[int] | None = None,
) -> tuple[float, list[float], list[int]]:
    from malweave.training.finetune_state import mixed_precision_context

    model.eval()
    loss_sum = 0.0
    count = 0
    probabilities: list[float] = []
    labels: list[int] = []
    with (
        torch.no_grad(),
        mixed_precision_context(device, precision),
    ):
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            targets = batch["labels"].to(device)
            kwargs = (
                {"attention_mask": batch["attention_mask"].to(device)}
                if use_attention_mask
                else {}
            )
            output = model(input_ids, labels=targets, **kwargs)
            assert output.loss is not None
            if (
                not torch.isfinite(output.loss).item()
                or not torch.isfinite(output.logits).all().item()
            ):
                raise SupervisedTrainingError("Nonfinite evaluation output; aborting run.")
            loss_sum += output.loss.item() * targets.numel()
            count += targets.numel()
            probabilities.extend(torch.softmax(output.logits.float(), dim=-1)[:, 1].cpu().tolist())
            labels.extend(targets.cpu().tolist())
            if predictions is not None:
                predictions.extend(output.logits.argmax(dim=-1).cpu().tolist())
    return loss_sum / count, probabilities, labels


def _git_revision() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _validate_transfer_config(config: dict[str, Any]) -> dict[str, Any]:
    """Require explicit settings; a scratch config cannot become a transfer run by accident."""
    try:
        transfer = config["finetuning"]
        training = config["tracks"]["mamba"]["training"]
        runtime = config["runtime"]
        exe = config["inputs"]["exe"]
        ratio_study = config["experiment"].get("protocol") == "vera_active_latent_ratios"
        completed_parent = transfer.get("initialization") == "completed_finetuning_run"
        if transfer.get("initialization") not in (
            None,
            "original_mlm",
            "completed_finetuning_run",
        ):
            raise ValueError("Unsupported fine-tuning initialization.")
        if config["experiment"]["dataset"] not in (
            {"rands", "vera_assemblage"} if completed_parent or ratio_study else {"rands"}
        ):
            raise ValueError("Unsupported dataset for checkpoint initialization.")
        if ratio_study:
            policy = config.get("cohort", {})
            if (
                config["experiment"]["dataset"] != "vera_assemblage"
                or transfer.get("initialization") != "original_mlm"
                or transfer["mode"] != "full"
                or training["precision"] != "fp16"
                or training.get("effective_batch_size") != 64
                or training["epochs"] > 5
                or policy.get("split_method") != "stratified_group_disjoint_non_temporal"
                or policy.get("deduplication") != "exact_model_tokens_after_full_exe"
                or policy.get("active_percentage") not in {0, 10, 30, 50, 70, 90, 100}
                or type(policy.get("active_percentage")) is not int
            ):
                raise ValueError(
                    "Ratio study requires original MLM, full FP16 and approved cohort policy."
                )
            if config["experiment"]["kind"] == "benchmark" and (
                policy.get("approval_status") != "approved_frozen"
                or not policy.get("final_training_authorized", False)
            ):
                raise ValueError(
                    "Ratio benchmark requires frozen cohort and final training authorization."
                )
        elif config["experiment"]["dataset"] == "vera_assemblage":
            policy = config.get("cohort", {})
            if config["experiment"]["kind"] == "benchmark" and (
                policy.get("approval_status") != "approved_frozen"
                or policy.get("variant") not in {"M1", "M2", "M3"}
                or not policy.get("train_end_exclusive_utc")
                or not policy.get("validation_end_exclusive_utc")
            ):
                raise ValueError(
                    "VERA benchmark requires approved frozen temporal variant policy."
                )
        if "architecture" in config["tracks"]["mamba"] or "tokenizer" in exe:
            raise ValueError(
                "Released runs must not override architecture or fit a RanDS tokenizer."
            )
        if transfer["representation"] != "exe" or transfer["mode"] not in {"full", "head_only"}:
            raise ValueError("Declare EXE and mode full or head_only.")
        expected_head = "preserve_parent" if completed_parent else "upstream_normal"
        if transfer["head"] != {"type": "linear", "initialization": expected_head}:
            raise ValueError(
                f"Declare the supported linear head with {expected_head} initialization."
            )
        if transfer["selection"] != {
            "checkpoint": "validation_roc_auc",
            "threshold": "argmax",
        }:
            raise ValueError(
                "Require validation ROC-AUC checkpoint selection and source argmax decisions."
            )
        for value in (
            training["epochs"],
            training["batch_size"],
            exe["truncation"]["max_tokens"],
            exe["checkpoint_context"],
        ):
            if type(value) is not int or value < 1:
                raise ValueError("Epoch, batch and context settings must be positive integers.")
        if transfer["early_stopping"] != {"patience": 3, "min_delta": 0}:
            raise ValueError("Require early stopping patience=3 and min_delta=0.")
        if training["epochs"] > 15:
            raise ValueError("The approved training budget is at most 15 epochs.")
        if config["experiment"]["kind"] == "benchmark" and training["epochs"] != 5:
            raise ValueError("Benchmark LR schedule must use the approved 5-epoch budget.")
        if type(exe["truncation"]["max_bytes"]) is not int or exe["truncation"]["max_bytes"] < 1:
            raise ValueError("Require an explicit positive byte prefix before tokenization.")
        if config["experiment"]["kind"] == "benchmark" and (
            exe["truncation"] != {"max_bytes": 65536, "max_tokens": 65536}
            or training["precision"] != ("fp16" if ratio_study else "bf16")
        ):
            raise ValueError("Benchmark requires approved 65536-byte/token limits and precision.")
        bootstrap_seed = 2026 if ratio_study else 0
        if (
            transfer["bootstrap"]["confidence"] != 0.95
            or transfer["bootstrap"]["seed"] != bootstrap_seed
        ):
            raise ValueError(f"Require 95% stratified bootstrap with seed {bootstrap_seed}.")
        if (
            type(transfer["bootstrap"]["replicates"]) is not int
            or transfer["bootstrap"]["replicates"] < 1
        ):
            raise ValueError("Bootstrap replicates must be positive.")
        if (
            config["experiment"]["kind"] == "benchmark"
            and transfer["bootstrap"]["replicates"] != 2000
        ):
            raise ValueError("Benchmark requires 2000 bootstrap replicates.")
        optimizer = training["optimizer"]
        scheduler = training["scheduler"]
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
        ):
            raise ValueError("Invalid optimizer/scheduler settings.")
        if scheduler["type"] != "linear" or training["precision"] not in {"fp32", "bf16", "fp16"}:
            raise ValueError("Supported scheduler/precision: linear and fp32 or CUDA bf16/fp16.")
        if any(
            type(runtime[key]) is not bool
            for key in ("gradient_checkpointing", "mamba_fast_path_required")
        ):
            raise ValueError("Explicit boolean runtime settings required.")
    except (KeyError, TypeError, ValueError) as error:
        raise SupervisedTrainingError(f"Invalid explicit fine-tuning config: {error}") from error
    return transfer


def run_supervised_training(request: SupervisedRunRequest) -> dict[str, Any]:
    """Run supervised training from private inputs and write immutable artifacts."""
    if request.track not in {"malconvgct", "hrrformer", "mamba"}:
        raise SupervisedTrainingError("track must be malconvgct, hrrformer, or mamba.")
    if request.gradient_accumulation_steps <= 0:
        raise SupervisedTrainingError("gradient_accumulation_steps must be positive.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", request.run_id):
        raise SupervisedTrainingError("run-id must be a simple name, not a path.")
    random.seed(request.seed)
    torch.manual_seed(request.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(request.seed)
    _private_path(request.artifact_root, "artifact_root")
    run_dir = request.artifact_root / request.run_id
    if run_dir.exists() and not request.resume:
        raise SupervisedTrainingError(f"Refusing to overwrite immutable run directory: {run_dir}.")
    if request.resume and not (run_dir / "last.pt").is_file():
        raise SupervisedTrainingError("Resume requires a committed last.pt training state.")
    if request.max_updates is not None and request.max_updates < 1:
        raise SupervisedTrainingError("max-updates must be positive.")
    if request.max_seconds is not None and (
        not math.isfinite(request.max_seconds) or request.max_seconds <= 0
    ):
        raise SupervisedTrainingError("max-seconds must be positive and finite.")
    config = _load_mapping(request.config_path)
    e2 = config.get("experiment", {}).get("protocol") == "lmlm_e2"
    e1 = config.get("experiment", {}).get("protocol") == "malconvgct_e1"
    malconv_baseline = e1 or e2
    if request.max_seconds is not None and not malconv_baseline:
        raise SupervisedTrainingError("max-seconds currently supports E1/E2 only.")
    if config.get("experiment", {}).get("kind") not in {"benchmark", "feasibility"}:
        raise SupervisedTrainingError("Experiment config kind must be benchmark or feasibility.")
    if "finetuning" in config and request.checkpoint_path is None:
        raise SupervisedTrainingError(
            "A fine-tuning config requires --checkpoint; random fallback is forbidden."
        )
    transfer = None
    batch_size = 1
    if malconv_baseline:
        from malweave.training.malconv_e1 import validate_e1_config
        from malweave.training.malconv_e2 import validate_e2_config

        transfer = (validate_e1_config if e1 else validate_e2_config)(config, request)
        batch_size = config["tracks"]["malconvgct"]["training"]["batch_size"]
    if request.checkpoint_path is not None:
        if request.track != "mamba":
            raise SupervisedTrainingError(
                "Released checkpoint loading currently supports BiMamba only."
            )
        transfer = _validate_transfer_config(config)
        batch_size = config["tracks"]["mamba"]["training"]["batch_size"]
        effective = config["tracks"]["mamba"]["training"].get("effective_batch_size")
        if effective is not None and batch_size * request.gradient_accumulation_steps != effective:
            raise SupervisedTrainingError(
                "microbatch × accumulation must match effective_batch_size."
            )
    elif not malconv_baseline and (request.resume or request.max_updates is not None):
        raise SupervisedTrainingError(
            "Resume/benchmark controls currently require a released checkpoint."
        )
    if malconv_baseline:
        from malweave.training.malconv_e2 import validate_malconv_cohort

        cohort_audit = validate_malconv_cohort(request, config)
    else:
        cohort_audit = _validate_audited_cohort(request, config)
    examples = load_supervised_split(request.split_manifest_path)
    train_rows = _partition(examples, "train")
    validation_rows = _partition(examples, "validation")
    test_rows = _partition(examples, "test")
    ratio_study = config.get("experiment", {}).get("protocol") == "vera_active_latent_ratios"
    if ratio_study:
        from malweave.training.finetune_state import state_recalls

        for rows in (train_rows, validation_rows, test_rows):
            state_recalls([r.state for r in rows], [r.label for r in rows], [0] * len(rows))
    if transfer is not None and any(
        {row.label for row in rows} != {0, 1} for rows in (train_rows, validation_rows, test_rows)
    ):
        raise SupervisedTrainingError("Each fine-tuning partition must contain both classes.")
    malconv_input_audit = None
    input_audit_key = "e1_input_audit" if e1 else "e2_input_audit"
    if malconv_baseline:
        from malweave.data.malconv_inputs import audit_malconv_inputs

        malconv_input_audit = audit_malconv_inputs(
            examples,
            request.raw_root,
            request.raw_samples_dir,
            None if e1 else config["inputs"]["raw"]["max_tokens"],
            _sha256_file(request.split_manifest_path),
            request.artifact_root / ("e1-input-audits" if e1 else "e2-input-audits"),
            protocol=config["experiment"]["protocol"],
        )
    device = torch.device(request.device)
    if malconv_baseline and config["experiment"]["kind"] == "benchmark" and device.type != "cuda":
        raise SupervisedTrainingError(
            "E1/E2 benchmark requires CUDA; CPU is for feasibility only."
        )
    if device.type == "cuda" and not torch.cuda.is_available():
        raise SupervisedTrainingError("CUDA device requested but unavailable.")
    if (
        request.track in {"hrrformer", "mamba"}
        and device.type != "cuda"
        and not (
            transfer is not None
            and config["experiment"]["kind"] == "feasibility"
            and device.type == "cpu"
        )
    ):
        raise SupervisedTrainingError("EXE LMLM tracks require CUDA for this configured run.")
    if request.track == "mamba" and config["runtime"].get("mamba_fast_path_required", False):
        from transformers.models.mamba.modeling_mamba import is_fast_path_available

        if not is_fast_path_available:
            raise SupervisedTrainingError(
                "Mamba CUDA fast kernels are unavailable; install matching mamba-ssm and causal-conv1d "
                "in the configured CUDA runtime before supervised training."
            )

    if (
        transfer is not None
        and not malconv_baseline
        and config["tracks"]["mamba"]["training"]["precision"] == "bf16"
        and (device.type != "cuda" or torch.cuda.get_device_capability(device)[0] < 8)
    ):
        raise SupervisedTrainingError("bf16 requires a supporting CUDA device.")
    if (
        transfer is not None
        and not malconv_baseline
        and config["tracks"]["mamba"]["training"]["precision"] == "fp16"
        and device.type != "cuda"
    ):
        raise SupervisedTrainingError("fp16 requires a CUDA device.")
    tokenizer = None
    released = None
    if request.checkpoint_path is not None:
        from malweave.training.lmlm_checkpoint import (
            load_finetuned_bimamba_for_transfer,
            load_released_bimamba,
        )

        if transfer.get("initialization") == "completed_finetuning_run":
            released = load_finetuned_bimamba_for_transfer(
                request.checkpoint_path,
                max_bytes=config["inputs"]["exe"]["truncation"]["max_bytes"],
                max_tokens=config["inputs"]["exe"]["truncation"]["max_tokens"],
                gradient_checkpointing=config["runtime"]["gradient_checkpointing"],
                source_context=config["inputs"]["exe"]["checkpoint_context"],
            )
        else:
            released = load_released_bimamba(
                request.checkpoint_path,
                representation=transfer["representation"],
                max_tokens=config["inputs"]["exe"]["truncation"]["max_tokens"],
                source_context=config["inputs"]["exe"]["checkpoint_context"],
                gradient_checkpointing=config["runtime"]["gradient_checkpointing"],
                head_initialization=transfer["head"]["initialization"],
                max_bytes=config["inputs"]["exe"]["truncation"]["max_bytes"],
            )
        tokenizer = released.inputs
    elif request.track != "malconvgct":
        exe_root = request.exe_root
        train_contents = ((exe_root / row.exe_relative_path).read_bytes() for row in train_rows)
        tokenizer = train_exe_bpe_tokenizer(
            train_contents, vocab_size=int(config["inputs"]["exe"]["tokenizer"]["vocab_size"])
        )
    if released is not None:
        model, max_length, use_attention_mask = released.model, tokenizer.max_tokens, False
        if transfer["mode"] == "head_only":
            for name, parameter in model.named_parameters():
                parameter.requires_grad_(name.startswith("classifier."))
    else:
        model, max_length, use_attention_mask = _build_model(config, request.track, tokenizer)
    resumable = released is not None or malconv_baseline
    model.to(device)
    collate = collate_raw_byte_ids if request.track == "malconvgct" else collate_exe_tokens
    if e2:
        # RawByteClf uses DataCollatorWithPadding(..., pad_to_multiple_of=8).
        collate = partial(collate_raw_byte_ids, pad_to_multiple_of=8)
    if released is not None:
        collate = partial(collate_exe_tokens, pad_token_id=tokenizer.pad_token_id)
    datasets = {
        split: _SupervisedDataset(
            rows,
            request.track,
            request.raw_root,
            request.raw_samples_dir,
            request.exe_root,
            tokenizer,
            max_length,
            e2=e2,
            e1=e1,
        )
        for split, rows in {
            "train": train_rows,
            "validation": validation_rows,
            "test": test_rows,
        }.items()
    }
    shuffle_rng = torch.Generator().manual_seed(request.seed)
    loaders = {
        split: DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=split == "train",
            collate_fn=collate,
            generator=shuffle_rng if split == "train" else None,
        )
        for split, dataset in datasets.items()
    }
    training = _track_config(config, request.track)["training"]
    optimizer_config = training["optimizer"]
    optimizer_parameters = (p for p in model.parameters() if p.requires_grad)
    if e2:
        from malweave.training.malconv_e2 import e2_optimizer_groups

        optimizer_parameters = e2_optimizer_groups(model, float(optimizer_config["weight_decay"]))
    optimizer = AdamW(
        optimizer_parameters,
        lr=float(optimizer_config["learning_rate"]),
        weight_decay=float(optimizer_config["weight_decay"]),
        betas=tuple(optimizer_config.get("betas", (0.9, 0.999))),
        eps=float(optimizer_config.get("epsilon", 1e-8)),
    )
    updates_per_epoch = math.ceil(len(loaders["train"]) / request.gradient_accumulation_steps)
    total_updates = updates_per_epoch * int(training["epochs"])
    if total_updates <= 0:
        raise SupervisedTrainingError(
            "Split is too small for the requested gradient accumulation."
        )
    warmup_ratio = float(training.get("scheduler", {}).get("warmup_ratio", 0.0))
    warmup_updates = math.ceil(total_updates * warmup_ratio)

    def learning_rate_factor(step):
        if e1:
            return 1.0
        if warmup_updates and step < warmup_updates:
            return step / warmup_updates
        return max(0.0, (total_updates - step) / max(total_updates - warmup_updates, 1))

    scheduler = LambdaLR(optimizer, learning_rate_factor)
    scaler = torch.amp.GradScaler("cuda", enabled=training["precision"] == "fp16")
    if not request.resume:
        run_dir.mkdir(parents=True, exist_ok=False)
    tokenizer_digest = (
        _sha256_file(run_dir / "tokenizer.json")
        if request.resume and tokenizer is not None
        else (
            write_private_tokenizer(
                tokenizer.tokenizer if released is not None else tokenizer,
                run_dir / "tokenizer.json",
            )
            if tokenizer
            else None
        )
    )
    if not request.resume:
        shutil.copyfile(request.config_path, run_dir / "config.yaml")
    if released is not None and not request.resume:
        for name in ("tokenizer_config.json", "special_tokens_map.json"):
            shutil.copyfile(request.checkpoint_path / name, run_dir / name)
    manifest = {
        "status": "running",
        "experiment_kind": config["experiment"]["kind"],
        "track": request.track,
        "initialization": released.provenance if released is not None else "random",
        "finetuning": transfer if not malconv_baseline else None,
        "batch_size": batch_size,
        "trainable_parameters": sum(p.numel() for p in model.parameters() if p.requires_grad),
        "run_id": request.run_id,
        "config_sha256": _sha256_file(request.config_path),
        "split_manifest_sha256": _sha256_file(request.split_manifest_path),
        "cohort_input_audit": cohort_audit,
        "tokenizer_sha256": tokenizer_digest,
        "git_revision": _git_revision(),
        "source_files_sha256": {
            path.relative_to(PROJECT_ROOT).as_posix(): _sha256_file(path)
            for path in sorted((PROJECT_ROOT / "malweave").rglob("*.py"))
        },
        "platform": platform.platform(),
        "torch": torch.__version__,
        "dependency_lock_sha256": _sha256_file(PROJECT_ROOT / "uv.lock"),
        "device": str(device),
        "seed": request.seed,
        "command": request.command,
        "gradient_accumulation_steps": request.gradient_accumulation_steps,
        "split_counts": dict(sorted(Counter(row.split for row in examples).items())),
        "artifacts": {
            "checkpoint": "model.safetensors" if resumable else "best.pt",
            "resume_state": "last.pt" if resumable else None,
            "metrics": "metrics.json",
            "predictions": "test-predictions.csv",
            "tokenizer": "tokenizer.json" if tokenizer else None,
        },
    }
    if malconv_baseline:
        # The elapsed audit time is observational and can differ on resume.
        manifest[input_audit_key] = malconv_input_audit["identity"]
        manifest["input_encoding"] = config["inputs"]["raw"]
        manifest["supervision"] = transfer
        manifest["malconv_source_behavior"] = {
            "implementation": model.config.implementation,
            "context_receives_gradients": not e2,
            "embedding_padding_idx": model.config.embedding_padding_idx,
            "batch_pad_to_multiple_of": 8 if e2 else 1,
            "protocol": config["experiment"]["protocol"],
            "upstream_commit": (
                "b5a865420e984b22a2474834bd1748318e84b553"
                if e1
                else "2502450e40ac00363e168106662aac29821d4a93"
            ),
        }
    from malweave.training.finetune_state import (
        mixed_precision_context,
        restore_rng,
        save_training_state,
        scaled_optimizer_step,
        write_json,
    )

    saved = None
    if request.resume:
        previous = json.loads((run_dir / "run-manifest.json").read_text())
        if previous["status"] == "completed":
            raise SupervisedTrainingError("A completed run cannot be resumed or extended.")
        for key in (
            "config_sha256",
            "split_manifest_sha256",
            "cohort_input_audit",
            "seed",
            "track",
            "device",
            "gradient_accumulation_steps",
            "initialization",
            "source_files_sha256",
            "dependency_lock_sha256",
        ):
            if previous[key] != manifest[key]:
                raise SupervisedTrainingError(f"Resume identity changed: {key}.")
        if malconv_baseline and previous.get(input_audit_key) != manifest[input_audit_key]:
            raise SupervisedTrainingError("Resume MalConv input audit identity changed.")
        if previous["tokenizer_sha256"] != tokenizer_digest:
            raise SupervisedTrainingError("Resume tokenizer digest changed.")
        if _sha256_file(run_dir / "config.yaml") != manifest["config_sha256"]:
            raise SupervisedTrainingError("Saved run config changed.")
        saved = torch.load(run_dir / "last.pt", map_location="cpu", weights_only=True)
        if request.max_updates is not None and request.max_updates <= saved["update"]:
            raise SupervisedTrainingError("max-updates must exceed the saved update count.")
        model.load_state_dict(saved["model"], strict=True)
        optimizer.load_state_dict(saved["optimizer"])
        scheduler.load_state_dict(saved["scheduler"])
        if scaler.is_enabled():
            if not saved.get("grad_scaler"):
                raise SupervisedTrainingError("FP16 resume requires saved GradScaler state.")
            scaler.load_state_dict(saved["grad_scaler"])
        shuffle_rng.set_state(saved["epoch_generator_state"])
        restore_rng(saved)
    write_json(run_dir / "run-manifest.json", manifest)
    if device.type == "cuda":
        torch.cuda.reset_peak_memory_stats(device)
    started = time.perf_counter()
    previous_elapsed = saved["elapsed_seconds"] if saved else 0.0
    session_samples = 0
    best_auc = saved["best_auc"] if saved else float("-inf")
    best_epoch = saved["best_epoch"] if saved else None
    best_threshold = 0.5
    stale_epochs = saved["stale_epochs"] if saved else 0
    history = saved["history"] if saved else []
    optimizer.zero_grad()
    update = saved["update"] if saved else 0
    skipped_updates = saved.get("skipped_updates", 0) if saved else 0
    first_epoch = saved["epoch"] if saved else 1
    last_log = started
    stopped_early = saved.get("stopped_early", False) if saved else False

    def persist(epoch, next_batch, generator_state, loss_sum, samples):
        save_training_state(
            run_dir / "last.pt",
            model,
            optimizer,
            scheduler,
            {
                "epoch": epoch,
                "next_batch": next_batch,
                "epoch_generator_state": generator_state,
                "epoch_loss_sum": loss_sum,
                "epoch_samples": samples,
                "update": update,
                "skipped_updates": skipped_updates,
                "grad_scaler": scaler.state_dict(),
                "best_auc": best_auc,
                "best_epoch": best_epoch,
                "stale_epochs": stale_epochs,
                "history": history,
                "stopped_early": stopped_early,
                "elapsed_seconds": previous_elapsed + time.perf_counter() - started,
            },
        )

    def malconv_progress(phase, epoch, **values):
        elapsed = time.perf_counter() - started
        event = {
            "phase": phase,
            "epoch": epoch,
            "updates": update,
            "session_samples": session_samples,
            "session_seconds": elapsed,
            "samples_per_second": session_samples / elapsed if elapsed else 0,
            "learning_rate": scheduler.get_last_lr()[0],
            "peak_memory_bytes": torch.cuda.max_memory_allocated(device)
            if device.type == "cuda"
            else 0,
            **values,
        }
        with (run_dir / "progress.jsonl").open("a") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
            handle.flush()
        print(json.dumps(event, sort_keys=True), file=sys.stderr, flush=True)

    if resumable and saved is None:
        persist(1, 0, shuffle_rng.get_state(), 0.0, 0)
    epochs = range(first_epoch, int(training["epochs"]) + 1) if not stopped_early else ()
    for epoch in epochs:
        model.train()
        if transfer is not None and transfer.get("mode") == "head_only":
            model.dropout.eval()
        skip_batches = saved["next_batch"] if saved and epoch == first_epoch else 0
        epoch_loss_sum = saved["epoch_loss_sum"] if skip_batches else 0.0
        epoch_samples = saved["epoch_samples"] if skip_batches else 0
        epoch_generator_state = shuffle_rng.get_state()
        # A dedicated loader RNG regenerates the original permutation on resume;
        # skipped batches do not consume the model's restored dropout RNG.
        for batch_index, batch in enumerate(loaders["train"], start=1):
            if batch_index <= skip_batches:
                continue
            input_ids = batch["input_ids"].to(device)
            labels = batch["labels"].to(device)
            kwargs = (
                {"attention_mask": batch["attention_mask"].to(device)}
                if use_attention_mask
                else {}
            )
            precision = training["precision"]
            with mixed_precision_context(device, precision):
                output = model(input_ids, labels=labels, **kwargs)
                assert output.loss is not None
                if not torch.isfinite(output.loss).item():
                    raise SupervisedTrainingError("Nonfinite training loss; aborting run.")
                group_start = (
                    ((batch_index - 1) // request.gradient_accumulation_steps)
                    * request.gradient_accumulation_steps
                    * batch_size
                )
                group_samples = min(
                    request.gradient_accumulation_steps * batch_size,
                    len(train_rows) - group_start,
                )
                loss = output.loss * labels.numel() / group_samples
            scaler.scale(loss).backward()
            epoch_loss_sum += output.loss.item() * labels.numel()
            epoch_samples += labels.numel()
            session_samples += labels.numel()
            if batch_index % request.gradient_accumulation_steps == 0 or batch_index == len(
                loaders["train"]
            ):
                max_grad_norm = training.get("scheduler", {}).get("max_grad_norm")
                stepped = scaled_optimizer_step(model, optimizer, scheduler, scaler, max_grad_norm)
                update += int(stepped)
                skipped_updates += int(not stepped)
                if resumable:
                    persist(
                        epoch, batch_index, epoch_generator_state, epoch_loss_sum, epoch_samples
                    )
                    if malconv_baseline:
                        malconv_progress(
                            "train", epoch, epoch_samples=epoch_samples, loss=output.loss.item()
                        )
                    if (request.max_updates is not None and update >= request.max_updates) or (
                        request.max_seconds is not None
                        and time.perf_counter() - started >= request.max_seconds
                    ):
                        manifest.update(
                            status="paused", updates=update, skipped_updates=skipped_updates
                        )
                        write_json(run_dir / "run-manifest.json", manifest)
                        elapsed = previous_elapsed + time.perf_counter() - started
                        metrics = {
                            "status": "paused",
                            "updates": update,
                            "skipped_updates": skipped_updates,
                            "runtime_seconds": elapsed,
                            "test_evaluated": False,
                            "epoch": epoch,
                            "epoch_samples_completed": epoch_samples,
                            "session_samples": session_samples,
                            "session_seconds": time.perf_counter() - started,
                            "peak_memory_bytes": torch.cuda.max_memory_allocated(device)
                            if device.type == "cuda"
                            else None,
                        }
                        write_json(run_dir / "benchmark.json", metrics)
                        if malconv_baseline:
                            malconv_progress("paused", epoch)
                        return {"manifest": manifest, "metrics": metrics}
            if resumable and not malconv_baseline and time.perf_counter() - last_log >= 5:
                if device.type == "cuda":
                    torch.cuda.synchronize(device)
                print(
                    json.dumps(
                        {
                            "phase": "train",
                            "epoch": epoch,
                            "samples": epoch_samples,
                            "epoch_samples_total": len(train_rows),
                            "updates": update,
                            "elapsed_seconds": previous_elapsed + time.perf_counter() - started,
                            "loss": output.loss.item(),
                            "learning_rate": scheduler.get_last_lr()[0],
                            "peak_memory_bytes": torch.cuda.max_memory_allocated(device)
                            if device.type == "cuda"
                            else None,
                        }
                    ),
                    file=sys.stderr,
                    flush=True,
                )
                last_log = time.perf_counter()
        validation_predictions = []
        validation_loss, probabilities, labels = _evaluate(
            model,
            loaders["validation"],
            device,
            use_attention_mask,
            training["precision"] if resumable else "fp32",
            predictions=validation_predictions,
        )
        validation_auc = _binary_auc(probabilities, labels)
        if validation_auc is None:
            raise SupervisedTrainingError(
                "Validation split lacks both labels; ROC-AUC selection is impossible."
            )
        threshold = 0.5 if resumable else _select_threshold(probabilities, labels)
        history.append(
            {
                "epoch": epoch,
                "train_loss": epoch_loss_sum / epoch_samples,
                "validation_loss": validation_loss,
                "validation_roc_auc": validation_auc,
                "validation_threshold": threshold,
            }
        )
        if resumable:
            print(
                json.dumps(
                    {
                        "phase": "validation" if malconv_baseline else "finetune",
                        "epoch": epoch,
                        "updates": update,
                        "elapsed_seconds": time.perf_counter() - started,
                        "validation_roc_auc": validation_auc,
                    }
                ),
                file=sys.stderr,
                flush=True,
            )
        if validation_auc > best_auc:
            best_auc = validation_auc
            best_epoch = epoch
            best_threshold = threshold
            stale_epochs = 0
            if resumable:
                from safetensors.torch import save_file

                temporary = run_dir / "model.safetensors.tmp"
                save_file(
                    {
                        name: value.detach().cpu().contiguous()
                        for name, value in model.state_dict().items()
                    },
                    str(temporary),
                )
                temporary.replace(run_dir / "model.safetensors")
            else:
                torch.save({"model": model.state_dict(), "epoch": epoch}, run_dir / "best.pt")
        else:
            stale_epochs += 1
        if resumable:
            stopped_early = stale_epochs >= transfer["early_stopping"]["patience"]
            persist(epoch + 1, 0, shuffle_rng.get_state(), 0.0, 0)
            write_json(run_dir / "history.json", history)
            if malconv_baseline:
                with (run_dir / "history.csv").open("w", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=list(history[0]))
                    writer.writeheader()
                    writer.writerows(history)
                malconv_progress("validation", epoch, validation_roc_auc=validation_auc)
            if stopped_early:
                break
    if resumable:
        from safetensors.torch import load_file

        model.load_state_dict(load_file(str(run_dir / "model.safetensors"), device=str(device)))
        checkpoint = {"epoch": best_epoch}
    else:
        checkpoint = torch.load(run_dir / "best.pt", map_location=device, weights_only=True)
        model.load_state_dict(checkpoint["model"])
    test_predictions = []
    test_loss, test_probabilities, test_labels = _evaluate(
        model,
        loaders["test"],
        device,
        use_attention_mask,
        training["precision"] if resumable else "fp32",
        predictions=test_predictions,
    )
    with (run_dir / "test-predictions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "source_sha256",
                "label",
                "family",
                "year",
                "ransomware_probability",
                "threshold",
                "prediction",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        for row, probability, label, prediction in zip(
            test_rows, test_probabilities, test_labels, test_predictions, strict=True
        ):
            writer.writerow(
                {
                    "source_sha256": row.source_sha256,
                    "label": label,
                    "family": row.family,
                    "year": row.year,
                    "ransomware_probability": probability,
                    "threshold": best_threshold,
                    "prediction": prediction if resumable else int(probability >= best_threshold),
                }
            )
    elapsed = previous_elapsed + time.perf_counter() - started
    peak_memory = torch.cuda.max_memory_allocated(device) if device.type == "cuda" else 0
    metrics = {
        "selection": {
            "checkpoint_epoch": checkpoint["epoch"],
            "validation_roc_auc": best_auc,
            "threshold": best_threshold,
        },
        "test": {
            "loss": test_loss,
            "roc_auc": _binary_auc(test_probabilities, test_labels),
            "pr_auc": _pr_auc(test_probabilities, test_labels),
            **_threshold_metrics(
                test_probabilities,
                test_labels,
                best_threshold,
                test_predictions if resumable else None,
            ),
        },
        "history": history,
        "runtime_seconds": elapsed,
        "peak_memory_bytes": peak_memory,
        "optimizer_updates": update,
        "skipped_updates": skipped_updates,
        "failures": [],
    }
    if resumable:
        from malweave.training.finetune_state import test_statistics

        metrics["selection"]["decision_rule"] = "softmax_argmax; ties select class 0"
        metrics["test"].pop("balanced_accuracy")
        metrics["test"].pop("pr_auc")
        metrics["test"].update(
            test_statistics(test_probabilities, test_labels, transfer["bootstrap"])
        )
        tn, fp = metrics["test"]["confusion_matrix"][0]
        fn, tp = metrics["test"]["confusion_matrix"][1]
        metrics["test"].update(fpr=fp / (tn + fp), tp=tp, fn=fn, fp=fp, tn=tn)
        if ratio_study:
            metrics["test"]["states"] = state_recalls(
                [row.state for row in test_rows], test_labels, test_predictions
            )
        train_families = {row.family for row in train_rows if row.label == 1 and row.family}
        family_support = Counter(row.family for row in test_rows if row.label == 1 and row.family)
        family_detected = Counter(
            row.family
            for row, prediction in zip(test_rows, test_predictions)
            if row.label == 1 and row.family and prediction == 1
        )
        families = {
            family: {
                "support": support,
                "detected": family_detected[family],
                "recall": family_detected[family] / support,
                "present_in_rands_train": family in train_families,
            }
            for family, support in sorted(family_support.items())
        }
        metrics["test"]["families"] = families
        metrics["test"]["mean_family_recall"] = (
            sum(row["recall"] for row in families.values()) / len(families) if families else None
        )
        metrics["test"]["ransomware_missing_family"] = sum(
            row.label == 1 and not row.family for row in test_rows
        )
        metrics["stopped_early"] = stopped_early
    (run_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest["status"] = "completed"
    if malconv_baseline:
        malconv_progress("completed", checkpoint["epoch"])
    if resumable:
        from malweave.training.lmlm_checkpoint import file_sha256

        manifest["artifact_files_sha256"] = {
            name: file_sha256(run_dir / name)
            for name in (
                ("model.safetensors",)
                if malconv_baseline
                else (
                    "model.safetensors",
                    "tokenizer.json",
                    "tokenizer_config.json",
                    "special_tokens_map.json",
                )
            )
        }
    (run_dir / "run-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {"manifest": manifest, "metrics": metrics}
