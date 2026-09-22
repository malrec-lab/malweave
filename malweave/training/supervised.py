"""Private, reproducible supervised-training orchestration."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import csv
from dataclasses import dataclass
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import subprocess
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


class SupervisedTrainingError(ValueError):
    """Raised when a supervised run would violate its declared contract."""


@dataclass(frozen=True)
class SplitExample:
    split: str
    source_sha256: str
    label: int
    raw_relative_path: str
    exe_relative_path: str
    exe_representation_sha256: str


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


def _private_path(path: Path, label: str) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if tuple(relative.parts[:2]) != ("data", "processed"):
        raise SupervisedTrainingError(
            f"{label} inside the repository must be under data/processed."
        )


def _sha256_file(path: Path) -> str:
    try:
        return sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise SupervisedTrainingError(
            f"Could not read required private artifact: {path}"
        ) from error


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
            sources.add(source)
            examples.append(
                SplitExample(
                    split=row["split"],
                    source_sha256=source,
                    label=labels[row["label"]],
                    raw_relative_path=row["raw_relative_path"],
                    exe_relative_path=row["exe_relative_path"],
                    exe_representation_sha256=exe_digest,
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
    for rank, (_, label) in enumerate(ordered, start=1):
        found += label
        if label:
            area += found / rank
    return area / positives


def _threshold_metrics(
    probabilities: list[float], labels: list[int], threshold: float
) -> dict[str, Any]:
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
    candidates = sorted({0.0, 1.0, *probabilities})
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
        max_length: int,
    ) -> None:
        self.examples = examples
        self.track = track
        self.raw_root = raw_root
        self.raw_samples_dir = raw_samples_dir
        self.exe_root = exe_root
        self.tokenizer = tokenizer
        self.max_length = max_length
        self._verified: set[str] = set()

    def __len__(self) -> int:
        return len(self.examples)

    def _content(self, example: SplitExample) -> bytes:
        if self.track == "malconvgct":
            path = (
                self.raw_root
                / self.raw_samples_dir
                / example.source_sha256[:2]
                / example.source_sha256
            )
        else:
            path = self.exe_root / example.exe_relative_path
        try:
            content = path.read_bytes()
        except OSError as error:
            raise SupervisedTrainingError(
                f"Could not read required representation for {self.track}."
            ) from error
        expected_digest = (
            example.source_sha256
            if self.track == "malconvgct"
            else example.exe_representation_sha256
        )
        if expected_digest not in self._verified:
            if sha256(content).hexdigest() != expected_digest:
                raise SupervisedTrainingError(
                    f"Representation digest changed for {self.track}; aborting run."
                )
            self._verified.add(expected_digest)
        return content

    def __getitem__(self, index: int) -> tuple[Tensor, int]:
        example = self.examples[index]
        content = self._content(example)
        if self.track == "malconvgct":
            return raw_bytes_to_ids(content, self.max_length), example.label
        assert self.tokenizer is not None
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
) -> tuple[nn.Module, int, bool]:
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
        return model, int(raw["truncation"]["max_bytes"]), False
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
) -> tuple[float, list[float], list[int]]:
    model.eval()
    losses: list[float] = []
    probabilities: list[float] = []
    labels: list[int] = []
    with torch.no_grad():
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
            losses.append(output.loss.item())
            probabilities.extend(torch.softmax(output.logits, dim=-1)[:, 1].cpu().tolist())
            labels.extend(targets.cpu().tolist())
    return sum(losses) / len(losses), probabilities, labels


def _git_revision() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def run_supervised_training(request: SupervisedRunRequest) -> dict[str, Any]:
    """Run supervised training from private inputs and write immutable artifacts."""
    if request.track not in {"malconvgct", "hrrformer", "mamba"}:
        raise SupervisedTrainingError("track must be malconvgct, hrrformer, or mamba.")
    if request.gradient_accumulation_steps <= 0:
        raise SupervisedTrainingError("gradient_accumulation_steps must be positive.")
    torch.manual_seed(request.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(request.seed)
    _private_path(request.artifact_root, "artifact_root")
    run_dir = request.artifact_root / request.run_id
    if run_dir.exists():
        raise SupervisedTrainingError(f"Refusing to overwrite immutable run directory: {run_dir}.")
    config = _load_mapping(request.config_path)
    if config.get("experiment", {}).get("kind") not in {"benchmark", "feasibility"}:
        raise SupervisedTrainingError("Experiment config kind must be benchmark or feasibility.")
    examples = load_supervised_split(request.split_manifest_path)
    train_rows = _partition(examples, "train")
    validation_rows = _partition(examples, "validation")
    test_rows = _partition(examples, "test")
    device = torch.device(request.device)
    if device.type == "cuda" and not torch.cuda.is_available():
        raise SupervisedTrainingError("CUDA device requested but unavailable.")
    if request.track in {"hrrformer", "mamba"} and device.type != "cuda":
        raise SupervisedTrainingError("EXE LMLM tracks require CUDA for this configured run.")
    if request.track == "mamba" and config["runtime"].get("mamba_fast_path_required", False):
        from transformers.models.mamba.modeling_mamba import is_fast_path_available

        if not is_fast_path_available:
            raise SupervisedTrainingError(
                "Mamba CUDA fast kernels are unavailable; install matching mamba-ssm and causal-conv1d "
                "in the configured CUDA runtime before supervised training."
            )

    tokenizer = None
    if request.track != "malconvgct":
        exe_root = request.exe_root
        train_contents = ((exe_root / row.exe_relative_path).read_bytes() for row in train_rows)
        tokenizer = train_exe_bpe_tokenizer(
            train_contents, vocab_size=int(config["inputs"]["exe"]["tokenizer"]["vocab_size"])
        )
    model, max_length, use_attention_mask = _build_model(config, request.track, tokenizer)
    model.to(device)
    collate = collate_raw_byte_ids if request.track == "malconvgct" else collate_exe_tokens
    datasets = {
        split: _SupervisedDataset(
            rows,
            request.track,
            request.raw_root,
            request.raw_samples_dir,
            request.exe_root,
            tokenizer,
            max_length,
        )
        for split, rows in {
            "train": train_rows,
            "validation": validation_rows,
            "test": test_rows,
        }.items()
    }
    loaders = {
        split: DataLoader(dataset, batch_size=1, shuffle=split == "train", collate_fn=collate)
        for split, dataset in datasets.items()
    }
    training = _track_config(config, request.track)["training"]
    optimizer_config = training["optimizer"]
    optimizer = AdamW(
        model.parameters(),
        lr=float(optimizer_config["learning_rate"]),
        weight_decay=float(optimizer_config["weight_decay"]),
    )
    updates_per_epoch = math.ceil(len(loaders["train"]) / request.gradient_accumulation_steps)
    total_updates = updates_per_epoch * int(training["epochs"])
    if total_updates <= 0:
        raise SupervisedTrainingError(
            "Split is too small for the requested gradient accumulation."
        )
    warmup_ratio = float(training.get("scheduler", {}).get("warmup_ratio", 0.0))
    warmup_updates = int(total_updates * warmup_ratio)
    scheduler = LambdaLR(
        optimizer,
        lambda step: min(
            (step + 1) / max(warmup_updates, 1),
            max(0.0, (total_updates - step) / max(total_updates - warmup_updates, 1)),
        ),
    )
    run_dir.mkdir(parents=True, exist_ok=False)
    tokenizer_digest = (
        write_private_tokenizer(tokenizer, run_dir / "tokenizer.json") if tokenizer else None
    )
    started = time.perf_counter()
    best_auc = float("-inf")
    best_threshold = 0.5
    history: list[dict[str, Any]] = []
    optimizer.zero_grad()
    update = 0
    for epoch in range(1, int(training["epochs"]) + 1):
        model.train()
        epoch_losses: list[float] = []
        for batch_index, batch in enumerate(loaders["train"], start=1):
            input_ids = batch["input_ids"].to(device)
            labels = batch["labels"].to(device)
            kwargs = (
                {"attention_mask": batch["attention_mask"].to(device)}
                if use_attention_mask
                else {}
            )
            precision = training["precision"]
            autocast = (
                torch.autocast(device_type="cuda", dtype=torch.bfloat16)
                if precision == "bf16"
                else torch.autocast(device_type="cpu", enabled=False)
            )
            with autocast:
                output = model(input_ids, labels=labels, **kwargs)
                assert output.loss is not None
                loss = output.loss / request.gradient_accumulation_steps
            loss.backward()
            epoch_losses.append(loss.item() * request.gradient_accumulation_steps)
            if batch_index % request.gradient_accumulation_steps == 0 or batch_index == len(
                loaders["train"]
            ):
                max_grad_norm = training.get("scheduler", {}).get("max_grad_norm")
                if max_grad_norm is not None:
                    torch.nn.utils.clip_grad_norm_(model.parameters(), float(max_grad_norm))
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()
                update += 1
        validation_loss, probabilities, labels = _evaluate(
            model, loaders["validation"], device, use_attention_mask
        )
        validation_auc = _binary_auc(probabilities, labels)
        if validation_auc is None:
            raise SupervisedTrainingError(
                "Validation split lacks both labels; ROC-AUC selection is impossible."
            )
        threshold = _select_threshold(probabilities, labels)
        history.append(
            {
                "epoch": epoch,
                "train_loss": sum(epoch_losses) / len(epoch_losses),
                "validation_loss": validation_loss,
                "validation_roc_auc": validation_auc,
                "validation_threshold": threshold,
            }
        )
        if validation_auc > best_auc:
            best_auc = validation_auc
            best_threshold = threshold
            torch.save({"model": model.state_dict(), "epoch": epoch}, run_dir / "best.pt")
    checkpoint = torch.load(run_dir / "best.pt", map_location=device, weights_only=True)
    model.load_state_dict(checkpoint["model"])
    test_loss, test_probabilities, test_labels = _evaluate(
        model, loaders["test"], device, use_attention_mask
    )
    with (run_dir / "test-predictions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "source_sha256",
                "label",
                "ransomware_probability",
                "threshold",
                "prediction",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        for row, probability, label in zip(
            test_rows, test_probabilities, test_labels, strict=True
        ):
            writer.writerow(
                {
                    "source_sha256": row.source_sha256,
                    "label": label,
                    "ransomware_probability": probability,
                    "threshold": best_threshold,
                    "prediction": int(probability >= best_threshold),
                }
            )
    elapsed = time.perf_counter() - started
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
            **_threshold_metrics(test_probabilities, test_labels, best_threshold),
        },
        "history": history,
        "runtime_seconds": elapsed,
        "peak_memory_bytes": peak_memory,
        "failures": [],
    }
    (run_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = {
        "experiment_kind": config["experiment"]["kind"],
        "track": request.track,
        "run_id": request.run_id,
        "config_sha256": _sha256_file(request.config_path),
        "split_manifest_sha256": _sha256_file(request.split_manifest_path),
        "tokenizer_sha256": tokenizer_digest,
        "git_revision": _git_revision(),
        "platform": platform.platform(),
        "torch": torch.__version__,
        "dependency_lock_sha256": _sha256_file(PROJECT_ROOT / "uv.lock"),
        "device": str(device),
        "seed": request.seed,
        "command": request.command,
        "gradient_accumulation_steps": request.gradient_accumulation_steps,
        "split_counts": dict(sorted(Counter(row.split for row in examples).items())),
        "artifacts": {
            "checkpoint": "best.pt",
            "metrics": "metrics.json",
            "predictions": "test-predictions.csv",
            "tokenizer": "tokenizer.json" if tokenizer else None,
        },
    }
    (run_dir / "run-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {"manifest": manifest, "metrics": metrics}
