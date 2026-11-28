"""Standalone supervised RanDS EXE baseline: random weights, train-only BPE, resume.

This is separate from the external-tokenizer scratch/pretrained transfer protocol.
Only immutable extracted byte arrays are read; PE execution is never involved.
"""

from __future__ import annotations

from contextlib import nullcontext
import csv
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import shutil
import signal
import subprocess
import threading
import time
from typing import Any

from tokenizers import Tokenizer
import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset

from malweave.config import PROJECT_ROOT
from malweave.data.byte_inputs import (
    SPECIAL_TOKENS,
    collate_exe_tokens,
    encode_exe_tokens,
    train_exe_bpe_tokenizer,
    write_private_tokenizer,
)
from malweave.data.rands_training import (
    Progress,
    RandsTrainingError,
    atomic_json,
    exclusive,
    file_digest,
    load_config,
    load_split,
    validate_experiment_prefix,
)
from malweave.models import (
    HRRFormerConfig,
    HRRFormerForSequenceClassification,
    MambaConfig,
    MambaForSequenceClassification,
)
from malweave.training import scratch_storage
from malweave.training.supervised import (
    _binary_auc,
    _git_revision,
    _private_path,
    _threshold_metrics,
)
from malweave.training.token_cache import token_cache


@dataclass(frozen=True)
class ScratchRequest:
    config: Path
    data: Path
    runs: Path
    run_id: str
    device: str = "cuda:0"
    resume: bool = False
    max_steps: int | None = None
    s3_prefix: str | None = None
    command: str | None = None


def code_identity() -> dict[str, str]:
    files = [
        "malweave/training/scratch.py",
        "malweave/training/scratch_storage.py",
        "malweave/training/token_cache.py",
        "malweave/data/rands_training.py",
        "malweave/data/byte_inputs.py",
        "malweave/models/hrrformer.py",
        "malweave/models/mamba.py",
        "malweave/training/supervised.py",
        "uv.lock",
    ]
    return {name: file_digest(PROJECT_ROOT / name) for name in files}


class ExeDataset(Dataset):
    def __init__(
        self, root: Path, rows: list[dict[str, Any]], tokenizer: Tokenizer, max_tokens: int
    ):
        self.root, self.rows = root, rows
        self.tokenizer, self.max_tokens = tokenizer, max_tokens
        self.verified: dict[str, tuple[int, int]] = {}

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> tuple[torch.Tensor, int]:
        row = self.rows[index]
        path = self.root / row["relative_path"]
        if (
            path.is_symlink()
            or path.parent.is_symlink()
            or self.root.is_symlink()
            or path.resolve().parent != (self.root / row["source_sha256"][:2]).resolve()
        ):
            raise RandsTrainingError("EXE path escapes the data root.")
        stat = path.stat()
        if stat.st_size != int(row["size"]):
            raise RandsTrainingError("EXE size changed since preparation.")
        fingerprint = (stat.st_mtime_ns, stat.st_ctime_ns)
        if self.verified.get(row["source_sha256"]) != fingerprint:
            if file_digest(path) != row["exe_sha256"]:
                raise RandsTrainingError("EXE digest changed since preparation.")
            self.verified[row["source_sha256"]] = fingerprint
        # BPE merges only inside 16-byte words. This bound includes all words
        # that can contribute to the first max_tokens-2 content tokens.
        with path.open("rb") as handle:
            content = handle.read((self.max_tokens - 2) * 16)
        return encode_exe_tokens(self.tokenizer, content, self.max_tokens), int(
            row["label"] == "ransomware"
        )


def _model(config: dict[str, Any], tokenizer: Tokenizer) -> nn.Module:
    architecture = config["model"]["architecture"]
    common = {
        "vocab_size": tokenizer.get_vocab_size(),
        "gradient_checkpointing": config["training"]["gradient_checkpointing"],
        **architecture,
    }
    if config["model"]["name"] == "hrrformer":
        if not architecture.get("mask_padding"):
            raise RandsTrainingError("Batched HRR scratch runs require mask_padding=true.")
        return HRRFormerForSequenceClassification(
            HRRFormerConfig(**common, max_position_embeddings=config["model"]["max_tokens"])
        )
    if config["model"]["name"] == "mamba":
        return MambaForSequenceClassification(
            MambaConfig(
                **common,
                pad_token_id=tokenizer.token_to_id(SPECIAL_TOKENS["pad"]),
                bos_token_id=tokenizer.token_to_id(SPECIAL_TOKENS["bos"]),
                eos_token_id=tokenizer.token_to_id(SPECIAL_TOKENS["eos"]),
            )
        )
    raise RandsTrainingError("Supported scratch models: hrrformer, mamba.")


def _precision(config: dict[str, Any], device: torch.device):
    if config["training"]["precision"] == "bf16":
        return torch.autocast("cuda", dtype=torch.bfloat16)
    return nullcontext()


def _kwargs(
    batch: dict[str, torch.Tensor], config: dict[str, Any], device: torch.device
) -> dict[str, Any]:
    return (
        {"attention_mask": batch["attention_mask"].to(device)}
        if config["model"]["name"] == "hrrformer"
        else {}
    )


def _rank_metrics(probabilities: list[float], labels: list[int]) -> tuple[float, float]:
    """Grouped-score average precision and best validation balanced-accuracy threshold."""
    positives, negatives = sum(labels), len(labels) - sum(labels)
    if positives == 0 or negatives == 0:
        raise RandsTrainingError("Evaluation needs both classes.")
    ordered = sorted(zip(probabilities, labels), reverse=True)
    tp = fp = index = 0
    ap = 0.0
    best_score, best_threshold = 0.5, 1.0000001
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        added = sum(label for _, label in ordered[index:end])
        tp += added
        fp += end - index - added
        ap += (added / positives) * tp / (tp + fp)
        score = (tp / positives + 1 - fp / negatives) / 2
        threshold = ordered[index][0]
        if score >= best_score:
            best_score, best_threshold = score, threshold
        index = end
    return ap, best_threshold


def _loader(
    dataset: ExeDataset, config: dict[str, Any], indices: list[int] | None = None, *, seed: int = 0
) -> DataLoader:
    workers = config["runtime"]["dataloader_workers"]
    return DataLoader(
        torch.utils.data.Subset(dataset, indices) if indices is not None else dataset,
        batch_size=config["training"]["batch_size"],
        shuffle=False,
        num_workers=workers,
        collate_fn=collate_exe_tokens,
        generator=torch.Generator().manual_seed(seed),
        pin_memory=torch.cuda.is_available(),
        **({"prefetch_factor": 2} if workers else {}),
    )


def evaluate(
    model: nn.Module,
    dataset: ExeDataset,
    config: dict[str, Any],
    device: torch.device,
    progress: Progress,
    phase: str,
) -> tuple[float, list[float], list[int]]:
    model.eval()
    probabilities: list[float] = []
    labels: list[int] = []
    loss_sum = 0.0
    last = time.monotonic()
    with torch.inference_mode():
        for batch in _loader(dataset, config):
            targets = batch["labels"].to(device)
            with _precision(config, device):
                output = model(
                    batch["input_ids"].to(device), labels=targets, **_kwargs(batch, config, device)
                )
            if not torch.isfinite(output.loss):
                raise RandsTrainingError("Non-finite evaluation loss.")
            loss_sum += output.loss.item() * len(targets)
            probabilities.extend(output.logits.float().softmax(-1)[:, 1].cpu().tolist())
            labels.extend(targets.cpu().tolist())
            if time.monotonic() - last >= config["runtime"]["progress_seconds"]:
                progress.emit(phase=phase, completed=len(labels), total=len(dataset))
                last = time.monotonic()
    return loss_sum / len(labels), probabilities, labels


def _save(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("wb") as handle:
        torch.save(payload, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _rng() -> dict[str, Any]:
    return {
        "torch": torch.get_rng_state(),
        "python": random.getstate(),
        "cuda": torch.cuda.get_rng_state_all() if torch.cuda.is_available() else [],
    }


def _restore_rng(state: dict[str, Any]) -> None:
    torch.set_rng_state(state["torch"].cpu())
    random.setstate(state["python"])
    if state["cuda"]:
        torch.cuda.set_rng_state_all([value.cpu() for value in state["cuda"]])


def _environment(device: torch.device) -> dict[str, Any]:
    try:
        driver = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        driver = None
    return {
        "platform": platform.platform(),
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "gpu": torch.cuda.get_device_name(device) if device.type == "cuda" else None,
        "gpu_capability": list(torch.cuda.get_device_capability(device))
        if device.type == "cuda"
        else None,
        "driver": driver,
        "device": str(device),
    }


def _validate(config: dict[str, Any], request: ScratchRequest) -> torch.device:
    _private_path(request.data, "EXE data root")
    _private_path(request.runs, "Training artifact root")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", request.run_id):
        raise RandsTrainingError("run-id must be a simple name, not a path.")
    t, runtime = config["training"], config["runtime"]
    if any(
        not isinstance(t[k], int) or t[k] <= 0
        for k in ["epochs", "batch_size", "gradient_accumulation_steps"]
    ):
        raise RandsTrainingError(
            "epochs/batch_size/gradient_accumulation_steps must be positive integers."
        )
    if (
        t["learning_rate"] <= 0
        or t["weight_decay"] < 0
        or not 0 <= t["warmup_ratio"] < 1
        or t["max_grad_norm"] <= 0
        or config["model"]["max_tokens"] < 3
        or runtime["cpu_threads"] < 1
        or runtime["dataloader_workers"] < 0
        or runtime["checkpoint_updates"] < 1
        or runtime["progress_seconds"] <= 0
    ):
        raise RandsTrainingError("Invalid training/runtime parameters.")
    if request.max_steps is not None and request.max_steps <= 0:
        raise RandsTrainingError("max-steps must be positive.")
    if t["precision"] not in {"fp32", "bf16"}:
        raise RandsTrainingError("Supported precision: fp32 or CUDA bf16.")
    if config["tokenizer"]["vocab_size"] < 263 or not config["tokenizer"]["full_byte_coverage"]:
        raise RandsTrainingError("Scratch BPE requires all 256 byte symbols plus special tokens.")
    if any(config["tokenizer"][k] <= 0 for k in ["max_train_files", "max_bytes_per_file"]):
        raise RandsTrainingError("Tokenizer fitting bounds must be positive.")
    device = torch.device(request.device)
    if device.type == "cuda":
        if not torch.cuda.is_available():
            raise RandsTrainingError(
                "CUDA unavailable. Check the rented image/driver before downloading data."
            )
        if torch.cuda.get_device_capability(device)[0] >= 12:
            raise RandsTrainingError(
                "Blackwell is not validated with the current Torch/CUDA lock."
            )
        if t["precision"] == "bf16" and not torch.cuda.is_bf16_supported():
            raise RandsTrainingError("This GPU does not support bf16; use a new fp32 config.")
    elif device.type != "cpu" or t["precision"] != "fp32":
        raise RandsTrainingError("CPU smoke tests require fp32.")
    if config["model"]["name"] == "mamba" and device.type == "cuda":
        from transformers.models.mamba.modeling_mamba import is_fast_path_available

        if not is_fast_path_available:
            raise RandsTrainingError(
                "BiMamba requires compatible mamba-ssm and causal-conv1d CUDA kernels. "
                "The current runtime does not provide them."
            )
    return device


def run_scratch(request: ScratchRequest) -> dict[str, Any]:
    if request.s3_prefix:
        validate_experiment_prefix(request.s3_prefix)
    config = load_config(request.config)
    device = _validate(config, request)
    with (
        exclusive(request.runs / ("." + request.run_id + ".lock")),
        Progress(config["runtime"]["progress_seconds"]) as progress,
    ):
        return _run(request, config, device, progress)


def _run(
    request: ScratchRequest, config: dict[str, Any], device: torch.device, progress: Progress
) -> dict[str, Any]:
    torch.set_num_threads(config["runtime"]["cpu_threads"])
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    torch.use_deterministic_algorithms(config["runtime"]["deterministic"])
    torch.backends.cudnn.benchmark = False
    seed = config["experiment"]["seed"]
    random.seed(seed)
    torch.manual_seed(seed)
    if device.type == "cuda":
        torch.cuda.manual_seed_all(seed)
        torch.cuda.reset_peak_memory_stats(device)
    progress.emit(phase="validate_split")
    rows, prepared = load_split(request.data, request.config)
    partitions = {
        name: [row for row in rows if row["split"] == name]
        for name in ["train", "validation", "test"]
    }
    run = request.runs / request.run_id
    if request.resume and not run.exists():
        if not request.s3_prefix:
            raise RandsTrainingError(
                "No local checkpoint and no training S3 prefix for remote restore."
            )
        progress.emit(phase="restore_checkpoint")
        scratch_storage.restore(run, request.s3_prefix)
    contract = {
        "code": code_identity(),
        "config": file_digest(request.config),
        "split": prepared["digests"]["split.csv"],
        "prepared": file_digest(request.data / "prepared.json"),
        "seed": seed,
    }
    environment = _environment(device)
    resumed = request.resume
    if run.exists() and not resumed:
        raise RandsTrainingError("Run directory already exists; use --resume or a new run-id.")
    initializing = run / "initialization.json"
    if resumed and not (run / "last.pt").exists():
        if not initializing.exists() or json.loads(initializing.read_text()) != contract:
            raise RandsTrainingError(
                "No committed checkpoint or matching initialization contract."
            )
        resumed = False
    if resumed:
        manifest = json.loads((run / "run-manifest.json").read_text())
        if manifest["contract"] != contract:
            raise RandsTrainingError("Resume rejected: code/config/split/seed changed.")
        if manifest["tokenizer_sha256"] != file_digest(run / "tokenizer.json"):
            raise RandsTrainingError("Resume tokenizer changed.")
        tokenizer = Tokenizer.from_file(str(run / "tokenizer.json"))
        if (run / "completed.json").exists():
            if request.s3_prefix:
                scratch_storage.publish(run, request.s3_prefix)
            return json.loads((run / "completed.json").read_text())
    else:
        run.mkdir(parents=True, exist_ok=initializing.exists())
        atomic_json(initializing, contract)
        shutil.copyfile(request.config, run / "config.yaml")
        scratch_storage.copy_preparation(request.data, run)
        progress.emit(
            phase="fit_train_only_bpe",
            completed=0,
            total=min(len(partitions["train"]), config["tokenizer"]["max_train_files"]),
        )

        def contents():
            for index, row in enumerate(
                partitions["train"][: config["tokenizer"]["max_train_files"]]
            ):
                path = request.data / "exe" / row["relative_path"]
                if file_digest(path) != row["exe_sha256"]:
                    raise RandsTrainingError("Tokenizer input checksum mismatch.")
                with path.open("rb") as handle:
                    yield handle.read(config["tokenizer"]["max_bytes_per_file"])
                if index % 100 == 0:
                    progress.emit(phase="fit_train_only_bpe", completed=index + 1)

        tokenizer = train_exe_bpe_tokenizer(
            contents(), config["tokenizer"]["vocab_size"], full_byte_coverage=True
        )
        tokenizer_digest = write_private_tokenizer(tokenizer, run / "tokenizer.json")
        manifest = {
            "contract": contract,
            "environment": environment,
            "git_revision": _git_revision(),
            "tokenizer_sha256": tokenizer_digest,
            "tokenizer_fit": "deterministic prefix of frozen RanDS training sources only",
            "initialization": "random; no pretrained weights",
            "command": request.command,
            "split_counts": prepared["split_counts"],
            "excluded_by_reason": prepared["excluded_by_reason"],
            "resume_environments": [],
        }
        atomic_json(run / "run-manifest.json", manifest)
    progress.emit(phase="build_model")
    model = _model(config, tokenizer).to(device)
    t = config["training"]
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=t["learning_rate"], weight_decay=t["weight_decay"]
    )
    batch_size, accumulation = t["batch_size"], t["gradient_accumulation_steps"]
    batches = math.ceil(len(partitions["train"]) / batch_size)
    updates_per_epoch = math.ceil(batches / accumulation)
    total_updates = updates_per_epoch * t["epochs"]
    warmup = int(total_updates * t["warmup_ratio"])
    scheduler = torch.optim.lr_scheduler.LambdaLR(
        optimizer,
        lambda step: min(
            (step + 1) / max(1, warmup),
            max(0, (total_updates - step) / max(1, total_updates - warmup)),
        ),
    )
    cache_identity = {
        "split": contract["split"],
        "tokenizer": manifest["tokenizer_sha256"],
        "max_tokens": config["model"]["max_tokens"],
    }
    datasets = {
        name: token_cache(
            ExeDataset(request.data / "exe", values, tokenizer, config["model"]["max_tokens"]),
            run / "cache",
            name,
            cache_identity,
            config,
            progress,
        )
        for name, values in partitions.items()
    }
    cache_digests = {name: file_digest(run / "cache" / (name + ".json")) for name in datasets}
    if "cache_digests" in manifest and manifest["cache_digests"] != cache_digests:
        raise RandsTrainingError("Token cache index differs from the frozen run.")
    manifest["cache_digests"] = cache_digests
    atomic_json(run / "run-manifest.json", manifest)
    state: dict[str, Any] = {
        "epoch": 0,
        "next_batch": 0,
        "updates": 0,
        "samples": 0,
        "epoch_loss_sum": 0.0,
        "epoch_samples": 0,
        "best_auc": -1.0,
        "best_threshold": 0.5,
        "history": [],
        "runtime_seconds": 0.0,
    }
    if resumed:
        checkpoint = torch.load(run / "last.pt", map_location="cpu", weights_only=True)
        if checkpoint["contract"] != contract:
            raise RandsTrainingError("Checkpoint contract mismatch.")
        model.load_state_dict(checkpoint["model"])
        if checkpoint.get("best") is not None:
            _save(run / "best.pt", checkpoint["best"])
        optimizer.load_state_dict(checkpoint["optimizer"])
        scheduler.load_state_dict(checkpoint["scheduler"])
        state = checkpoint["state"]
        _restore_rng(checkpoint["rng"])
        manifest["resume_environments"].append(environment)
        atomic_json(run / "run-manifest.json", manifest)
    state["parameter_count"] = sum(parameter.numel() for parameter in model.parameters())
    invocation_started = time.monotonic()
    previous_runtime = state["runtime_seconds"]
    previous_samples = state["samples"]
    interrupted = threading.Event()
    old_handlers = {}
    if threading.current_thread() is threading.main_thread():
        for number in [signal.SIGINT, signal.SIGTERM]:
            old_handlers[number] = signal.signal(number, lambda signum, frame: interrupted.set())

    def checkpoint_now() -> None:
        state["runtime_seconds"] = previous_runtime + time.monotonic() - invocation_started
        progress.emit(
            phase="checkpoint",
            epoch=state["epoch"] + 1,
            updates=state["updates"],
            samples=state["samples"],
        )
        _save(
            run / "last.pt",
            {
                "schema": 1,
                "contract": contract,
                "model": model.state_dict(),
                "optimizer": optimizer.state_dict(),
                "scheduler": scheduler.state_dict(),
                "state": state,
                "rng": _rng(),
                "best": torch.load(run / "best.pt", map_location="cpu", weights_only=True)
                if (run / "best.pt").exists()
                else None,
            },
        )
        atomic_json(run / "history.json", state["history"])
        if request.s3_prefix:
            progress.emit(phase="upload_checkpoint")
            scratch_storage.publish(run, request.s3_prefix)

    try:
        if not resumed:
            checkpoint_now()
        if request.max_steps is not None and state["updates"] >= request.max_steps:
            return {
                "status": "stopped",
                "updates": state["updates"],
                "samples": state["samples"],
                "run_id": request.run_id,
            }
        while state["epoch"] < t["epochs"]:
            epoch = state["epoch"]
            order = torch.randperm(
                len(datasets["train"]), generator=torch.Generator().manual_seed(seed + epoch)
            ).tolist()
            start_batch = state["next_batch"]
            loader = _loader(
                datasets["train"], config, order[start_batch * batch_size :], seed=seed + epoch
            )
            model.train()
            optimizer.zero_grad(set_to_none=True)
            last_log = time.monotonic()
            for batch_index, batch in enumerate(loader, start=start_batch):
                # Every saved next_batch is an optimizer boundary; the last short
                # accumulation window is weighted by its actual number of samples.
                window_start = (batch_index // accumulation) * accumulation * batch_size
                window_samples = min(accumulation * batch_size, len(order) - window_start)
                targets = batch["labels"].to(device)
                with _precision(config, device):
                    output = model(
                        batch["input_ids"].to(device),
                        labels=targets,
                        **_kwargs(batch, config, device),
                    )
                    loss = output.loss * len(targets) / window_samples
                if not torch.isfinite(loss):
                    raise RandsTrainingError(
                        "Non-finite training loss; checkpoint remains at last committed update."
                    )
                loss.backward()
                state["epoch_loss_sum"] += output.loss.item() * len(targets)
                state["epoch_samples"] += len(targets)
                state["samples"] += len(targets)
                boundary = (batch_index + 1) % accumulation == 0 or batch_index + 1 == batches
                if boundary:
                    norm = torch.nn.utils.clip_grad_norm_(model.parameters(), t["max_grad_norm"])
                    if not torch.isfinite(norm):
                        raise RandsTrainingError(
                            "Non-finite gradients; last checkpoint preserved."
                        )
                    optimizer.step()
                    scheduler.step()
                    optimizer.zero_grad(set_to_none=True)
                    state["updates"] += 1
                    state["next_batch"] = batch_index + 1
                    stopped = interrupted.is_set() or (
                        request.max_steps is not None and state["updates"] >= request.max_steps
                    )
                    if state["updates"] % config["runtime"]["checkpoint_updates"] == 0 or stopped:
                        checkpoint_now()
                    if stopped:
                        result = {
                            "status": "stopped",
                            "updates": state["updates"],
                            "samples": state["samples"],
                            "run_id": request.run_id,
                        }
                        progress.emit(phase="stopped", **result)
                        return result
                if time.monotonic() - last_log >= config["runtime"]["progress_seconds"]:
                    elapsed = time.monotonic() - invocation_started
                    rate = (state["samples"] - previous_samples) / max(elapsed, 1e-9)
                    progress.emit(
                        phase="train",
                        epoch=epoch + 1,
                        epochs=t["epochs"],
                        samples=state["samples"],
                        epoch_samples=state["epoch_samples"],
                        epoch_total=len(order),
                        updates=state["updates"],
                        total_updates=total_updates,
                        loss=round(output.loss.item(), 6),
                        samples_per_second=round(rate, 3),
                        eta_seconds=round(
                            (len(order) * t["epochs"] - state["samples"]) / max(rate, 1e-9)
                        ),
                    )
                    last_log = time.monotonic()
            progress.emit(phase="validation", completed=0, total=len(datasets["validation"]))
            val_loss, probabilities, labels = evaluate(
                model, datasets["validation"], config, device, progress, "validation"
            )
            auc = _binary_auc(probabilities, labels)
            ap, threshold = _rank_metrics(probabilities, labels)
            record = {
                "epoch": epoch + 1,
                "train_loss": state["epoch_loss_sum"] / state["epoch_samples"],
                "validation_loss": val_loss,
                "validation_roc_auc": auc,
                "validation_average_precision": ap,
                "validation_threshold": threshold,
            }
            if auc > state["best_auc"]:
                state["best_auc"], state["best_threshold"] = auc, threshold
                _save(
                    run / "best.pt",
                    {"model": model.state_dict(), "epoch": epoch + 1, "threshold": threshold},
                )
            state["history"].append(record)
            progress.emit(phase="epoch_complete", **record)
            state.update(epoch=epoch + 1, next_batch=0, epoch_loss_sum=0.0, epoch_samples=0)
            checkpoint_now()
            if interrupted.is_set():
                return {"status": "stopped", "updates": state["updates"], "run_id": request.run_id}
        best = torch.load(run / "best.pt", map_location=device, weights_only=True)
        model.load_state_dict(best["model"])
        progress.emit(phase="test", completed=0, total=len(datasets["test"]))
        test_loss, probabilities, labels = evaluate(
            model, datasets["test"], config, device, progress, "test"
        )
        ap, _ = _rank_metrics(probabilities, labels)
        threshold = best["threshold"]
        metrics = {
            "test": {
                "loss": test_loss,
                "roc_auc": _binary_auc(probabilities, labels),
                "average_precision": ap,
                **_threshold_metrics(probabilities, labels, threshold),
            },
            "selection": {
                "epoch": best["epoch"],
                "validation_roc_auc": state["best_auc"],
                "threshold": threshold,
            },
            "runtime_seconds": previous_runtime + time.monotonic() - invocation_started,
            "peak_gpu_memory_bytes": torch.cuda.max_memory_allocated(device)
            if device.type == "cuda"
            else 0,
            "parameter_count": state["parameter_count"],
            "history": state["history"],
            "context_tokens": config["model"]["max_tokens"],
            "input_policy": "prefix, retain BOS/EOS; full EXE preserved",
            "input_bytes": {
                name: sum(int(row["size"]) for row in values)
                for name, values in partitions.items()
            },
            "token_lengths": {name: dataset.stats for name, dataset in datasets.items()},
            "definitely_byte_prefix_limited": {
                name: sum(
                    int(row["size"]) > (config["model"]["max_tokens"] - 2) * 16 for row in values
                )
                for name, values in partitions.items()
            },
        }
        atomic_json(run / "metrics.json", metrics)
        with (run / "test-predictions.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                ["source_sha256", "label", "ransomware_probability", "threshold", "prediction"]
            )
            for row, probability, label in zip(
                partitions["test"], probabilities, labels, strict=True
            ):
                writer.writerow(
                    [
                        row["source_sha256"],
                        label,
                        probability,
                        threshold,
                        int(probability >= threshold),
                    ]
                )
        result = {
            "status": "complete",
            "updates": state["updates"],
            "samples": state["samples"],
            "run_id": request.run_id,
            "test": metrics["test"],
        }
        atomic_json(run / "completed.json", result)
        if request.s3_prefix:
            progress.emit(phase="upload_final_artifacts")
            scratch_storage.publish(run, request.s3_prefix)
        progress.emit(phase="complete", updates=state["updates"], samples=state["samples"])
        return result
    finally:
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
