"""Intact-detector A evaluation and synthetic GPU capacity probe; never train models."""

from collections import Counter
import csv
from dataclasses import dataclass
import fcntl
from hashlib import sha256
import json
from pathlib import Path
import platform
import resource
import sqlite3
import struct
import time

import torch
import yaml

from malweave.config import PROJECT_ROOT
from malweave.data.malconv_inputs import verified_prefix
from malweave.training.contracts import SupervisedTrainingError
from malweave.training.finetune_state import test_statistics
from malweave.training.finetune_state import write_json as _write_json
from malweave.training.lmlm_checkpoint import file_sha256
from malweave.training.lmlm_detector import load_released_detector
from malweave.training.supervised import _binary_auc, _threshold_metrics, load_supervised_split


@dataclass(frozen=True)
class ARequest:
    config_path: Path
    checkpoint_path: Path
    split_manifest_path: Path
    exe_root: Path
    output_dir: Path
    device: str
    resume: bool = False
    max_samples: int | None = None
    max_seconds: float | None = None


def write_json(path, value):
    _write_json(path, value)
    path.chmod(0o600)


def _output(path: Path) -> None:
    resolved = path.resolve()
    if resolved.is_relative_to(PROJECT_ROOT):
        relative = resolved.relative_to(PROJECT_ROOT).parts
        if relative[:1] != ("models",) and relative[:2] != ("data", "processed"):
            raise SupervisedTrainingError(
                "A outputs inside the repo belong in models/ or data/processed/."
            )
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def _config(path):
    try:
        return _validated_config(path)
    except (OSError, KeyError, TypeError, AttributeError, yaml.YAMLError) as error:
        raise SupervisedTrainingError(f"Invalid A evaluation configuration: {error}") from error


def _validated_config(path):
    config = yaml.safe_load(path.read_text())
    if (
        config.get("experiment", {}).get("protocol") != "lmlm_a"
        or config["experiment"].get("kind") not in {"benchmark", "feasibility"}
        or "finetuning" in config
        or "tracks" in config
    ):
        raise SupervisedTrainingError(
            "Require explicit lmlm_a evaluation config; training is forbidden."
        )
    evaluation = config["evaluation"]
    for key, expected in {
        "partition": "test",
        "precision": "fp32",
        "batch_size": 1,
        "decision_rule": "argmax",
    }.items():
        if evaluation[key] != expected:
            raise SupervisedTrainingError(f"A requires {key}={expected}.")
    policy = evaluation["bootstrap"]
    if (
        policy["confidence"] != 0.95
        or type(policy["seed"]) is not int
        or policy["seed"] != 0
        or type(policy["replicates"]) is not int
        or policy["replicates"] < 1
    ):
        raise SupervisedTrainingError("Invalid bootstrap policy.")
    if config["experiment"]["kind"] == "benchmark" and policy["replicates"] != 2000:
        raise SupervisedTrainingError("A benchmark requires 2000 bootstrap replicates.")
    limits = config["inputs"]["exe"]
    if set(limits) != {"max_bytes", "max_tokens"}:
        raise SupervisedTrainingError("A requires explicit max_bytes and max_tokens.")
    if config["experiment"]["kind"] == "benchmark" and limits != {
        "max_bytes": 65536,
        "max_tokens": 65536,
    }:
        raise SupervisedTrainingError("A benchmark must preserve the 65536-byte/token context.")
    if type(config["runtime"]["mamba_fast_path_required"]) is not bool:
        raise SupervisedTrainingError("mamba_fast_path_required must be a boolean.")
    if (
        config["experiment"]["kind"] == "benchmark"
        and not config["runtime"]["mamba_fast_path_required"]
    ):
        raise SupervisedTrainingError("A benchmark requires native Mamba CUDA kernels.")
    return config


def _device(name: str, require_fast: bool) -> torch.device:
    device = torch.device(name)
    if require_fast:
        from transformers.models.mamba import modeling_mamba

        if device.type != "cuda" or not torch.cuda.is_available():
            raise SupervisedTrainingError("A requires a CUDA device with native Mamba kernels.")
        if not modeling_mamba.is_fast_path_available:
            raise SupervisedTrainingError(
                "Native mamba-ssm and causal-conv1d kernels are unavailable."
            )
    if device.type == "cuda":
        torch.backends.cuda.matmul.allow_tf32 = False
        torch.backends.cudnn.allow_tf32 = False
    return device


def _hardware(device):
    return {
        "python": platform.python_version(),
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "device": str(device),
        "precision": "fp32",
        "gpu": torch.cuda.get_device_name(device) if device.type == "cuda" else None,
        "peak_allocated_bytes": torch.cuda.max_memory_allocated(device)
        if device.type == "cuda"
        else 0,
        "peak_reserved_bytes": torch.cuda.max_memory_reserved(device)
        if device.type == "cuda"
        else 0,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
    }


def _cohort(request, config, loaded):
    """Reuse C's frozen cohort, checking the detector's tokenizer, not its different config hash."""
    if config["experiment"]["kind"] != "benchmark":
        return None
    summary_path = request.split_manifest_path.parent / "summary.json"
    summary = json.loads(summary_path.read_text())
    identity = summary["model_input_audit"]["identity"]
    if (
        summary["policy"] != config["cohort"]
        or summary["output_sha256"]["split.csv"] != file_sha256(request.split_manifest_path)
        or identity["tokenizer_sha256"]
        != loaded.provenance["source_files_sha256"]["tokenizer.json"]
        or identity["production_adapter_sha256"]
        != file_sha256(PROJECT_ROOT / "malweave/data/lmlm_inputs.py")
        or identity["max_bytes"] != loaded.inputs.max_bytes
        or identity["max_tokens_including_bos_eos"] != loaded.inputs.max_tokens
    ):
        raise SupervisedTrainingError(
            "Detector preprocessing does not match the frozen round-02 audit."
        )
    source = loaded.provenance["source_config"]
    if source["hidden_size"] != 384 or source["num_hidden_layers"] != 32:
        raise SupervisedTrainingError("A benchmark requires the selected H384, 32-layer detector.")
    if loaded.provenance["source_global_step"] != 1923:
        raise SupervisedTrainingError(
            "A benchmark requires metadata for the selected detector 1923."
        )
    return {"summary_sha256": file_sha256(summary_path), **summary["model_input_audit"]}


def run_a(request: ARequest) -> dict:
    """Evaluate test only, commit one prediction at a time, and resume an identical run."""
    if request.max_samples is not None and (
        type(request.max_samples) is not int or request.max_samples < 1
    ):
        raise SupervisedTrainingError("max-samples must be a positive integer.")
    if request.max_seconds is not None and not 0 < request.max_seconds < float("inf"):
        raise SupervisedTrainingError("max-seconds must be positive and finite.")
    config = _config(request.config_path)
    limits = config["inputs"]["exe"]
    loaded = load_released_detector(request.checkpoint_path, **limits)
    audit = _cohort(request, config, loaded)
    examples = [
        row for row in load_supervised_split(request.split_manifest_path) if row.split == "test"
    ]
    if {r.label for r in examples} != {0, 1}:
        raise SupervisedTrainingError("A requires both classes in the frozen test partition.")
    device = _device(request.device, config["runtime"]["mamba_fast_path_required"])
    if (
        request.output_dir.resolve().is_relative_to(request.checkpoint_path.resolve())
        or request.output_dir.resolve().is_relative_to(request.exe_root.resolve())
        or request.split_manifest_path.resolve().is_relative_to(request.output_dir.resolve())
    ):
        raise SupervisedTrainingError("A output directory must be separate from its inputs.")
    _output(request.output_dir)
    with (request.output_dir / "run.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SupervisedTrainingError(
                "Another A evaluator owns this output directory."
            ) from error
        return _evaluate(request, config, loaded, audit, examples, device)


def _evaluate(request, config, loaded, audit, examples, device):
    root = request.output_dir
    groups = {}
    if audit:
        with request.split_manifest_path.open() as stream:
            groups = {
                r["source_sha256"]: r["active_leakage_group_sha256"]
                for r in csv.DictReader(stream)
            }
    identity = {
        "config_sha256": file_sha256(request.config_path),
        "split_sha256": file_sha256(request.split_manifest_path),
        "checkpoint": loaded.provenance["source_files_sha256"],
        "trainer_state_sha256": loaded.provenance["source_trainer_state_sha256"],
        "cohort_summary_sha256": audit["summary_sha256"] if audit else None,
        "device_type": device.type,
        "torch": torch.__version__,
        "code_sha256": {
            name: file_sha256(PROJECT_ROOT / name)
            for name in (
                "malweave/evaluation/lmlm_a.py",
                "malweave/training/lmlm_detector.py",
                "malweave/models/mamba.py",
                "malweave/data/lmlm_inputs.py",
                "malweave/data/malconv_inputs.py",
                "malweave/training/supervised.py",
                "malweave/training/finetune_state.py",
                "uv.lock",
            )
        },
    }
    state_path = root / "state.sqlite3"
    existed = state_path.exists()
    if existed and not request.resume:
        raise SupervisedTrainingError(
            "A state already exists; use --resume or a new output directory."
        )
    with sqlite3.connect(state_path) as db:
        state_path.chmod(0o600)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS identity (value TEXT NOT NULL)")
        db.execute(
            "CREATE TABLE IF NOT EXISTS result (source TEXT PRIMARY KEY, payload TEXT NOT NULL)"
        )
        old = db.execute("SELECT value FROM identity").fetchone()
        if old and json.loads(old[0]) != identity:
            raise SupervisedTrainingError(
                "A resume identity changed: source/config/cohort/checkpoint/runtime."
            )
        if not old:
            db.execute("INSERT INTO identity VALUES (?)", (json.dumps(identity, sort_keys=True),))
            db.commit()
        records = {s: json.loads(p) for s, p in db.execute("SELECT source,payload FROM result")}
        if not set(records) <= {row.source_sha256 for row in examples}:
            raise SupervisedTrainingError("State contains sources outside the frozen test split.")
        previous = (
            json.loads((root / "progress.json").read_text())
            if (root / "progress.json").exists()
            else {}
        )
        elapsed_before = previous.get("elapsed_seconds", 0)
        loaded.model.to(device)
        if device.type == "cuda":
            torch.cuda.reset_peak_memory_stats(device)
        started = time.monotonic()
        manifest = {
            "experiment": "A",
            "status": "running",
            "identity": identity,
            "initialization": loaded.provenance,
            "cohort_input_audit": audit,
            "decision_rule": "softmax_argmax; ties select class 0",
            "test_total": len(examples),
            "hardware": _hardware(device),
            "training": False,
        }
        write_json(root / "run-manifest.json", manifest)

        def progress(phase):
            classes = {}
            for label, name in [(0, "benign"), (1, "ransomware")]:
                subset = [r for r in records.values() if r["label"] == label]
                classes[name] = {
                    "total": sum(r.label == label for r in examples),
                    "completed": len(subset),
                    "success": sum(r["status"] == "success" for r in subset),
                    "failed": sum(r["status"] != "success" for r in subset),
                }
            statuses = Counter(r["status"] for r in records.values())
            value = {
                "phase": phase,
                "total": len(examples),
                "completed": len(records),
                "success": statuses["success"],
                "failed": len(records) - statuses["success"],
                "pending": len(examples) - len(records),
                "by_class": classes,
                "elapsed_seconds": elapsed_before + time.monotonic() - started,
                "updated_unix": time.time(),
                "hardware": _hardware(device),
            }
            write_json(root / "progress.json", value)
            return value

        progress("evaluating")
        this_session = 0
        for row in examples:
            if row.source_sha256 in records:
                continue
            if (request.max_samples is not None and this_session >= request.max_samples) or (
                request.max_seconds is not None
                and time.monotonic() - started >= request.max_seconds
            ):
                break
            item = {
                "source_sha256": row.source_sha256,
                "label": row.label,
                "family": row.family,
                "year": row.year,
            }
            sample_started = time.monotonic()
            try:
                path = (request.exe_root / row.exe_relative_path).resolve()
                if not path.is_relative_to(request.exe_root.resolve()):
                    raise ValueError("EXE path escapes the supplied root.")
                content, size = verified_prefix(
                    path, row.exe_representation_sha256, loaded.inputs.max_bytes
                )
                tokens = loaded.inputs.encode_bytes(content)
                token_digest = sha256(
                    struct.pack("<Q", tokens.numel()) + tokens.numpy().astype("<u4").tobytes()
                ).hexdigest()
                if audit and token_digest != groups[row.source_sha256]:
                    raise ValueError(
                        "Actual detector tokens differ from the frozen cohort input group."
                    )
                with torch.inference_mode():
                    logits = loaded.model(tokens.unsqueeze(0).to(device)).logits
                    if logits.shape != (1, 2) or not torch.isfinite(logits).all().item():
                        raise ValueError("Nonfinite or invalid detector logits.")
                    probabilities = torch.softmax(logits.float(), dim=-1)
                    score = probabilities[0, 1].item()
                    prediction = probabilities.argmax(dim=-1).item()
                item.update(
                    status="success",
                    ransomware_probability=score,
                    prediction=prediction,
                    threshold=0.5,
                    input_tokens=tokens.numel(),
                    input_sha256=token_digest,
                    exe_bytes_verified=size,
                )
            except (OSError, ValueError, RuntimeError) as error:
                item.update(status="error", error_type=type(error).__name__, error=str(error))
            item["runtime_seconds"] = time.monotonic() - sample_started
            db.execute("INSERT INTO result VALUES (?,?)", (row.source_sha256, json.dumps(item)))
            db.commit()
            records[row.source_sha256] = item
            this_session += 1
            current = progress("evaluating")
            if this_session == 1 or this_session % 10 == 0:
                print(json.dumps(current), flush=True)
            if item.get("error_type") == "OutOfMemoryError":
                break
        phase = (
            "failed"
            if any(r["status"] != "success" for r in records.values())
            else ("completed" if len(records) == len(examples) else "paused")
        )
        current = progress(phase)
        manifest.update(
            status=phase, hardware=current["hardware"], elapsed_seconds=current["elapsed_seconds"]
        )
        _export(root, [records[r.source_sha256] for r in examples if r.source_sha256 in records])
        if phase == "completed":
            ordered = [records[r.source_sha256] for r in examples]
            probabilities = [r["ransomware_probability"] for r in ordered]
            labels = [r["label"] for r in ordered]
            predictions = [r["prediction"] for r in ordered]
            test = _threshold_metrics(probabilities, labels, 0.5, predictions)
            test.pop("balanced_accuracy")
            matrix = test["confusion_matrix"]
            test.update(
                tn=matrix[0][0],
                fp=matrix[0][1],
                fn=matrix[1][0],
                tp=matrix[1][1],
                fpr=matrix[0][1] / sum(matrix[0]),
                roc_auc=_binary_auc(probabilities, labels),
            )
            test.update(test_statistics(probabilities, labels, config["evaluation"]["bootstrap"]))
            families = {}
            train_families = {
                row.family
                for row in load_supervised_split(request.split_manifest_path)
                if row.split == "train" and row.label == 1 and row.family
            }
            for row in ordered:
                if row["label"] == 1 and row["family"]:
                    family = families.setdefault(
                        row["family"],
                        {
                            "support": 0,
                            "detected": 0,
                            "present_in_rands_train": row["family"] in train_families,
                        },
                    )
                    family["support"] += 1
                    family["detected"] += row["prediction"]
            for value in families.values():
                value["recall"] = value["detected"] / value["support"]
            test.update(
                families=families,
                mean_family_recall=(
                    sum(v["recall"] for v in families.values()) / len(families)
                    if families
                    else None
                ),
                ransomware_missing_family=sum(
                    r["label"] == 1 and not r["family"] for r in ordered
                ),
            )
            write_json(
                root / "metrics.json",
                {
                    "test": test,
                    "test_sources": len(ordered),
                    "runtime_seconds": current["elapsed_seconds"],
                    "failures": [],
                },
            )
        write_json(root / "run-manifest.json", manifest)
        return current


def _export(root, records):
    names = [
        "source_sha256",
        "label",
        "family",
        "year",
        "ransomware_probability",
        "threshold",
        "prediction",
    ]
    temporary = root / "test-predictions.csv.tmp"
    with temporary.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=names, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(r for r in records if r["status"] == "success")
    temporary.replace(root / "test-predictions.csv")
    (root / "test-predictions.csv").chmod(0o600)
    write_json(root / "failures.json", [r for r in records if r["status"] != "success"])


def probe_a(checkpoint: Path, output: Path, *, device_name="cuda:0", require_fast=True):
    if output.resolve().is_relative_to(checkpoint.resolve()):
        raise SupervisedTrainingError("Probe output must be separate from the checkpoint.")
    _output(output)
    with (output / "run.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SupervisedTrainingError("Another A probe owns this output directory.") from error
        return _probe_a(checkpoint, output, device_name=device_name, require_fast=require_fast)


def _probe_a(checkpoint: Path, output: Path, *, device_name, require_fast):
    """Synthetic bytes and worst-length token IDs only; no RanDS reads or quality metrics."""
    report_path = output / "probe.json"
    if report_path.exists():
        raise SupervisedTrainingError("Probe output already exists; use a fresh output directory.")
    device = _device(device_name, require_fast)
    loaded = load_released_detector(checkpoint)
    loaded.model.to(device)
    report = {
        "kind": "synthetic_capacity",
        "training": False,
        "status": "running",
        "initialization": loaded.provenance,
        "cases": [],
        "hardware": _hardware(device),
    }
    write_json(report_path, report)
    generator = torch.Generator().manual_seed(0)
    vocabulary = sorted(
        set(loaded.inputs.tokenizer.get_vocab().values()) - set(loaded.inputs.special_ids.values())
    )
    cases = [
        ("bytes_256", loaded.inputs.encode_bytes(bytes(range(256)))),
        ("bytes_65536", loaded.inputs.encode_bytes(bytes(range(256)) * 256)),
    ]
    ids = torch.tensor(vocabulary)[torch.randint(len(vocabulary), (65534,), generator=generator)]
    cases.append(
        (
            "tokens_65536_capacity_only",
            torch.cat(
                [
                    torch.tensor([loaded.inputs.special_ids["bos"]]),
                    ids,
                    torch.tensor([loaded.inputs.special_ids["eos"]]),
                ]
            ).long(),
        )
    )
    try:
        for name, tokens in cases:
            if device.type == "cuda":
                torch.cuda.synchronize(device)
                torch.cuda.reset_peak_memory_stats(device)
            started = time.monotonic()
            with torch.inference_mode():
                logits = loaded.model(tokens.unsqueeze(0).to(device)).logits
            if device.type == "cuda":
                torch.cuda.synchronize(device)
            if not torch.isfinite(logits).all().item():
                raise SupervisedTrainingError("Probe produced nonfinite logits.")
            report["cases"].append(
                {
                    "name": name,
                    "tokens": tokens.numel(),
                    "seconds": time.monotonic() - started,
                    "logits": logits.cpu().tolist(),
                    "hardware": _hardware(device),
                }
            )
            write_json(report_path, report)
        report["status"] = "completed"
    except Exception as error:
        report.update(status="failed", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        report["hardware"] = _hardware(device)
        write_json(report_path, report)
    return report
