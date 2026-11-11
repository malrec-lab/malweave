"""Test-only inference, durable resume, and visible integrity failures on synthetic bytes."""

import csv
from dataclasses import replace
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest
from tests.training.test_lmlm_detector import detector_checkpoint
import torch
import yaml

from malweave import cli
from malweave.config import PROJECT_ROOT
from malweave.evaluation import lmlm_a as a
from malweave.experiments.rands_comparison import SPLIT_FIELDS
from malweave.training.contracts import SupervisedTrainingError
from malweave.training.lmlm_checkpoint import file_sha256


@pytest.fixture(autouse=True)
def single_thread():
    previous = torch.get_num_threads()
    torch.set_num_threads(1)
    yield
    torch.set_num_threads(previous)


def experiment(tmp_path):
    checkpoint = tmp_path / "detector"
    detector_checkpoint(checkpoint)
    exe = tmp_path / "exe"
    exe.mkdir()
    rows = []
    for index, partition in enumerate(("train", "validation", "test")):
        for label in ("benign", "ransomware"):
            content = bytes([index, int(label == "ransomware"), 254, 255])
            digest = sha256(content).hexdigest()
            # Intentionally do not stage train/validation payloads.
            if partition == "test":
                (exe / digest).write_bytes(content)
            row = dict.fromkeys(SPLIT_FIELDS, "")
            row.update(
                split=partition,
                label=label,
                source_sha256=sha256(b"PE" + content).hexdigest(),
                exe_representation_sha256=digest,
                active_leakage_group_sha256=digest,
                exe_relative_path=digest,
                family="synthetic" if label == "ransomware" else "",
            )
            rows.append(row)
    split = tmp_path / "split.csv"
    with split.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=SPLIT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    config = yaml.safe_load((PROJECT_ROOT / "configs/experiments/rands-lmlm-a.yaml").read_text())
    config["experiment"]["kind"] = "feasibility"
    config["inputs"]["exe"] = {"max_bytes": 32, "max_tokens": 12}
    config["runtime"]["mamba_fast_path_required"] = False
    config["evaluation"]["bootstrap"]["replicates"] = 20
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))
    return a.ARequest(config_path, checkpoint, split, exe, tmp_path / "output", "cpu")


def test_pause_resume_matches_continuous_without_training_or_input_mutation(tmp_path, monkeypatch):
    request = experiment(tmp_path)
    before = {p: file_sha256(p) for p in request.checkpoint_path.iterdir()}

    def no_training(*args, **kwargs):
        pytest.fail("A must never train or fit")

    monkeypatch.setattr(torch.optim.AdamW, "step", no_training)
    monkeypatch.setattr("malweave.training.supervised.train_exe_bpe_tokenizer", no_training)
    paused = a.run_a(replace(request, max_samples=1))
    assert paused["phase"] == "paused" and paused["pending"] == 1
    assert not (request.output_dir / "metrics.json").exists()
    with pytest.raises(SupervisedTrainingError, match="already exists"):
        a.run_a(request)
    complete = a.run_a(replace(request, resume=True))
    assert complete["phase"] == "completed" and complete["success"] == 2
    other = replace(request, output_dir=tmp_path / "continuous")
    a.run_a(other)
    assert (request.output_dir / "test-predictions.csv").read_bytes() == (
        other.output_dir / "test-predictions.csv"
    ).read_bytes()
    metrics = json.loads((request.output_dir / "metrics.json").read_text())
    assert metrics["test_sources"] == 2
    assert metrics["test"]["families"]["synthetic"]["present_in_rands_train"]
    assert metrics["test"]["roc_auc_ci"]["replicates"] == 20
    assert all(file_sha256(path) == digest for path, digest in before.items())
    assert (request.output_dir / "test-predictions.csv").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("fault", ["missing", "checksum", "escape"])
def test_failed_source_is_durable_and_cannot_produce_final_metrics(tmp_path, fault):
    request = experiment(tmp_path)
    payload = next(request.exe_root.iterdir())
    if fault == "missing":
        payload.unlink()
    elif fault == "checksum":
        payload.write_bytes(b"changed")
    else:
        outside = tmp_path / "outside"
        payload.rename(outside)
        payload.symlink_to(outside)
    result = a.run_a(request)
    assert result["phase"] == "failed"
    assert result["failed"] == 1 and result["completed"] == 2
    failures = json.loads((request.output_dir / "failures.json").read_text())
    assert len(failures) == 1
    assert not (request.output_dir / "metrics.json").exists()
    assert a.run_a(replace(request, resume=True))["failed"] == 1


def test_resume_rejects_changed_inputs_and_softmax_ties_select_benign(tmp_path):
    request = experiment(tmp_path)
    from safetensors.torch import load_file, save_file

    weights = request.checkpoint_path / "model.safetensors"
    tensors = load_file(str(weights))
    for key in ("head_clf.final_layer.weight", "head_clf.final_layer.bias"):
        tensors[key].zero_()
    save_file(tensors, str(weights))
    a.run_a(replace(request, max_samples=1))
    a.run_a(replace(request, resume=True))
    rows = list(csv.DictReader((request.output_dir / "test-predictions.csv").open()))
    assert {r["prediction"] for r in rows} == {"0"}
    assert {r["ransomware_probability"] for r in rows} == {"0.5"}
    request.config_path.write_text(request.config_path.read_text() + "\n")
    with pytest.raises(SupervisedTrainingError, match="identity changed"):
        a.run_a(replace(request, resume=True))


@pytest.mark.parametrize("payload", ["[]", "evaluation: {}", "null"])
def test_malformed_config_has_actionable_error(tmp_path, payload):
    request = experiment(tmp_path)
    request.config_path.write_text(payload)
    with pytest.raises(SupervisedTrainingError):
        a.run_a(request)
    assert not request.output_dir.exists()


def test_cli_test_only_entrypoint(tmp_path):
    request = experiment(tmp_path)
    assert (
        cli.main(
            [
                "experiment",
                "evaluate-a",
                "--experiment",
                str(request.config_path),
                "--checkpoint",
                str(request.checkpoint_path),
                "--split-manifest",
                str(request.split_manifest_path),
                "--exe-root",
                str(request.exe_root),
                "--output-dir",
                str(request.output_dir),
                "--device",
                "cpu",
            ]
        )
        == 0
    )


def test_probe_uses_synthetic_bytes_and_maximum_valid_tokens_only(tmp_path, monkeypatch):
    root = tmp_path / "detector"
    detector_checkpoint(root)
    actual = a.load_released_detector(root)
    calls = []

    class FakeModel:
        def to(self, device):
            return self

        def __call__(self, ids):
            assert not torch.is_grad_enabled()
            calls.append(ids.shape[1])
            assert ids[0, 0] == actual.inputs.special_ids["bos"]
            assert ids[0, -1] == actual.inputs.special_ids["eos"]
            assert ids.max() < actual.inputs.vocab_size
            return SimpleNamespace(logits=torch.tensor([[0.0, 1.0]]))

    actual.model = FakeModel()
    monkeypatch.setattr(a, "load_released_detector", lambda *args, **kwargs: actual)
    result = a.probe_a(root, tmp_path / "probe", device_name="cpu", require_fast=False)
    assert calls == [258, 65536, 65536]
    assert result["status"] == "completed" and result["training"] is False
    with pytest.raises(SupervisedTrainingError, match="already exists"):
        a.probe_a(root, tmp_path / "probe", device_name="cpu", require_fast=False)


@pytest.mark.parametrize("fault", [None, "tokenizer", "adapter", "split", "step"])
def test_benchmark_binds_detector_to_frozen_audit(tmp_path, fault):
    request = experiment(tmp_path)
    config = yaml.safe_load(request.config_path.read_text())
    config["experiment"]["kind"] = "benchmark"
    loaded = a.load_released_detector(request.checkpoint_path, max_bytes=32, max_tokens=12)
    loaded.provenance["source_config"].update(hidden_size=384, num_hidden_layers=32)
    identity = {
        "tokenizer_sha256": file_sha256(request.checkpoint_path / "tokenizer.json"),
        "production_adapter_sha256": file_sha256(PROJECT_ROOT / "malweave/data/lmlm_inputs.py"),
        "max_bytes": 32,
        "max_tokens_including_bos_eos": 12,
    }
    summary = {
        "policy": config["cohort"],
        "output_sha256": {"split.csv": file_sha256(request.split_manifest_path)},
        "model_input_audit": {"identity": identity},
    }
    if fault == "tokenizer":
        identity["tokenizer_sha256"] = "0" * 64
    elif fault == "adapter":
        identity["production_adapter_sha256"] = "0" * 64
    elif fault == "split":
        summary["output_sha256"]["split.csv"] = "0" * 64
    elif fault == "step":
        loaded.provenance["source_global_step"] = 799
    (tmp_path / "summary.json").write_text(json.dumps(summary))
    if fault:
        with pytest.raises(SupervisedTrainingError):
            a._cohort(request, config, loaded)
    else:
        assert a._cohort(request, config, loaded)["identity"] == identity


def test_actual_tokens_must_match_frozen_input_group(tmp_path, monkeypatch):
    request = experiment(tmp_path)
    monkeypatch.setattr(a, "_cohort", lambda *args: {"summary_sha256": "synthetic"})
    result = a.run_a(request)
    assert result["phase"] == "failed" and result["failed"] == 2
    failures = json.loads((request.output_dir / "failures.json").read_text())
    assert all("tokens differ" in row["error"] for row in failures)
    assert not (request.output_dir / "metrics.json").exists()


def test_versioned_notebook_is_parameterized_compilable_and_has_no_outputs():
    notebook = json.loads((PROJECT_ROOT / "notebooks/02-mw-a-kaggle-probe.ipynb").read_text())
    for cell in notebook["cells"]:
        if cell["cell_type"] == "code":
            assert cell["outputs"] == [] and cell["execution_count"] is None
            assert "X-Amz-" not in cell["source"]
            compile(cell["source"], "a-notebook", "exec")
