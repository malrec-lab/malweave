"""Config-driven CLI selection without touching private training inputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from malweave.cli import _experiment_root_path, _parser, _staging_root, _training_request
from malweave.config import PROJECT_ROOT
from malweave.data.s3.inventory import validate_private_path
from malweave.experiments.rands_raw_manifest import load_rands_raw_manifest_preset
from malweave.training.supervised import SupervisedTrainingError, _private_path


def test_committed_full_config_is_balanced_and_uses_new_staging_report():
    config = PROJECT_ROOT / "configs/experiments/malconv-raw.yaml"
    preset = load_rands_raw_manifest_preset(config, "full")
    assert preset.balanced is False
    assert preset.balance_splits == ("train",)
    assert preset.total is None
    assert preset.manifest.name == "raw-train-balanced-full-split.csv"
    args = _parser().parse_args(
        [
            "experiment",
            "train",
            "--experiment",
            str(config),
            "--preset",
            "full",
            "--run-id",
            "synthetic",
        ]
    )
    request = _training_request(args, None)
    assert request.split_manifest_path == preset.manifest
    assert request.staging_report.parent.name == "full-train-balanced"


def test_stage_cli_passes_config_cache_and_separate_root(monkeypatch):
    from malweave import cli

    captured = {}

    def stage(*args, **kwargs):
        captured.update(kwargs)
        captured["root"] = args[2]
        return {"passed": True}

    monkeypatch.setenv("MALWEAVE_RANDS_S3_BUCKET", "synthetic")
    monkeypatch.setattr(cli, "stage_manifest_from_s3", stage)
    assert cli.main(["experiment", "stage-inputs", "--preset", "full", "--workers", "4"]) == 0
    assert captured["root"].name == "full-train-balanced"
    assert captured["reuse_root"].name == "full"
    assert captured["workers"] == 4


def test_train_cli_resolves_single_track_and_preset_from_yaml(
    tmp_path: Path,
) -> None:
    config = tmp_path / "experiment.yaml"
    manifest = tmp_path / "split.csv"
    config.write_text(
        f"""
experiment: {{kind: feasibility, seed: 42}}
runtime: {{device: cuda:0, gradient_accumulation_steps: 64}}
data:
  manifest_presets:
    pilot: {{manifest: {manifest}}}
tracks: {{malconvgct: {{}}}}
""",
        encoding="utf-8",
    )
    args = _parser().parse_args(
        [
            "experiment",
            "train",
            "--experiment",
            str(config),
            "--preset",
            "pilot",
            "--run-id",
            "synthetic",
        ]
    )
    request = _training_request(args, None)
    assert request.track == "malconvgct"
    assert request.split_manifest_path == manifest
    assert (request.device, request.gradient_accumulation_steps, request.seed) == (
        "cuda:0",
        64,
        42,
    )
    assert request.artifact_root == PROJECT_ROOT / "work" / "runs" / "experiment"
    assert request.staging_report == (
        PROJECT_ROOT / "work" / "staged" / "experiment" / "pilot" / "staging-summary.json"
    )


def test_work_root_resolves_from_project_not_shell_cwd_or_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MALWEAVE_ROOT_PATH", str(tmp_path / "unused"))
    monkeypatch.chdir(tmp_path)
    assert _experiment_root_path() == PROJECT_ROOT / "work"
    assert _staging_root(
        {"experiment": {"name": "rands-malconv-raw"}}, tmp_path / "config.yaml", "pilot"
    ) == (PROJECT_ROOT / "work" / "staged" / "rands-malconv-raw" / "pilot")
    validate_private_path(PROJECT_ROOT / "work" / "staged" / "rands-malconv-raw" / "pilot")
    _private_path(PROJECT_ROOT / "work" / "runs" / "rands-malconv-raw", "artifact_root")


def test_train_cli_requires_track_when_config_has_multiple(tmp_path: Path) -> None:
    config = tmp_path / "experiment.yaml"
    config.write_text(
        "experiment: {seed: 42}\n"
        "runtime: {device: cpu, gradient_accumulation_steps: 1}\n"
        "tracks: {malconvgct: {}, hrrformer: {}}\n",
        encoding="utf-8",
    )
    args = _parser().parse_args(
        [
            "experiment",
            "train",
            "--experiment",
            str(config),
            "--split-manifest",
            str(tmp_path / "split.csv"),
            "--artifact-root",
            str(tmp_path / "runs"),
            "--run-id",
            "synthetic",
        ]
    )
    with pytest.raises(SupervisedTrainingError, match="Select a track"):
        _training_request(args, None)
