"""Config-driven CLI selection without touching private training inputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from malweave.cli import _experiment_root_path, _parser, _staging_root, _training_request
from malweave.config import PROJECT_ROOT
from malweave.data.s3.inventory import validate_private_path
from malweave.experiments.rands_raw_manifest import load_rands_raw_manifest_preset
from malweave.training.supervised import SupervisedTrainingError, _private_path


@pytest.mark.parametrize("command", ["stage-inputs", "stage-network"])
def test_exe_staging_reuses_common_backends_and_config_representation(monkeypatch, command):
    from malweave import cli

    captured = {}

    def stage(*args, **kwargs):
        captured.update(kwargs)
        return {"passed": True}

    monkeypatch.setenv("MALWEAVE_RANDS_S3_BUCKET", "synthetic")
    for name in ("BUCKET", "ENDPOINT_URL", "REGION"):
        monkeypatch.setenv("RUNPOD_S3_" + name, "synthetic")
    monkeypatch.setattr(cli, "stage_manifest_from_s3", stage)
    monkeypatch.setattr(cli, "stage_network", stage)
    args = [
        "experiment",
        command,
        "--experiment",
        str(PROJECT_ROOT / "configs/experiments/malconv-exe.yaml"),
        "--preset",
        "full",
    ]
    if command == "stage-network":
        args.append("--acknowledge-isolated-worker")
    assert cli.main(args) == 0
    assert captured["representation"] == "exe"
    if command == "stage-network":
        assert captured["destination_prefix"].endswith(
            "rands-malconv-exe/full-train-balanced-dedup"
        )


def test_exe_freeze_and_prepare_are_independent_metadata_aliases(monkeypatch, tmp_path):
    from malweave import cli

    captured = {}

    def freeze(*args, **kwargs):
        captured.update(kwargs)
        return {"passed": True}

    def forbid_raw(*args, **kwargs):
        raise AssertionError("EXE must not call RAW freezing")

    monkeypatch.setattr(cli, "freeze_rands_raw_manifest", forbid_raw)
    monkeypatch.setattr(cli, "prepare_rands_metadata", lambda *a, **kw: tmp_path)
    monkeypatch.setattr(cli, "freeze_exe_s3_manifest", freeze)
    monkeypatch.setenv("MALWEAVE_RANDS_S3_BUCKET", "synthetic")
    config = str(PROJECT_ROOT / "configs/experiments/malconv-exe.yaml")
    assert (
        cli.main(["experiment", "freeze-rands-exe", "--experiment", config, "--preset", "full"])
        == 0
    )
    assert captured["total"] is None
    assert captured["metadata_filters"] == {"arch": "I386", "packed": False}
    assert captured["year_ranges"]["train"] == {"max": 2022}
    captured.clear()
    assert (
        cli.main(["experiment", "prepare-rands-exe", "--experiment", config, "--preset", "full"])
        == 0
    )
    assert captured["metadata_key"] == "rands/representations/exe/manifest.csv"


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
