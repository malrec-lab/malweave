"""Config-driven CLI selection without touching private training inputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from malweave.cli import _experiment_root_path, _parser, _staging_root, _training_request
from malweave.config import PROJECT_ROOT
from malweave.data.s3.inventory import validate_private_path
from malweave.training.supervised import SupervisedTrainingError, _private_path


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
