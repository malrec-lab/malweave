"""Tests for versioned RanDS dataset configuration."""

from pathlib import Path

import pytest

from malweave.data.dataset_config import DatasetConfigError, load_rands_dataset_config


def test_load_rands_dataset_config_and_resolve_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "rands.yaml"
    config_path.write_text(
        """
dataset:
  name: rands
  snapshot: "test"
  root_env: TEST_RANDS_ROOT
layout:
  benign_csv: Benign.csv
  ransomware_csv: Ransomware.csv
  samples_dir: dataset
expected:
  shards: 2
  files: 2
  labels:
    benign: 1
    ransomware: 1
protocols:
  full: {}
  x86_unpacked:
    arch: I386
    packed: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    corpus = tmp_path / "corpus"
    monkeypatch.setenv("TEST_RANDS_ROOT", str(corpus))

    config = load_rands_dataset_config(config_path)

    assert config.name == "rands"
    assert config.expected.labels == {"benign": 1, "ransomware": 1}
    assert config.protocols["x86_unpacked"].packed is False
    assert config.resolve_root() == corpus.resolve()
    assert config.resolve_locations().metadata_root == corpus.resolve()


def test_config_resolves_separate_metadata_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "rands.yaml"
    config_path.write_text(
        """
dataset:
  name: rands
  snapshot: test
  root_env: TEST_RANDS_RAW_ROOT
  metadata_root_env: TEST_RANDS_METADATA_ROOT
layout: {benign_csv: Benign.csv, ransomware_csv: Ransomware.csv, samples_dir: dataset}
expected: {shards: 0, files: 0, labels: {benign: 0, ransomware: 0}}
protocols: {full: {}}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    raw_root = tmp_path / "raw"
    metadata_root = tmp_path / "metadata"
    monkeypatch.setenv("TEST_RANDS_RAW_ROOT", str(raw_root))
    monkeypatch.setenv("TEST_RANDS_METADATA_ROOT", str(metadata_root))

    locations = load_rands_dataset_config(config_path).resolve_locations()

    assert locations.raw_root == raw_root.resolve()
    assert locations.metadata_root == metadata_root.resolve()


def test_config_requires_a_local_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "rands.yaml"
    config_path.write_text(
        """
dataset: {name: rands, snapshot: test, root_env: TEST_RANDS_ROOT}
layout: {benign_csv: Benign.csv, ransomware_csv: Ransomware.csv, samples_dir: dataset}
expected:
  shards: 0
  files: 0
  labels: {benign: 0, ransomware: 0}
protocols: {full: {}}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("TEST_RANDS_ROOT", raising=False)

    config = load_rands_dataset_config(config_path)

    with pytest.raises(DatasetConfigError, match="TEST_RANDS_ROOT"):
        config.resolve_root()
