"""Validated configuration for versioned dataset snapshots."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

import yaml


class DatasetConfigError(ValueError):
    """Raised when a dataset configuration is missing or malformed."""


@dataclass(frozen=True)
class RandsProtocol:
    """Filters defining one reproducible view of the RanDS corpus."""

    arch: str | None = None
    packed: bool | None = None


@dataclass(frozen=True)
class RandsExpectedCounts:
    """Release contract used to catch incomplete or unexpected local data."""

    shards: int
    files: int
    labels: dict[str, int]


@dataclass(frozen=True)
class RandsDatasetLocations:
    """Separate local roots for immutable bytes and shared metadata."""

    raw_root: Path
    metadata_root: Path


@dataclass(frozen=True)
class RandsDatasetConfig:
    """Paths, release identity, and protocols for one RanDS snapshot."""

    name: str
    snapshot: str
    root_env: str
    benign_csv: str
    ransomware_csv: str
    samples_dir: str
    expected: RandsExpectedCounts
    protocols: dict[str, RandsProtocol]
    metadata_root_env: str | None = None

    def resolve_root(self, override: Path | None = None) -> Path:
        """Resolve the raw corpus root; retained for combined-root compatibility."""
        if override is not None:
            return override.expanduser().resolve()

        value = os.environ.get(self.root_env)
        if not value:
            raise DatasetConfigError(
                f"Set {self.root_env} or pass --root to locate the RanDS corpus."
            )
        return Path(value).expanduser().resolve()

    def resolve_locations(
        self,
        raw_override: Path | None = None,
        metadata_override: Path | None = None,
    ) -> RandsDatasetLocations:
        """Resolve separate raw and metadata roots without recording machine paths in Git."""
        raw_root = self.resolve_root(raw_override)
        if metadata_override is not None:
            metadata_root = metadata_override.expanduser().resolve()
        elif self.metadata_root_env is None:
            metadata_root = raw_root
        else:
            value = os.environ.get(self.metadata_root_env)
            metadata_root = Path(value).expanduser().resolve() if value else raw_root
        return RandsDatasetLocations(raw_root=raw_root, metadata_root=metadata_root)


def _mapping(value: Any, key: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DatasetConfigError(f"{key} must be a mapping.")
    return value


def _required_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise DatasetConfigError(f"{key} must be a non-empty string.")
    return value


def _optional_string(mapping: dict[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise DatasetConfigError(f"{key} must be a non-empty string or null.")
    return value


def _required_int(mapping: dict[str, Any], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DatasetConfigError(f"{key} must be a non-negative integer.")
    return value


def load_rands_dataset_config(path: Path) -> RandsDatasetConfig:
    """Load a RanDS YAML config with explicit validation and no code execution."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise DatasetConfigError(f"Dataset config does not exist: {path}") from error
    except yaml.YAMLError as error:
        raise DatasetConfigError(f"Invalid YAML in {path}: {error}") from error

    root = _mapping(raw, "config")
    dataset = _mapping(root.get("dataset"), "dataset")
    layout = _mapping(root.get("layout"), "layout")
    expected_raw = _mapping(root.get("expected"), "expected")
    expected_labels_raw = _mapping(expected_raw.get("labels"), "expected.labels")
    protocols_raw = _mapping(root.get("protocols"), "protocols")

    protocols: dict[str, RandsProtocol] = {}
    for name, protocol_raw in protocols_raw.items():
        if not isinstance(name, str) or not name:
            raise DatasetConfigError("Protocol names must be non-empty strings.")
        protocol = _mapping(protocol_raw, f"protocols.{name}")
        arch = protocol.get("arch")
        packed = protocol.get("packed")
        if arch is not None and not isinstance(arch, str):
            raise DatasetConfigError(f"protocols.{name}.arch must be a string or null.")
        if packed is not None and not isinstance(packed, bool):
            raise DatasetConfigError(f"protocols.{name}.packed must be a boolean or null.")
        protocols[name] = RandsProtocol(arch=arch, packed=packed)

    labels = {
        str(label): _required_int(expected_labels_raw, str(label)) for label in expected_labels_raw
    }
    if set(labels) != {"benign", "ransomware"}:
        raise DatasetConfigError("expected.labels must define benign and ransomware counts.")

    return RandsDatasetConfig(
        name=_required_string(dataset, "name"),
        snapshot=_required_string(dataset, "snapshot"),
        root_env=_required_string(dataset, "root_env"),
        benign_csv=_required_string(layout, "benign_csv"),
        ransomware_csv=_required_string(layout, "ransomware_csv"),
        samples_dir=_required_string(layout, "samples_dir"),
        expected=RandsExpectedCounts(
            shards=_required_int(expected_raw, "shards"),
            files=_required_int(expected_raw, "files"),
            labels=labels,
        ),
        protocols=protocols,
        metadata_root_env=_optional_string(dataset, "metadata_root_env"),
    )
