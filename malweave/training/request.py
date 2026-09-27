"""Training request contract without importing GPU libraries."""

from dataclasses import dataclass
from pathlib import Path


class SupervisedTrainingError(ValueError):
    """Raised when a supervised run would violate its declared contract."""


@dataclass(frozen=True)
class SupervisedRunRequest:
    track: str
    config_path: Path
    split_manifest_path: Path
    raw_root: Path | None
    exe_root: Path | None
    artifact_root: Path
    run_id: str
    device: str
    gradient_accumulation_steps: int
    seed: int
    command: str | None = None
    raw_samples_dir: str = "dataset"
    staging_report: Path | None = None
