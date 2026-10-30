"""Artifact-path and error contracts available without training dependencies."""

from pathlib import Path

from malweave.config import PROJECT_ROOT


class SupervisedTrainingError(ValueError):
    """Raised when a supervised run would violate its declared contract."""


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
