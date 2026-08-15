"""Central, side-effect-free paths used by the research pipeline."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _directory_from_environment(variable: str, default: Path) -> Path:
    """Allow large or sensitive artifacts to live outside the repository."""
    value = os.environ.get(variable)
    return Path(value).expanduser().resolve() if value else default


DATA_DIR = _directory_from_environment("MALWEAVE_DATA_DIR", PROJECT_ROOT / "data")
RAW_DATA_DIR = DATA_DIR / "raw"
EXTERNAL_DATA_DIR = DATA_DIR / "external"
INTERIM_DATA_DIR = DATA_DIR / "interim"
PROCESSED_DATA_DIR = DATA_DIR / "processed"

MODELS_DIR = _directory_from_environment("MALWEAVE_MODELS_DIR", PROJECT_ROOT / "models")
REPORTS_DIR = _directory_from_environment("MALWEAVE_REPORTS_DIR", PROJECT_ROOT / "reports")
FIGURES_DIR = REPORTS_DIR / "figures"
CONFIGS_DIR = PROJECT_ROOT / "configs"
