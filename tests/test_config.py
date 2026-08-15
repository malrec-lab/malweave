"""Regression checks for the project path contract."""

import os
from pathlib import Path
import unittest
from unittest.mock import patch

from malweave import config


class ConfigPathTests(unittest.TestCase):
    def test_project_paths_are_consistent(self) -> None:
        self.assertEqual(config.PROJECT_ROOT, Path(__file__).resolve().parents[1])
        self.assertEqual(config.RAW_DATA_DIR, config.DATA_DIR / "raw")
        self.assertEqual(config.EXTERNAL_DATA_DIR, config.DATA_DIR / "external")
        self.assertEqual(config.INTERIM_DATA_DIR, config.DATA_DIR / "interim")
        self.assertEqual(config.PROCESSED_DATA_DIR, config.DATA_DIR / "processed")
        self.assertEqual(config.FIGURES_DIR, config.REPORTS_DIR / "figures")

    def test_directory_defaults_when_environment_variable_is_unset(self) -> None:
        default = config.PROJECT_ROOT / "data"
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                config._directory_from_environment("MALWEAVE_TEST_DATA_DIR", default), default
            )

    def test_directory_uses_environment_override(self) -> None:
        configured = config.PROJECT_ROOT / "local-artifacts"
        with patch.dict(os.environ, {"MALWEAVE_TEST_DATA_DIR": str(configured)}, clear=True):
            self.assertEqual(
                config._directory_from_environment(
                    "MALWEAVE_TEST_DATA_DIR", config.PROJECT_ROOT / "data"
                ),
                configured.resolve(),
            )


if __name__ == "__main__":
    unittest.main()
