"""Keep tests independent of local storage destinations and credentials."""

import pytest


@pytest.fixture(autouse=True)
def isolated_project_environment(tmp_path, monkeypatch):
    from malweave import cli

    # Tests can explicitly replace this path when exercising dotenv behavior.
    # A real project .env must never redirect synthetic jobs to a live S3 bucket.
    monkeypatch.setattr(cli, "DOTENV_PATH", tmp_path / ".env")
    monkeypatch.setenv("MALWEAVE_S3_ACCOUNT_ID", "123456789012")
    for variable in (
        "MALWEAVE_RANDS_EXE_S3_PREFIX",
        "MALWEAVE_RANDS_METADATA_S3_PREFIX",
        "MALWEAVE_RANDS_TRAIN_S3_PREFIX",
    ):
        monkeypatch.delenv(variable, raising=False)
