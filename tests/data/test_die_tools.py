"""Setup preserves preexisting files and rejects corrupted public downloads."""

from hashlib import sha256
import subprocess

import pytest

from malweave.data import die_tools as setup
from malweave.data.storage_io import DataError


def test_fetch_reuses_only_verified_files(tmp_path, monkeypatch):
    target = tmp_path / "tool.tar.gz"
    target.write_bytes(b"synthetic")
    checksum = sha256(b"synthetic").hexdigest()
    monkeypatch.setattr(setup, "_run", lambda *args, **kwargs: pytest.fail("unexpected download"))
    setup._fetch("https://example.invalid/tool.tar.gz", target, checksum)
    with pytest.raises(DataError, match="existing file preserved"):
        setup._fetch("https://example.invalid/tool.tar.gz", target, "wrong")
    assert target.read_bytes() == b"synthetic"


def test_fetch_checks_before_final_rename(tmp_path, monkeypatch):
    target = tmp_path / "tool.tar.gz"

    def download(command):
        (tmp_path / "tool.tar.gz.part").write_bytes(b"bad download")

    monkeypatch.setattr(setup, "_run", download)
    with pytest.raises(DataError, match="Download checksum"):
        setup._fetch("https://example.invalid/tool.tar.gz", target, "wrong")
    assert not target.exists()


def test_setup_command_failure_is_actionable(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "curl")

    monkeypatch.setattr(setup.subprocess, "run", fail)
    with pytest.raises(DataError, match="curl.*prerequisites"):
        setup._run(["curl"])
