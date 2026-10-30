"""Setup preserves preexisting files and rejects corrupted public downloads."""

from hashlib import sha256
import subprocess

import pytest

from malweave.data import sorel_setup as setup
from malweave.data.sorel_io import SorelError


def test_fetch_reuses_only_verified_files(tmp_path, monkeypatch):
    target = tmp_path / "meta.db"
    target.write_bytes(b"synthetic")
    checksum = sha256(b"synthetic").hexdigest()
    monkeypatch.setattr(setup, "_run", lambda *args, **kwargs: pytest.fail("unexpected download"))
    setup._fetch("https://example.invalid/meta.db", target, checksum)
    with pytest.raises(SorelError, match="existing file preserved"):
        setup._fetch("https://example.invalid/meta.db", target, "wrong")
    assert target.read_bytes() == b"synthetic"


def test_fetch_checks_before_final_rename(tmp_path, monkeypatch):
    target = tmp_path / "meta.db"

    def download(command):
        (tmp_path / "meta.db.part").write_bytes(b"bad download")

    monkeypatch.setattr(setup, "_run", download)
    with pytest.raises(SorelError, match="Download checksum"):
        setup._fetch("https://example.invalid/meta.db", target, "wrong")
    assert not target.exists()


def test_setup_command_failure_is_actionable(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "curl")

    monkeypatch.setattr(setup.subprocess, "run", fail)
    with pytest.raises(SorelError, match="curl.*prerequisites"):
        setup._run(["curl"])
