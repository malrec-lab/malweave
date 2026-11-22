"""Synthetic-only checks for native setup, integrity and bounded pilot failures."""

from hashlib import sha256
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
from types import SimpleNamespace
import zipfile

import pytest
import yaml

from malweave.data import ghidra_tools as tools
from malweave.data.sorel_io import SorelError


@pytest.mark.parametrize(
    "system,machine,expected",
    [
        ("Linux", "amd64", "linux-x86_64"),
        ("Darwin", "arm64", "darwin-arm64"),
        ("Darwin", "x86_64", "darwin-x86_64"),
    ],
)
def test_native_platform(monkeypatch, system, machine, expected):
    monkeypatch.setattr(tools.platform, "system", lambda: system)
    monkeypatch.setattr(tools.platform, "machine", lambda: machine)
    assert tools.native_platform() == expected


def test_unsupported_platform_never_emulates(monkeypatch):
    monkeypatch.setattr(tools.platform, "system", lambda: "Linux")
    monkeypatch.setattr(tools.platform, "machine", lambda: "aarch64")
    with pytest.raises(SorelError, match="Unsupported"):
        tools.native_platform()


@pytest.mark.parametrize("name", ["../escaped", "/absolute", "dir\\escaped"])
def test_zip_rejects_unsafe_members_before_writes(tmp_path, name):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("valid", b"synthetic")
        output.writestr(name, b"synthetic")
    destination = tmp_path / "extract"
    with pytest.raises(SorelError, match="Unsafe"):
        tools._extract(archive, destination, zipped=True)
    assert not destination.exists()
    assert not (tmp_path / "escaped").exists()


def test_download_rejects_changed_cached_archive(tmp_path):
    archive = tmp_path / "cached.zip"
    archive.write_bytes(b"synthetic")
    with pytest.raises(SorelError, match="Cached tool archive changed"):
        tools._download("https://example.test/tool.zip", "0" * 64, archive)


def test_setup_reuses_verified_native_tree_and_rejects_tampering(tmp_path, monkeypatch):
    ghidra = tmp_path / "ghidra.zip"
    with zipfile.ZipFile(ghidra, "w") as archive:
        item = zipfile.ZipInfo("ghidra/support/analyzeHeadless")
        item.external_attr = 0o100755 << 16
        archive.writestr(item, b"synthetic launcher")
    jdk = tmp_path / "jdk.tgz"
    with tarfile.open(jdk, "w:gz") as archive:
        for name in ("java", "javac"):
            item = tarfile.TarInfo("jdk/bin/" + name)
            item.size, item.mode = 9, 0o755
            archive.addfile(item, io.BytesIO(b"synthetic"))
    pins = {
        "schema_version": 1,
        "ghidra": {
            "url": str(ghidra),
            "sha256": sha256(ghidra.read_bytes()).hexdigest(),
            "root": "ghidra",
        },
        "jdk": {
            "linux-x86_64": {
                "url": str(jdk),
                "sha256": sha256(jdk.read_bytes()).hexdigest(),
                "home": "jdk",
            }
        },
    }
    config = tmp_path / "pins.yaml"
    config.write_text(yaml.safe_dump(pins))
    calls = []

    def download(url, expected, path):
        assert sha256(Path(url).read_bytes()).hexdigest() == expected
        calls.append(url)
        shutil.copyfile(url, path)

    monkeypatch.setattr(tools, "native_platform", lambda: "linux-x86_64")
    monkeypatch.setattr(tools, "_download", download)
    monkeypatch.setattr(
        tools.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stderr='openjdk version "21.0.13" synthetic\n'),
    )
    cache = tmp_path / "cache"
    first = tools.setup_ghidra(cache, pins_path=config)
    second = tools.setup_ghidra(cache, pins_path=config)
    assert not first["reused"] and second["reused"]
    assert first["identity"] == second["identity"]
    assert len(calls) == 2
    assert Path(first["analyze_headless"]).stat().st_mode & 0o100
    relocated = tmp_path / "restored-cache"
    shutil.copytree(cache, relocated, symlinks=True)
    restored = tools.setup_ghidra(relocated, pins_path=config)
    assert restored["reused"] and restored["identity"] == first["identity"]
    assert Path(restored["analyze_headless"]).is_relative_to(relocated)
    assert len(calls) == 2
    Path(first["analyze_headless"]).write_bytes(b"changed")
    with pytest.raises(SorelError, match="tree changed"):
        tools.setup_ghidra(cache, pins_path=config)


def test_existing_pilot_is_never_overwritten(tmp_path):
    with pytest.raises(SorelError, match="already exists"):
        tools.run_ghidra_pilot(tmp_path / "cache", tmp_path)


def test_setup_failure_still_retains_pilot_report(tmp_path, monkeypatch):
    def fail(*args):
        raise SorelError("Synthetic installer failure")

    monkeypatch.setattr(tools, "setup_ghidra", fail)
    with pytest.raises(SorelError):
        tools.run_ghidra_pilot(tmp_path / "cache", tmp_path / "pilot")
    report = json.loads((tmp_path / "pilot/pilot-report.json").read_text())
    assert report["status"] == "failed" and report["phase"] == "tool_setup"
    assert report["real_samples"] == 0


def test_failed_pilot_retains_report_and_scrubs_parser_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-reach-parser")
    monkeypatch.setenv("KAGGLE_API_TOKEN", "must-not-reach-parser")
    monkeypatch.setattr(tools, "setup_ghidra", lambda *args: {"java_home": "/fake/jdk"})
    seen = []

    def fail(command, **kwargs):
        seen.append(kwargs["env"])
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(tools.subprocess, "run", fail)
    output = tmp_path / "pilot"
    with pytest.raises(subprocess.CalledProcessError):
        tools.run_ghidra_pilot(tmp_path / "cache", output)
    report = json.loads((output / "pilot-report.json").read_text())
    assert report["status"] == "failed" and report["real_samples"] == 0
    assert report["failures"] == ["CalledProcessError"]
    assert "AWS_SECRET_ACCESS_KEY" not in seen[0]
    assert "KAGGLE_API_TOKEN" not in seen[0]
