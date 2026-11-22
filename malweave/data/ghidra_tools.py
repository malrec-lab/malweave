"""Opt-in native tool cache and synthetic-only pilot using the existing data CLI."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
import time
from urllib.parse import urlsplit
from urllib.request import urlopen
import zipfile

import yaml

from malweave.config import CONFIGS_DIR, PROJECT_ROOT
from malweave.data.sorel_io import SorelError, digest, job_lock, json_write

PINS = CONFIGS_DIR / "tools" / "ghidra.yaml"


def native_platform() -> str:
    machine = {"amd64": "x86_64", "aarch64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    key = f"{platform.system().lower()}-{machine}"
    if key not in {"linux-x86_64", "darwin-arm64", "darwin-x86_64"}:
        raise SorelError(f"Unsupported native Ghidra platform: {key}; no automatic emulation.")
    return key


def _tree_digest(root: Path) -> str:
    result = sha256()
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            if not path.resolve().is_relative_to(root.resolve()):
                raise SorelError("Tool installation contains an escaping symlink.")
            record = ["link", name, target]
        elif path.is_file():
            record = ["file", name, path.stat().st_mode & 0o777, digest(path)]
        else:
            continue
        result.update(json.dumps(record, separators=(",", ":")).encode() + b"\n")
    return result.hexdigest()


def _download(url: str, expected: str, path: Path) -> None:
    location = urlsplit(url)
    if location.scheme != "https" or not location.netloc or location.username:
        raise SorelError("Tool archives require HTTPS.")
    if path.exists():
        if digest(path) != expected:
            raise SorelError("Cached tool archive changed; refusing to overwrite it.")
        return
    temporary = path.with_suffix(".part")
    try:
        with urlopen(url, timeout=180) as response, temporary.open("wb") as output:
            size = 0
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > 1024**3:
                    raise SorelError("Tool download exceeds its 1 GiB limit.")
                output.write(block)
        if digest(temporary) != expected:
            raise SorelError("Official tool archive checksum mismatch.")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _extract(archive: Path, destination: Path, *, zipped: bool) -> None:
    if zipped:
        with zipfile.ZipFile(archive) as source:
            members = source.infolist()
            if sum(item.file_size for item in members) > 4 * 1024**3:
                raise SorelError("Expanded tool archive exceeds 4 GiB.")
            for item in members:
                path = PurePosixPath(item.filename)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or "\\" in item.filename
                    or (item.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise SorelError("Unsafe tool ZIP member.")
            for item in members:
                output = destination / item.filename
                if item.is_dir():
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with source.open(item) as incoming, output.open("wb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
                    output.chmod((item.external_attr >> 16) & 0o777 or 0o644)
    else:
        with tarfile.open(archive) as source:
            if sum(item.size for item in source.getmembers()) > 4 * 1024**3:
                raise SorelError("Expanded tool archive exceeds 4 GiB.")
            # Python's data filter rejects escaping links, paths and device nodes.
            source.extractall(destination, filter="data")


def setup_ghidra(cache_dir: Path, *, pins_path: Path = PINS) -> dict:
    """Install pinned native tools once; verify the complete cached tree on reuse."""
    key = native_platform()
    pins = yaml.safe_load(pins_path.read_text())
    selected = {"platform": key, "ghidra": pins["ghidra"], "jdk": pins["jdk"][key]}
    identity = sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()
    cache_dir = cache_dir.expanduser().resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    install = cache_dir / f"{key}-{identity[:16]}"
    receipt = install / "tools.json"
    with job_lock(cache_dir / "install.lock"):
        reused = receipt.exists()
        if reused:
            record = json.loads(receipt.read_text())
            if record["identity"] != identity:
                raise SorelError("Tool cache identity mismatch.")
            for name in ("ghidra", "jdk"):
                if _tree_digest(install / name) != record["tree_sha256"][name]:
                    raise SorelError("Installed tool tree changed; use a new clean cache.")
        else:
            if install.exists():
                raise SorelError("Incomplete/conflicting tool installation; choose a clean cache.")
            archives = cache_dir / "archives"
            archives.mkdir(exist_ok=True)
            with TemporaryDirectory(prefix=".ghidra-install-", dir=cache_dir) as temporary:
                staging = Path(temporary)
                for name in ("ghidra", "jdk"):
                    pin = selected[name]
                    archive = archives / (pin["sha256"] + (".zip" if name == "ghidra" else ".tgz"))
                    _download(pin["url"], pin["sha256"], archive)
                    target = staging / name
                    target.mkdir()
                    _extract(archive, target, zipped=name == "ghidra")
                record = {
                    "schema_version": 1,
                    "identity": identity,
                    "platform": key,
                    "pins": selected,
                    "tree_sha256": {
                        name: _tree_digest(staging / name) for name in ("ghidra", "jdk")
                    },
                }
                json_write(staging / "tools.json", record)
                staging.rename(install)
        java_home = install / "jdk" / selected["jdk"]["home"]
        headless = install / "ghidra" / selected["ghidra"]["root"] / "support/analyzeHeadless"
        if not headless.is_file() or not (java_home / "bin/javac").is_file():
            raise SorelError("Pinned installation is missing Ghidra or a complete JDK.")
        version = subprocess.run(
            [str(java_home / "bin/java"), "-version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stderr
        if 'version "21.' not in version:
            raise SorelError("This extraction contract requires JDK 21.")
        return {
            **record,
            "analyze_headless": str(headless),
            "java_home": str(java_home),
            "java_version": version.strip(),
            "tools_file": str(receipt),
            "reused": reused,
        }


def run_ghidra_pilot(cache_dir: Path, output_dir: Path, *, verify_unlimited: bool = False) -> dict:
    """Three generated benign PEs, DIS/DEC, then verified resume; never corpus data."""
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise SorelError("Pilot output already exists; choose a new directory.")
    started = time.monotonic()
    try:
        tools = setup_ghidra(cache_dir)
    except Exception as error:
        output_dir.mkdir(parents=True, mode=0o700)
        json_write(
            output_dir / "pilot-report.json",
            {
                "status": "failed",
                "phase": "tool_setup",
                "scope": "synthetic_environment_compatibility_only",
                "real_samples": 0,
                "failures": [type(error).__name__],
                "seconds": time.monotonic() - started,
            },
        )
        raise
    output_dir.mkdir(parents=True, mode=0o700)
    environment = {
        "PATH": str(Path(tools["java_home"]) / "bin") + os.pathsep + os.defpath,
        "JAVA_HOME": tools["java_home"],
        "HOME": str(output_dir / "runtime/home"),
        "TMPDIR": str(output_dir / "runtime/tmp"),
        "JAVA_TOOL_OPTIONS": "-Djava.awt.headless=true -Xmx2g",
        "LANG": "C.UTF-8",
    }
    for name in ("HOME", "TMPDIR"):
        Path(environment[name]).mkdir(parents=True)
    environment["JAVA_TOOL_OPTIONS"] += (
        f' -Duser.home="{environment["HOME"]}" -Djava.io.tmpdir="{environment["TMPDIR"]}"'
    )
    report = {
        "status": "started",
        "scope": "synthetic_environment_compatibility_only",
        "synthetic_sources": 3,
        "real_samples": 0,
        "gpu_required": False,
        "host": {
            "platform": f"{platform.system()}-{platform.machine()}",
            "cpu_count": os.cpu_count(),
            "python": sys.version.split()[0],
        },
        "tools": tools,
        "phases": [],
        "failures": [],
    }

    def save():
        report["seconds"] = time.monotonic() - started
        json_write(output_dir / "pilot-report.json", report)

    def run(name: str, command: list[str]):
        begin = time.monotonic()
        with (output_dir / f"{name}.log").open("wb") as log:
            subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=1800,
                check=True,
            )
        report["phases"].append({"phase": name, "seconds": time.monotonic() - begin})
        save()

    save()
    try:
        fixture = output_dir / "fixture"
        run(
            "fixture",
            [
                sys.executable,
                str(PROJECT_ROOT / "examples/benign-ghidra/create_fixture.py"),
                str(fixture),
            ],
        )
        common = [sys.executable, "-m", "malweave", "data"]
        run(
            "exe",
            common
            + [
                "extract-exe",
                "--dataset",
                "rands",
                "--config",
                str(fixture / "dataset.yaml"),
                "--root",
                str(fixture / "corpus"),
                "--representation-dir",
                str(fixture / "output/exe"),
                "--state-db",
                str(fixture / "state/exe.sqlite"),
                "--manifest",
                str(fixture / "state/exe-manifest.csv"),
                "--summary",
                str(fixture / "reports/exe.json"),
            ],
        )
        command = common + [
            "extract-ghidra",
            "--dataset",
            "rands",
            "--config",
            str(fixture / "dataset.yaml"),
            "--root",
            str(fixture / "corpus"),
            "--representations",
            "dis",
            "dec",
            "--analyze-headless",
            tools["analyze_headless"],
            "--dis-representation-dir",
            str(fixture / "output/dis"),
            "--dec-representation-dir",
            str(fixture / "output/dec"),
            "--state-db",
            str(fixture / "state/ghidra.sqlite"),
            "--work-dir",
            str(fixture / "work"),
            "--dis-manifest",
            str(fixture / "state/dis-manifest.csv"),
            "--dec-manifest",
            str(fixture / "state/dec-manifest.csv"),
            "--summary",
            str(fixture / "reports/ghidra.json"),
            "--workers",
            "1",
            "--max-cpu",
            "1",
            "--process-timeout-seconds",
            "1080",
        ]
        run("ghidra", command)
        run(
            "assert",
            [
                sys.executable,
                str(PROJECT_ROOT / "examples/benign-ghidra/assert_e2e.py"),
                str(fixture),
            ],
        )
        before = _tree_digest(fixture / "output")
        run("resume", command + ["--resume"])
        if _tree_digest(fixture / "output") != before:
            raise SorelError("Resume changed completed representations.")
        if verify_unlimited:
            count = 0
            for index, source in enumerate(sorted((fixture / "corpus/dataset").glob("*/*"))):
                raw = output_dir / "unlimited" / f"raw-{index}"
                job = output_dir / "unlimited" / f"job-{index}"
                raw.mkdir(parents=True)
                job.mkdir()
                shutil.copyfile(source, raw / source.name)
                config_path = job / "parser-config.json"
                json_write(
                    config_path,
                    {
                        "source": {"sha256": source.name, "transfer": {"status": "synthetic"}},
                        "raw_root": str(raw),
                        "job": str(job),
                        "headless": tools["analyze_headless"],
                        "heap_mb": 1024,
                        "timeout_policy": "unlimited",
                    },
                )
                run(
                    f"unlimited-{index}",
                    [
                        sys.executable,
                        "-c",
                        (
                            "from pathlib import Path;"
                            "from malweave.data.ghidra_benchmark import parser_source;"
                            f"parser_source(Path({str(config_path)!r}))"
                        ),
                    ],
                )
                views = json.loads((job / "parser-result.json").read_text())["views"]
                for view in views:
                    baseline = (
                        fixture
                        / "output"
                        / view["view"]
                        / source.name[:2]
                        / (source.name + (".asm" if view["view"] == "dis" else ".c"))
                    )
                    if (
                        view["status"] != "success"
                        or (job / view["output_path"]).read_bytes() != baseline.read_bytes()
                    ):
                        raise SorelError("Unlimited synthetic outputs differ from baseline.")
                    count += 1
            report["unlimited_verified_views"] = count
        cache = setup_ghidra(cache_dir)
        if not cache["reused"]:
            raise SorelError("Tool cache was not reusable.")
        report.update(
            status="passed",
            resume_outputs_unchanged=True,
            tool_cache_reused=True,
            output_sha256=before,
            extraction=json.loads((fixture / "reports/ghidra.json").read_text()),
            output_bytes=sum(
                p.stat().st_size for p in (fixture / "output").rglob("*") if p.is_file()
            ),
        )
    except Exception as error:
        report["status"] = "failed"
        report["failures"].append(type(error).__name__)
        raise
    finally:
        save()
    return report
