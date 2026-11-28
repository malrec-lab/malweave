"""Install a checksum-pinned portable Detect It Easy scanner."""

from hashlib import sha256
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile

from malweave.data.storage_io import DataError, digest, json_write

DIE_SHA256 = "4d85614dd169c0d23f52084f86e05a503c30429df5fb5ec14de50f23808bc2d4"
ICU_SHA256 = "00d0de456134668f41bd9ea308a076bc0a6a805180445af8a37209d433f41efe"
DIE_URL = (
    "https://github.com/horsicq/DIE-engine/releases/download/3.21/"
    "die_3.21_portable_Ubuntu_20.04_amd64.tar.gz"
)
PORTABLE_ROOT = Path("data/external/tools/die-portable-3.21")
PORTABLE_BASE = PORTABLE_ROOT / "die_linux_portable/base"
ICU_URL = "https://archive.ubuntu.com/ubuntu/pool/main/i/icu/libicu66_66.1-2ubuntu2.1_amd64.deb"


def _fetch(url: str, target: Path, checksum: str) -> None:
    if target.exists():
        if digest(target) != checksum:
            raise DataError(f"Checksum mismatch: {target}; existing file preserved.")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    _run(
        [
            "curl",
            "--fail",
            "--location",
            "--retry",
            "3",
            "--continue-at",
            "-",
            "--output",
            str(partial),
            url,
        ],
    )
    if digest(partial) != checksum:
        raise DataError(f"Download checksum mismatch: {partial}")
    partial.replace(target)


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, check=True, **kwargs)
    except (OSError, subprocess.CalledProcessError) as error:
        raise DataError(
            f"Setup command failed: {command[0]}; check system prerequisites."
        ) from error


def setup_die(root: Path) -> dict[str, str]:
    """No sudo, environment mutation, sample download or sample execution."""
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise DataError("The prepared DiE tool requires Linux x86_64.")
    for command in ("curl", "file", "dpkg-deb"):
        if not shutil.which(command):
            raise DataError(f"Install system prerequisite: {command}")
    tools = root / "data/external/tools"
    portable = root / PORTABLE_ROOT
    base = root / PORTABLE_BASE
    if not (portable / "installation.json").exists():
        _fetch(DIE_URL, tools / "die-portable-3.21.tar.gz", DIE_SHA256)
        _fetch(ICU_URL, tools / "libicu66.deb", ICU_SHA256)
        portable.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tools / "die-portable-3.21.tar.gz") as archive:
            # This exact official archive is pinned above; reject escaping members/links.
            for member in archive.getmembers():
                if not (portable / member.name).resolve().is_relative_to(portable.resolve()):
                    raise DataError("Unsafe tool archive path")
                if member.issym() or member.islnk():
                    raise DataError("Unexpected link in tool archive")
            archive.extractall(portable)
        with tempfile.TemporaryDirectory(dir=tools) as temporary:
            _run(["dpkg-deb", "-x", str(tools / "libicu66.deb"), temporary])
            for path in (Path(temporary) / "usr/lib/x86_64-linux-gnu").glob("libicu*.so*"):
                shutil.copyfile(path, base / path.name)
        json_write(portable / "installation.json", {"die": DIE_SHA256, "icu": ICU_SHA256})
    environment = os.environ.copy()
    environment["LD_LIBRARY_PATH"] = str(base) + ":" + environment.get("LD_LIBRARY_PATH", "")
    version = _run(
        [str(base / "diec"), "--version"],
        env=environment,
        capture_output=True,
        text=True,
    ).stdout.strip()
    env = portable / "env.sh"
    env.write_text(
        "# Source this file from Bash.\n"
        'MALWEAVE_DIE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"\n'
        'export PATH="$MALWEAVE_DIE_ROOT/die_linux_portable/base:$PATH"\n'
        'export LD_LIBRARY_PATH="$MALWEAVE_DIE_ROOT/die_linux_portable/base${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"\n'
    )
    return {
        "die": version,
        "environment": str(env),
    }


def rule_digest(root: Path) -> str:
    result = sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result.update(path.relative_to(root).as_posix().encode())
            result.update(bytes.fromhex(digest(path)))
    return result.hexdigest()
