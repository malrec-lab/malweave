"""Read raw sample bytes and names out of zip archives without extracting to disk."""

from __future__ import annotations

from typing import Generator, Optional
import zipfile
from pathlib import Path


def get_data_from_archives(
    archives: list[Path],
    names: bool = True,
    contents: bool = True,
) -> Generator[tuple[Optional[str], Optional[bytes]], None, None]:
    for archive in archives:
        with zipfile.ZipFile(archive, "r") as zp:
            for n in sorted(zp.namelist()):
                b = zp.read(n) if contents else None
                n = n if names else None
                yield n, b


def get_processed_data(root: Path, dataset: str, lift_level: str) -> Generator[tuple[str, bytes], None, None]:
    path = Path(root) / dataset / lift_level
    for archive in sorted(path.iterdir()):
        with zipfile.ZipFile(archive, "r") as zp:
            for n in sorted(zp.namelist()):
                yield n, zp.read(n)
