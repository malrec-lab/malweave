"""Filesystem and path helpers."""

from __future__ import annotations

import contextlib
import fnmatch
from itertools import chain
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Collection, Generator, Optional


def rglob(top: str, pattern: str, followlinks: bool = True) -> Generator[str, None, None]:
    for root, dirs, files in os.walk(top, followlinks=followlinks):  # pylint: disable=unused-variable
        for name in chain(files, dirs):
            if fnmatch.fnmatch(name, pattern):
                yield os.path.join(root, name)


@contextlib.contextmanager
def maybe_temp_file(path: str | os.PathLike | None, mode: str = "w+b", directory: bool = False, **kwds):
    """
    Yields (path_obj, file_handle). Cleans up temp file automatically.
    """
    if path is None:
        if directory:
            with tempfile.TemporaryDirectory(**kwds) as tmpdir:
                yield Path(tmpdir), None
        else:
            with tempfile.NamedTemporaryFile(mode=mode, **kwds) as f:
                yield Path(f.name), f
    else:
        with open(path, mode) as f:
            yield Path(path), f


def get_unique_files(files: list[os.PathLike | Path]) -> list[os.PathLike | Path]:
    shas, remove = set(), set()
    for i, f in enumerate(files):
        sha = Path(f).stem
        if sha in shas:
            remove.add(i)
        shas.add(sha)
    return [f for i, f in enumerate(files) if i not in remove]


def count_lines_big_file(file: os.PathLike) -> int:
    args = ["wc", "-l", file]
    result = subprocess.run(args, check=True, capture_output=True)
    total = int(result.stdout.split()[0])
    return total


def output_root(vocab_size: int, n_sorel: int, n_windows: int) -> Path:
    return Path(f"{vocab_size}/{n_windows}/{n_sorel}")


def remove_empty_directories(directory: str, missing_ok: bool = False) -> None:
    if missing_ok and not os.path.exists(directory):
        return

    for root, dirs, files in os.walk(directory, topdown=False):  # pylint: disable=unused-variable
        for d in dirs:
            dir_path = os.path.join(root, d)
            if not os.listdir(dir_path):
                os.rmdir(dir_path)


def get_paths_sorted_numerically(
    path: Collection[Path] | Path,
    lstrip: str = "",
    rstrip: str = "",
    reverse: bool = False,
) -> list[Path]:
    def key(p: Path) -> int:
        return int(p.stem.lstrip(lstrip).rstrip(rstrip))

    files = Path(path).iterdir() if isinstance(path, (Path, str)) else path
    return list(sorted(files, key=key, reverse=reverse))


def get_highest_path(
    path: Collection[Path] | Path,
    lstrip: Optional[str] = None,
    rstrip: Optional[str] = None,
    idx: int = -1,
) -> Path:
    """
    Get the highest/lowest numerically indexed path from a directory or a collection of paths.

    Note that lstrip and rstrip are applied to the stem of the path and that they do not align
    with the typical API for str.lstrip and str.rstrip.
    """

    def key(p: Path) -> int:
        s = p.stem
        if lstrip and s.startswith(lstrip):
            s = s[len(lstrip):]
        if rstrip and s.endswith(rstrip):
            s = s[:-len(rstrip)]
        return int(s)

    files = list(Path(path).iterdir()) if isinstance(path, (Path, str)) else path
    if len(files) == 0:
        raise FileNotFoundError(f"{path=}")
    return list(sorted(files, key=key))[idx]


def is_dataset_path(path: Path) -> bool:
    REQUIRED = ("dataset_info.json", "state.json")
    ALLOWED = (".arrow",)

    paths = [p.name for p in path.iterdir()]
    if not all(p in paths for p in REQUIRED):
        return False

    for p in paths:
        if p in REQUIRED:
            continue
        if Path(p).suffix not in ALLOWED:
            return False
    return True


def is_dataset_path_completed(path: Path) -> bool:
    tr_path = path / "tr"
    vl_path = path / "vl"
    ts_path = path / "ts"
    return all(p.exists() for p in (tr_path, vl_path, ts_path)) and all(
        is_dataset_path(p) for p in (tr_path, vl_path, ts_path)
    )
