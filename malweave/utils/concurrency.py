"""Async helpers for running blocking file operations concurrently."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable


async def _process_files_asynch(files: list[Path], fn: Callable[[Path], Any], *args) -> list[Any]:
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as pool:
        tasks = [loop.run_in_executor(pool, fn, file, *args) for file in files]
    return await asyncio.gather(*tasks)


def process_files_asynch(files: list[Path], fn: Callable[[Path], Any], *args) -> list[Any]:
    return asyncio.run(_process_files_asynch(files, fn, *args))
