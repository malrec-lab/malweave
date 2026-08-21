"""Read and write raw binary sample files, synchronously or concurrently."""

from __future__ import annotations

import asyncio
import math
from pathlib import Path
from typing import AsyncGenerator, Generator, Literal, Optional

import numpy as np
import torch
from torch import ByteTensor
from tqdm import tqdm

from malweave.utils import batched

DEFAULT_ASYNCH_CHUNK_SIZE = 500000
DEFAULT_DISABLE_TQDM = True


def read_binary_file(
    f: Path,
    max_length: Optional[int] = None,
    in_memory_dtype: Literal["bytes", "np", "pt"] = "bytes",
) -> bytes | np.ndarray | ByteTensor:
    """
    Will warn with "UserWarning: The given buffer is not writable...", which can
    safely be ignored because we don't care about modifying the bytes object.
    """
    with open(f, "rb") as fp:
        b = fp.read(max_length)

    if in_memory_dtype == "bytes":
        return b
    if in_memory_dtype == "np":
        return np.frombuffer(b, dtype=np.uint8)
    if in_memory_dtype == "pt":
        return torch.frombuffer(b, dtype=torch.uint8)

    raise ValueError(f"Unknown {in_memory_dtype=}")


def read_binary_files(
    files: list[str],
    max_length: Optional[int] = None,
    in_memory_dtype: Literal["bytes", "np", "pt"] = "bytes",
    disable_tqdm: bool = DEFAULT_DISABLE_TQDM,
) -> list[bytes | np.ndarray | ByteTensor]:

    iterable = files
    if not disable_tqdm:
        iterable = tqdm(
            files,
            desc=f"Synchronously loading {len(files)} files...",
        )

    return [read_binary_file(f, max_length, in_memory_dtype) for f in iterable]


def read_binary_files_lazy(
    files: list[str],
    max_length: Optional[int] = None,
    in_memory_dtype: Literal["bytes", "np", "pt"] = "bytes",
    disable_tqdm: bool = DEFAULT_DISABLE_TQDM,
) -> Generator[bytes | np.ndarray | ByteTensor, None, None]:

    iterable = files
    if not disable_tqdm:
        iterable = tqdm(
            files,
            desc=f"Synchronously loading {len(files)} files...",
        )

    for f in iterable:
        yield read_binary_file(f, max_length, in_memory_dtype)


async def read_binary_file_asynch(
    f: Path,
    max_length: Optional[int] = None,
    in_memory_dtype: Literal["bytes", "np", "pt"] = "bytes",
) -> bytes | np.ndarray | ByteTensor:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, read_binary_file, f, max_length, in_memory_dtype)


async def read_binary_files_asynch(
    files: list[str],
    max_length: Optional[int] = None,
    in_memory_dtype: Literal["bytes", "np", "pt"] = "bytes",
    disable_tqdm: bool = DEFAULT_DISABLE_TQDM,
    asynch_chunk_size: int = DEFAULT_ASYNCH_CHUNK_SIZE,
) -> list[bytes | np.ndarray | ByteTensor]:
    """
    Usage
    -----
    >>> loop = asyncio.get_event_loop()
    >>> future = read_binary_files_asynch(files)
    >>> data = loop.run_until_complete(future)
    """
    file_chunks = batched(files, asynch_chunk_size)

    iterable = file_chunks
    if not disable_tqdm:
        n_chunks = math.ceil(len(files) / asynch_chunk_size)
        iterable = tqdm(
            file_chunks,
            desc=f"Asynchronously loading {len(files)} files in {n_chunks} chunks...",
            total=n_chunks,
        )

    x = []
    for batch_files in iterable:
        tasks = [read_binary_file_asynch(f, max_length, in_memory_dtype) for f in batch_files]
        x_i = await asyncio.gather(*tasks)
        x.extend(x_i)
    return x


async def read_binary_files_asynch_lazy(
    files: list[str],
    max_length: Optional[int] = None,
    in_memory_dtype: Literal["bytes", "np", "pt"] = "bytes",
    disable_tqdm: bool = DEFAULT_DISABLE_TQDM,
    asynch_chunk_size: int = DEFAULT_ASYNCH_CHUNK_SIZE,
) -> AsyncGenerator[list[bytes | np.ndarray | ByteTensor], None]:
    """
    Usage
    -----
    >>> loop = asyncio.get_event_loop()
    >>> data = []
    >>> async for result in read_binary_files_asynch(files):
    >>>     data.append(result)
    """
    file_chunks = batched(files, asynch_chunk_size)

    iterable = file_chunks
    if not disable_tqdm:
        n_chunks = math.ceil(len(files) / asynch_chunk_size)
        iterable = tqdm(
            file_chunks,
            desc=f"Asynchronously loading {len(files)} files in {n_chunks} chunks...",
            total=n_chunks,
        )

    for batch_files in iterable:
        tasks = [read_binary_file_asynch(f, max_length, in_memory_dtype) for f in batch_files]
        x_i = await asyncio.gather(*tasks)
        yield x_i


def write_binary_file(f: Path, b: bytes) -> None:
    with open(f, "wb") as fp:
        fp.write(b)


async def write_binary_file_asynch(f: Path, b: bytes) -> None:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, write_binary_file, f, b)


async def write_binary_files_asynch(
    files: list[str],
    data: list[bytes],
    disable_tqdm: bool = DEFAULT_DISABLE_TQDM,
    asynch_chunk_size: int = DEFAULT_ASYNCH_CHUNK_SIZE,
) -> None:
    file_chunks = batched(files, asynch_chunk_size)
    data_chunks = batched(data, asynch_chunk_size)

    iterable = zip(file_chunks, data_chunks)
    if not disable_tqdm:
        n_chunks = math.ceil(len(files) / asynch_chunk_size)
        iterable = tqdm(
            iterable,
            desc=f"Asynchronously writing {len(files)} files in {n_chunks} chunks...",
            total=n_chunks,
        )

    for batch_files, batch_data in iterable:
        tasks = [write_binary_file_asynch(f, b) for f, b in zip(batch_files, batch_data)]
        await asyncio.gather(*tasks)
