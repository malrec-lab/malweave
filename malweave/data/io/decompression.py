"""Detect and reverse ad-hoc compression applied to raw sample bytes."""

from __future__ import annotations

import bz2
import gc
from functools import partial
import gzip
from io import BytesIO
import lzma
import multiprocessing as mp
import os
from pathlib import Path
from pprint import pformat
from typing import Optional
import zlib

import numpy as np
from tqdm.asyncio import tqdm as atqdm

from malweave.data.io.binary_files import read_binary_files_asynch_lazy, write_binary_files_asynch


class Decompressor:
    # Signatures, for specific compression methods.
    SIG_GZIP = b"\x1f\x8b\x08"
    SIG_BZIP2 = b"\x42\x5a\x68"
    SIG_LZMA = b"\xfd7zXZ\x00"
    SIG_ZLIB = b"x\x9c"
    SIG_7Z = b"7z"

    # Return codes for specific compression methods.
    NONE = 0
    GZIP = 1
    BZIP2 = 2
    LZMA = 3
    ZLIB = 4
    S7Z = 5

    def __init__(self, alg: Optional[int] = None, must_decompress: bool = False) -> None:
        """A universal decompression utility.

        Args:
            alg (Optional[int], optional): An optional integer indicating the expected compression
                algorithm of input data. Defaults to None.
            must_decompress (bool, optional): If True, raises a RuntimeError if the data cannot be
                decompressed using a known algorithm. Defaults to False.
        """
        if alg == Decompressor.S7Z:
            raise NotImplementedError("7z decompression is not supported yet.")
        self.alg = alg
        self.must_decompress = must_decompress

    def __call__(self, data: os.PathLike | BytesIO | bytes, outfile: Optional[os.PathLike] = None) -> tuple[int, bytes]:
        if self.alg == Decompressor.NONE:
            alg = self.alg

        if isinstance(data, (str, Path)):
            with open(data, "rb") as fp:
                if self.alg == Decompressor.NONE:
                    b = fp.read()
                else:
                    alg, b = self.decompress(fp)

        elif isinstance(data, bytes):
            fp = BytesIO(data)
            if self.alg == Decompressor.NONE:
                b = data
            else:
                alg, b = self.decompress(fp)

        elif isinstance(data, BytesIO):
            fp = data
            if self.alg == Decompressor.NONE:
                fp.seek(0)
                b = fp.read()
            else:
                alg, b = self.decompress(fp)

        else:
            raise TypeError(f"Unsupported data type: {type(data)=}")

        if outfile:
            with open(outfile, "rb") as fp:
                fp.write(b)

        return alg, b

    def decompress(self, fp: BytesIO) -> tuple[int, bytes]:
        fp.seek(0)
        signature = fp.read(10)
        fp.seek(0)

        # Try to detect specific signatures and decompress using a targeting method.
        if (self.alg is None or self.alg == Decompressor.GZIP) and signature.startswith(Decompressor.SIG_GZIP):
            return Decompressor._gzip(fp)
        if (self.alg is None or self.alg == Decompressor.BZIP2) and signature.startswith(Decompressor.SIG_BZIP2):
            return Decompressor._bzip2(fp)
        if (self.alg is None or self.alg == Decompressor.LZMA) and signature.startswith(Decompressor.SIG_LZMA):
            return Decompressor._lzma(fp)
        if (self.alg is None or self.alg == Decompressor.ZLIB) and signature.startswith(Decompressor.SIG_ZLIB):
            return Decompressor._zlib(fp)
        if (self.alg is None or self.alg == Decompressor.S7Z) and signature.startswith(Decompressor.SIG_7Z):
            return Decompressor._py7zr(fp)

        # Raise an error if a specific algorithm is requested but the data does not match the signature.
        if self.alg is not None:
            raise RuntimeError(f"Could not decompress the data using {self.alg=}")

        # Brute-force decompression methods if all else fails.
        fns = [
            Decompressor._bzip2,
            Decompressor._gzip,
            Decompressor._lzma,
            Decompressor._zlib,
            # Decompressor._py7zr,  # "7z decompression is not supported yet.")
        ]
        for fn in fns:
            try:
                return fn(fp)
            except Exception as err:  # pylint: disable=broad-exception-caught
                print(err)
                fp.seek(0)

        if self.must_decompress:
            raise RuntimeError("Could not decompress the data using any method.")

        # Return the original file if no decompression method works.
        fp.seek(0)
        return Decompressor.NONE, fp.read()

    @staticmethod
    def _gzip(fp: BytesIO) -> tuple[int, bytes]:
        with gzip.open(fp, "rb") as compressed_file:
            return Decompressor.GZIP, compressed_file.read()

    @staticmethod
    def _bzip2(fp: BytesIO) -> tuple[int, bytes]:
        with bz2.BZ2File(fp, "rb") as compressed_file:
            return Decompressor.BZIP2, compressed_file.read()

    @staticmethod
    def _lzma(fp: BytesIO) -> tuple[int, bytes]:
        with lzma.open(fp, "rb") as compressed_file:
            return Decompressor.LZMA, compressed_file.read()

    @staticmethod
    def _zlib(fp: BytesIO) -> tuple[int, bytes]:
        return Decompressor.ZLIB, zlib.decompress(fp.read())

    @staticmethod
    def _py7zr(fp: BytesIO) -> tuple[int, bytes]:
        raise NotImplementedError("7z decompression is not supported yet.")


def decompress_error_resilient(b: bytes, decompress: Decompressor) -> Optional[tuple[int, bytes]]:
    try:
        return decompress(b)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


async def decompress_collection(
    input_files: list[os.PathLike] = None,
    output_files: Optional[list[os.PathLike]] = None,
    num_workers: int = 1,
    chunk_size: int = 100000,
    delete: bool = False,
    save: bool = True,
) -> None:

    def stats(sizes: list[int | float], div: float = 1.0):
        return {
            "n": len(sizes),
            "median": np.median(sizes) / div,
            "mean": np.mean(sizes) / div,
            "std": np.std(sizes) / div,
            "min": np.min(sizes) / div,
            "max": np.max(sizes) / div,
            "sum": np.sum(sizes) / div,
        }

    decompress = Decompressor(Decompressor.ZLIB, must_decompress=True)
    fn = partial(decompress_error_resilient, decompress=decompress)
    iterable = read_binary_files_asynch_lazy(input_files, asynch_chunk_size=chunk_size)
    pbar = atqdm(
        iterable,
        total=len(input_files) // chunk_size,
        desc="Reading...",
    )

    compressed_sizes = []
    decompressed_sizes = []

    i = 0
    async for data_batch in pbar:
        n = len(data_batch)
        pbar.set_description(f"Decompressing {n} files...")
        compressed_sizes.extend([len(d) for d in data_batch])
        with mp.Pool(num_workers) as p:
            decompressed_data = [d[1] if d is not None else None for d in p.map(fn, data_batch)]
        del data_batch
        gc.collect()
        decompressed_sizes.extend([len(d) for d in decompressed_data if d is not None])

        if delete:
            pbar.set_description(f"Removing {n} files...")
            input_files_batch = input_files[i : i + n]
            for f in input_files_batch:
                os.remove(f)

        if save:
            pbar.set_description(f"Writing {n} files...")
            output_files_batch = output_files[i : i + n]
            non_null_files = [f for j, f in enumerate(output_files_batch) if decompressed_data[j] is not None]
            non_null_data = [d for d in decompressed_data if d is not None]
            await write_binary_files_asynch(non_null_files, non_null_data)

        i += n
        pbar.set_description("Reading...")

    print(f"Compressed File Statistics: {pformat(stats(compressed_sizes, 1e9))}")
    print(f"Decompressed File Statistics: {pformat(stats(decompressed_sizes, 1e9))}")
