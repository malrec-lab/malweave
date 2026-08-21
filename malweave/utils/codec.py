"""Byte compression and encryption helpers."""

from __future__ import annotations

import bz2
from enum import Enum
import gzip
from io import BytesIO
import lzma
from typing import Optional
import zlib

import numpy as np

try:
    from Crypto.Cipher import AES
except (ModuleNotFoundError, ImportError) as _err:
    print(f"{_err.__class__.__name__}: Crypto")
try:
    import py7zr
except (ModuleNotFoundError, ImportError) as _err:
    print(f"{_err.__class__.__name__}: py7zr")


class CompressionAlgorithm(Enum):
    GZIP = "gzip"
    BZ2  = "bz2"
    LZMA = "lzma"
    ZLIB = "zlib"
    S7Z  = "s7z"


class EncryptionAlgorithm(Enum):
    AES = "aes"


def compress(
    bs: bytes,
    compression_type: CompressionAlgorithm,
    compression_level: int = 9,
    **kwds,
) -> bytes:

    compression_type = CompressionAlgorithm(compression_type)

    if compression_type == CompressionAlgorithm.GZIP:
        if kwds.get("compresslevel", compression_level) != compression_level:
            raise RuntimeError("Cannot specify both `compresslevel` and `compression_level`.")
        kwds["compresslevel"] = compression_level
        return gzip.compress(bs, **kwds)

    if compression_type == CompressionAlgorithm.BZ2:
        if kwds.get("compresslevel", compression_level) != compression_level:
            raise RuntimeError("Cannot specify both `compresslevel` and `compression_level`.")
        kwds["compresslevel"] = compression_level
        return bz2.compress(bs, **kwds)

    if compression_type == CompressionAlgorithm.LZMA:
        if kwds.get("preset", compression_level) != compression_level:
            raise RuntimeError("Cannot specify both `preset` and `compression_level`.")
        kwds["preset"] = compression_level
        return lzma.compress(bs, **kwds)

    if compression_type == CompressionAlgorithm.ZLIB:
        if kwds.get("level", compression_level) != compression_level:
            raise RuntimeError("Cannot specify both `level` and `compression_level`.")
        kwds["level"] = compression_level
        return zlib.compress(bs, **kwds)

    if compression_type == CompressionAlgorithm.S7Z:
        fp = BytesIO()
        with py7zr.SevenZipFile(fp, "w", **kwds) as archive:
            archive.writef(BytesIO(bs), "tmp")
        fp.seek(0)
        return fp.read()

    raise ValueError(f"Unknown compression type: {compression_type}")


def encrypt(bs: bytes, encryption_type: EncryptionAlgorithm, key: Optional[bytes] = None, **kwds) -> bytes:

    encryption_type = EncryptionAlgorithm(encryption_type)

    key = np.random.randint(0, 256, 16, dtype=np.uint8).tobytes() if key is None else key

    if encryption_type == EncryptionAlgorithm.AES:
        kwds["mode"] = kwds.pop("mode", AES.MODE_CTR)
        cipher = AES.new(key, **kwds)
        return key + cipher.encrypt(bs)

    raise ValueError(f"Unknown encryption type: {encryption_type}")
