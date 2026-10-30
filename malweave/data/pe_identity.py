"""Verify erased SOREL header metadata using the original source digest.

RawByteClf commit 2502450e40ac00363e168106662aac29821d4a93 contains a digest-search
utility in src/data/pe_utils.py. This independent implementation only feeds candidate
metadata to a hash function: it never constructs, writes or returns a re-armed PE.
The subsystem field is at OptionalHeader + 68 for BOTH PE32 and PE32+ (PE/COFF).
A match authenticates header metadata, not the behavior or validity of machine code.
"""

from __future__ import annotations

from collections.abc import Callable
from hashlib import sha256
from itertools import product
from pathlib import Path
import re
import struct
import time
from typing import Any, BinaryIO

METHOD = "sorel-original-sha256-header-metadata-v1"
MACHINES = (
    0x014C,
    0x8664,
    0xAA64,
    0x01C0,
    0x01C2,
    0x01C4,
    0xA641,
    0xA64E,
    0x0200,
    0x01F0,
    0x01F1,
    0x0166,
    0x0169,
    0x0266,
    0x0366,
    0x0466,
    0x01A2,
    0x01A3,
    0x01A6,
    0x01A8,
    0x9041,
    0x0EBC,
    0x6232,
    0x6264,
    0x5032,
    0x5064,
    0x5128,
    0x0184,
    0x0284,
    0x0520,
    0x03A0,
    0x01D3,
    0,
)
SUBSYSTEMS = (2, 3, 1, 0, 5, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17)


def _architecture(machine: int) -> str:
    if machine == 0x014C:
        return "i386"
    if machine == 0x8664:
        return "amd64"
    if machine in (0x01C0, 0x01C2, 0x01C4):
        return "arm"
    if machine == 0xAA64:
        return "arm64"
    if machine in (0xA641, 0xA64E):
        return "arm64_hybrid"
    return "unknown" if machine == 0 else "other"


def _feed(
    stream: BinaryIO, hasher: Any, length: int, cancelled: Callable[[], bool] | None
) -> None:
    while length:
        if cancelled is not None and cancelled():
            raise InterruptedError("Header identity verification interrupted")
        chunk = stream.read(min(length, 1024**2))
        if not chunk:
            raise ValueError("PE changed or was truncated during identity verification")
        hasher.update(chunk)
        length -= len(chunk)


def verify_sorel_architecture(
    path: Path, source_sha256: str, *, cancelled: Callable[[], bool] | None = None
) -> dict[str, Any]:
    """Return authenticated original ISA metadata or an explicit unknown result.

    The candidate list is finite, not a proof that every possible original value was
    searched. A mismatch is never evidence that the original ISA was ARM or x86.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        raise ValueError("Expected a lowercase SHA-256 source identifier")
    started = time.monotonic()
    size = path.stat().st_size
    result: dict[str, Any] = {
        "method": METHOD,
        "status": "unknown",
        "architecture": "unknown",
        "candidate_pairs_tested": 0,
        "input_bytes": size,
        "original_sha256": source_sha256,
    }

    def finish(**values: Any) -> dict[str, Any]:
        result.update(values, runtime_seconds=round(time.monotonic() - started, 6))
        return result

    with path.open("rb") as stream:
        dos = stream.read(64)
        if dos[:2] != b"MZ":
            return finish(status="invalid_pe", reason="not_pe")
        if len(dos) < 64:
            return finish(status="invalid_pe", reason="truncated_header")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_offset + 24 > size:
            return finish(status="invalid_pe", reason="truncated_header")
        stream.seek(pe_offset)
        header = stream.read(24)
        if header[:4] != b"PE\0\0":
            return finish(status="invalid_pe", reason="not_pe")
        machine_offset = pe_offset + 4
        optional_offset = pe_offset + 24
        optional_size = struct.unpack_from("<H", header, 20)[0]
        section_count = struct.unpack_from("<H", header, 6)[0]
        if optional_offset + optional_size + section_count * 40 > size:
            return finish(status="invalid_pe", reason="invalid_section_table")
        if optional_size < 70:
            return finish(status="unknown", reason="unsupported_optional_header")
        stream.seek(optional_offset)
        magic = struct.unpack("<H", stream.read(2))[0]
        if magic not in (0x10B, 0x20B):
            return finish(reason="unsupported_optional_header")
        subsystem_offset = optional_offset + 68
        stream.seek(subsystem_offset)
        observed_subsystem = struct.unpack("<H", stream.read(2))[0]
        observed_machine = struct.unpack_from("<H", header, 4)[0]
        result.update(
            pe_format="PE32" if magic == 0x10B else "PE32+",
            observed_machine=observed_machine,
            observed_subsystem=observed_subsystem,
            machine_offset=machine_offset,
            subsystem_offset=subsystem_offset,
        )
        stream.seek(0)
        released = sha256()
        _feed(stream, released, size, cancelled)
        result["released_pe_sha256"] = released.hexdigest()
        if released.hexdigest() == source_sha256:
            return finish(
                status="verified",
                evidence="released_digest_matches_source",
                architecture=_architecture(observed_machine),
                original_machine=observed_machine,
                original_subsystem=observed_subsystem,
            )
        machines = MACHINES if observed_machine == 0 else (observed_machine,)
        subsystems = SUBSYSTEMS if observed_subsystem == 0 else (observed_subsystem,)
        preferred = ((0x14C, 2), (0x14C, 3), (0x8664, 2), (0x8664, 3))
        pairs = list(
            dict.fromkeys(
                pair
                for pair in (*preferred, *product(machines, subsystems))
                if pair[0] in machines and pair[1] in subsystems
            )
        )
        stream.seek(0)
        prefix = sha256()
        _feed(stream, prefix, machine_offset, cancelled)
        # This short span contains the rest of COFF and the optional header prefix.
        middle_size = subsystem_offset - machine_offset - 2
        suffix_offset = subsystem_offset + 2
        for machine, subsystem in pairs:
            candidate = prefix.copy()
            candidate.update(struct.pack("<H", machine))
            stream.seek(machine_offset + 2)
            _feed(stream, candidate, middle_size, cancelled)
            candidate.update(struct.pack("<H", subsystem))
            stream.seek(suffix_offset)
            _feed(stream, candidate, size - suffix_offset, cancelled)
            result["candidate_pairs_tested"] += 1
            if candidate.hexdigest() == source_sha256:
                return finish(
                    status="verified",
                    evidence="original_digest_matches_header_metadata",
                    architecture=_architecture(machine),
                    original_machine=machine,
                    original_subsystem=subsystem,
                )
    return finish(reason="no_matching_original_digest")
