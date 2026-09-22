"""Synthetic PE tests for RawByteClf-compatible EXE section extraction."""

from __future__ import annotations

import hashlib
import struct

from malweave.data.pe_sections import (
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE,
    extract_executable_sections,
)


def _synthetic_pe(sections: list[tuple[bytes, int, int, int]], *, file_size: int = 0x900) -> bytes:
    """Build a minimal PE32 byte string with caller-controlled section table entries."""
    content = bytearray(file_size)
    content[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", content, 0x3C, pe_offset)
    content[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<H", content, file_header, 0x14C)  # I386
    struct.pack_into("<H", content, file_header + 2, len(sections))
    struct.pack_into("<H", content, file_header + 16, 0xE0)  # PE32 optional header size
    optional_header = file_header + 20
    struct.pack_into("<H", content, optional_header, 0x10B)  # PE32 magic
    section_table = optional_header + 0xE0
    for index, (name, raw_offset, raw_size, characteristics) in enumerate(sections):
        header = section_table + index * 40
        content[header : header + 8] = name[:8].ljust(8, b"\0")
        struct.pack_into("<I", content, header + 16, raw_size)
        struct.pack_into("<I", content, header + 20, raw_offset)
        struct.pack_into("<I", content, header + 36, characteristics)
        for byte_offset in range(raw_offset, min(raw_offset + raw_size, len(content))):
            content[byte_offset] = 0x41 + index
    return bytes(content)


def test_extracts_code_and_executable_sections_in_section_table_order() -> None:
    content = _synthetic_pe(
        [
            (b".data", 0x400, 0x20, 0),
            (b".code", 0x500, 0x20, IMAGE_SCN_CNT_CODE),
            (b".exec", 0x600, 0x20, IMAGE_SCN_MEM_EXECUTE),
        ]
    )

    result = extract_executable_sections(content)

    assert result.status == "success"
    assert result.warnings == ()
    assert result.section_count == 3
    assert result.executable_section_count == 2
    assert result.extracted_bytes == b"B" * 0x20 + b"C" * 0x20
    assert result.representation_sha256 == hashlib.sha256(result.extracted_bytes).hexdigest()


def test_clips_ranges_like_rawbyteclf_and_records_warnings() -> None:
    content = _synthetic_pe(
        [
            (b".code", 0x400, 0x200, IMAGE_SCN_CNT_CODE),
            (b".data", 0x500, 0x20, 0),
        ]
    )

    result = extract_executable_sections(content)

    assert result.status == "success"
    assert result.warnings == ("section_over_next_section",)
    assert result.extracted_bytes == b"A" * 0x100


def test_reports_stable_malformed_and_empty_executable_results() -> None:
    assert extract_executable_sections(b"not a PE").status == "not_pe"
    assert extract_executable_sections(b"MZ").status == "truncated_header"

    invalid_table = bytearray(0xA0)
    invalid_table[:2] = b"MZ"
    struct.pack_into("<I", invalid_table, 0x3C, 0x80)
    invalid_table[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", invalid_table, 0x86, 1)
    struct.pack_into("<H", invalid_table, 0x94, 0xE0)
    assert extract_executable_sections(bytes(invalid_table)).status == "invalid_section_table"

    no_code = _synthetic_pe([(b".data", 0x400, 0x20, 0)])
    assert extract_executable_sections(no_code).status == "no_executable_section"

    empty_code = _synthetic_pe([(b".code", 0x900, 0x20, IMAGE_SCN_CNT_CODE)], file_size=0x900)
    empty = extract_executable_sections(empty_code)
    assert empty.status == "empty_executable_section"
    assert empty.warnings == ("section_over_file_boundary", "section_empty")
