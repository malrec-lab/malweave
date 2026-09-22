"""Static extraction of executable PE sections for the LMLM EXE representation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import struct

import lief

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass(frozen=True)
class ExeExtractionResult:
    """The extracted representation or a stable reason why it could not be produced."""

    status: str
    warnings: tuple[str, ...]
    section_count: int
    executable_section_count: int
    extracted_bytes: bytes | None
    representation_sha256: str | None

    @property
    def extracted_size(self) -> int:
        return len(self.extracted_bytes) if self.extracted_bytes is not None else 0


@dataclass(frozen=True)
class _Section:
    offset: int
    size: int
    is_executable: bool


def _preflight_status(content: bytes) -> str | None:
    """Classify malformed headers before passing bytes to the third-party parser."""
    if len(content) < 2 or content[:2] != b"MZ":
        return "not_pe"
    if len(content) < 0x40:
        return "truncated_header"

    pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
    if pe_offset + 24 > len(content):
        return "truncated_header"
    if content[pe_offset : pe_offset + 4] != b"PE\0\0":
        return "not_pe"

    section_count = struct.unpack_from("<H", content, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", content, pe_offset + 20)[0]
    section_table_end = pe_offset + 24 + optional_header_size + section_count * 40
    if section_table_end > len(content):
        return "invalid_section_table"
    return None


def _sections(binary: lief.PE.Binary) -> list[_Section]:
    return [
        _Section(
            offset=section.offset,
            size=section.size,
            is_executable=bool(
                section.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
            ),
        )
        for section in binary.sections
    ]


def extract_executable_sections(content: bytes) -> ExeExtractionResult:
    """Extract EXE bytes without executing or changing the source PE.

    This ports RawByteClf's default LIEF behavior: select sections marked executable or code in
    section-table order, clip a declared range at the file end or following section, and concatenate
    the remaining raw bytes.
    """
    preflight_status = _preflight_status(content)
    if preflight_status is not None:
        return ExeExtractionResult(preflight_status, (), 0, 0, None, None)

    try:
        # Native parser diagnostics are not stable CLI output; structured results carry failures.
        lief.logging.disable()
        binary = lief.parse(content)
    except (RuntimeError, ValueError):
        binary = None
    if not isinstance(binary, lief.PE.Binary):
        return ExeExtractionResult("malformed_pe", (), 0, 0, None, None)

    parsed_sections = _sections(binary)
    if not parsed_sections:
        return ExeExtractionResult("no_sections", (), 0, 0, None, None)

    sections = [section for section in parsed_sections if section.size > 0]
    if not sections:
        return ExeExtractionResult("no_nonempty_sections", (), len(parsed_sections), 0, None, None)

    executable_sections = [section for section in sections if section.is_executable]
    if not executable_sections:
        return ExeExtractionResult(
            "no_executable_section", (), len(parsed_sections), 0, None, None
        )

    output = bytearray()
    warnings: list[str] = []
    for index, section in enumerate(sections):
        if not section.is_executable:
            continue

        lower = section.offset
        upper = section.offset + section.size
        if upper > len(content):
            upper = len(content)
            warnings.append("section_over_file_boundary")
        if index + 1 < len(sections) and upper > sections[index + 1].offset:
            upper = sections[index + 1].offset
            warnings.append("section_over_next_section")
        if lower >= upper:
            warnings.append("section_empty" if lower == upper else "section_lower_over_upper")
            continue

        output.extend(content[lower:upper])

    if not output:
        return ExeExtractionResult(
            "empty_executable_section",
            tuple(warnings),
            len(parsed_sections),
            len(executable_sections),
            None,
            None,
        )

    extracted = bytes(output)
    return ExeExtractionResult(
        "success",
        tuple(warnings),
        len(parsed_sections),
        len(executable_sections),
        extracted,
        sha256(extracted).hexdigest(),
    )
