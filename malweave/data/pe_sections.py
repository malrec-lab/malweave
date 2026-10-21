"""Static extraction of executable PE sections for the LMLM EXE representation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import struct
from typing import Any

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
    audit: dict[str, Any] | None = None

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


def extract_executable_sections(
    content: bytes, *, collect_audit: bool = False, native_diagnostics: bool = False
) -> ExeExtractionResult:
    """Extract EXE bytes without executing or changing the source PE.

    This ports RawByteClf's default LIEF behavior: select sections marked executable or code in
    section-table order, clip a declared range at the file end or following section, and concatenate
    the remaining raw bytes.
    """
    audit: dict[str, Any] | None = (
        {
            "lief_version": lief.__version__,
            "input_bytes": len(content),
            "input_sha256": sha256(content).hexdigest(),
            "native_diagnostics": "captured by isolated worker"
            if native_diagnostics
            else "disabled",
            "sections": [],
        }
        if collect_audit
        else None
    )

    def finish(
        status: str,
        warnings: tuple[str, ...] = (),
        count: int = 0,
        executable_count: int = 0,
        output: bytes | None = None,
    ) -> ExeExtractionResult:
        digest = sha256(output).hexdigest() if output is not None else None
        if audit is not None:
            audit.update(
                status=status,
                warnings=list(warnings),
                section_count=count,
                executable_section_count=executable_count,
                extracted_bytes=len(output) if output is not None else 0,
                representation_sha256=digest,
            )
        return ExeExtractionResult(
            status, warnings, count, executable_count, output, digest, audit
        )

    preflight_status = _preflight_status(content)
    if preflight_status is not None:
        return finish(preflight_status)

    try:
        # Native parser diagnostics are not stable CLI output; structured results carry failures.
        if native_diagnostics:
            lief.logging.enable()
            lief.logging.set_level(lief.logging.LEVEL.INFO)
        else:
            lief.logging.disable()
        binary = lief.parse(content)
    except (RuntimeError, ValueError) as error:
        if audit is not None:
            audit["parse_error"] = str(error)
        binary = None
    if not isinstance(binary, lief.PE.Binary):
        return finish("malformed_pe")

    if audit is not None:
        # Preserve LIEF's structured PE output, not a hand-picked header summary.
        try:
            audit["pe"] = json.loads(lief.to_json(binary))
        except (RuntimeError, ValueError, TypeError) as error:
            audit["serialization_error"] = str(error)
            return finish("lief_audit_error")
        audit["sections"] = [
            {
                "index": index,
                "name": section.name,
                "raw_offset": section.offset,
                "raw_size": section.size,
                "virtual_address": section.virtual_address,
                "virtual_size": section.virtual_size,
                "characteristics": section.characteristics,
                "selected": bool(
                    section.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
                ),
                "copied_bytes": 0,
                "warnings": [],
            }
            for index, section in enumerate(binary.sections)
        ]

    parsed_sections = _sections(binary)
    if not parsed_sections:
        return finish("no_sections")

    sections = [section for section in parsed_sections if section.size > 0]
    if not sections:
        return finish("no_nonempty_sections", count=len(parsed_sections))

    executable_sections = [section for section in sections if section.is_executable]
    if not executable_sections:
        return finish("no_executable_section", count=len(parsed_sections))

    output = bytearray()
    warnings: list[str] = []
    nonempty_indices = [index for index, section in enumerate(parsed_sections) if section.size > 0]
    for index, section in enumerate(sections):
        if not section.is_executable:
            continue

        lower = section.offset
        upper = section.offset + section.size
        section_warnings: list[str] = []
        if upper > len(content):
            upper = len(content)
            section_warnings.append("section_over_file_boundary")
        if index + 1 < len(sections) and upper > sections[index + 1].offset:
            upper = sections[index + 1].offset
            section_warnings.append("section_over_next_section")
        if lower >= upper:
            section_warnings.append(
                "section_empty" if lower == upper else "section_lower_over_upper"
            )
        warnings.extend(section_warnings)
        if audit is not None:
            audit["sections"][nonempty_indices[index]].update(
                effective_start=lower,
                effective_end=upper,
                output_offset=len(output),
                copied_bytes=max(0, upper - lower),
                warnings=section_warnings,
            )
        if lower >= upper:
            continue

        output.extend(content[lower:upper])

    if not output:
        return finish(
            "empty_executable_section",
            tuple(warnings),
            len(parsed_sections),
            len(executable_sections),
        )

    extracted = bytes(output)
    return finish(
        "success",
        tuple(warnings),
        len(parsed_sections),
        len(executable_sections),
        extracted,
    )
