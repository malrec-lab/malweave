"""Conservative, static PE routing; COFF I386 alone does not establish native x86."""

from __future__ import annotations

from hashlib import sha256
import struct

ROUTING_VERSION = "pe-clr-routing-v2-exclude-dotnet"
MANAGED_POLICY = "exclude_declared_clr_from_dis_dec"


def classify_pe(content: bytes) -> dict:
    """Inspect bounded PE/CLR structures, never execute or repair an input.

    A missing CLR directory is not proof that bytes contain no managed code.
    Malformed/ambiguous declarations must not fall through to native analysis.
    """
    evidence = {
        "version": ROUTING_VERSION,
        "managed_policy": MANAGED_POLICY,
        "input_sha256": sha256(content).hexdigest(),
        "input_bytes": len(content),
        "route": "pending_review",
        "kind": "malformed",
    }

    def require(condition: bool, reason: str) -> None:
        if not condition:
            raise ValueError(reason)

    def number(offset: int, fmt: str = "<I") -> int:
        require(0 <= offset <= len(content) - struct.calcsize(fmt), "truncated_structure")
        return struct.unpack_from(fmt, content, offset)[0]

    try:
        require(content[:2] == b"MZ", "missing_dos_signature")
        pe = number(0x3C)
        require(pe >= 0x40 and content[pe : pe + 4] == b"PE\0\0", "invalid_pe_signature")
        machine = number(pe + 4, "<H")
        sections = number(pe + 6, "<H")
        optional_size = number(pe + 20, "<H")
        optional = pe + 24
        end = optional + optional_size
        require(end <= len(content), "truncated_optional_header")
        magic = number(optional, "<H")
        require(magic in (0x10B, 0x20B), "invalid_optional_magic")
        directory_offset = 96 if magic == 0x10B else 112
        require(optional_size >= directory_offset, "short_optional_header")
        directories = number(optional + directory_offset - 4)
        require(directories <= (optional_size - directory_offset) // 8, "truncated_directories")
        table_end = end + sections * 40
        require(sections > 0 and table_end <= len(content), "invalid_section_table")
        size_of_headers = number(optional + 60)
        require(table_end <= size_of_headers <= len(content), "invalid_size_of_headers")
        evidence.update(machine=machine, optional_magic=magic)

        def file_offset(rva: int, size: int) -> int:
            matches = []
            if 0 < rva and rva + size <= size_of_headers:
                matches.append(rva)
            for index in range(sections):
                section = end + index * 40
                virtual_size, va, raw_size, raw = struct.unpack_from("<IIII", content, section + 8)
                if va <= rva < va + max(virtual_size, raw_size):
                    delta = rva - va
                    require(delta + size <= raw_size, "rva_not_file_backed")
                    offset = raw + delta
                    require(
                        raw >= size_of_headers and offset + size <= len(content),
                        "invalid_raw_range",
                    )
                    matches.append(offset)
            require(len(matches) == 1, "unmapped_or_ambiguous_rva")
            return matches[0]

        clr_rva = clr_size = 0
        if directories > 14:
            directory = optional + directory_offset + 14 * 8
            clr_rva, clr_size = struct.unpack_from("<II", content, directory)
        evidence.update(clr_directory_rva=clr_rva, clr_directory_size=clr_size)
        if clr_rva or clr_size:
            evidence["kind"] = "managed_declared"
            require(clr_rva > 0 and clr_size > 0, "invalid_clr_directory")
            evidence.update(
                route="excluded_dotnet",
                reason="researcher_excluded_dotnet_from_dis_dec",
            )
            require(clr_size >= 72, "invalid_clr_directory")
            clr = file_offset(clr_rva, clr_size)
            header_size = number(clr)
            require(72 <= header_size <= clr_size, "invalid_clr_header_size")
            metadata_rva, metadata_size = struct.unpack_from("<II", content, clr + 8)
            flags = number(clr + 16)
            evidence.update(
                clr_flags=flags,
                il_only=bool(flags & 1),
                native_entrypoint=bool(flags & 0x10),
                managed_native_header_rva=number(clr + 64),
                managed_native_header_size=number(clr + 68),
            )
            require(metadata_rva > 0 and metadata_size >= 20, "invalid_clr_metadata")
            metadata = file_offset(metadata_rva, metadata_size)
            require(content[metadata : metadata + 4] == b"BSJB", "invalid_metadata_signature")
            version_size = number(metadata + 12)
            require(0 < version_size <= metadata_size - 16, "invalid_metadata_version_size")
            version = content[metadata + 16 : metadata + 16 + min(version_size, 256)]
            evidence.update(
                kind="managed_il" if flags & 1 else "managed_mixed",
                route="excluded_dotnet",
                reason="researcher_excluded_dotnet_from_dis_dec",
                metadata_validation="signature_and_version_header_only",
                metadata_version=version.rstrip(b"\0").decode("ascii", errors="replace"),
            )
        elif machine == 0x14C and magic == 0x10B:
            evidence.update(
                kind="native_x86_candidate",
                route="ghidra_x86",
                reason="pe32_i386_no_declared_clr",
            )
        else:
            evidence.update(
                kind="unsupported_machine",
                reason="native_profile_requires_pe32_i386",
            )
    except (ValueError, struct.error) as error:
        if evidence["route"] == "excluded_dotnet":
            evidence["clr_validation_warning"] = str(error)
        else:
            evidence["reason"] = str(error)
    return evidence
