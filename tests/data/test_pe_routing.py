"""All PE/CLR bytes here are synthetic structures, not corpus excerpts."""

from hashlib import sha256
import struct

import pytest

from malweave.data.pe_routing import classify_pe


def synthetic_pe(*, managed=False, flags=1, pe64=False):
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if pe64 else 224
    struct.pack_into("<HH", data, 0x84, 0x8664 if pe64 else 0x14C, 1)
    struct.pack_into("<H", data, 0x94, optional_size)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B if pe64 else 0x10B)
    struct.pack_into("<I", data, optional + 60, 0x200)
    directories = optional + (112 if pe64 else 96)
    struct.pack_into("<I", data, directories - 4, 16)
    section = optional + optional_size
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x600, 0x2000, 0x600, 0x200)
    if managed:
        struct.pack_into("<II", data, directories + 14 * 8, 0x2000, 72)
        struct.pack_into("<IHHIIII", data, 0x200, 72, 2, 5, 0x2100, 0x40, flags, 0)
        data[0x300:0x304] = b"BSJB"
        struct.pack_into("<I", data, 0x30C, 12)
        data[0x310:0x31C] = b"v4.0.30319\0\0"
    return bytes(data)


def test_native_profile_requires_more_than_metadata_i386():
    content = synthetic_pe()
    result = classify_pe(content)
    assert result["route"] == "ghidra_x86"
    assert result["kind"] == "native_x86_candidate"
    assert result["input_sha256"] == sha256(content).hexdigest()
    assert result["reason"] == "pe32_i386_no_declared_clr"


@pytest.mark.parametrize("pe64", [False, True])
@pytest.mark.parametrize(
    "flags,kind",
    [(1, "managed_il"), (9, "managed_il"), (0, "managed_mixed"), (16, "managed_mixed")],
)
def test_clr_including_anycpu_mixed_and_native_entrypoint_is_not_native_x86(pe64, flags, kind):
    result = classify_pe(synthetic_pe(managed=True, flags=flags, pe64=pe64))
    assert result["route"] == "excluded_dotnet"
    assert result["kind"] == kind
    assert result["metadata_version"] == "v4.0.30319"
    assert result["native_entrypoint"] == bool(flags & 16)


def test_other_native_architectures_stay_pending():
    result = classify_pe(synthetic_pe(pe64=True))
    assert result["route"] == "pending_review"
    assert result["kind"] == "unsupported_machine"


@pytest.mark.parametrize(
    "offset,fmt,value,reason",
    [
        (0x98 + 96 + 14 * 8, "<I", 0, "invalid_clr_directory"),
        (0x98 + 96 + 14 * 8 + 4, "<I", 0, "invalid_clr_directory"),
        (0x200, "<I", 8, "invalid_clr_header_size"),
        (0x208, "<I", 0x9000, "unmapped_or_ambiguous_rva"),
        (0x20C, "<I", 0xFFFF, "rva_not_file_backed"),
        (0x300, "<I", 0, "invalid_metadata_signature"),
        (0x30C, "<I", 0xFFFF, "invalid_metadata_version_size"),
        (0x98 + 92, "<I", 17, "truncated_directories"),
    ],
)
def test_malformed_clr_never_falls_back_to_native(offset, fmt, value, reason):
    content = bytearray(synthetic_pe(managed=True))
    struct.pack_into(fmt, content, offset, value)
    result = classify_pe(bytes(content))
    if offset in (0x98 + 96 + 14 * 8, 0x98 + 96 + 14 * 8 + 4, 0x98 + 92):
        assert result["route"] == "pending_review"
        assert result["reason"] == reason
    else:
        assert result["route"] == "excluded_dotnet"
        assert result["clr_validation_warning"] == reason


@pytest.mark.parametrize("size", [0, 2, 64, 128, 200, 300, 512, 800])
def test_truncated_inputs_are_explicit_not_native(size):
    result = classify_pe(synthetic_pe(managed=True)[:size])
    assert result["route"] == ("excluded_dotnet" if size >= 512 else "pending_review")
    assert result["reason"]


def test_ready_to_run_evidence_is_preserved_without_treating_it_as_native():
    content = bytearray(synthetic_pe(managed=True))
    struct.pack_into("<II", content, 0x240, 0x2200, 16)
    result = classify_pe(bytes(content))
    assert result["route"] == "excluded_dotnet"
    assert result["managed_native_header_rva"] == 0x2200
