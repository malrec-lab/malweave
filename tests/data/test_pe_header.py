"""Header slicing uses only redistributable synthetic PEs."""

from hashlib import sha256
import struct

import pytest

from malweave.data.pe_header import extract_header
from tests.data.test_pe_sections import _synthetic_pe


def test_header_keeps_original_padding():
    content = bytearray(_synthetic_pe([(b".text", 0x400, 0x20, 0x60000020)]))
    struct.pack_into("<I", content, 0x98 + 60, 0x400)
    content[0x300:0x400] = b"P" * 0x100
    header, evidence = extract_header(bytes(content))
    assert evidence["status"] == "success"
    assert header == bytes(content[:0x400])
    assert evidence["header_sha256"] == sha256(header).hexdigest()
    assert "pe" in evidence


@pytest.mark.parametrize("size", [0, 0x100, 0x1000])
def test_invalid_size_is_not_clipped(size):
    content = bytearray(_synthetic_pe([(b".text", 0x400, 0x20, 0x60000020)]))
    struct.pack_into("<I", content, 0x98 + 60, size)
    header, evidence = extract_header(bytes(content))
    assert header is None
    assert evidence["status"] == "invalid_size_of_headers"


def test_non_pe_is_explicit_failure():
    header, evidence = extract_header(b"synthetic non-PE")
    assert header is None
    assert evidence["status"] == "not_pe"
