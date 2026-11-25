"""Only synthetic PE metadata is used to validate erased-header identity recovery."""

from hashlib import sha256
import struct

import pytest

from malweave.data.pe_identity import verify_sorel_architecture
from malweave.data.pe_sections import IMAGE_SCN_CNT_CODE
from tests.data.test_pe_sections import _synthetic_pe


@pytest.mark.parametrize(
    ("machine", "magic", "subsystem", "architecture"),
    [
        (0x14C, 0x10B, 2, "i386"),
        (0x8664, 0x20B, 3, "amd64"),
        (0x1C4, 0x10B, 9, "arm"),
        (0xAA64, 0x20B, 2, "arm64"),
        (0xA641, 0x20B, 3, "arm64_hybrid"),
        (0x200, 0x20B, 1, "other"),
    ],
)
def test_verifies_original_metadata_without_modifying_source(
    tmp_path, machine, magic, subsystem, architecture
):
    original = bytearray(_synthetic_pe([(b".text", 0x400, 32, IMAGE_SCN_CNT_CODE)]))
    struct.pack_into("<H", original, 0x84, machine)
    struct.pack_into("<H", original, 0x98, magic)
    struct.pack_into("<H", original, 0x98 + 68, subsystem)
    # A nonzero value at +72 catches the incorrect PE32+ subsystem offset.
    struct.pack_into("<H", original, 0x98 + 72, 0xBEEF)
    identifier = sha256(original).hexdigest()
    released = bytearray(original)
    struct.pack_into("<H", released, 0x84, 0)
    struct.pack_into("<H", released, 0x98 + 68, 0)
    path = tmp_path / "synthetic.pe"
    path.write_bytes(released)
    report = verify_sorel_architecture(path, identifier)
    assert report["status"] == "verified"
    assert report["architecture"] == architecture
    assert report["original_machine"] == machine
    assert report["original_subsystem"] == subsystem
    assert report["subsystem_offset"] == 0x98 + 68
    assert report["released_pe_sha256"] == sha256(released).hexdigest()
    assert path.read_bytes() == released
    assert list(tmp_path.iterdir()) == [path]


def test_wrong_digest_remains_unknown_and_pe32_is_not_x86_evidence(tmp_path):
    released = bytearray(_synthetic_pe([(b".text", 0x400, 32, IMAGE_SCN_CNT_CODE)]))
    struct.pack_into("<H", released, 0x84, 0)
    path = tmp_path / "synthetic.pe"
    path.write_bytes(released)
    report = verify_sorel_architecture(path, "f" * 64)
    assert report["status"] == "unknown"
    assert report["architecture"] == "unknown"
    assert report["candidate_pairs_tested"] > 4
    assert path.read_bytes() == released


def test_non_disarmed_exact_digest_authenticates_existing_metadata(tmp_path):
    content = _synthetic_pe([(b".text", 0x400, 32, IMAGE_SCN_CNT_CODE)])
    path = tmp_path / "synthetic.pe"
    path.write_bytes(content)
    report = verify_sorel_architecture(path, sha256(content).hexdigest())
    assert report["architecture"] == "i386"
    assert report["candidate_pairs_tested"] == 0


def test_bad_headers_and_cancellation_do_not_mutate_file(tmp_path):
    path = tmp_path / "synthetic.pe"
    path.write_bytes(b"MZ")
    assert verify_sorel_architecture(path, "f" * 64)["reason"] == "truncated_header"
    content = _synthetic_pe([(b".text", 0x400, 32, IMAGE_SCN_CNT_CODE)])
    path.write_bytes(content)
    with pytest.raises(InterruptedError):
        verify_sorel_architecture(path, "f" * 64, cancelled=lambda: True)
    assert path.read_bytes() == content
