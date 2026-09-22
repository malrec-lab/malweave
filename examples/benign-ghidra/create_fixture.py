"""Create a tiny, synthetic RanDS-shaped benign PE corpus for the Docker e2e flow."""

from __future__ import annotations

import csv
from hashlib import md5, sha1, sha256
from pathlib import Path
import struct
import sys


BENIGN_HEADER = (
    "SHA256",
    "SHA1",
    "MD5",
    "Size in bytes",
    "File extension",
    "Arch",
    "Packed",
    "Entropy",
    "Year",
    "Filepath",
)
RANSOMWARE_HEADER = (
    "SHA256",
    "SHA1",
    "MD5",
    "Size in bytes",
    "File extension",
    "Arch",
    "Packed",
    "Entropy",
    "Family",
    "Year",
    "Filepath",
)


def _synthetic_i386_pe(code: bytes) -> bytes:
    """Build a minimal PE32 image with a `.text` entry point and no external content."""
    content = bytearray(0x400)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", content, 0x84, 0x14C)  # Intel 80386
    struct.pack_into("<H", content, 0x86, 1)  # one section
    struct.pack_into("<H", content, 0x94, 0xE0)  # PE32 optional-header size
    struct.pack_into("<H", content, 0x96, 0x0102)
    optional_header = 0x98
    struct.pack_into("<H", content, optional_header, 0x10B)  # PE32
    struct.pack_into("<I", content, optional_header + 16, 0x1000)  # entry point RVA
    struct.pack_into("<I", content, optional_header + 20, 0x1000)  # base of code
    struct.pack_into("<I", content, optional_header + 24, 0x2000)  # base of data
    struct.pack_into("<I", content, optional_header + 28, 0x400000)  # image base
    struct.pack_into("<I", content, optional_header + 32, 0x1000)  # section alignment
    struct.pack_into("<I", content, optional_header + 36, 0x200)  # file alignment
    struct.pack_into("<I", content, optional_header + 56, 0x2000)  # image size
    struct.pack_into("<I", content, optional_header + 60, 0x200)  # header size
    struct.pack_into("<H", content, optional_header + 68, 3)  # Windows CUI subsystem
    struct.pack_into("<I", content, optional_header + 92, 16)  # data-directory count
    section_header = 0x178
    content[section_header : section_header + 8] = b".text\0\0\0"
    struct.pack_into("<I", content, section_header + 8, len(code))
    struct.pack_into("<I", content, section_header + 12, 0x1000)
    struct.pack_into("<I", content, section_header + 16, 0x200)
    struct.pack_into("<I", content, section_header + 20, 0x200)
    struct.pack_into("<I", content, section_header + 36, 0x60000020)
    content[0x200 : 0x200 + len(code)] = code
    return bytes(content)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_fixture.py <empty-output-directory>")
    root = Path(sys.argv[1])
    if root.exists():
        raise SystemExit(f"refusing to overwrite existing fixture path: {root}")
    samples_dir = root / "corpus" / "dataset"
    samples = [
        _synthetic_i386_pe(b"\x90\x90\xc3"),
        _synthetic_i386_pe(b"\x90\x40\xc3"),
        _synthetic_i386_pe(b"\x90\x41\xc3"),
    ]
    benign_rows = []
    ransomware_rows = []
    for index, content in enumerate(samples):
        digest = sha256(content).hexdigest()
        path = samples_dir / digest[:2] / digest
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        common = [
            digest,
            sha1(content).hexdigest(),
            md5(content).hexdigest(),
            len(content),
            "exe",
            "I386",
            index % 2,
            "1.0",
        ]
        if index < 2:
            benign_rows.append([*common, "2026", "synthetic-benign"])
        else:
            # RanDS requires both CSVs. This is a harmless NOP/RET PE labelled
            # only to exercise that metadata contract; it is not ransomware.
            ransomware_rows.append([*common, "synthetic-fixture", "2026", "synthetic-benign"])
    corpus_root = root / "corpus"
    with (corpus_root / "Benign.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(BENIGN_HEADER)
        writer.writerows(benign_rows)
    with (corpus_root / "Ransomware.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(RANSOMWARE_HEADER)
        writer.writerows(ransomware_rows)
    shards = len({row[0][:2] for row in [*benign_rows, *ransomware_rows]})
    (root / "dataset.yaml").write_text(
        "\n".join(
            (
                "dataset: {name: rands, snapshot: synthetic-benign-e2e, root_env: E2E_RANDS_ROOT}",
                "layout: {benign_csv: Benign.csv, ransomware_csv: Ransomware.csv, samples_dir: dataset}",
                f"expected: {{shards: {shards}, files: 3, labels: {{benign: 2, ransomware: 1}}}}",
                "protocols: {full: {}}",
                "",
            )
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
