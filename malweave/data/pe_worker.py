"""Isolated static LIEF parser. Submitted PEs are read as data, never executed."""

import argparse
import json
from pathlib import Path

from malweave.data.pe_sections import extract_executable_sections


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    result = extract_executable_sections(
        arguments.input.read_bytes(), collect_audit=True, native_diagnostics=True
    )
    if result.extracted_bytes is not None:
        arguments.output.write_bytes(result.extracted_bytes)
    arguments.report.write_text(json.dumps(result.audit), encoding="utf-8")


if __name__ == "__main__":
    main()
