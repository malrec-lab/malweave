"""Isolated static LIEF parser. Submitted PEs are read as data, never executed."""

import argparse
import json
import os
from pathlib import Path
import resource

from malweave.data.pe_sections import extract_executable_sections


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--memory-limit", type=int, default=0)
    arguments = parser.parse_args()
    if arguments.memory_limit:
        resource.setrlimit(resource.RLIMIT_AS, (arguments.memory_limit, arguments.memory_limit))
    try:
        result = extract_executable_sections(
            arguments.input.read_bytes(), collect_audit=True, native_diagnostics=True
        )
    except MemoryError:
        arguments.report.write_text(
            json.dumps({"status": "deferred_resource", "resource_reason": "lief_memory_limit"})
        )
        return
    if result.extracted_bytes is not None:
        with arguments.output.open("wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(result.extracted_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    arguments.report.write_text(json.dumps(result.audit), encoding="utf-8")


if __name__ == "__main__":
    main()
