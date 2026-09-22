"""Validate the benign-only EXE and Ghidra e2e artifacts without printing sample identities."""

from __future__ import annotations

import json
from pathlib import Path
import sys


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: assert_e2e.py <fixture-directory>")
    root = Path(sys.argv[1])
    exe = _load(root / "reports" / "exe.json")
    if exe["job"]["complete"] is not True or exe["extraction"]["successful"] != 3:
        raise SystemExit("EXE e2e extraction did not produce three successful representations")
    ghidra = _load(root / "reports" / "ghidra.json")
    if ghidra["job"]["complete"] is not True:
        raise SystemExit("unified Ghidra e2e extraction did not complete")
    for representation in ("dis", "dec"):
        if ghidra["representations"][representation]["successful"] != 3:
            raise SystemExit(f"{representation} e2e extraction did not produce three successes")
        if not any(path.is_file() for path in (root / "output" / representation).rglob("*")):
            raise SystemExit(f"{representation} e2e output is empty")
    print("benign-only EXE and unified Ghidra e2e: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
