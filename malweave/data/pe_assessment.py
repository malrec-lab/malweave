"""Shared static file/DiE checks, ported from RawByteClf's packing protocol.

Scanners inspect bytes on disk; they never execute the submitted PE. A negative
packing result requires valid reports from all three modes, not just no matches.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import time
from typing import Any

DIEC_MODES = ("recursive", "deep", "heuristic")
OBFUSCATION_TYPES = frozenset(
    {
        "Packer",
        "Protector",
        "Protection",
        "Crypter",
        "Cryptor",
        "patcher",
        "scrambler",
        "sfx",
        "Archive",
        "Joiner",
    }
)


def architecture_from_file(description: str) -> str:
    normalized = description.lower()
    if "intel 80386" in normalized or "i386" in normalized:
        return "i386"
    if any(value in normalized for value in ("x86-64", "x86_64", "amd64")):
        return "amd64"
    if "aarch64" in normalized or "arm64" in normalized:
        return "arm64"
    if "arm" in normalized:
        return "arm"
    return "unknown"  # PE32 alone does not prove an x86 instruction set.


def _types(value: Any) -> set[str]:
    if isinstance(value, dict):
        # DiE 3.21 emits lowercase names; older RawByteClf reports use title case.
        type_name = value.get("type")
        canonical = next(
            (
                name
                for name in OBFUSCATION_TYPES
                if isinstance(type_name, str) and name.casefold() == type_name.casefold()
            ),
            None,
        )
        found = {canonical} if canonical else set()
        for child in value.values():
            found.update(_types(child))
        return found
    if isinstance(value, list):
        return set().union(*(_types(child) for child in value))
    return set()


def assess_file(command: str, path: Path, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    record: dict[str, Any] = {"command": [command, "-b", str(path)], "status": "error"}
    try:
        result = subprocess.run(
            record["command"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if result.returncode == 0 and result.stdout.strip():
            record["status"] = "success"
    except subprocess.TimeoutExpired as error:
        record.update(status="timeout", error=str(error))
        record.update(_timeout_output(error))
    except OSError as error:
        record["error"] = str(error)
    record["runtime_seconds"] = round(time.monotonic() - started, 6)
    return record


def _timeout_output(error: subprocess.TimeoutExpired) -> dict[str, str]:
    return {
        key: value.decode("utf-8", "replace") if isinstance(value, bytes) else value or ""
        for key, value in (("stdout", error.stdout), ("stderr", error.stderr))
    }


def assess_packing(command: str, path: Path, timeout: float) -> dict[str, Any]:
    modes: dict[str, str] = {}
    reports: dict[str, Any] = {}
    found: set[str] = set()
    for mode in DIEC_MODES:
        started = time.monotonic()
        arguments = [command, f"--{mode}scan", "--json", str(path)]
        record: dict[str, Any] = {"command": arguments}
        reports[mode] = record
        try:
            result = subprocess.run(
                arguments,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                check=False,
            )
            record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            if result.returncode:
                modes[mode] = "error"
                continue
            text = result.stdout
            report = json.loads(text[text.find("{") : text.rfind("}") + 1])
            record["report"] = report
            detects = report.get("detects")
            if (
                not isinstance(detects, list)
                or not detects
                or not any(
                    isinstance(item, dict)
                    and item.get("filetype") in {"PE", "PE32", "PE32+", "PE64"}
                    for item in detects
                )
                or not all(
                    isinstance(item, dict) and isinstance(item.get("values"), list)
                    for item in detects
                )
            ):
                modes[mode] = "invalid_report"
                continue
            found.update(_types(detects))
            modes[mode] = "success"
        except subprocess.TimeoutExpired as error:
            modes[mode] = "timeout"
            record.update(_timeout_output(error), error=str(error))
        except (OSError, ValueError, AttributeError, TypeError) as error:
            modes[mode] = "error"
            record["error"] = str(error)
        finally:
            record["status"] = modes[mode]
            record["runtime_seconds"] = round(time.monotonic() - started, 6)
    negative = all(value == "success" for value in modes.values())
    return {
        "state": "obfuscated" if found else "not_detected" if negative else "unknown",
        "types": sorted(found),
        "modes": modes,
        "reports": reports,
    }
