"""Supervise static-analysis/transfer subprocesses without buffering their output in RAM."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import Any

from malweave.data.sorel_io import digest, json_write
from malweave.data.sorel_protocol import now


class Processes:
    """Only processes created by this job are signalled; submitted PEs are never executed."""

    def __init__(self) -> None:
        self.abort = threading.Event()
        self._lock = threading.Lock()
        self._children: dict[int, subprocess.Popen] = {}

    def terminate(self) -> None:
        self.abort.set()
        with self._lock:
            for child in self._children.values():
                self._kill(child)

    @staticmethod
    def _kill(child: subprocess.Popen) -> None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def run(
        self,
        command: list[str],
        root: Path,
        name: str,
        *,
        timeout: float,
        memory_bytes: int = 0,
        env: dict[str, str] | None = None,
        observed_file: Path | None = None,
        file_budget: int = 0,
        output_budget: int = 0,
    ) -> dict[str, Any]:
        root.mkdir(parents=True, exist_ok=True)
        stdout, stderr = root / (name + ".stdout"), root / (name + ".stderr")
        result: dict[str, Any] = {"command": command, "started_at_utc": now(), "status": "error"}
        started = time.monotonic()
        peak = 0
        with stdout.open("wb") as out, stderr.open("wb") as err:
            try:
                child = subprocess.Popen(
                    command,
                    stdout=out,
                    stderr=err,
                    start_new_session=True,
                    env=env,
                )
                with self._lock:
                    self._children[child.pid] = child
                try:
                    while child.poll() is None:
                        if self.abort.is_set():
                            result["status"] = "interrupted"
                            self._kill(child)
                            break
                        if time.monotonic() - started > timeout:
                            result["status"] = "timeout"
                            self._kill(child)
                            break
                        try:
                            for line in Path(f"/proc/{child.pid}/status").read_text().splitlines():
                                if line.startswith("VmRSS:"):
                                    peak = max(peak, int(line.split()[1]) * 1024)
                        except (OSError, ValueError):
                            pass
                        if memory_bytes and peak > memory_bytes:
                            result["status"] = "resource_memory"
                            self._kill(child)
                            break
                        if (
                            observed_file
                            and file_budget
                            and observed_file.exists()
                            and observed_file.stat().st_size > file_budget
                        ):
                            result["status"] = "resource_disk"
                            self._kill(child)
                            break
                        if (
                            output_budget
                            and stdout.stat().st_size + stderr.stat().st_size > output_budget
                        ):
                            result["status"] = "resource_disk"
                            self._kill(child)
                            break
                        try:
                            child.wait(timeout=0.05)
                        except subprocess.TimeoutExpired:
                            continue
                    child.wait()
                    result["returncode"] = child.returncode
                    if result["status"] == "error" and child.returncode == 0:
                        result["status"] = "success"
                finally:
                    with self._lock:
                        self._children.pop(child.pid, None)
            except OSError as error:
                result["error"] = str(error)
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
        result.update(
            runtime_seconds=round(time.monotonic() - started, 6),
            finished_at_utc=now(),
            peak_rss_sampled_bytes=peak,
            stdout_file=stdout.name,
            stderr_file=stderr.name,
            stdout_sha256=digest(stdout),
            stderr_sha256=digest(stderr),
        )
        json_write(root / (name + ".json"), result)
        return result


def read_json_output(root: Path, result: dict[str, Any], memory_budget: int) -> Any:
    path = root / result["stdout_file"]
    if path.stat().st_size > max(1024**2, memory_budget // 8):
        raise MemoryError(
            "Tool report exceeds the task's decoding budget; full output is retained"
        )
    text = path.read_text(errors="replace")
    return json.loads(text[text.find("{") : text.rfind("}") + 1])


def rule_digest(root: Path) -> str:
    result = sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result.update(path.relative_to(root).as_posix().encode())
            result.update(bytes.fromhex(digest(path)))
    return result.hexdigest()
