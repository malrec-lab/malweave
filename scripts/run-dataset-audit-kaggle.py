"""Run a dataset audit in one Kaggle session and save a portable SQLite checkpoint."""

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
from threading import Event, Timer


def audit_cli(action: str, job: Path, *options: str, workflow: str = "dataset-audit") -> list[str]:
    return [
        sys.executable,
        "-m",
        "malweave",
        "data",
        workflow,
        action,
        "--job-dir",
        str(job),
        *options,
    ]


def copy_checkpoint(source: Path, destination: Path) -> None:
    """Copy a consistent database, including committed results still in the WAL."""
    temporary = destination.with_suffix(".tmp")
    temporary.unlink(missing_ok=True)
    with (
        closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as incoming,
        closing(sqlite3.connect(temporary)) as outgoing,
    ):
        incoming.backup(outgoing)
        outgoing.execute("PRAGMA journal_mode=DELETE")
    temporary.replace(destination)


def run_cli(
    job: Path, log: Path, options: list[str], budget: float, workflow: str
) -> tuple[int, bool]:
    timed_out = Event()
    with (
        log.open("a", encoding="utf-8") as console,
        subprocess.Popen(
            audit_cli("run", job, *options, workflow=workflow),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        ) as process,
    ):

        def pause() -> None:
            if process.poll() is None:
                timed_out.set()
                process.send_signal(signal.SIGINT)

        timer = Timer(budget, pause)
        timer.daemon = True
        timer.start()
        try:
            for line in process.stdout:
                print(line, end="", flush=True)
                console.write(line)
                console.flush()
        except KeyboardInterrupt:
            pause()
        finally:
            timer.cancel()
        return process.wait(), timed_out.is_set()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("pilot", "full"))
    parser.add_argument(
        "--dataset", choices=("rands", "vera", "assemblage", "rawmal"), default="vera"
    )
    parser.add_argument("--limit", type=int, help="Maximum sources attempted in full mode.")
    parser.add_argument(
        "--workflow", choices=("dataset-audit", "dataset-die"), default="dataset-audit"
    )
    parser.add_argument("--labels-csv", type=Path)
    parser.add_argument("--sha-list", type=Path)
    parser.add_argument("--timeout-per-mode", type=int)
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--restore", type=Path)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--session-seconds", type=float, default=10 * 60 * 60)
    args = parser.parse_args()
    if args.workers < 1 or args.session_seconds <= 0:
        parser.error("workers and session duration must be positive")
    if args.limit is not None and (args.limit < 1 or args.mode != "full"):
        parser.error("--limit requires full mode and a positive number of sources")

    packing = args.workflow == "dataset-die"
    if packing and args.mode != "full":
        parser.error("dataset-die requires full mode. Use --sha-list for a subset.")
    if not packing and (args.sha_list is not None or args.timeout_per_mode is not None):
        parser.error("--sha-list and --timeout-per-mode require the dataset-die workflow")

    job = args.job.resolve()
    output = args.output.resolve()
    if job == output:
        parser.error("the live job and saved output must use different directories")
    job.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    database = job / "state.sqlite3"
    if args.restore and not database.exists():
        copy_checkpoint(args.restore, database)
        print(f"Restored a previous {args.dataset} audit checkpoint.", flush=True)

    options = ["--dataset", args.dataset, "--workers", str(args.workers)]
    if args.mode == "pilot":
        existing = 0
        if database.is_file():
            with closing(sqlite3.connect(database)) as db:
                existing = db.execute("SELECT COUNT(*) FROM result").fetchone()[0]
        if existing < 1000:
            options.extend(["--limit", str(1000 - existing)])
    else:
        if not packing:
            options.append("--retry-errors")
        if packing and args.labels_csv:
            options.extend(["--labels-csv", str(args.labels_csv)])
        if args.sha_list is not None:
            options.extend(["--sha-list", str(args.sha_list)])
        if args.timeout_per_mode is not None:
            options.extend(["--timeout-per-mode", str(args.timeout_per_mode)])
        if args.limit is not None:
            options.extend(["--limit", str(args.limit)])

    if args.mode == "full" or existing < 1000:
        code, interrupted = run_cli(
            job, output / "console.log", options, args.session_seconds, args.workflow
        )
    else:
        code, interrupted = 0, False

    if packing and args.sha_list is not None and code not in (0, 1, 130):
        raise RuntimeError("Selected DiE run failed. See console.log for details.")

    if packing:
        for name in ("progress.json", "tools.json", "release-audit.json"):
            if (job / name).is_file():
                shutil.copyfile(job / name, output / name)
    if not database.is_file():
        raise RuntimeError("The audit stopped before creating its SQLite state.")

    copy_checkpoint(database, output / "state.sqlite3")
    status = subprocess.check_output(audit_cli("status", job, workflow=args.workflow), text=True)
    summary = json.loads(status)
    summary["process_exit_code"] = code
    summary["interrupted"] = interrupted
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    if args.mode == "full" and summary["pending"] == 0:
        csv = output / ("packing.csv" if packing else "native-dotnet.csv")
        csv.unlink(missing_ok=True)
        subprocess.run(
            audit_cli("export", job, "--output", str(csv), workflow=args.workflow), check=True
        )

    finished = summary["completed" if packing else "finalized"]
    print(
        f"{args.dataset} progress: {finished} of {summary['total']} completed, "
        f"{summary['pending']} pending. Output: {output}",
        flush=True,
    )
    if code and not interrupted:
        print(
            f"The audit CLI exited with code {code}. See console.log; SQLite is saved.", flush=True
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
