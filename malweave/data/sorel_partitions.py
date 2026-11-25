"""Read-only summaries for fixed, independent SOREL partition jobs."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
from typing import Any

from malweave.data import sorel_ledger as ledger
from malweave.data.sorel_io import SorelError


def part_status(job: Path) -> dict[str, Any]:
    """Read committed counters, including after a runner was interrupted mid-batch."""
    job = job.expanduser().resolve()
    selection_path = job / "selection.json"
    if not selection_path.is_file():
        raise SorelError("Part is not prepared; run sorel-prepare --part N first.")
    selection = json.loads(selection_path.read_text())
    with closing(sqlite3.connect((job / "state.sqlite").as_uri() + "?mode=ro", uri=True)) as db:
        result = ledger.summary(db, selection["selected"])
    result.update(
        partition_index=selection["config"].get("partition_index", 1),
        partition_count=selection["config"].get("partition_count", 1),
        job_dir=str(job),
    )
    return result
