"""Conversion must work in a worker that has no model or tokenization packages."""

import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import textwrap

from malweave.config import PROJECT_ROOT


def test_conversion_cli_without_training_dependencies(tmp_path):
    metadata = tmp_path / "meta.db"
    with sqlite3.connect(metadata) as db:
        db.execute("CREATE TABLE meta (sha256 TEXT PRIMARY KEY, is_malware INT, rl_fs_t REAL)")
        db.executemany(
            "INSERT INTO meta VALUES (?, 1, 0)", [(f"{index:064x}",) for index in range(2)]
        )
    (tmp_path / "config.yaml").write_text(
        json.dumps({"samples": 2, "workers": 1, "batch_size": 1})
    )
    script = textwrap.dedent(
        """
        import importlib.abc
        from pathlib import Path
        import sys

        class NoTraining(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname.split(".")[0] in {"torch", "tokenizers", "transformers"}:
                    raise ModuleNotFoundError("Training disabled in this worker", name=fullname)

        sys.meta_path.insert(0, NoTraining())
        from malweave import cli
        root = Path(sys.argv[1])
        cli.DOTENV_PATH = root / "absent.env"
        assert cli.main([
            "data", "sorel-prepare", "--metadata", str(root / "meta.db"),
            "--config", str(root / "config.yaml"), "--job-dir", str(root / "job"),
        ]) == 0
        assert cli.main(["data", "sorel-status", "--job-dir", str(root / "job")]) == 0
        assert cli.main([
            "experiment", "rands-smoke", "--work-dir", str(root / "unused"),
        ]) == 2
        assert not (root / "unused").exists()
        """
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", script, str(tmp_path)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert '"selected": 2' in result.stdout
    assert "--no-default-groups --group train" in result.stderr
    assert not (Path(tmp_path) / "unused").exists()
