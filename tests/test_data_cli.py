"""Data commands load without model or tokenization packages."""

from pathlib import Path
import subprocess
import sys
import textwrap

from malweave.config import PROJECT_ROOT


def test_data_cli_without_training_dependencies(tmp_path):
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
        from malweave.data import die_tools
        die_tools.setup_die = lambda path: {"die": "3.21", "environment": "fixture"}
        assert cli.main(["data", "die-setup"]) == 0
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
    assert '"die": "3.21"' in result.stdout
    assert "--no-default-groups --group train" in result.stderr
    assert not (Path(tmp_path) / "unused").exists()
