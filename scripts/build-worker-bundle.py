"""Package reviewed source and pinned DiE downloads, excluding private data/env/credentials."""

from __future__ import annotations

from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def build() -> None:
    sources = {
        ROOT / name
        for name in [
            ".env.example",
            ".gitignore",
            ".python-version",
            "AGENTS.md",
            "CONTRIBUTING.md",
            "Makefile",
            "README.md",
            "Dockerfile.sorel",
            "pyproject.toml",
            "uv.lock",
            "docs/mkdocs/mkdocs.yml",
        ]
    }
    for folder in [
        "malweave",
        "configs",
        "tests",
        "scripts",
        "ghidra_scripts",
        "docs/mkdocs/docs",
    ]:
        for path in (ROOT / folder).rglob("*"):
            if (
                path.is_file()
                and not path.is_symlink()
                and "__pycache__" not in path.parts
                and path.suffix
                in {".py", ".md", ".yaml", ".yml", ".json", ".java", ".sh", ".RawByteClf"}
                and not path.name.startswith(".env")
            ):
                sources.add(path)
    for name in (
        "reports/sorel-v3/image.json",
        "reports/sorel-v3/repository-checks.json",
        "reports/sorel-v3/acceptance-summary.json",
    ):
        if (ROOT / name).is_file():
            sources.add(ROOT / name)
    tools = {
        "data/external/tools/die-portable-3.21.tar.gz": "4d85614dd169c0d23f52084f86e05a503c30429df5fb5ec14de50f23808bc2d4",
        "data/external/tools/libicu66.deb": "00d0de456134668f41bd9ea308a076bc0a6a805180445af8a37209d433f41efe",
    }
    for name, expected in tools.items():
        path = ROOT / name
        if sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Missing or changed pinned tool: " + name)
        sources.add(path)
    deployment = ROOT / "data/external/deploy"
    deployment.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for path in sorted(sources):
        relative = path.relative_to(ROOT).as_posix()
        if path.is_symlink() or any(
            part in {".aws", ".git", ".venv", "__pycache__"} for part in path.parts
        ):
            raise ValueError("Unexpected private source: " + relative)
        if relative != ".env.example" and path.name.startswith(".env"):
            raise ValueError("Refusing env: " + relative)
        payload = path.read_bytes()
        manifest[relative] = {"bytes": len(payload), "sha256": sha256(payload).hexdigest()}
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (deployment / "deployment-manifest.json").write_bytes(payload)
    target = deployment / "malweave-sorel-worker.tar.gz"
    temporary = target.with_suffix(".tmp")
    with tarfile.open(temporary, "w:gz") as archive:
        for path in sorted(sources):
            archive.add(
                path, arcname="malweave/" + path.relative_to(ROOT).as_posix(), recursive=False
            )
        info = tarfile.TarInfo("malweave/DEPLOYMENT-MANIFEST.json")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    temporary.replace(target)
    checksum = sha256(target.read_bytes()).hexdigest()
    (deployment / (target.name + ".sha256")).write_text(checksum + "  " + target.name + "\n")
    print(
        json.dumps(
            {
                "bundle": str(target.relative_to(ROOT)),
                "bytes": target.stat().st_size,
                "files": len(manifest),
                "sha256": checksum,
            }
        )
    )


if __name__ == "__main__":
    build()
