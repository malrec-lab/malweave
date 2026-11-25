"""Launch the pinned CPU worker with mounted data and only the selected AWS identity."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

from malweave.data.sorel_io import SorelError


def launch(
    action: str,
    part: int,
    image: str,
    metadata: Path,
    job: Path,
    *,
    prefix: str,
    workers: int | None = None,
    limit: int | None = None,
    takeover: str | None = None,
) -> int:
    if not shutil.which("docker") or not shutil.which("aws"):
        raise SorelError("Container launcher requires Docker and AWS CLI on the host")
    inspect = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspect.returncode:
        raise SorelError("Load/build the reviewed worker image first: " + inspect.stderr[-800:])
    image_id = inspect.stdout.strip()
    credentials = subprocess.run(
        ["aws", "configure", "export-credentials", "--format", "process"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if credentials.returncode:
        raise SorelError("Cannot resolve the selected worker AWS credentials")
    values = json.loads(credentials.stdout)
    environment = dict(os.environ)
    for key, source in (
        ("AWS_ACCESS_KEY_ID", "AccessKeyId"),
        ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"),
        ("AWS_SESSION_TOKEN", "SessionToken"),
    ):
        environment[key] = values.get(source) or ""
    environment["AWS_DEFAULT_REGION"] = os.environ.get("AWS_DEFAULT_REGION", "ap-southeast-1")
    environment["MALWEAVE_SOREL_S3_PREFIX"] = prefix
    environment["MALWEAVE_WORKER_IMAGE_DIGEST"] = image_id
    job = job.resolve()
    metadata = metadata.resolve()
    job.mkdir(parents=True, exist_ok=True)
    if not metadata.is_file():
        raise SorelError("Download the verified metadata before launching the worker")
    command = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--stop-signal",
        "SIGINT",
        "--user",
        str(os.getuid()) + ":" + str(os.getgid()),
        "--env",
        "HOME=/tmp",
        "--mount",
        "type=bind,src=" + str(metadata.parent) + ",dst=/data/metadata,readonly",
        "--mount",
        "type=bind,src=" + str(job) + ",dst=/data/job",
    ]
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_DEFAULT_REGION",
        "MALWEAVE_SOREL_S3_PREFIX",
        "MALWEAVE_WORKER_IMAGE_DIGEST",
    ):
        command += ["--env", name]
    command += [
        image_id,
        "data",
        "sorel-convert",
        action,
        "--part",
        str(part),
        "--metadata",
        "/data/metadata/" + metadata.name,
        "--job-dir",
        "/data/job",
    ]
    if workers is not None:
        command += ["--workers", str(workers)]
    if limit is not None:
        command += ["--limit", str(limit)]
    if takeover:
        command += ["--takeover", takeover]
    # Credentials travel via inherited environment, never command arguments/files/logs.
    # exec forwards terminal signals directly to Docker instead of leaving an orphan child.
    os.execvpe(command[0], command, environment)
    return 0
