# SOREL conversion run guide (v3.1)

**Status: paused**, under [self-pretraining](self-pretraining.md).
These commands document how to resume the SOREL pilot. See the
[research overview](research-protocol.md) for the current study.

Revision v3.1 fixes reporting of non-UTF-8 section names and uses grouped PUTs
with S3 connection reuse. The old v3 run is retained separately and is not used
as a measurement of this revision.

Approved rules: [SOREL conversion protocol](sorel-protocol.md).
Recorded progress: [self-pretraining](self-pretraining.md).
This guide covers SOREL only. Inspect PE samples statically only.

Implementation lives in `malweave/data/sorel_conversion.py` (coordinator),
`sorel_stage.py` (per-source processing), `sorel_protocol.py` (state) and
`sorel_publication.py` (S3). Runtime settings are in `configs/datasets/sorel-full.yaml`.

## 1. Prepare a host if conversion resumes

Run from the repository directory. Requirements: Linux x86-64, Python 3.12.12, uv 0.11.9,
`curl`, `file`, `dpkg-deb` and AWS CLI v2 supporting conditional PUT/DELETE.
No GPU/CUDA/PyTorch required. The CPU Docker image pins this environment.

```bash
uv sync --locked --no-default-groups
uv run --locked --no-default-groups malweave data sorel-setup
aws configure --profile sorel-worker
```

Setup downloads approximately 3.8 GB of metadata and portable DiE 3.21 + ICU66, verifying SHA-256.
The conversion CLI finds this DiE installation automatically; no need to source env.sh on each run.
Use worker credentials; do not copy an administrative profile.

Add these three lines to the repository's **private** `.env`, replacing the placeholder bucket:

```dotenv
AWS_PROFILE=sorel-worker
AWS_DEFAULT_REGION=ap-southeast-1
MALWEAVE_SOREL_S3_PREFIX=s3://YOUR-BUCKET/malweave/datasets/sorel-20m/09-DEC-2020/exe-v1
```

The CLI reads `.env`; exported shell variables take precedence. No additional export is needed.
AWS CLI itself does not read `.env`: pass `--profile sorel-worker` when invoking `aws` directly.
The prefix is the collection root; the new CLI appends **`/v3.1/part-NN`** to isolate it from old jobs.
Example policy: `configs/storage/sorel-worker-policy.example.json`.

```bash
uv run --locked --no-default-groups malweave data sorel-s3-check --write-test
```

This checks permissions by uploading and deleting a small text file. Conditional-lock permissions
are checked when the runner acquires a real lock; the text preflight does not replace that check.

## Pinned Docker image

Use the same verified image on every machine to preserve tool identity on resume.
There are two separate packages in `data/external/deploy/`: the source bundle and Docker image archive,
each with a `.sha256` file. Neither contains samples, metadata or credentials.

After transferring the packages to `/workspace` on a host with Docker:

```bash
cd /workspace
sha256sum -c malweave-sorel-worker.tar.gz.sha256
sha256sum -c malweave-sorel-v3.docker.tar.gz.sha256
tar -xzf malweave-sorel-worker.tar.gz
docker load -i malweave-sorel-v3.docker.tar.gz
cd malweave
```

The host needs uv/AWS CLI for the launcher and metadata download. If missing, install uv 0.11.9
and AWS CLI 2.34.45; the AWS ZIP SHA-256 is recorded in `configs/worker-images.json`.
Ubuntu system prerequisites for `sorel-setup`, running as root:

```bash
apt-get update
apt-get install -y curl ca-certificates file dpkg unzip libglib2.0-0 libpcre2-16-0 libdouble-conversion3 libatomic1 libstdc++6 zlib1g
```

If uv/AWS CLI is absent on Ubuntu, after installing the prerequisites above:

```bash
curl -fsSL https://astral.sh/uv/0.11.9/install.sh -o /tmp/install-uv.sh
sh /tmp/install-uv.sh
export PATH="$HOME/.local/bin:$PATH"
uv python install 3.12.12
curl -fL https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.34.45.zip -o /tmp/malweave-aws.zip
echo '2b382fd5c1e8d73f6aaca18e5850758fb9f70a20af9c17deb3078df0dd4af095  /tmp/malweave-aws.zip' | sha256sum -c -
unzip -qo /tmp/malweave-aws.zip -d /tmp/malweave-aws
/tmp/malweave-aws/aws/install --update
```

After completing setup/profile/`.env` above, a future continuation test on a Docker host would be:

```bash
uv run --locked --no-default-groups malweave data sorel-container run --part 1 --limit 1000
```

The launcher mounts metadata read-only and the state directory writable, passing only the selected profile's credentials
through environment variables. It does not mount the entire `~/.aws` directory. Credentials are
absent from command arguments and bundles. Select another image with `--image`; a different
tool/protocol identity rejects resume. For rented containers without nested Docker, resolve the
host/image requirements before choosing a host.

## 2. Test conversion and continue existing progress

### Retained handover: process the next 1,000 sources if resumed

Verified on 2026-10-27: S3 v3.1 part 1 has 1,000 published outcomes, no pending uploads
and 548 unique EXEs. If conversion resumes with this protocol, the continuation test must process
**1,000 additional pending sources**:

```bash
uv run --locked --no-default-groups malweave data sorel-convert run --part 1 --limit 1000
```

On a host with Docker and the frozen worker image, use
`sorel-container run --part 1 --limit 1000` instead. Inside the worker image, invoke
`/opt/malweave/.venv/bin/python -m malweave data sorel-convert run --part 1 --limit 1000`
directly; do not assume Docker is available inside a Runpod Pod.

Before starting, verify the configured collection root and S3 latest pointer refer to
this existing part with 1,000 published outcomes. A fresh local state directory restores
the snapshot and replays complete groups automatically. A wrong prefix with no snapshot
can initialize a new job; the runner does not enforce an expected starting count.
Existing local state is not automatically replaced by a newer remote snapshot.

`--limit 1000` limits new processing attempts in this session, rather than capping the
part at 1,000 outcomes. With the verified state and no explicit retries, this processes
sources 1,001–2,000; a complete, successful session leaves 2,000 published outcomes.
Previous failures/filtered/deferred outcomes are retained without automatic retries.
If interrupted, the same command allows up to another 1,000 attempts in the new session;
reduce the limit to the remainder if the intended total is still 2,000 outcomes.

A synthetic restore test verified the 1,000 → 2,000 transition, unchanged previous
outcomes and no retries of previously failed/filtered/deferred sources. No additional
real sources were processed during this check. The saved image matches the current
source tree and frozen scientific/tool identity. Registry publication and Runpod
startup/SSH remain unfinished; the image's default entrypoint is the MalWeave CLI,
not an SSH service. Do not start a paid Pod expecting interactive SSH from this image.

### Initial acceptance benchmark (already completed)

```bash
uv run --locked --no-default-groups malweave data sorel-convert benchmark --part 1
```

There is no separate 10-source run. New state is stored at `data/processed/sorel/v3.1/part-01`.
After a clean interruption before 1,000 sources, repeat the command to process the remainder.
Valid results remain as progress when the protocol is unchanged.

JSON terminal logs every 5 seconds, including during uploads and snapshots:
`elapsed_seconds`, `processed_sources`, `successful_sources`, `published_sources`,
`unique_exe_s3`, `upload_pending_sources`, `status_counts`, `active_workers`,
`processed_sources_per_second`, `published_sources_per_second`, `eta_seconds`.
Setup has its own timer; ETA needs at least 5 minutes of publication-rate observations in the current session.
CPU/RAM logs reflect completed-process measurements/sampled peaks; host network counters may include other jobs.
`s3_traffic.cli_invocations` counts CLI invocations, not billable S3 requests.
`benchmark-1000.json` and `summary.json` contain measurements; do not extrapolate full duration with low coverage.

```bash
uv run --locked --no-default-groups malweave data sorel-convert status --part 1
uv run --locked --no-default-groups malweave data sorel-convert export --part 1
uv run --locked --no-default-groups malweave data sorel-convert audit --part 1
```

`export` builds `results.csv` from the DB without rescanning. `audit` reports missing requirements.
Unknown-ISA policy still needs researcher review of benchmark evidence before a full run,
even after technical checks pass. The audit does not treat a benchmark as scientific approval.
**Full-run commands are blocked until the release audit passes.**

## 3. Continue parts on a rented host after the release audit passes

```bash
uv run --locked --no-default-groups malweave data sorel-convert run --part 1
```

With Docker, use `sorel-container run --part 1` to retain the benchmarked image.
Change to `--part 2` through `--part 5` to process parts sequentially. A second machine can take a different part.
Each part has its own coordinator/lock. No machine has been rented or full run launched during preparation.
Do not use legacy `sorel-run` for the new protocol or copy old round-robin DBs into v3.1.

Workers/queue/batch/budgets are operational settings; select them from rented-host measurements.
`workers: 0` derives a value from CPU/cgroup/RAM rather than silently fixing 32 workers.
Override with `--workers N`. Scientific rules/tool identity must remain unchanged for resume.

## 4. Stop, move machines and retry

First Ctrl+C: stop scheduling, drain active work/uploads, take a final snapshot and release the lock.
Shut down only after the command exits. Second Ctrl+C: stop subprocesses, retaining local state and the remote lock.
On upload failure, retain the job directory for later publication; do not delete it to free disk space.

On a new machine, use the same image/code, profile and collection root; rerun the correct part's command.
The runner acquires ownership, restores the snapshot and replays groups published after it.
Unpublished sources whose local files were lost are scheduled again; history marks missing evidence.

If the old machine dies with a lock remaining, confirm the old job has stopped, read the token in
`v3.1/part-NN/main/owner.json` and add `--takeover TOKEN` to the corresponding command.
Do not steal the lock merely because its heartbeat is old.

Explicit retries by error group preserve previous history:

```bash
uv run --locked --no-default-groups malweave data sorel-convert run --part 1 --limit 1000 --retry die_scan_failed lief_timeout download_failed
```

The command may also process pending sources within the specified limit. Do not retry filtered outcomes as errors.
Reuse successful DiE modes only with identical PE/tools/rules and evidence still available locally;
sources whose local files were cleaned are downloaded/scanned again while retaining prior history.

## 5. S3 layout

```text
<COLLECTION-ROOT>/v3.1/part-01/
  exe/ab/<EXE-SHA256>.exe
  main/
    owner.json                      # present while owned or after an unclean handover
    latest.json                     # points to the current consistent snapshot
    snapshots/<generation>/
      state.sqlite                  # pending sources + current + history + index
      results.csv                   # one current row per processed source, all 15 original fields
      selection.json
      protocol.json
      remote.json
      summary.json
    run-summary.json                # most recent session measurements
    benchmark-1000.json              # benchmark measurements, if available
  details/
    <group-id>.tar.gz                # reports, stdout/stderr, manifest, detailed CSV
    <group-id>.json                  # commit marker, only after all EXE/archive uploads succeed
```

Parts 2–5 use the same layout. Identical EXE hashes within a part share one object.
Replace `main/latest.json` only after the entire new snapshot uploads successfully;
then clean up the previous snapshot. DB/CSV always belong to the same generation.
Update approximately every 30 minutes, on clean shutdown and on completion.
Each CSV row has `exe_s3_uri`, `details_s3_uri`, `details_sha256`, `details_member_root` for lookup.
Detailed evidence stays in immutable groups rather than one huge merged archive.
Raw PE and compressed source files are not uploaded.

## 6. Known handover gaps

The Runpod image still needs a validated startup/SSH path and registry publication.
Record the committed source revision separately from the worker image digest.
Do not treat a local Docker archive as a pullable image URL.

- SOREL defaults do not follow `MALWEAVE_DATA_DIR`. For a mounted volume, pass
  `--metadata /path/to/meta.db --job-dir /path/to/part-01` explicitly. `sorel-setup`
  downloads metadata into the repository's `data/raw/sorel/metadata/` directory.
- Snapshot restore does not recover `benchmark-1000.json` or the external release
  validation records used by `audit`. These must be supplied through the release
  process before auditing on a new host; DB restore alone is insufficient.
- Final unknown-ISA policy still needs researcher review before the full launch.

## 7. Pre-launch checks

Synthetic tests and `make check`; build/pin the CPU image digest; real 1,000-source benchmark;
check ISA/DiE/LIEF coverage, errors, timeouts, publication rate, resources and snapshot traffic.
This machine's benchmark does not establish rented-host performance. Approve price/host and full launch separately.

The handover above records the pilot scope and the remaining checks for a future run.
