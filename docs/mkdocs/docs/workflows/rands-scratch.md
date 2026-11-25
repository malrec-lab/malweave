# RanDS EXE Scratch Training

**Status: paused.** Confirmed on 2026-10-29 as a baseline within
[self-pretraining](self-pretraining.md). This guide's model, tokenizer, split and
five-epoch schedule belong to that baseline. See the
[research overview](research-protocol.md) for the current study.

This independent supervised baseline initializes bidirectional Mamba randomly and fits BPE on the frozen
RanDS training partition only. It requires no SOREL conversion or pretrained checkpoint.
It is separate from the external-tokenizer scratch/pretrained comparison in the
[self-pretraining plan](self-pretraining.md); its results cannot be substituted into that comparison.

## Configuration And Data Policy

`configs/experiments/rands-exe-scratch.yaml` selects bidirectional Mamba, the architecture
chosen in the research plan. The paper-scale setting from LMLM IV-B is hidden size 384,
32 layers **per direction** (32 forward + 32 backward), state size 16, expansion 2 and
untied directional weights. The two final directional states are added for classification,
following the pinned RawByteClf classifier port. It uses a 65,536-token context,
16,384 BPE vocabulary entries, BF16, FP32 residuals, activation checkpointing and seed 42.
Section VI-F's scratch-classifier schedule is 5 epochs, peak learning rate 0.0001,
weight decay 0.01, 5% linear warmup/linear decay and effective batch 64. We use
microbatch 1 with 64 accumulation steps on one GPU; this is a memory choice, not a
claim about the paper's classifier microbatch. The retained config sets two loader workers and four PyTorch CPU
threads; these are not measured resource requirements for checkpoint fine-tuning.

A reduced-depth option would use 16 layers **per direction**, keeping hidden size 384;
that is a separate experiment and is not the default or an approved size change.
HRRFormer remains a supported component; its earlier use as this experiment's default
was a configuration mistake and does not change the selected BiMamba architecture.

All retained training groups participate in every epoch. RanDS, train-only tokenizer fitting,
group-safe split, quarantine and validation selection remain declared adaptations. This does
not reproduce the complete pretraining/multi-view/multi-task experiment suite. Mamba's native
CUDA runtime is not installed/validated by the base lock: the runner requires both compatible
`mamba-ssm` and `causal-conv1d` kernels before any CUDA run. CPU tests use the reference scan.
This is a pending GPU deployment prerequisite, not a reason to change the architecture.

Preparation requires exactly 215,040 nonempty EXE `.bin` files, normalizes the original label CSV
schema and hashes every EXE. Hash receipts commit to SQLite in bounded batches; repeated
preparation reuses unchanged receipts. The split is deterministic and class-stratified 70/15/15
by exact EXE group. Quarantine every conflicting-label group (historical audit: 73 groups;
current preparation recomputes the count), and retain the smallest source ID as representative
of each remaining group. `excluded.csv` records all other sources, including metadata without
EXE, without reconstructing unknown extraction failure reasons. Aggregate coverage includes
excluded classes and architecture/packing by class and split. This is an exact-duplicate policy,
not proof against near-duplicate or family/time leakage. No architecture/packing filter is added.

BPE uses all retained training sources (the cap is the entire 215,040-file input release) and
the first 1,048,544 bytes per source, covering every 16-byte word that can contribute to the
model's first 65,534 content tokens.
All 256 byte symbols are in the vocabulary, including bytes unseen during fitting. Validation
and test bytes never fit the tokenizer. Tokenization checks full-file SHA-256 before encoding a
bounded byte prefix; full EXE files remain intact. The final token context keeps BOS/EOS.
A checksummed, memory-mapped token cache avoids repeated EXE reads/tokenization each epoch.
Cache statistics report lengths and context-filled samples; byte-prefix-limited counts are
reported separately and are not an exact token truncation rate.

BiMamba preserves the upstream classifier's BOS/content/EOS reversal and pools the final valid
position. It does not use HRR attention heads, rotary positions or HRR padding-masking settings.
An attention mask is not passed to the Mamba implementation. Token-aligned hidden states for
future MLM pretraining remain a separate task; this path is supervised sequence classification.

## Machine And AWS Setup

Use a Linux NVIDIA Ampere/Ada machine (3090, A40, 4090 or RTX 5000 Ada), the locked Python
requirements and a compatible driver. Run the GPU smoke **before downloading the dataset**.
The current Torch 2.6 / CUDA 12.4 lock has not been validated for Blackwell.
The default BiMamba needs compatible native CUDA kernels; the base environment alone is
insufficient. The GPU smoke uses a tiny BiMamba to validate the kernel/training path and
fails when kernels are unavailable. It does not establish full-size/context VRAM feasibility.

Allow **at least 250 GB disk** for joint RanDS/SOREL work. RanDS EXE alone is 96.9 GiB; leave
space for Python/CUDA dependencies, SOREL metadata/staging/state, token cache (up to about 52.5 GiB
before EXE grouping at 65,536 int32 tokens/sample) and checkpoint temporaries. Re-estimate storage
for unusually large SOREL batches/state. A 100 GB rental disk does not fit the full joint workload.
With Vast volumes, reserve 250 GB for inputs/runs/SOREL state plus a separate 50 GB container
disk for code and dependencies; 300 GB of volume offers more headroom. Prefer 48 GB+ VRAM for
this implementation. The paper used A100 40 GB, but the port's long-context CUDA peak memory
has not been measured. Do not silently shrink the model/context if memory fails.

Use the private root `.env` and an AWS CLI worker profile. In addition to SOREL rights, the
identity needs read access to RanDS EXE and the two label CSVs, and read/write access to a
separate training-result prefix. The template `configs/storage/rands-worker-policy.example.json`
is additive to the SOREL policy; it gives no raw payload access. Actual locations and credentials
stay outside Git and deployment archives. Configure keys on the target machine, not in commands.

```bash
aws configure --profile sorel-worker
```

Private `.env` example (replace addresses; the prepared deployment env already has actual values):

```dotenv
AWS_PROFILE=sorel-worker
AWS_DEFAULT_REGION=ap-southeast-1
MALWEAVE_RANDS_EXE_S3_PREFIX=s3://YOUR-RANDS-BUCKET/rands/representations/exe
MALWEAVE_RANDS_METADATA_S3_PREFIX=s3://YOUR-RANDS-BUCKET/RanDS_PE_Dataset
MALWEAVE_RANDS_TRAIN_S3_PREFIX=s3://YOUR-RANDS-BUCKET/experiments
```

## Commands

Run from the project root after `uv sync --locked`. Use fresh smoke directories on repeated
smoke tests; these contain only generated printable byte arrays. CPU smoke validates orchestration,
not CUDA performance or native kernels. The GPU smoke runs BPE, forward/backward, validation,
checkpoint writing and final test on 16 synthetic sources. Its metrics are not research results.

```bash
uv run --locked malweave experiment rands-smoke --work-dir data/interim/rands-scratch/gpu-smoke
uv run --locked malweave experiment rands-check --write-test
uv run --locked malweave experiment rands-prepare --download
```

`rands-check` reads input inventory and metadata headers and performs an optional temporary
text PUT/GET/SHA-256/delete at the training destination. `rands-prepare --download` downloads only
EXE and the two metadata CSVs. It never syncs the raw payload prefix, deletes local files or
changes existing RanDS objects. AWS CLI handles download progress; hashing has JSON heartbeats.
A failed/incomplete download stops before splitting; rerun the same command. Without `--download`,
preparation uses existing `inputs/exe/<shard>/<source>.bin` and `inputs/metadata/*.csv`.

Check `inputs/prepared.json` and class/group coverage before the training pilot. Then start
10 optimizer updates on real training data, preserving the exact schedule for continuation:

```bash
mkdir -p data/interim/rands-scratch/logs
set -o pipefail
/usr/bin/time -f 'wall=%e s cpu=%P max_rss=%M KB' \
  uv run --locked malweave experiment rands-train --run-id scratch-01 --max-steps 10 \
  2>&1 | tee data/interim/rands-scratch/logs/scratch-01-pilot.log
```

The first run fits BPE and builds token caches for all splits before training. Preparation time
can dominate a 10-update pilot. Training JSON lines show epoch, processed sample exposures,
optimizer updates, loss, samples/second, elapsed seconds and ETA. Heartbeats continue through
fitting, cache building, validation and checkpoint upload. Metrics runtime covers training and
evaluation after preprocessing; `/usr/bin/time` includes startup, BPE/cache and uploads.

Continue without resetting weights or refitting BPE:

```bash
uv run --locked malweave experiment rands-train --run-id scratch-01 --resume
```

`--max-steps` is a **total** optimizer-update limit, not additional updates. The pilot stops before
final evaluation; final test metrics appear only after training completes. Validation selects
best ROC-AUC and its balanced-accuracy threshold; the test split is used once at the end. Report
F1, balanced accuracy, precision/recall, ROC-AUC and tie-correct average precision (step PR area),
not an ambiguously defined trapezoidal PR-AUC.

## Resume And Artifacts

Local data lives in `data/interim/rands-scratch/inputs`; runs in `.../runs/<run-id>`. Override
with `--data-dir`, `--runs-dir` and `--config`. Freeze config before preparation. Changed code,
config, split or seed is rejected on resume; a new experiment needs a new preparation/config/run.
One local writer is enforced; never run the same remote run ID on two machines.

`Ctrl-C`/SIGTERM requests a stop at the next optimizer boundary. The runner saves model,
optimizer, scheduler, RNG state, epoch/batch position, loss accumulators and best-validation
state. An interruption during validation waits for validation and its checkpoint. Periodic saves
occur every 100 optimizer updates and every epoch. A hard kill can lose work since the last
committed save. Non-finite loss/gradients stop without replacing the last valid checkpoint.
Interrupted BPE/cache initialization can be repeated with `--resume` before training begins.
Resume order/RNG equivalence is tested on CPU with a partial final accumulation window;
GPU changes may change floating-point results and do not promise bitwise identity.

With `MALWEAVE_RANDS_TRAIN_S3_PREFIX`, committed artifacts are uploaded to
`<prefix>/<run-id>/objects/<artifact-sha256>/<filename>` before replacing `latest.json`.
Unchanged artifacts share the same object key. No raw data, EXE input or token cache is uploaded.
Upload failures stop the run and retain local state; the previous remote pointer remains valid.
Final outputs include config/split/exclusions/provenance, tokenizer, `last.pt`, `best.pt`,
`history.json`, `metrics.json`, `test-predictions.csv` and `completed.json`.
Old checkpoint objects remain for recovery and accrue S3 storage charges; no automatic retention
policy deletes them. Do not delete objects referenced by `latest.json`.

On another machine, install the **same bundle/config** and AWS profile, run the GPU smoke/check,
then `rands-prepare --download` and `rands-train --run-id scratch-01 --resume`. In a missing local
run directory the runner downloads the remote pointer, verifies every artifact checksum and
rebuilds local token caches before resuming. The full input EXE download is needed again unless
persistent disk was retained. The model weights alone are insufficient for training resume.

The current workstation has no working NVIDIA driver. CPU synthetic training/resume and fake-S3
publication/restore tests establish orchestration; run the GPU smoke and real-data pilot to
measure target VRAM, throughput and concurrent SOREL interference before estimating full cost for this retained workflow. Concurrent conversion/training is not the current plan.
