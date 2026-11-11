# LMLM checkpoints on RanDS

**Status:** current priority. `metadata-round-02` is frozen after full-pool exact
model-input deduplication. Experiment C has CPU tests and A100 native BF16 probes;
C/E1/E2 runs are completed and preserved in private local run directories.
A now has an intact-detector loader, resumable test evaluator and a synthetic
Kaggle capacity notebook. **Updated:** 2026-11-08.

The previous `metadata-round-01` benchmark contains exact input leakage and is
retained only as operational evidence. **Start a new round-02 run from the author
checkpoint; do not resume the old update-10 run with the new cohort.** The cleanup
verified all 74,658 pre-undersampling candidates, then independently confirmed zero
source/full-EXE/final-token duplicates in the new selected cohort. DEC/near-duplicate
and author-pretraining overlap checks remain outside this audit.

## Approved scope

Use public pretrained LMLM checkpoints, fine-tune and evaluate on RanDS.
Self-pretraining and further SOREL conversion are not prerequisites. The researcher has
approved the initial A/B/C/D/E1/E2 protocol, including artifact selection, input limits,
training settings and evaluation. The detailed decision record is
research-notes/lmlm/notes/02-checkpoints-rands-study.md in the parent research workspace
(decisions 1–68). It distinguishes source evidence, approved adaptations and implementation
gaps. On 2026-11-01 the researcher requested the first training round use RanDS metadata,
without a DiE admission gate. That cohort is now frozen; the DiE-based protocol remains
separate. This approval does not establish GPU readiness.

### Approved RanDS DIS/DEC extraction

On 2026-11-02 the researcher approved preparing both DIS and DEC on the current
machine for **all available original PEs** with RanDS metadata `Arch=I386`,
`Packed=false`, and valid negative packing evidence from all three DiE modes.
Unknown, failed or missing DiE evidence does not admit a sample. Architecture is
selected from RanDS metadata; PE32 alone is not proof of native x86 code, and this
choice adds no new CLR/AnyCPU exclusion.

The extraction pool is independent of the frozen training cohorts: no
undersampling, temporal filtering or EXE deduplication is applied here. This
approval does not change the EXE experiment inputs, splits or training protocol.
Potential DIS/DEC experiments and deduplication policies remain separate decisions.

The approved execution schedule uses 16 source workers and batches of 16 PEs,
prefetching one additional batch during analysis. Each source worker runs DIS
then DEC separately. Commit per-view results before cleaning batch scratch;
retain normalized outputs, partial-output evidence and failure accounting.
See [data preparation](data-preparation.md#streaming-rands-ghidra-disdec) for
commands, verification and resource limits. The researcher subsequently approved
local Ghidra/JDK installation, synthetic verification and a 32-PE pilot using two
batches. That pilot is complete; measurements and limitations are recorded in the
research workspace's `research-notes/lmlm/notes/01-data-preparation.md`, section 2.6.
Full-corpus execution still requires review of DEC failures, runtime and output
storage. The streaming runner currently retains results locally, without S3 output
publication or remote-backed eviction.

The researcher subsequently requested testing one Ghidra session that emits both
views. The bounded comparison is complete on the same 32 pilot sources, retaining
the 16-worker/prefetch schedule; the data-preparation execution notes, section 2.7,
record timing, output-hash equivalence and timeout-category differences.
Its experimental `shared-full` profile uses DEC's
full analysis for both outputs; the output comparison is limited to this pilot.
This timing test does not approve the shared profile for
full-corpus extraction or training; see the workflow's benchmark instructions.

## A on Kaggle: intact detector and test-only evaluation

A loads the published EXE detector `checkpoint-1923` initialized from MLM
`checkpoint-799`, preserving **every backbone and original linear head tensor**.
It does not use C's MLM transfer loader, initialize another head, train, select a
threshold or fit a tokenizer on RanDS. The source labels are `ben=0, mal=1`;
A uses the malware score for the ransomware-positive class on this RanDS cohort.
This does not make the original detector ransomware-specific.

The released trainer metadata points to best checkpoint **768**, which is absent
from this downloaded run. A evaluates the approved published **1923** artifact;
it is not a claim to reproduce the paper's best-checkpoint result.

### Synthetic T4 capacity check

`notebooks/02-mw-a-kaggle-probe.ipynb` runs the shared CLI in a private Kaggle
notebook, with Internet and a T4 enabled. It installs standalone uv 0.11.9,
Python 3.12.12 and the existing locked `gpu` dependency group in temporary storage.
It requires native Mamba CUDA kernels and keeps FP32, with TF32 disabled.
It uses one GPU; it does not distribute the detector across two T4s.

Prepare an enumerated private bundle using `pack_snapshot` from
`malweave.training.session_storage`: source files under `repo/malweave/`, plus
`repo/{README.md,pyproject.toml,uv.lock,.python-version}` and
`repo/configs/experiments/rands-lmlm-a.yaml`; put the selected detector's
`config.json`, `model.safetensors`, `tokenizer.json`, `tokenizer_config.json`,
`special_tokens_map.json` and `trainer_state.json` under `detector/`.
Include no credentials or RanDS payloads. Provide a private HTTPS GET URL,
archive SHA-256 and byte size as `MALWEAVE_A_BUNDLE_URL`,
`MALWEAVE_A_BUNDLE_SHA256`, `MALWEAVE_A_BUNDLE_BYTES` in environment/Kaggle Secrets.
The notebook verifies archive and member sizes/digests before importing source;
links, duplicate members and traversal paths are rejected. Keep the saved
notebook private if parameters contain a scoped signed URL.

The probe uses 256 and 65,536 synthetic bytes through the saved tokenizer, followed
by a **65,536-token capacity-only** case built from valid nonspecial vocabulary
IDs with the saved BOS/EOS. It records finite logits, wall time, CUDA allocated/
reserved peaks, host RSS and software/GPU identity. These cases neither evaluate
RanDS quality nor estimate full-run throughput. No precision, context or model
changes are made to force the probe to fit.

Inputs/environment remain under `/kaggle/temp/malweave-a-probe`; only reports/logs
are exported under `/kaggle/working/a-probe/`. Preserve the probe output before
ending the session. A failed capacity check requires investigation before a full
RanDS evaluation.

### Frozen RanDS test and recovery

After hardware verification, the evaluation CLI is:

```bash
uv run --locked --no-default-groups --group gpu malweave experiment evaluate-a \
  --experiment configs/experiments/rands-lmlm-a.yaml \
  --checkpoint /private/detector \
  --split-manifest /private/metadata-round-02/split.csv \
  --exe-root /private/exe \
  --output-dir /kaggle/working/a-test \
  --device cuda:0
```

Stage the original frozen `split.csv` and its `summary.json`, plus **test EXE
representations only**, preserving `exe_relative_path` below `--exe-root`.
Train/validation payloads and original PEs are not needed. Benchmark mode checks
the frozen cohort policy, split SHA, adapter/tokenizer SHA and exact 64-KiB input
limits. Each test EXE is hashed in full before its first 65,536 bytes are tokenized;
the final token digest must match the frozen input group. It does not truncate
the PE before section extraction or change the cohort to resolve failures.

`--max-samples N` or `--max-seconds N` pauses after committed predictions.
Resume the same command/output with `--resume`; configuration, cohort, checkpoint,
code/lock and Torch/device-type identity must match. A SQLite transaction commits
each success/failure and an exclusive lock prevents concurrent writers.
Failures are retained, not retried or silently dropped. Resolve the cause and use
a fresh output directory for a clean rerun. The local state is resumable, but this
CLI does **not** upload a remote backup automatically: stop/pause first, then
preserve the entire output directory before a Kaggle session expires.

`progress.json` has total/pending/success/failure and per-class coverage, runtime
and memory; CLI stdout can be redirected to a log. `state.sqlite3` retains
per-source runtime, token digest/length and verified EXE size. A partial CSV and
`failures.json` are exported at a clean pause/end. `metrics.json` is written only
after **all test sources succeed**. It includes the shared ROC-AUC, AP,
accuracy/precision/recall/F1/FPR, confusion matrix, approved 2,000-replicate
class-stratified ROC-AUC interval and per-family recall/support. Softmax then
argmax preserves source tie handling (class 0); there is no threshold tuning.
`run-manifest.json` records the original head/backbone provenance and missing-best
limitation. The detector is read-only and no new model checkpoint is saved.

### Official A session and local view

After the successful FP32/T4 capacity check, the researcher authorized the full A
run on 2026-11-08. The private session uses only the frozen **6,554 test EXEs**
(3,282 benign/3,272 ransomware; 2.710 GiB), with no train/validation payloads.
It keeps the validated detector, preprocessing, FP32 and batch 1 unchanged.
The notebook checks full EXE sizes/SHA-256 with ETag-pinned GETs; evaluation also
checks the frozen token digest. Source/detector and cohort/session archives are
preserved separately in this run's private S3 prefix and local run directory.

The session wrapper adds backup to the test-only CLI: first pause after ten
committed predictions, upload/read back a snapshot, verify and restore the actual
SQLite, then resume this same run. Subsequent pauses are approximately every
30 minutes at source boundaries. Two rotating S3 slots and a latest pointer
preserve state; the local observer verifies archive/member digests before
admitting each snapshot under `backups/latest/`. It never sends AWS keys to Kaggle.
Temporary EXE payloads/capabilities are removed before notebook outputs are saved.

From the parent research workspace:

```bash
python3 malweave/models/rands/a-kaggle-full-20261108/view.py
```

Use `--once` for one view. The view reports sample/class coverage, recent speed,
ETA, CUDA peaks and mirrored backup coverage. Ctrl+C closes only the view.
`models/rands/a-kaggle-full-20261108/README.md` maps private artifacts and recovery
files. Final metrics/predictions appear under
`backups/latest/results/a-metadata-round02-detector1923-20261108/` once evaluation
completes; the original unchanged detector remains in the frozen source archive.
A first session uses a 10.5-hour budget within Kaggle's 12-hour limit. If unfinished,
`session_budget_paused` preserves state for another session; the observer does not
submit a new GPU job automatically. Launch acceptance is distinct from successful
staging/evaluation and final verified coverage; measurements belong to the
research workspace execution notes and private run evidence.

## Sources and recovered artifacts

The paper and [RawByteClf source](https://github.com/lkurlandski/RawByteClf/tree/2502450e40ac00363e168106662aac29821d4a93)
were inspected at revision `2502450e40ac00363e168106662aac29821d4a93`.
The README's [artifact Drive](https://drive.google.com/drive/folders/1BV91yePpZNryhdLsiAeIQXKbYE567ayA?usp=drive_link)
contains `output/upload-to-drive.tar.zst` and a separate tokenizer directory.
The demo-image Drive is a different artifact. The paper also links
[Zenodo](https://doi.org/10.5281/zenodo.17047102).

With the researcher's authorization, the incomplete local folder was deleted and the
archive was downloaded and streamed into a fresh `upload-to-drive/` on 2026-10-30.
The 61,494,688,639 compressed bytes were fully received, zstd validation completed,
and 2,703 files totaling 67,257,595,916 bytes were extracted in about 284 minutes.
All **255 safetensors files opened successfully**; an independent header/size check
also found no missing tensor data. The previous copy had only 185 checkpoints,
147 with incomplete weights. Those historical failures do not describe the recovered copy.

This verifies transfer completeness and safetensors structure, not an official checksum,
training quality or the contents of every tensor. No author-provided checksum has been
verified. Checkpoint usage terms and possible pretraining/RanDS overlap remain open.
Downloaded Python and pickle files were not executed or deserialized.

## How the folder is organized

Paths encode experiment settings, not dataset shards:

```text
upload-to-drive/
  lift_level--<representation>/
    lift_level_ddp--<deduplication representation>/
      <packing, encoding, tokenizer, vocabulary and context settings>/
        model_name--<architecture>/
          <architecture settings>/
            task--<objective>/
              <split, loss, optimizer, schedule, batch and seed settings>/
                results/checkpoints/checkpoint-<global training step>/
```

This is a schematic; individual settings occupy separate levels. The naming comes
from `OutputHelper` in RawByteClf's `src/learn/helpers.py`.
`checkpoint-799` means training step 799, not 799 epochs or samples. Read
`config.json` and `trainer_state.json`; an epoch budget in a path is not proof
that training finished or that the selected checkpoint is the best one.

| Path component | Meaning |
| --- | --- |
| `lift_level--raw` | **EXE:** executable-section bytes, not the full PE. |
| `lift_level--nop` | **RAW:** the complete PE. |
| `lift_level--dis` / `dec` | Disassembly / decompiled code. |
| `lift_level--all` | Combined representations / ensemble classification. |
| `lift_level_ddp--dec` | Deduplication using DEC digests; not distributed data parallelism. |
| `task--mlm` / `clm` | Masked / causal language-model outputs. |
| `task--det` / `fam` / `beh` | Detection / family classification / behavioral tagging. |

The RAW/EXE naming is explicit in the paper's artifact appendix. Classification
outputs are not automatically pretrained backbones: inspect their initialization
lineage rather than inferring it from the task name.

### Current inventory

These are 255 saved artifacts across tasks/settings, not 255 pretrained language models.

| Representation | Language models (`mlm`, `clm`) | Classifiers (`det`, `fam`, `beh`) | Total |
| --- | ---: | ---: | ---: |
| EXE (`raw`) | 32 | 63 | 95 |
| DIS | 21 | 38 | 59 |
| DEC | 20 | 38 | 58 |
| Combined (`all`) | 0 | 27 | 27 |
| Full PE (`nop`) | 0 | 16 | 16 |
| **Total** | **73** | **182** | **255** |

A checkpoint contains model/config and tokenizer files plus training metadata:

| File | Role |
| --- | --- |
| `config.json` | Architecture, dimensions and task-related settings. |
| `model.safetensors` | Backbone and the applicable LM/classification head. |
| `tokenizer.json` | Algorithm and learned vocabulary. |
| `tokenizer_config.json`, `special_tokens_map.json` | Tokenizer options and special tokens. |
| `trainer_state.json` | Training step, epoch, logs and best-checkpoint references. |
| `training_args.bin` | Serialized training arguments; not deserialized by this workflow. |

Other files include RNG states and training/evaluation summaries. Fine-tuning starts
with a fresh optimizer; exact continuation of the author's original training has not
been established. Structural validity does not establish convergence or metric quality.

## Implemented BiMamba transfer path

`training/lmlm_checkpoint.py` loads released **EXE bidirectional Mamba MLM** checkpoints.
Architecture dimensions come from `config.json`, including the padded vocabulary;
there is no hard-coded choice of the large or small model. It rejects causal Mamba,
HRRFormer, other representations, mixed/tied directional modes, incomplete weights,
nonfinite tensors and any missing/unexpected backbone keys. It discards the MLM head
and initializes a fresh two-class linear head with the source initializer scale.
It does not execute remote code or deserialize author pickle files.

`data/lmlm_inputs.py` maps bytes to a **contiguous** string using `chr(byte + 10752)`
and applies the checkpoint's saved tokenizer/postprocessor, retaining BOS/EOS during
right truncation. Do not insert spaces every 16 bytes at inference: synthetic tests
show they introduce unknown tokens with Unigram. The existing scratch adapter remains
separate. Preserve the model/tokenizer pairing; the nominal BPE vocabulary 16,384
corresponds to 16,391 tokenizer entries and 16,392 embedding rows in the main model.

The `experiment train --checkpoint` path uses a frozen EXE split, without raw PE
access or fitting a tokenizer. It supports full fine-tuning and a frozen-backbone head.
It streams the whole EXE to verify its digest, retains only the approved byte prefix,
then applies the saved tokenizer and token limit. Classification uses source argmax,
with class 0 winning ties; there is no validation threshold optimization.

`configs/experiments/rands-lmlm-c.yaml` declares full fine-tuning, 65,536-byte/token
limits, native BF16, AdamW LR 1e-5/WD 0.01, effective batch 64, 5 planned epochs,
ceil(5%) warmup and linear decay. Early stopping monitors validation ROC-AUC from
epoch 1, patience 3, strict improvement. Partial accumulation groups use actual counts.

Each private run directory contains:

| Artifact | Purpose |
| --- | --- |
| `run-manifest.json`, `config.yaml` | Status, source-code/config/data/tokenizer hashes and initialization provenance. |
| `last.pt` | Latest model, optimizer, scheduler, epoch/batch position, shuffle and Python/Torch/CUDA RNG. Locally generated trusted recovery state. |
| `model.safetensors` | Best validation checkpoint, saved in FP32. |
| Tokenizer files | Reload with the matching author tokenizer. |
| `history.json`, `metrics.json`, `test-predictions.csv` | Epoch history, final evaluation and private sample predictions. |
| `benchmark.json` | Deliberate `--max-updates` pause; no test evaluation. |

Recovery state is replaced atomically after each optimizer update and validation.
Resume regenerates the shuffle permutation and skips committed batches; it rejects
changed data/config/tokenizer/code/lock/initialization. It cannot extend a completed
run. `--max-updates` preserves the full learning-rate schedule while pausing a run.
Final evaluation uses the best validation checkpoint and reports ROC-AUC, accuracy,
precision/recall/F1, FPR, confusion counts, sklearn AP and the approved 95%
class-stratified ROC-AUC interval (2,000 bootstrap draws, seed 0). Family labels
remain in the frozen cohort; final metrics also report family recall/support and
whether each family is represented in RanDS train, without claims about pretraining overlap.
`load_finetuned_bimamba` reloads completed artifacts without the source checkpoint.

## E1 versus E2: original MalConvGCT and the LMLM implementation

On 2026-11-03 the researcher requested a comparison of the original implementation
and the LMLM adaptation using the existing E1/E2 experiments. These are two source
configurations, not an ablation isolating context gradients or padding.

| Behavior | E1: original MalConvGCT | E2: LMLM MalConvGCT |
| --- | --- | --- |
| Config | `configs/experiments/rands-lmlm-e1.yaml` | `configs/experiments/rands-lmlm-e2.yaml` |
| Model implementation | `original` | `lmlm` |
| Input | Entire original PE, no prefix cap | First at most 1,048,574 PE bytes plus BOS/EOS |
| Byte encoding | byte+1, no BOS/EOS, 257 embeddings | byte+7, BOS=3/EOS=4, 264 embeddings |
| Kernel / stride | 256 / 64 | 64 / 64 |
| Context branch | Receives gradients, as original train script `low_mem=False` | Detached, as the pinned source custom checkpoint call |
| Embedding padding index | 0; PAD row starts/stays zero | `None`; PAD row is random and can learn in the main branch |
| Batch padding | Longest input | Longest input rounded up to a multiple of 8 |
| Configured physical / effective batch | 1 / 128, accumulation 128 (T4) | 64 / 64, accumulation 1 |
| AdamW weight decay | 0.01 on all parameters with gradients, including biases | 0.01 on non-bias parameters with gradients; no bias decay |
| LR | Fixed 0.001 | Warmup 5%, linear decay from peak 0.001 |
| Gradient clipping | None | Global norm 1.0 |

Both retain embedding size 8, channels 256, one layer, FP32, seed 0, the unchanged
round-02 cohort, validation ROC-AUC selection, argmax classification, patience 3
and the approved 15-epoch cap. These shared RanDS choices are not a claim to repeat
the papers' full experiments: original MalConvGCT reports 20 epochs/last epoch;
LMLM uses 5 epochs and its code defaults to validation loss selection. The original
train script uses Adam, while the agreed E1 adaptation uses AdamW/weight decay 0.01.
Its CLI also defaults to a 16,000,000-byte cap and size-grouped batches; this study
retains the already approved whole-file E1 scope and shared per-epoch shuffle.

After the 2026-11-03 T4 capacity check showed that physical batch 128 cannot
hold the longest inputs, the researcher approved reducing E1's microbatch while
retaining effective batch 128. The subsequent private synthetic sweep selected
microbatch 1 with accumulation 128, using the shared CLI for complete updates and
fresh-process resume, plus separate full-length train/inference capacity probes.
The sweep tested train inputs up to the frozen maximum of 67,324,616 bytes and
inference inputs up to 92,274,688 bytes, covering the validation/test size maxima.
Selection required memory headroom as well as measured speed. Keep FP32, whole-file
input, constant LR, the cohort and all other scientific settings unchanged.
Physical batch 1 is an explicit adaptation of the source recipe: padding within
each microbatch can differ from physical batch 128, so accumulation is not a claim
of exact numerical equivalence. Start a new run for the selected config; do not
resume an old checkpoint whose configuration differs. Measured results and cleanup
evidence remain in the research execution note and private run reports.

References are original MalConv2 commit
`b5a865420e984b22a2474834bd1748318e84b553` (`MalConvGCT_nocatTrain.py:95`,
`MalConvGCT_nocat.py`, `binaryLoader.py`) and RawByteClf commit
`2502450e40ac00363e168106662aac29821d4a93` (`src/architectures/malconv2.py`).
Synthetic CPU differential tests compare same-seed initialization without copying
weights, logits/loss, parameter gradients and an AdamW step against each source.
Original-source tests require a reviewed checkout via `MALWEAVE_MALCONV2_REFERENCE`;
they never download source automatically. E1's AdamW comparison tests use the
approved adaptation on both models, rather than asserting source-script optimizer parity.

Both readers verify the entire source SHA-256 on every access. Their separate
durable input audits use full-file identity for E1 and prefix identity for E2.
Neither changes the frozen split or discards failed/colliding samples. E1 reads
the entire file into host memory before encoding; the model retains the source
chunk/pool algorithm, including its handling of short trailing chunks. No implicit
truncation or out-of-memory fallback changes E1's input scope.

Use distinct artifact roots/run IDs. For an approved local GPU run with complete
original inputs, the shared CLI supports E1 as follows:

```bash
uv run --locked malweave experiment train \
  --track malconvgct --experiment configs/experiments/rands-lmlm-e1.yaml \
  --split-manifest data/processed/COHORT/split.csv \
  --raw-root /path/to/full-originals --exe-root /path/to/unused-exe \
  --artifact-root data/processed/lmlm-e1 --run-id metadata-round02 \
  --device cuda:0 --gradient-accumulation-steps 128 --seed 0 --max-updates 2
```

For E2, select its config, `data/processed/lmlm-e2` artifact root and
`--gradient-accumulation-steps 1`. Resume each
own run with `--resume` and a larger total `--max-updates`; config/source/audit
identity prevents resuming one implementation as the other. Manifests record the
source commit, context-gradient behavior, embedding padding index and input encoding.
E1 supports the same full optimizer/scheduler/RNG resume, progress and evaluation
as E2. The 2026-11-03 private T4 capacity check passed for both final profiles with
full batches of distinct synthetic inputs of about 1 MiB, including fresh-process
resume, validation and finite checkpoint tensors. This establishes the tested
workload only: E1 has uncapped inputs, and the frozen train split contains files
whose padded batch-128 input tensor alone exceeds Kaggle RAM and one T4's VRAM.
That initial result is historical; the subsequently approved microbatch sweep
above supplies capacity evidence for the updated E1 configuration. Detailed
measurements and cleanup evidence are in the research workspace execution note
and private `data/processed/` reports. These
commands describe the runner; the synthetic capacity check did not start a
real-data training run.

For a synthetic E1 capacity fixture, run `malweave experiment prepare-e1-smoke
--output-dir data/processed/e1-smoke --sample-bytes 4096` through `uv run --locked`.
It uses the real E1 architecture/batch 128, one accumulation step, three planned
epochs and 20 bootstrap draws. `--sample-bytes` sizes the generated test files;
the E1 reader still has no truncation. `--tiny-model` selects the small CPU model,
batch 1/effective batch 4 (use accumulation 4). Point the train command at the
fixture's `config.yaml`, `split.csv` and `raw` directory to test without RanDS.

## E2 on Kaggle: synthetic capacity and recovery

The researcher approved preparing E2 on 2026-11-02. The scientific config is
`configs/experiments/rands-lmlm-e2.yaml`: random-init MalConvGCT, embedding 8,
channels 256, kernel/stride 64, FP32, physical/effective batch 64, accumulation 1,
seed 0 and a 15-epoch
planned schedule. C retains its separate 5-epoch config and running Vast deployment.
The earlier synthetic T4 check verified the recovery mechanism with the previous
hybrid implementation and microbatch 1. Its timing/VRAM is not a measurement of
the current source-specific E2 profile at batch 64. The updated source behavior
has CPU differential/resume coverage and passed a fresh private T4 check on
2026-11-03 at physical batch 64, accumulation 1 and full-length distinct synthetic
inputs. The latter checked three optimizer updates, fresh-process resume and
finite model/optimizer tensors; it did not evaluate scientific test data.
Those synthetic checks did not start a scientific run. The later full E2 run
completed with early stopping; measured results and artifact verification are in
the research execution note. B/D still require native BF16 under their approved
protocol.

Source inspection resolved the E2 byte convention: pinned RawByteClf's WORDLEVEL
`bytes_to_input_ids` uses byte+7, PAD=0, BOS=3 and EOS=4. The released NOP/PE
MalConvGCT JSON has 264 embedding rows and embedding size 8. Its 1,048,576-token
limit includes BOS/EOS, leaving at most **1,048,574 original PE bytes** visible.
This differs from the generic RAW byte+1 adapter. E2's AdamW groups follow the
source Transformers Trainer: no decay for biases; weight decay 0.01 for other
parameters (this architecture has no LayerNorm). No source classifier weights,
author Python or author pickle are needed by the E2 runner.

The 2026-11-03 differential audit uses the pinned RawByteClf model on synthetic
inputs, including physical batches of 64. It identified and fixed E2's missing
padding to multiples of eight and the port's differing initial pooling sentinel
(upstream starts winners at -1). These are implementation checks against source,
not evidence that the scientific protocol exactly reproduces the paper.
The researcher subsequently selected the two source-specific profiles above.
E2 now reproduces the detached context branch and `embedding.padding_idx=None`;
E1 keeps context learning and `embedding.padding_idx=0`. Tokenizer PAD remains
ID 0 in both cases. The E2 differential tests now check initialization, all parameter
gradients and an optimizer step, rather than only forward after copying weights.

The E2 reader streams the full original PE for SHA-256 verification, retaining only
the bounded prefix in memory. It currently requires the complete original locally;
a prefix-only file fails the original-source hash check. Thus **13.06 GiB of visible
prefixes is not a supported 13.06 GiB staging format**. The round-02 full-PE payload
is approximately 26.10 GiB before environment, checkpoint and filesystem overhead.
On 2026-11-03 the researcher clarified that authorized scientific research includes
transferring original inputs to private research storage and GPU/Kaggle training
environments. Handle them as byte data, keep access private and never execute
samples. The full-session wrapper below implements real-input staging; the historical
synthetic notebook itself does not fetch RanDS or carry credentials.

Before training, E2 validates the unchanged frozen C split/summary and performs a
static input audit. Its SQLite state under the private artifact root records each
source's success/failure, full size and retained-prefix digest, committing each row.
Equal retained prefixes imply equal E2 inputs. Cross-split or conflicting-label
collisions, missing files and hash failures stop the run without dropping samples
or changing round-02. Audit summaries include status/class coverage, runtime and
input sizes; audit reuse does not replace the reader's per-access hash verification.

E2 reuses the trainer's atomic `last.pt` state, source/config/data/lock binding,
validation ROC-AUC selection, argmax tie-to-class-0 decisions, family reporting and
95% stratified bootstrap. Resume restores optimizer/scheduler, epoch/batch position,
shuffle/Python/Torch/CUDA RNG, history and early-stopping state. `--max-updates`
pauses at a committed total update count without evaluating test or rescheduling LR.
`--max-seconds` is an E1/E2 training-session budget checked after optimizer updates;
it excludes environment setup and the initial data audit and is not a hard wall-time
limit. Reserve time for those operations, checkpoint persistence and session shutdown.

Run only synthetic inputs at this stage:

```bash
uv run --locked malweave experiment prepare-e2-smoke \
  --output-dir data/processed/e2-smoke --max-tokens 4096

uv run --locked malweave experiment train \
  --track malconvgct \
  --experiment data/processed/e2-smoke/config.yaml \
  --split-manifest data/processed/e2-smoke/split.csv \
  --raw-root data/processed/e2-smoke/raw \
  --exe-root data/processed/e2-smoke/UNUSED_EXE \
  --artifact-root data/processed/e2-smoke/runs \
  --run-id synthetic-e2 --device cuda:0 \
  --gradient-accumulation-steps 1 --seed 0 --max-updates 2
```

Repeat the train command with `--resume --max-updates 3` instead of
`--max-updates 2` to exercise another committed update in a fresh process.
Use `--tiny-model --max-tokens 130` during fixture preparation, accumulation **4**
and `--device cpu` for a small CPU recovery test. The default fixture has 128 train
inputs and batch 64/accumulation 1; the tiny CPU fixture retains six train inputs
and batch 1/accumulation 4. Both have three planned epochs and 20 bootstrap draws;
they are not scientific E2 results. Add `--full-length` to generate distinct,
deterministic synthetic random bytes with every input reaching the token limit.

The source notebook `notebooks/01-mw-e2-kaggle-smoke.ipynb` restores a uv-locked
training environment, generates synthetic non-PE bytes, uses the actual E2
architecture, physical batch 64 and maximum-length synthetic random inputs by default,
and invokes the
shared CLI twice. It records benchmark/recovery evidence without evaluating test.
Make the previous **private output directory** available and set
`E2_SMOKE_RESTORE_FROM` to exercise recovery in a new Kaggle session. Supply the
identical reviewed source/config/lock. The verified recovery method downloaded
our own private output files over scoped HTTPS with SHA-256 checks and regenerated
the deterministic synthetic inputs with digest verification. Automatic mounting
through the MCP notebook-source attachment was not available in the attempted run.
Only restore your own trusted recovery artifacts; retain the run's `config.yaml`
as well as the fixture config. The notebook checks required recovery paths before
environment setup and keeps its dependency environment under `/tmp` so saved
outputs exclude the installed libraries.

`progress.jsonl` logs each committed update, session samples/time/rate, LR/loss and
GPU peak memory. `history.json`/`history.csv` record validation epochs; `last.pt`
provides recovery, `model.safetensors` holds the best model, and final evaluation
writes `metrics.json`/`test-predictions.csv`. Save and verify private outputs before
ending a session; session-local disk is not durable backup. A real long run still
needs a verified checkpoint-delivery mechanism for unexpected session loss.

After the synthetic T4 check, benchmark approved real **train** inputs before
estimating duration or choosing microbatch/accumulation. Two T4s do not pool VRAM;
this implementation uses one device. Keep the effective batch, FP32, input limit,
cohort and 15-epoch schedule fixed. A remains subsequent work. E1 has its own
source-specific reader/model/schedule and a separate synthetic capacity result;
its uncapped real-input memory requirements are not established by the E2 smoke
notebook. Historical synthetic checkpoints and redundant local source bundles
were removed after verification; compact reports, logs and integrity manifests
remain. Prior saved Kaggle versions may still contain their historical synthetic
outputs; the connector used here exposes no notebook-deletion operation.

## E1/E2 data and checkpoint lifetime

The frozen split is local metadata under
`data/processed/rands-lmlm/metadata-round-02/{split.csv,summary.json}`. It is not
the training payload. E1/E2 require the full original files in the supplied
`--raw-root`, using `dataset/<two-character-shard>/<source-sha256>`. Both verify
the original digest before encoding; E1 retains the entire file, whereas E2
retains at most 1,048,574 bytes and adds BOS/EOS. The DataLoader creates padded
int64 batches in host RAM, then copies them to the selected CUDA device. Neither
runner automatically downloads S3 data or uses C's staged EXE data.

The final-profile private Kaggle capacity notebook generates only synthetic
non-PE inputs below `/tmp/malweave-final/{e1,e2}/raw`, with temporary environments
and source under the same `/tmp` root. It extracts compact reports into
`/kaggle/working/final-profile-reports`, verifies checkpoint state, and removes
the generated inputs, checkpoints and environment before the notebook finishes.
These reports are evidence, not checkpoints from which to start scientific training.

For full training, choose separate private E1/E2 artifact roots and new run IDs.
The save sequence in each `<artifact-root>/<run-id>` is:

| When | Files and purpose |
| --- | --- |
| Startup / input audit | Config, run manifest and durable per-source input-audit SQLite state under the artifact root. |
| Initial state, every optimizer update, and after validation | Atomic replacement of `last.pt`, including optimizer/scheduler, epoch/batch position, shuffle/RNG and early-stop state. |
| Each committed update | Appended `progress.jsonl` with loss, LR, samples, time/rate and PyTorch allocated peak. |
| End-of-epoch validation | Updated `history.json`/`history.csv`; replace `model.safetensors` only when validation ROC-AUC improves. |
| Deliberate update/time-budget pause | `benchmark.json`, paused manifest and recovery state; test is not evaluated. |
| Completion or early stopping | Evaluate the best validation model, then write final `metrics.json` and `test-predictions.csv`. |

An interruption during an update recovers from the last committed update, rather
than the partially processed batch. `last.pt` on Kaggle session disk remains
session-local: there is no automatic periodic remote backup in this runner.
Saved private notebook outputs become available after execution and must be
downloaded/verified; they do not protect intermediate updates from abrupt session
loss. Full-run readiness therefore also requires verified real-input staging and
durable checkpoint delivery. Private research transfers are allowed under the
researcher's clarification; source samples remain unmodified and are never executed.

## E2 full Kaggle session and durable delivery

The researcher approved starting E2 before E1 on 2026-11-03. Full-session
orchestration retains the scientific config and calls the same supervised CLI;
it adds staging, monitoring and periodic verified delivery around committed
pauses. C/Vast remains independent. It uses the locked `train` environment on
one T4, physical/effective batch 64, accumulation 1, FP32, seed 0, 15 planned
epochs and the existing early-stopping/evaluation policy.

`data/rands_raw_stage.py` stages exactly the frozen original sources into
`/kaggle/temp/malweave-e2-inputs/dataset/<shard>/<source>`, outside saved notebook
outputs. Each HTTPS GET is scoped to one audited S3 object and pinned by ETag;
complete size/SHA-256 is verified before atomic admission. A SQLite ledger commits
each attempted source, reuse/failure, attempts and aggregate class coverage.
Failure stops admission; no failed sample is silently removed. The regular E2
input audit still runs before training and can reject prefix collisions without
changing the cohort. Scoped transfer tickets are private and expire; AWS access
keys are not bundled or sent to Kaggle.

`training/session_storage.py` packs enumerated source/config/cohort/audit or
committed run files with per-file sizes and SHA-256, rejects unsafe archive
members and restores only into a fresh directory. A remote upload is read back
and hashed before the latest pointer is replaced. The full-session wrapper keeps
two rotating snapshot objects in an isolated E2 prefix, leaving the prior
generation available on upload failure. Source, frozen cohort and input-audit
state are backed up separately from frequently changing model/optimizer state.
Raw originals, `.env`, AWS keys and transfer tickets are excluded from snapshots.

The first full-run delivery occurs at update 2, followed by verified HTTPS
restore and actual resume. Later snapshots follow each 25 additional committed
updates, and also completion, failure or a session-budget pause. Local `last.pt`
still saves each update; a crash can lose work after the last durable remote
snapshot. Chunk boundaries preserve the original total LR schedule and avoid
test evaluation during pauses. A completed/early-stopped run alone evaluates
test from the best validation checkpoint.

Results live under `/kaggle/working/e2-full/`, with status/progress delivered to
the private E2 S3 prefix and mirrored by a local supervisor. The notebook has a
12-hour session limit; the wrapper reserves setup/delivery time and pauses after
its 10.5-hour overall budget if unfinished. Another session must restore the
identical source/config/cohort/lock and verified latest generation before
continuing. Temporary original inputs and transfer bootstrap are removed before
normal notebook completion. Real S3 snapshot read-back/restore/resume and scoped
staging were verified first using synthetic non-PE inputs; full-run execution
status and any input-audit findings belong in the private execution record.

## E1 full Kaggle session

On 2026-11-04 the researcher requested starting E1 after the completed E2 run.
E1 keeps the canonical original-source config: whole original PE, microbatch 1,
accumulation 128, effective batch 128, FP32, seed 0, fixed LR 0.001 and the
approved maximum 15 epochs / validation ROC-AUC early stopping. It starts from
random initialization with a new run ID, private notebook and isolated S3 prefix.
It does not reuse E2 weights or change C/Vast.

The private E1 wrapper reuses the same audited full-source staging and verified
snapshot/restore helpers above. Originals live under
`/kaggle/temp/malweave-e1-inputs`, results under `/kaggle/working/e1-full/`.
Its separate full-input audit must pass for all frozen sources before training.
The first snapshot is after update 2; it is read back, restored and used for a
real resume to update 3, which is also backed up. Subsequent committed pauses
use `--max-seconds 3600` rather than a fixed number of updates. Hourly delivery
reduces repeated data loading when regenerating the shuffle on resume. It
changes the delivery interval, not the scientific LR/epoch schedule. Local
`last.pt` continues to save each optimizer update; work after the latest remote
snapshot can be lost if the session disk disappears.

The wrapper reserves time within a 12-hour Kaggle session using a 10.5-hour
budget from notebook startup. It may pause unfinished work and must then resume
from the same frozen source/config/cohort and verified remote generation in a
new session. Do not restart as a fresh experiment or extend a completed run.
The saved code bundle, source digests, metadata and audit are retained separately
from the two rotating model/optimizer snapshots; AWS keys and raw PE are excluded
from outputs. Original inputs are removed at normal session termination.

A local supervisor mirrors status and verifies/extracts each new snapshot. The
private viewer shows epoch/update, recent throughput, estimated remaining train
time for the current epoch, Torch peak, sampled GPU/RSS, and the validation
history from the saved epoch history delivered with live status, with verified
snapshots as a fallback. For the approved full run, from the research workspace:

```bash
python3 malweave/models/rands/e1-kaggle-full-20261104/view.py
```

The initial audit/staging phases have no training ETA. Validation results appear
after epoch evaluation and status delivery; missing/pending results are not
replaced with microbatch loss. Closing the viewer does not stop training or
backups. Actual launch/recovery/resource observations belong in the execution
note, not in this guide.

## Current cohort: metadata round 02

Use curator metadata `Arch=I386`, `Packed=false`, successful verified EXE conversion,
then full-EXE deduplication. Audit **all candidates before undersampling** with the
saved author tokenizer and approved byte/token limits. Group by the exact final
unpadded token IDs, including BOS/EOS. Remove every conflicting-label group; keep
the earliest recorded year, then smallest source SHA-256, for same-label groups.
Only then split years 2006–2023/2024/2025 and undersample **train only**, once, seed 0.
Do not add a CLR/AnyCPU filter or a DiE admission gate to this metadata round.

Frozen on 2026-11-02:

| Partition | Benign | Ransomware | Total |
| --- | ---: | ---: | ---: |
| Train | 22,778 | 22,778 | 45,556 |
| Validation | 2,464 | 1,883 | 4,347 |
| Test | 3,282 | 3,272 | 6,554 |

Total: **56,457 EXEs / 17,131,281,762 bytes**. Before train undersampling there
were 39,737 benign and 22,778 ransomware train representatives; 16,959 benign
representatives remain excluded. Validation/test retain all eligible representatives.
The input cleanup removed 1,216 same-label duplicates and all 26 sources in 12
conflicting-label groups from the 74,658 full-EXE representatives. This is additional
to the earlier full-EXE filtering, not a replacement for it.

Private cohort evidence is in `data/processed/rands-lmlm/metadata-round-02/`:
`split.csv`, `excluded.csv`, `summary.json`. Every one of the 237,687 metadata
sources is accounted for. Family counts are in the summary, with provenance on
each split row. `active_leakage_group_sha256` now identifies **final model tokens**;
`exe_representation_sha256` still identifies the full EXE. No payloads or token IDs
are stored in these reports. Detailed audit SQLite/identity/logs and independent
verification are outside Git in `~/.config/malweave/rands-input-leakage-02/`.

Reproduce into a **new** directory; frozen output directories cannot be overwritten:

```bash
uv run --locked malweave experiment freeze-rands-metadata \
  --metadata-dir data/processed/rands-die-local/metadata \
  --exe-manifest data/processed/rands-lmlm/source-exe-manifest.csv \
  --experiment configs/experiments/rands-lmlm-c.yaml \
  --input-audit "$HOME/.config/malweave/rands-input-leakage-02/evidence" \
  --output-dir data/processed/rands-lmlm/metadata-round-03
```

The CLI requires a complete audited pre-sampling pool, database checksum and matching
preprocessing identity; missing/stale/error evidence fails before any cohort is
written. Training also binds the split/summary to the actual tokenizer/checkpoint
and rejects active input groups spanning partitions or conflicting labels. This does
not run DiE or change its separate job. Other representations/tokenizers require
their own actual-input audit before making an equivalent leakage claim.

## Transfer to a GPU worker

The current benchmark worker is Vast instance `58649375`, A100 SXM4 80 GB,
16 allocated EPYC 7763 vCPUs and about 126 GiB RAM on host `153016`. Its container
disk is 25 GB; volume `58649037` is 50 GB mounted at `/data`. The original A40
instance/volume were deleted after rechecking their S3 recovery archive.
Keep Python/CUDA dependencies on the container
disk; keep source, the selected checkpoint, cohort, EXEs and run artifacts on the
volume. A Vast local volume needs a running attached instance to receive data;
setup and downloads therefore incur compute charges. It survives instance deletion
but can only be attached again on the same physical host and cannot be resized.

The existing dedicated Ed25519 public key is registered with Vast. The private key
stays at `~/.ssh/malweave_vast_ed25519` on the operator's workstation, with mode 600.
The workstation alias `malweave-vast` in `~/.ssh/config` now points to the A100
worker through Vast's relay. Use `ssh malweave-vast` while the instance is running. Rental
state is in `~/.config/malweave/vast-rands.json`. These account-specific files are
outside Git. The original worker also used Vast's relay because direct SSH
disconnected during file transfer. Keep SSH host-key verification enabled.

From the local repository, transfer the reviewed working source and frozen cohort:

```bash
ssh malweave-vast 'mkdir -p /data/malweave-round-02 /data/rands/cohort/metadata-round-02 /data/lmlm/checkpoint'

rsync -az --exclude='__pycache__/' --exclude='*.pyc' --exclude='site/' \
  malweave configs tests docs pyproject.toml uv.lock README.md Makefile AGENTS.md \
  malweave-vast:/data/malweave-round-02/

rsync -az data/processed/rands-lmlm/metadata-round-02/ \
  malweave-vast:/data/rands/cohort/metadata-round-02/
```

Copy only the selected MLM-799 checkpoint's five files into
`/data/lmlm/checkpoint/`: `config.json`, `model.safetensors`, `tokenizer.json`,
`tokenizer_config.json`, `special_tokens_map.json`. Verify transferred source,
configuration and checkpoint digests before running. The unique source path has
EXE/raw, BPE-16384, context-65536, H384, 32 layers, bidirectional/untied directions
and task MLM. Do not copy the entire collection, raw corpus or author pickle files.

Configure worker AWS access privately using temporary credentials where possible.
The local AWS profile does not automatically exist on the worker. Credentials must
remain outside Git, images and logs. Set the region and private
`MALWEAVE_RANDS_EXE_S3_PREFIX` in the worker's private `.env`; the worker downloads
EXEs directly from S3. The initial deployment uses a temporary session inheriting
the existing profile's permissions: AWS denied the attempt to issue a narrower
federated session. Renew credentials before expiry if another download or backup
needs them; do not replace them with a copied long-lived key.

Delivery uses SSH/rsync plus the locked uv environment. The base image is PyTorch
2.6.0 / CUDA 12.4 / cuDNN 9 runtime, pinned by its registry digest in the private
rental record. The SOREL conversion image is not the training environment.

## Worker setup, benchmark and resume

On a fresh worker, install pinned uv 0.11.9 and a system C compiler first. The runtime
base image does not include a compiler; Triton needs one even when Mamba wheels are
prebuilt. The initial deployment installed `build-essential`. Its GPU preflight then
passed BF16 forward/backward at 65,536 tokens using 7.91 GiB peak allocated VRAM on
synthetic input; this is not measured RanDS training throughput.

From `/data/malweave-round-02`, with Python dependencies on the container disk:

```bash
# Create the target before linking it: uv cannot create a venv through a dangling symlink.
uv venv --python 3.12.12 /opt/malweave-venv
ln -s /opt/malweave-venv .venv
uv sync --locked --python 3.12.12 --no-default-groups --group gpu

uv run --locked --no-default-groups --group gpu python - <<'PY'
import torch
from transformers.models.mamba.modeling_mamba import is_fast_path_available
assert torch.cuda.is_available(), "CUDA unavailable"
assert torch.cuda.get_device_capability(0)[0] >= 8, "Native BF16 unavailable"
assert is_fast_path_available, "Mamba CUDA kernels unavailable"
print(torch.cuda.get_device_name(0), torch.__version__, torch.version.cuda)
PY
```

The optional GPU group pins official Mamba 2.2.4 / causal-conv1d 1.5.0.post8
CUDA-12/Torch-2.6/CPython-3.12 ABI wheels. Downloads and lock hashes are verified;
imports and GPU forward/backward still require testing on the actual worker.

On the existing worker, round-02 source is separate from the original benchmark
source. It reuses `/opt/malweave-venv` through `.venv`; use `python -m malweave`
from the round-02 checkout so the old editable-install entry point is not selected.
`--no-sync` reuses the already validated locked GPU environment. A fresh worker must
complete the locked setup and native preflight above first.

Download only the frozen cohort, verifying full EXE hashes. Repeat to reuse verified
completed files:

```bash
uv run --locked --no-sync --no-default-groups --group gpu python -m malweave experiment stage-rands-exe \
  --split-manifest /data/rands/cohort/metadata-round-02/split.csv \
  --exe-root /data/rands/exe
```

Set common arguments once in Bash:

```bash
train_args=(
  --track mamba
  --experiment configs/experiments/rands-lmlm-c.yaml
  --checkpoint /data/lmlm/checkpoint
  --split-manifest /data/rands/cohort/metadata-round-02/split.csv
  --exe-root /data/rands/exe
  --artifact-root /data/rands/runs
  --run-id c-metadata-round02-5ep-seed0
  --device cuda:0
  --gradient-accumulation-steps 64
  --seed 0
)

# Pause after the first 10 updates; keep recovery state, do not evaluate test.
uv run --locked --no-sync --no-default-groups --group gpu python -m malweave experiment train \
  "${train_args[@]}" --max-updates 10

# After reviewing memory, speed and cost, continue that same run.
uv run --locked --no-sync --no-default-groups --group gpu python -m malweave experiment train \
  "${train_args[@]}" --resume
```

Keep logs outside the run directory: the runner requires a new run directory on its
first invocation. Run preparation/training in tmux so SSH disconnection does not
stop the job. On the A100 worker, setup and EXE staging are complete;
logs are under `/data/rands/logs/`:

```bash
ssh malweave-vast
# Inspect setup, preparation checks, or EXE download progress.
tail -f /data/rands/logs/setup.log
tail -f /data/rands/logs/stage-exe.log
# Attach only when interactive access is needed; Ctrl+B, then D detaches.
tmux list-sessions
# During the benchmark, if this session is listed:
tmux attach -t rands-benchmark
```

Microbatch 1 × accumulation 64 preserves effective batch 64. This measurement includes
real loading/tokenization/checkpoint I/O. Ten initial updates do not guarantee the
longest later input fits; validate long-context memory before unattended training.
Do not silently shorten inputs, change precision or drop samples on resource errors.
Progress reports samples, epoch, updates, loss, LR, elapsed time and peak allocated
GPU memory. Keep worker storage intact while paused; local state is not an off-machine
backup. After interruption, reuse identical arguments with `--resume`.

## A100 batch selection

On 2026-11-01 the A100 completed a synthetic worst-case full update at 65,536 tokens
per file with microbatch 8 × accumulation 8: 92.26 seconds, 62.79 GiB peak allocated
and 64.27 GiB sampled whole-device NVML memory. AdamW states were initialized before
measurement. Microbatch 16 exceeded VRAM. Short variable-length batch versus single
inference passed BF16 tolerances `rtol=0.02`, `atol=0.02`; this is not bitwise parity.

Separate processes then measured the same first 256 real train samples, discarding
one warmup update and timing the next 192 samples, including read/hash/tokenization,
training and checkpoint I/O:

| Microbatch × accumulation | Samples/second | Peak allocated GiB | Sampled whole-device GiB |
| --- | ---: | ---: | ---: |
| 8 × 8 | 0.7784 | 51.94 | 55.57 |
| 4 × 16 | 0.8900 | 26.49 | 44.78 |
| 1 × 64 | 1.4086 | 7.37 | 13.08 |

The 640-sample confirmation selected microbatch 1 × accumulation 64: 10 updates
completed in 448.91 seconds; after one warmup update, 576 samples took 405.29 seconds
(1.4212 samples/second). Peak allocated/reserved memory was 7.91/18.03 GiB; sampled
whole-device NVML memory was 19.30 GiB and process RSS 1.95 GiB. The run paused at
update 10 with no validation/test. Effective batch remains 64. Larger batches pad
every input to the longest sequence in that batch; capacity alone does not select the fastest configuration. These measurements
do not isolate every cause of the throughput difference or measure a full epoch.

The first attempt at the real benchmark exposed a stale 15-epoch validation guard.
It was corrected to the approved 5-epoch schedule and covered by a test loading the
actual C config; all 192 CPU tests and repository checks passed. During the separate
640-sample microbatch-8 attempt, Vast reported the worker stopped. Its cause was not
established. The same instance was restarted; data remained intact and `last.pt`
contained update 1 / 64 committed samples. Do not count that interrupted run as a
completed 640-sample benchmark.

## Active round-02 training

The researcher authorized the full C fine-tuning run on 2026-11-02. Run
`c-metadata-round02-5ep-seed0` uses the reviewed round-02 source/cohort, the author's
MLM-799 initialization, microbatch 1 × accumulation 64, seed 0 and at most 5 epochs.
It has no benchmark update cap. The old round-01 update-10 checkpoint is not used.

The active worker is an **A100 PCIe 40 GB on-demand** instance (`58773607`, host
`152434`), with 16 allocated vCPUs, about 126 GiB RAM, a 25 GB container disk and
one 50 GB volume (`58773078`) mounted at `/data`. GPU and both disks cost
**USD 0.358796/hour (~USD 8.61/day)** before traffic. The SSH alias below now points
to this worker. It runs the training service in tmux `rands-c-round02`.

On 2026-11-02, the researcher reported **outbid** in Vast's UI for the old 80 GB
spot instance and authorized migration to a cheaper on-demand worker. Recovery used
the fully checksum-verified S3 checkpoint at **update 57**. The old worker's logs
reached update 75, but that newer state was unavailable while outbid; the intervening
updates must be repeated. After verifying the new worker and its S3 recovery copy,
the old instance `58649375` and volume `58649037` were deleted on 2026-11-02.
The unrecovered old checkpoint around update 75 was discarded; its later updates
are repeated from the durable update-57 backup. Old storage no longer adds
~USD 1.79/day. Full training results remain pending.

All 56,457 frozen EXEs were staged with size/SHA-256 verification. The locked
Python 3.12.12 / PyTorch 2.6.0+cu124 BF16 runtime and Mamba fast kernels passed.
A separate one-microbatch capacity probe at 65,536 tokens, with initialized AdamW
state, forward/backward and an optimizer step, passed: **8.43 GiB PyTorch peak
allocated**, **9.95 GiB sampled device memory**. This is a capacity check, not a
full effective-batch throughput benchmark. The scientific training config is unchanged.
Current model/recovery artifacts are in `/data/rands/runs/c-metadata-round02-5ep-seed0/`.
Monitor without attaching to the training process:

```bash
ssh malweave-vast 'tail -f /data/rands/logs/c-metadata-round02-5ep-seed0.log'
```

Worker supervisor state and backup receipts are under
`/data/rands/operations/c-metadata-round02-5ep-seed0/`. A private workstation guard
records GPU/progress/credit every approximately 20–60 seconds. Its state is in
`~/.config/malweave/c-metadata-round02-5ep-seed0-a10040/`; its log can be followed locally:

```bash
tail -f ~/.config/malweave/c-metadata-round02-5ep-seed0-a10040/guardian.log
```

Training keeps atomic local recovery state after each optimizer update. The worker
supervisor briefly suspends the training process group to pin committed run files,
then resumes it before compressing/uploading. It backs up after the first update,
hourly and on termination, replacing one S3 object at suffix
`c-metadata-round02-5ep-seed0/latest.tar.gz` under the private training prefix.
The archive includes reviewed source/config/lock, author checkpoint/tokenizer,
cohort and current run state; EXEs, environments and credentials are excluded.
Uploads verify size/SHA-256 metadata; initial/final backups also download and hash
the complete S3 payload. The workstation guard refreshes temporary AWS credentials
every eight hours; the account's Vast API key stays on the workstation.

The researcher explicitly approved hourly backups and the USD 1 credit stop in chat
on 2026-11-02. The guard requests a stop when credit falls to USD 1, a backup repeatedly fails or
the operator requests it, and stops the instance after the worker exits. A budget
stop preserves the last committed optimizer update; an incomplete accumulation group
may be repeated on resume. The five-epoch schedule is unchanged. This is a persistent
workstation guard: keep its host/process running for credit monitoring and instance
shutdown. The worker's tmux session survives SSH disconnection.

## Historical A100 80 GB benchmark and budget

The new 5-epoch run is `c-metadata-5ep-bench-mb1-seed0`, under
`/data/rands/probes/a100-batch-01/runs/`. Its private `config-mb1.yaml` is byte-identical
to the source C config; use microbatch 1 and accumulation 64 when resuming. The
microbatch-8 interrupted run and short comparison runs are separate probes.

Using the old benchmark rate of 1.4212 samples/second, the new 45,556 train
samples × 5 epochs extrapolate to 44.52 train hours. Adding an **unmeasured 20%
time allowance** for validation/test and I/O gives 53.42 hours (~2.23 days), before setup or interruptions. Running GPU,
25 GB container and 50 GB volume total **$0.475748/hour (~$11.42/day)** at the historical
spot bid. This is not the active 40 GB worker price above. That allowance corresponds to **$25.42** of running resources. A planning
budget including about one setup hour, staging/verification traffic and paid AWS
outbound is **about $30**, or **$36 with 20% financial reserve**. Hourly backups are now approved; their network/request/storage costs were excluded
from this earlier estimate. These are extrapolations from 640
samples, not a completed epoch or a guaranteed bill; spot interruptions add time.

Vast transfer is $0.013333/GB in each direction; AWS S3 outbound depends on the
account's remaining monthly free quota. Stopped container + volume storage remains
**$0.074748/hour (~$1.79/day)**; the volume alone is ~$1.20/day. The round-02 run has started under the credit guard; full five-epoch results remain
pending. Keep sufficient credit for the intended duration.

## Paused benchmark backup and recovery

GPU instance `58649375` was verified stopped at **2026-11-01 11:57 UTC** after
backup/restore and local evidence collection. Volume `58649037` and the container
disk are retained. The setup/benchmark session decreased Vast credit by about
**$0.754**, excluding AWS charges and storage accrued after stopping.

The old-cohort A100 benchmark is paused at update 10. A **1,024,084,972-byte** recovery archive
was uploaded to the configured private `MALWEAVE_RANDS_TRAIN_S3_PREFIX`, followed by
`/c-metadata-5ep-bench-mb1-seed0/backup.tar.gz`. It contains the exact deployed
source/config/lock, released checkpoint/tokenizer, frozen cohort, selected paused run
and benchmark evidence; it excludes EXEs, virtual environments and `.env`/credentials.

S3 length/checksum metadata were checked; the complete archive was then downloaded
from S3 and its SHA-256 verified. The downloaded copy was extracted to an isolated
directory. With the restored source and state, training resumed from update 10 to
11 and paused; the original update-10 checkpoint hash remained unchanged. The
recovery probe used the **same A100/container runtime and staged EXEs**, not a rebuilt
worker. That benchmark used a one-off backup. The current round-02 supervisor adds periodic
off-host backup; recovery on a fresh worker remains unverified.

Lightweight logs/manifests and aggregate results are also stored on the workstation
under `~/.config/malweave/a100-setup-01/`. The earlier 15-epoch A40 archive remains
historical evidence at suffix `/c-metadata-seed0/backup.tar.gz`; its instance and
volume were deleted. Do not resume it under the 5-epoch configuration.

The update-10 benchmark uses the old cohort and source. **Do not resume it for
round-02 results.** Its source/cohort/run and S3 recovery archive are preserved as
benchmark evidence. Start the reviewed round-02 source with a fresh run ID using the
commands above with the current supervisor and approved credit/backup policy.
Temporary AWS credentials need renewal before expiry for later S3 operations; the
workstation SSH private key stays local with mode 600.

## Verification and remaining work

CPU synthetic coverage includes byte/token truncation, exact backbone load, frozen
features, malformed artifacts, argmax ties, early stopping, partial accumulation,
metadata temporal splitting/full-EXE and final-token dedup/undersampling, incomplete
or stale audit rejection, checkpoint/audit binding, fake-S3 staging, AP/bootstrap and
exact mid-epoch resume with dropout. The main checkpoint loaded all 642 backbone
tensors and gave finite loss/nonzero finite gradients on a 10-token synthetic input;
no optimizer step or RanDS sample was used.

The A40 worker subsequently passed native-kernel BF16 forward/backward at 65,536
synthetic tokens. Its first real C benchmark processed 640 train samples / 10 updates
in 730.22 seconds, with 7.90 GiB peak allocated tensor memory. It paused before
validation/test; these measurements do not establish RanDS accuracy, long-run BF16
stability, full-run cost or absence of pretraining overlap. The local Quadro
T2000 has 4 GB and lacks native BF16 for this protocol. The separate DiE job was not
modified. A/D still require their own implementation/parity checks. E1/E2 now have
separate implementations and synthetic CPU source checks as described above;
C readiness is not readiness of the entire suite or proof of E1/E2 GPU capacity.

Verification on 2026-11-01 after correcting the stale epoch guard: `make check`
passed all 192 tests, lock/lint/format and
strict documentation build. A separate static staging check fetched six real EXEs
(one per class/partition), 4,635 bytes total; full hashes/sizes matched, a repeat reused
all six files without transfer, and temporary payloads were removed. No file was
executed or used for training. Frozen split/config digests remain unchanged.
