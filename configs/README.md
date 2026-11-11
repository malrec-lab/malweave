# Research configuration

Keep non-sensitive dataset and experiment inputs here. Credentials, private URLs,
source inventories and generated artifacts stay outside Git. Preserve resolved config
with each reported run; existing configs are not approval to start a new experiment.

The current priority is [LMLM checkpoint fine-tuning/evaluation on RanDS](../docs/mkdocs/docs/workflows/lmlm-checkpoints.md).
`experiments/rands-lmlm-c.yaml` declares experiment C's first metadata-filtered round:
released MLM BiMamba, full fine-tuning, a 65,536-byte prefix before BPE, BF16 and the
approved 5-epoch budget. Native BF16/Mamba kernels and maximum-context memory have
been tested on A100 SXM4 80 GB; measured throughput is recorded in the workflow.
See the linked workflow for staging, benchmark and resume commands.

`experiments/rands-lmlm-e1.yaml` declares the original MalConvGCT implementation:
whole-file byte+1 input, learned context, fixed PAD embedding, kernel 256, effective
batch 128 and constant LR. The T4 microbatch sweep selected physical batch 1;
pass `--gradient-accumulation-steps 128` to retain the effective batch.
`experiments/rands-lmlm-e2.yaml` declares the LMLM implementation:
round-02 sample list, source byte+7/BOS/EOS encoding, FP32, physical/effective batch 64,
gradient accumulation 1, detached context, unfixed PAD embedding and 15 planned epochs.
Both use the shared RanDS cohort/evaluation policy; this is not exact replication
of every source training choice. See the [E1/E2 comparison](../docs/mkdocs/docs/workflows/lmlm-checkpoints.md#e1-versus-e2-original-malconvgct-and-the-lmlm-implementation).
The synthetic Kaggle preparation and resume workflow are in
[E2 on Kaggle](../docs/mkdocs/docs/workflows/lmlm-checkpoints.md#e2-on-kaggle-synthetic-capacity-and-recovery).
Real PE transfer and a long training run are not part of that preparation.

`experiments/rands-lmlm-a.yaml` declares test-only evaluation of the intact
released EXE detector 1923 (MLM-799 lineage), including its original linear head.
It fixes FP32, batch 1, 65,536-byte/token limits and softmax/argmax. No optimizer,
training or threshold fitting is involved. See [A on Kaggle](../docs/mkdocs/docs/workflows/lmlm-checkpoints.md#a-on-kaggle-intact-detector-and-test-only-evaluation)
for the synthetic GPU notebook, frozen-cohort checks, outputs and resume limits.

## Retained configurations

These support the [paused self-pretraining direction](../docs/mkdocs/docs/workflows/self-pretraining.md)
or existing data tools:

| File/group | Purpose |
| --- | --- |
| `datasets/rands-raw-2026.yaml` | RanDS raw-release audit expectations. |
| `datasets/sorel-full.yaml` | SOREL v3.1 conversion; [protocol](../docs/mkdocs/docs/workflows/sorel-protocol.md) and [guide](../docs/mkdocs/docs/workflows/sorel-conversion.md). |
| `datasets/sorel-pilot.yaml` | Legacy pilot/round-robin workflow; incompatible with v3.1 resume. |
| `experiments/rands-exe-scratch.yaml` | Independent RanDS scratch baseline; random BiMamba weights, RanDS-training-only BPE and resumable supervised training. |
| `worker-images.json` | Retained worker image/tool identity. |
| `storage/` | Example AWS access policies; actual destinations and credentials are private. |

The scratch config's architecture, context, split and five-epoch schedule do not
define the checkpoint experiment. See its [retained guide](../docs/mkdocs/docs/workflows/rands-scratch.md).
