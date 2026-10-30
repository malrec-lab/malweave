# Research configuration

Keep non-sensitive dataset and experiment inputs here. Credentials, private URLs,
source inventories and generated artifacts stay outside Git. Preserve resolved config
with each reported run; existing configs are not approval to start a new experiment.

The current priority is [LMLM checkpoint fine-tuning/evaluation on RanDS](../docs/mkdocs/docs/workflows/lmlm-checkpoints.md).
**No config for that experiment has been established.** Model, tokenizer, cohort and
schedule will be discussed after checkpoint verification.

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
