# Model Components

Components are independent from private data preparation and must be tested with synthetic inputs.
The active baseline is a small bidirectional Mamba with HRRFormer as a runtime fallback.

| Component | Current scope | Work for the new plan |
| --- | --- | --- |
| Byte IDs and BPE (`data/byte_inputs.py`) | Reversible byte mapping and BPE utilities. | Freeze external-training-only fit, full byte coverage and special-token policy. |
| Mamba (`models/mamba.py`) | Bidirectional sequence classifier. | Add/validate token-aligned hidden states for MLM; verify reverse padding/alignment and target-runtime kernels. |
| HRRFormer (`models/hrrformer.py`) | Bidirectional sequence classifier. | Alternative MLM backbone if Mamba feasibility is inadequate; freeze choice before comparison. |
| Supervised runner (`training/supervised.py`) | Training, metrics, checkpoints, predictions and provenance. | Connect pretrained weights and common label-budget views; existing CLI is a RAW/EXE comparison path. |
| MLM head/loss/runner | Planned; no completed pretraining run established. | Mask eligible tokens, compute loss only at valid masked positions, save/load backbone and tokenizer. |
| Transfer smoke test | Planned. | Synthetic EXE → tokens → MLM backward → checkpoint → classifier fine-tune → evaluation. |
| MalConvGCT | Implemented RAW classifier. | Retain as optional reference; not required for the selected EXE-only base experiment. |

A classifier port and forward/backward tests do not establish a working pretraining system.
Check both-direction token alignment, padding, masked-position loss and checkpoint round-trip
before spending on full pretraining. CPU checks do not validate CUDA/native Mamba performance.

The scratch/pretrained comparison must share architecture, tokenizer, context and downstream
subsets. Keep full EXE bytes in data storage; measure token lengths and truncation in the model
pipeline. Declare any chunk aggregation as a separate experimental factor.

Follow the [research protocol](research-protocol.md) and [environment policy](../development/environment.md).
