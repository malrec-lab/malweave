# Model Components

The repository keeps model components independent from RanDS data preparation. They can be developed
and tested with synthetic bytes before any private corpus job exists.

| Component | Input | Responsibility |
| --- | --- | --- |
| MalConvGCT | RAW byte IDs | Convolutional byte classifier with global-context gates. |
| HRRFormer | Tokenized EXE bytes | Bidirectional sequence classification. |
| Mamba | Tokenized EXE bytes | Bidirectional state-space sequence classification. |
| Byte/token utilities | RAW and EXE bytes | Reversible byte IDs and train-partition BPE fitting. |
| Supervised runner | Frozen private split | Optimization, checkpoints, metrics, predictions, and run provenance. |

An experiment configuration combines these pieces; it is not checked in as a generic fixed cohort.
It names the input products and split, representation, model shapes, tokenizer, loss, optimizer,
schedule, epochs, seed, metrics, and device policy. The runner writes a private immutable run
directory containing the resolved config, input digests, metrics history, checkpoint, predictions,
and environment details.

For a legitimate comparison, deduplicate exact active-representation groups and freeze the split
before fitting BPE or tuning settings. A local smoke run uses synthetic inputs and makes no research
claim. CUDA and Mamba's native fast path are verified in the target runtime when a real run is
declared.
