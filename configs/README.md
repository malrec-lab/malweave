# Versioned Research Configuration

Keep human-reviewed, non-sensitive configuration here. `datasets/` describes release-specific inputs and `experiments/` captures model, training, evaluation, and logging choices. Never place credentials, raw sample lists, private URLs, or downloaded data in these files.

Create one committed experiment configuration per reported result and write the fully resolved copy into its ignored model/run directory at execution time.

Dataset configs use YAML and identify local roots through environment-variable names. Developers
may set those variables in the ignored root `.env` using `.env.example` as a template. Configs may
contain aggregate release counts and protocol filters, but never absolute machine paths or sample
inventories.

Define external-pretraining and EXE downstream configs using the
[research protocol](../docs/mkdocs/docs/workflows/research-protocol.md). Configs record source
scope, input manifests, model/tokenizer settings and evaluation choices.
`datasets/sorel-pilot.yaml` is a development smoke-test config, not the pretraining corpus scope.
For corpus preparation, use an explicit reviewed config and a separate job directory; see
[data preparation](../docs/mkdocs/docs/workflows/data-preparation.md).
`data sorel-run` prepares and processes batches continuously; repeat it to resume the same job.
The config controls workers/batch and size limits, per-tool deadlines, downloader and retries.
The Assemblage adapter and EXE-only runner interface are implementation tasks.
