# Versioned Research Configuration

Keep human-reviewed, non-sensitive configuration here. `datasets/` describes release-specific inputs and `experiments/` captures model, training, evaluation, and logging choices. Never place credentials, raw sample lists, private URLs, or downloaded data in these files.

Create one committed experiment configuration per reported result and write the fully resolved copy into its ignored model/run directory at execution time.

Dataset configs use YAML and identify local roots through environment-variable names. Developers
may set those variables in the ignored root `.env` using `.env.example` as a template. Configs may
contain aggregate release counts and protocol filters, but never absolute machine paths or sample
inventories.

Define external-pretraining and EXE downstream configs using the
[research protocol](../docs/mkdocs/docs/workflows/research-protocol.md). Configs record source
scope, input manifests, model/tokenizer settings and evaluation choices. SOREL/Assemblage
adapters and the EXE-only runner interface are implementation tasks.
