# Local Data Layout

All contents below `data/` are ignored by Git. Keep the small `.gitkeep` files so the layout remains visible, but never force-add real data.

| Directory | Purpose |
| --- | --- |
| `raw/` | Immutable archives or original downloads. Do not modify in place. |
| `external/` | Inputs managed by third parties or copied from another approved source. |
| `interim/` | Reproducible but disposable transformation outputs. |
| `processed/` | Canonical model-ready datasets, created from versioned code and config. |

These four directories exist at two possible levels:

- **Shared, top-level** (`data/raw/`, `data/external/`, ...): use this when a file does not belong to one specific dataset.
- **Per-dataset** (`data/<dataset_name>/raw/`, `data/<dataset_name>/external/`, ...): use this once a dataset has enough of its own artifacts to warrant isolation, e.g. `data/ranDS/raw/`. Give the dataset directory the same name used in `configs/datasets/` and the dataset catalog.

`.gitignore` covers both levels (`/data/raw/*` and `/data/*/raw/*`, same for the other three), so raw contents stay untracked either way — always run `git add -n` before staging a new dataset directory to confirm nothing large or restricted is about to be committed.

For each acquisition, record the provider URL, release/revision, local retrieval date, license/terms, checksum, and preprocessing configuration in the local experiment record. Keep raw malware, sample inventories, credentials, and any restricted metadata in an approved isolated storage location. Set `MALWEAVE_DATA_DIR` to use that location without changing source code.

Dataset-specific requirements and safety guidance live in the [dataset catalog](../docs/mkdocs/docs/datasets/index.md).
