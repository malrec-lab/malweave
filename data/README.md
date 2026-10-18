# Local Data Layout

All contents below `data/` are ignored by Git. Keep the small `.gitkeep` files so the layout remains visible, but never force-add real data.

| Directory | Purpose |
| --- | --- |
| `raw/` | Immutable archives or original downloads. Do not modify in place. |
| `external/` | Inputs managed by third parties or copied from another approved source. |
| `interim/` | Working transformations; check provenance/run references before treating any output as disposable. |
| `processed/` | Canonical model-ready datasets, created from versioned code and config. |

For each acquisition, record the provider URL, release/revision, local retrieval date, license/terms, checksum, and preprocessing configuration in the local experiment record. Keep raw malware, sample inventories, credentials, and any restricted metadata in an approved isolated storage location. Set `MALWEAVE_DATA_DIR` to use that location without changing source code.

Dataset-specific requirements and safety guidance live in the [dataset catalog](../docs/mkdocs/docs/datasets/index.md).

RanDS has been converted to EXE and uploaded to S3. Store EXE outputs with source/representation
manifests, metadata, extraction state and reports, as defined in
[data preparation](../docs/mkdocs/docs/workflows/data-preparation.md).
