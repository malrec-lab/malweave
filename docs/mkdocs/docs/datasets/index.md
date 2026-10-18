# Malware Datasets

This directory records datasets considered for malware machine-learning research. Each dataset has its own page covering its contents, access method, loading steps, evaluation considerations, safety restrictions, and official references.

## Dataset Index

| Dataset | Current role | Scope | Documentation |
| --- | --- | --- | --- |
| SOREL-20M | External MLM pretraining | Registered malware PE subset; no public raw benign | [SOREL-20M](sorel-20m.md) |
| Assemblage | External MLM pretraining | Windows PE background software; project/build groups | [Assemblage](assemblage.md) |
| RanDS | Downstream detection | EXE converted and uploaded to S3; ransomware vs benign | [RanDS](rands.md) |

## Documentation Rules

- Treat each page as a reproducibility note, not a redistribution source. Dataset archives, sample hashes, credentials, and raw malware must not be committed to this repository.
- Preserve the original license, access conditions, and citation requirements. Do not assume a public metadata or feature download also permits access to raw binaries.
- Record the dataset release date, a local acquisition date, checksums, and any preprocessing performed in the experiment that uses it.
- Keep dataset-specific code and large artifacts outside `docs/`; document their expected local locations on the relevant dataset page.

## Adding a Dataset

Create one lowercase, hyphenated Markdown file per dataset (for example, `sorel-20m.md`). Include: overview, access and licensing, file layout/schema, loading example, validation steps, known limitations, safety guidance, and official references.
