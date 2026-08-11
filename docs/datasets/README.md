# Malware Datasets

This directory records datasets considered for malware machine-learning research. Each dataset has its own page covering its contents, access method, loading steps, evaluation considerations, safety restrictions, and official references.

## Dataset Index

| Dataset | Platform | Primary use | Documentation |
| --- | --- | --- | --- |
| BODMAS | Windows Portable Executable (PE) | Static-feature detection, family classification, and temporal analysis | [BODMAS](bodmas.md) |

## Documentation Rules

- Treat each page as a reproducibility note, not a redistribution source. Dataset archives, sample hashes, credentials, and raw malware must not be committed to this repository.
- Preserve the original license, access conditions, and citation requirements. Do not assume a public metadata or feature download also permits access to raw binaries.
- Record the dataset release date, a local acquisition date, checksums, and any preprocessing performed in the experiment that uses it.
- Keep dataset-specific code and large artifacts outside `docs/`; document their expected local locations on the relevant dataset page.

## Adding a Dataset

Create one lowercase, hyphenated Markdown file per dataset (for example, `sorel-20m.md`). Include: overview, access and licensing, file layout/schema, loading example, validation steps, known limitations, safety guidance, and official references.
