# Malware Datasets

The table identifies the source cohorts used by the shared audits and their possible
roles in the current paper. The shared paths, publication tables and
dataset-specific artifacts are documented in the [S3 layout](s3-layout.md).

## Dataset index

| Dataset | CLI ID | Scope and research role | Documentation |
| --- | --- | --- | --- |
| RanDS | `rands` | Primary ransomware-versus-benign dataset. The new split is pending. | [RanDS](rands.md) |
| VERA | `vera` | Ransomware repository. Active/latent are dataset states, so external evaluation needs a clearly stated population and overlap check. | [Zenodo record](https://doi.org/10.5281/zenodo.17904705) · [Local artifacts](s3-layout.md#local-audit-inputs-and-evidence) |
| RawMal-TF | `rawmal` | Malware with type and family task branches. The shared audit uses the PE subset. Secondary-task use is proposed. | [Local artifacts](s3-layout.md#local-audit-inputs-and-evidence) |
| Assemblage | `assemblage` | Windows binaries built from open-source projects. Confirm project provenance before a project-disjoint split. | [Assemblage](assemblage.md) |

## Documentation Rules

- Treat each page as a reproducibility note, not a redistribution source. Dataset archives, sample hashes, credentials, and raw malware must not be committed to this repository.
- Preserve the original license, access conditions, and citation requirements. Do not assume a public metadata or feature download also permits access to raw binaries.
- Record the dataset release date, a local acquisition date, checksums, and any preprocessing performed in the experiment that uses it.
- Keep dataset-specific code and large artifacts outside `docs/`; document their expected local locations on the relevant dataset page.

## Adding a Dataset

Create one lowercase, hyphenated Markdown file per dataset (for example, `rands.md`). Include: overview, access and licensing, file layout/schema, loading example, validation steps, known limitations, safety guidance, and official references.
