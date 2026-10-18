# Assemblage Windows PE

Assemblage builds binaries from licensed open-source repositories and publishes metadata about
projects and build configurations. This study selects **GitHub Windows PE** as background software
for self-supervised pretraining. The generator is MIT-licensed; each binary retains its source
repository's license. This is not an AV-labelled benign/malware classification corpus.

## Selected Distribution

- Dataset: [changliu8541/Assemblage_PE](https://huggingface.co/datasets/changliu8541/Assemblage_PE).
- Revision: **`19a8f947f5a04d03edea78e61790226b55f92ac2`**.
- Scope: Windows PE; exclude the separate Linux ELF, Rust, vcpkg and DeepHistory collections.

The [actual file listing](https://huggingface.co/datasets/changliu8541/Assemblage_PE/tree/19a8f947f5a04d03edea78e61790226b55f92ac2)
contains:

| File | Compressed bytes | Approximate GB |
| --- | ---: | ---: |
| `winpe.sqlite.tar.xz` | 9,317,926,086 | 9.32 |
| `binaries.tar.xz` | 33,827,018,671 | 33.83 |

The dataset card still mentions `binaries.csv`, `functions.csv` and
`winpe_pdbs.sqlite.tar.xz`; these names are absent from the selected revision. Download the actual
archives above rather than constructing URLs from those descriptions. The card describes 91k PEs
while the project page describes 88k Windows binaries; obtain experiment counts from the selected
database and archive instead of combining website totals.

## Download And Storage Plan

Download the metadata archive first, list/extract its database and inspect it read-only. Then
obtain the binary archive using the same revision. The two compressed archives total 43.15 GB;
allow additional space for unpacked metadata, EXE outputs and download-tool cache.

`binaries.tar.xz` is a compressed tar archive, not individually downloadable PE objects. The plan
uses one local archive download and sequential member reads. Selecting 100 PEs reduces the number
of extractions, not necessarily archive download or scan time. Read regular member bytes without
unpacking the complete PE tree to disk. Record archive-rescan costs when testing resume.

## Metadata And Mapping

The official access guide documents a `binaries` table and path (`path` or `binary_path`) or hash
mapping to the binary archive. Inspect the downloaded schema and actual tar names before writing
queries or path normalization. The current generator ORM is reference material, not proof of the
older release's exact column names.

Extract only binary-level information needed for EXE and provenance: ID, archive member/path,
hash, size, repository/project, license, compiler/toolset, optimization, build mode and commit/build
ID when provided. Keep missing fields explicit. Functions, source lines and PDB tables are not
needed for this EXE study.

## Sampling And Leakage

Start with roughly 100 sources across projects/build settings. Keep the selected list and seed.
Report missing members, malformed PEs and EXE failures. Multiple compiler/optimization variants
of one project are related samples; keep the project together in external train/validation.
Deduplicate exact EXE content, preserve source/project relations and check overlap with RanDS.
Static inspection is sufficient; do not execute the binaries.

Follow [data preparation](../workflows/data-preparation.md) for the complete source-to-EXE plan.

## Citation

```bibtex
@misc{liu2024assemblageautomaticbinarydataset,
  title={Assemblage: Automatic Binary Dataset Construction for Machine Learning},
  author={Chang Liu and Rebecca Saul and Yihao Sun and Edward Raff and Maya Fuchs
          and Townsend Southard Pantano and James Holt and Kristopher Micinski},
  year={2024},
  eprint={2405.03991},
  archivePrefix={arXiv},
  primaryClass={cs.CR},
  url={https://arxiv.org/abs/2405.03991}
}
```

## Official References

- [Assemblage dataset access guide](https://assemblagedocs.readthedocs.io/en/latest/dataset.html).
- [Assemblage project](https://assemblage-dataset.net/).
- [Selected Windows PE files](https://huggingface.co/datasets/changliu8541/Assemblage_PE/tree/19a8f947f5a04d03edea78e61790226b55f92ac2).
- [Dataset API file sizes](https://huggingface.co/api/datasets/changliu8541/Assemblage_PE/tree/19a8f947f5a04d03edea78e61790226b55f92ac2).
- [Generator and metadata ORM](https://github.com/Assemblage-Dataset/Assemblage/blob/main/backend/assemblage/dataset/orm.py).
- [Paper: Assemblage, NeurIPS 2024 Datasets and Benchmarks](https://arxiv.org/abs/2405.03991).
