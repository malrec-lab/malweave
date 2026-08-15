# Assemblage Binary Dataset

## Overview

**Assemblage** is a distributed corpus generator and a collection of binaries it builds from licensed open-source repositories. It produces x86-64 Windows Portable Executable (PE) and Linux ELF binaries under varied compiler and optimization configurations, together with function-level ground truth.

> **Not a malware dataset:** Assemblage contains compiled open-source software, not malware labels or malware-family labels. Use it as benign/background data, for binary-model pretraining, or for function-level binary analysis. A malware detector still requires a separately sourced malware corpus and an evaluation protocol that prevents source/build overlap.

The project targets binary analysis tasks including compiler provenance, binary-function similarity, function-boundary work, reverse engineering, and static/dynamic analysis. It is particularly useful to complement malware datasets whose benign class is small, unavailable, or lacks build provenance.

## What Is Released

Assemblage is both:

1. an **MIT-licensed generator** that discovers repositories and builds a configurable corpus; and
2. **published corpus snapshots** containing only the subset cleared for public distribution under the source repositories' licenses.

The official project page's May 2026 public-snapshot statistics are:

| Source | Platform | Binaries | Repositories | Functions |
| --- | --- | ---: | ---: | ---: |
| GitHub | Windows | 88,000 | 13,000 | 50 million |
| GitHub | Linux | 249,000 | 16,000 | 613 million |
| vcpkg | Windows | 29,000 | 1,000 | 48 million |
| DeepHistory | Windows/Linux | 73,000 | 248 | 441 million |

The same project also publishes a separate Rust release: 18,450 compiled binaries from 3,034 permissively licensed repositories, with DWARF function/line metadata, source trees, and compiler IR for a subset.

Numbers differ between releases. For example, the official Windows PE Hugging Face card describes a 91,000-binary snapshot last updated in October 2024, while the official project page reports an 88,000-binary Windows GitHub snapshot in May 2026. Always identify the exact repository, revision, retrieval date, and manifest rather than combining counts from different snapshots.

## Access and Licensing

- **Generator:** the [official GitHub repository](https://github.com/Assemblage-Dataset/Assemblage) is MIT-licensed.
- **Published corpus:** the corpus does *not* inherit a single permissive project-wide license. Each binary retains the license of its originating source repository. The official releases include a GitHub-URL-to-license JSON mapping; preserve and follow those source licenses.
- **Current hosting:** the project states that, from May 2026, it updates the Hugging Face copies rather than Kaggle because of size limits. Use the project's [dataset access page](https://assemblagedocs.readthedocs.io/en/latest/dataset.html) as the canonical release directory.
- **Safety:** Assemblage is intended to be benign, but it is still a large collection of third-party executables. Analyse binaries statically by default; do not execute them on a workstation or treat their benign provenance as a security guarantee.

## Dataset Structure

Historically, a release consists of two coordinated artifacts:

```text
assemblage-release/
  binaries.tar.xz              # compressed binary tree
  <platform>.sqlite.tar.xz     # metadata database for that release
  license.json                 # source GitHub URL -> license mapping, when supplied
```

The metadata database tells consumers where an executable belongs in the binary archive: the `binaries.path` field identifies its relative path. The project's legacy data guide documents SQLite; the project page announced a migration to DuckDB for newly updated releases starting May 2026. Inspect each release manifest and database extension before scripting a pipeline.

The official Windows PE Hugging Face snapshot currently exposes `binaries.tar.xz` and `winpe.sqlite.tar.xz`. Their declared compressed sizes are approximately 33.8 GB and 9.3 GB respectively. The released archive layout and database schema can change, so list the archive before extraction and check the database tables instead of assuming an older snapshot's filenames.

### Metadata Schema

The March 2024 datasheet documents these core SQLite tables:

| Table | Contents |
| --- | --- |
| `binaries` | Binary path/name, size, compiler/toolset version, optimization, and source repository URL |
| `functions` | Function metadata, including source code and a hash of the function bytes |
| `rvas` | Relative virtual-address ranges for functions; a function can have multiple chunks |
| `lines` | Source-line-to-address mapping |
| `pdbs` | Program Database (PDB) path for Windows binaries |

Windows metadata is populated from build outputs and PDB information; Linux/Rust releases can use DWARF-derived information. Ground-truth coverage varies by platform, compiler, optimization, and release. Verify non-null labels for the precise task instead of treating every binary or function as fully labelled.

## Download and Use a Published Snapshot

The following process downloads only the Windows PE metadata first. It avoids accidentally retrieving the much larger binary archive. Install [Git LFS](https://git-lfs.com/) before cloning a Hugging Face release that stores large archives with LFS.

```bash
git lfs install
GIT_LFS_SKIP_SMUDGE=1 git clone https://huggingface.co/datasets/changliu8541/Assemblage_PE data/assemblage/pe
cd data/assemblage/pe
git lfs pull --include="winpe.sqlite.tar.xz"
tar -tJf winpe.sqlite.tar.xz
mkdir metadata
tar -xJf winpe.sqlite.tar.xz -C metadata
```

After confirming available disk space and the archive layout, retrieve and extract binaries only when needed:

```bash
git lfs pull --include="binaries.tar.xz"
tar -tJf binaries.tar.xz | sed -n '1,40p'
mkdir binaries
tar -xJf binaries.tar.xz -C binaries
```

The exact database filename inside the metadata archive is release-specific. Locate it before opening it:

```bash
find metadata -type f \( -name '*.sqlite' -o -name '*.duckdb' \)
```

For Linux ELF, Windows vcpkg, Rust, and newer snapshots, select the corresponding official Hugging Face release from the project documentation. Do not assume that the Windows PE archive, metadata filename, or schema applies to those releases.

## Querying the Metadata

For a SQLite snapshot, open the database read-only and first examine its tables:

```python
from pathlib import Path
import sqlite3

root = Path("data/assemblage/pe")
metadata_dir = root / "metadata"
db_path = next(metadata_dir.glob("*.sqlite"), None)
if db_path is None:
    raise FileNotFoundError(f"No *.sqlite found under {metadata_dir}; check the extracted archive contents.")
connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

tables = connection.execute(
    "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
).fetchall()
print(tables)
```

The following query joins a binary to its functions and relative virtual addresses. It should be adapted only after confirming the local schema with `PRAGMA table_info(...)`:

```python
rows = connection.execute(
    """
    SELECT b.id AS binary_id, b.path, f.id AS function_id, f.name, r.start
    FROM binaries AS b
    JOIN functions AS f ON f.binary_id = b.id
    JOIN rvas AS r ON r.function_id = f.id
    WHERE b.id = ?
    ORDER BY r.start ASC
    """,
    (1,),
).fetchall()
```

Use `binaries.path` to map a database record to the extracted binary root. Keep function rows together with their parent binary when creating a split: the same project and source build can appear under multiple optimization/compiler configurations.

## Using Assemblage for Malware Research

### Appropriate Roles

- Pretrain byte-, disassembly-, control-flow-, or function-level representations on labelled benign code and build provenance, then fine-tune on a licensed malware dataset.
- Create a **benign-only auxiliary corpus** for static PE research, compiler-provenance controls, or function-similarity evaluation.
- Use source, line, function, and address labels to validate feature extraction and reverse-engineering components independently of malware detection.

### What It Cannot Provide

- A malware/benign target label, malware families, threat categories, or malicious behavior traces.
- A valid negative class by itself for a malware detector. If mixed with malware, document the selection process; source/provenance, compiler artifacts, debug information, and time period can otherwise become shortcuts that a model learns instead of maliciousness.
- A current software distribution. Its contents reflect source repositories and build configurations collected for a particular snapshot, not an ecosystem-wide or current endpoint population.

## Important Evaluation and Reproducibility Notes

- **Avoid build leakage:** Split by source repository (and preferably upstream project/version), not only by binary or function. Multiple optimization levels and compilers can produce highly similar binary variants.
- **Avoid provenance shortcuts:** A classifier trained with malware from one pipeline and Assemblage as its benign class may learn compiler, PDB/DWARF, packer, signing, path, or source-provenance artifacts. Strip or control such fields if the research question is malware detection.
- **Treat ground truth as configuration-dependent:** Function names, source lines, PDBs, DWARF records, and optimization-dependent function boundaries are not uniformly available in every build.
- **Record the exact release:** Save the Hugging Face revision, LFS object/checksum, archive filenames, extraction commands, database engine/version, schema inspection results, and license manifest used.
- **Respect upstream licenses:** Retain the release's license mapping and check all sources before redistributing binaries, source snippets, function-level data, or model-training derivatives.
- **Do not run arbitrary binaries:** Static inspection is sufficient for most training-data preparation. If dynamic analysis is required, use an isolated, disposable environment with no secrets or production connectivity.

## Building a New Corpus (Optional)

Cloning the generator is separate from downloading a published snapshot:

```bash
git clone https://github.com/Assemblage-Dataset/Assemblage.git
cd Assemblage
```

The upstream system uses Python 3.12, Docker Compose, RabbitMQ, PostgreSQL, and MinIO. It searches licensed GitHub repositories, builds them in a compiler/configuration matrix, extracts metadata, and exports a corpus. Follow the [upstream installation guide](https://github.com/Assemblage-Dataset/Assemblage/blob/main/INSTALL.md) rather than running it against personal credentials or production infrastructure without reviewing its resource, storage, and licensing implications.

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

## Official Resources

- [Assemblage project page](https://assemblage-dataset.net/) - current public-snapshot statistics, hosting policy, and project contacts.
- [Dataset access documentation](https://assemblagedocs.readthedocs.io/en/latest/dataset.html) - distribution format, metadata examples, and official release links.
- [Assemblage GitHub repository](https://github.com/Assemblage-Dataset/Assemblage) - generator code, installation guidance, and MIT license.
- [Windows PE Hugging Face release](https://huggingface.co/datasets/changliu8541/Assemblage_PE) - current archive manifest for the PE snapshot described above.
- [Rust Hugging Face release](https://huggingface.co/datasets/changliu8541/assemblage-rust) - Rust corpus and its dataset card.
- [Assemblage paper](https://arxiv.org/abs/2405.03991) - dataset design and initial evaluation; presented at NeurIPS 2024 Datasets and Benchmarks.
- [March 2024 total-binaries datasheet](https://assemblage-dataset.net/assets/total-datasheet.pdf) - legacy snapshot methodology, configuration distribution, and detailed SQLite schema.
