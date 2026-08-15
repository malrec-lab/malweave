# RanDS Ransomware Dataset

## Overview

**RanDS** is a Windows Portable Executable (PE) corpus for ransomware research. It provides raw ransomware and benign PE samples through a searchable web interface, plus separately downloadable processed releases for static strings, imported/exported APIs, and sandbox-observed behavior. The dataset is intended for ransomware detection, ransomware-family classification, and static/dynamic feature research.

The official site currently reports the following corpus totals:

| Class | Samples | Additional label information |
| --- | ---: | --- |
| Ransomware | 104,616 | 533 ransomware families |
| Benign | 110,788 | No ransomware-family label |
| Total | 215,404 | Windows PE samples |

The live sample tables expose SHA-256, CPU architecture, file extension, file size, and first-submission year. Ransomware records additionally expose a family label. The available raw extensions are EXE and DLL. Treat the web-site counts and family assignments as release-state metadata: save a local snapshot date and the exported metadata used in an experiment.

## Access, Use Terms, and Safety

RanDS states that its ransomware samples are **live** and are provided solely for research. It prohibits malicious use, exploitation, and distribution; users are responsible for complying with applicable laws. The site also warns that samples can harm devices and data.

- Do not download raw samples to a personal workstation, commit them to this repository, execute them, restore them, or redistribute them.
- Obtain institutional approval where required. Handle raw material only in an isolated, disposable malware-analysis environment with no credentials, shared folders, production connectivity, or bridged network access.
- Prefer the processed feature releases for machine-learning work. The site describes these as containing no executable content, but their metadata and behavioral indicators can still be sensitive research material.
- Keep raw archives, extracted datasets, metadata exports, and experiment artifacts outside version control and document their local access controls.

The official pages do not present a source-code repository for RanDS itself, so there is no dataset repository to clone. Access the dataset through the official website and retain its current research-use notice with the acquisition record.

## Official Access Paths

| Resource | Official location | Intended use |
| --- | --- | --- |
| Dataset home | [RanDS home](https://ran-ds.com/home) | Corpus totals, citation, and safety notice |
| Raw ransomware records | [Ransomware samples](https://ran-ds.com/ransomware) | Search/filter metadata and request individual live samples |
| Raw benign records | [Benign samples](https://ran-ds.com/benigns) | Search/filter benign metadata and request individual samples |
| Family catalogue | [Ransomware families](https://ran-ds.com/families) | Inspect available ransomware-family labels |
| Processed releases | [Processed datasets](https://ran-ds.com/features) | Download non-executable feature archives |
| Distribution charts | [Sample charts](https://ran-ds.com/samples-charts) | Inspect site-provided corpus distributions |

The site distributes individual raw samples as password-protected ZIP archives. Its documented archive password is `infected`. That password is a handling convention, not a safety control: a downloaded raw sample remains live malware. Do not automate bulk raw-sample collection from the browser interface without explicit authorization and an approved collection protocol.

## Processed Dataset Releases

The [processed-datasets page](https://ran-ds.com/features) currently offers five feature representations. Download only the representation required for the experiment; every release may be a password-protected ZIP archive using the password above. The site states that these archives contain no executables.

| Release | Representation and extraction method | Per-sample file |
| --- | --- | --- |
| PE Static Raw Strings | Printable ASCII and UTF-16LE strings, minimum length 3, cleaned, lowercased, deduplicated, and consolidated | Text |
| PE Static English Strings | Raw-string representation filtered with Python Enchant to retain deduplicated English words | Text |
| PE Static APIs | Imports and exports parsed with `pefile`, with functions grouped by DLL/module | JSON |
| PE Static Demangled APIs | Static API representation after Demumble processing for Itanium and Visual Studio symbols | JSON |
| PE Behavioral Activities | CAPEv2 and Cuckoo Sandbox observations | JSON |

The behavioral JSON has 15 activity entries. The official description covers accessed/created registry keys; accessed, created, deleted, and changed files; network IPs and DNS lookups; created and killed processes; a process tree; accessed and created mutexes; loaded modules; executed commands; and critical API calls. Not every PE could be executed, including samples that were outdated or unsupported by the sandbox architecture. Therefore, absence of a behavioral file or activity is not evidence of benignness or of non-occurrence.

## Archive Layout and Data Model

Each processed release is described as a ZIP archive with this high-level layout:

```text
<release>.zip
  Benign.csv                       # metadata and references for benign samples
  Ransomware.csv                   # metadata and references for ransomware samples
  dataset/
    ab/                            # first two characters of a sample SHA-256
      <sample feature file>        # text or JSON, depending on the release
    ...
```

Use the sample SHA-256 as the join key between a CSV row and its feature file. The official page specifies the two-character SHA-256 shard directory but does not publish a stable CSV column schema or a feature filename extension convention. Inspect the downloaded CSV headers and one feature file before writing a pipeline; do not hard-code undocumented column names, JSON keys, row order, or a one-to-one coverage assumption.

The following read-only inspection keeps archive extraction and model preparation separate. It verifies that each recognized SHA-256 in the metadata has at least one file under its expected shard; it never opens or executes raw PEs.

```python
from pathlib import Path
import csv
import re

root = Path("data/rands/pe-static-apis")  # extracted processed release
feature_root = root / "dataset"
sha_pattern = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

for csv_name in ("Benign.csv", "Ransomware.csv"):
    with (root / csv_name).open(newline="", encoding="utf-8-sig") as handle:
        rows = csv.DictReader(handle)
        if not rows.fieldnames:
            raise ValueError(f"{csv_name} has no header")

        sha_column = next(
            (
                column
                for column in rows.fieldnames
                if column.lower().replace("-", "").replace("_", "") == "sha256"
            ),
            None,
        )
        if sha_column is None:
            raise ValueError(f"No SHA-256 column in {csv_name}: {rows.fieldnames}")

        total = missing = 0
        for row in rows:
            sha256 = row[sha_column].strip().lower()
            if not sha_pattern.fullmatch(sha256):
                raise ValueError(f"Invalid SHA-256 in {csv_name}: {sha256!r}")
            total += 1
            if not any((feature_root / sha256[:2]).glob(f"{sha256}*")):
                missing += 1
        print(f"{csv_name}: {total} rows, {missing} without a matching feature file")
```

If an archive is encrypted, list it and extract it only into a controlled data directory. Record the archive filename, retrieval date, checksum calculated locally, release type, extraction tool/version, CSV headers, and resulting feature coverage. Do not place that local data directory under `docs/` or Git.

## Using RanDS in a Model

1. Select one representation and create labels from the CSV source: benign `0`, ransomware `1`; use a ransomware family only for ransomware-only multi-class tasks.
2. Join rows to features by SHA-256, then report how many samples are excluded because their selected representation is unavailable or malformed.
3. Split before fitting tokenizers, vocabularies, normalizers, feature selection, resampling, or hyperparameters. Keep all representations of one SHA-256 in the same partition.
4. For ransomware-family classification, split by family or use a carefully documented family-disjoint protocol when measuring generalization to unseen families. Report the support for each family rather than relying only on a micro-average.
5. For realistic detection claims, use time-aware and provenance-aware splits when the supplied metadata permits them. Record exactly which `Year` values and collection snapshot were used.

## Important Caveats

- **Task scope:** The malicious class is ransomware, not all malware. A ransomware-versus-benign result must not be presented as a general-malware detection result without external validation.
- **Family labels:** The ransomware families are likely imbalanced and may reflect the curator's naming and labelling policy. Family labels are not independent ground truth and can change as samples are reclassified.
- **Representation leakage:** Raw strings, English strings, APIs, demangled APIs, and behavior traces can describe the same underlying sample. Never put different representations of the same SHA-256 across train, validation, and test sets.
- **Dynamic-analysis bias:** Sandbox output depends on OS image, execution time, network policy, anti-analysis behavior, payload stage, and tool support. Missing or sparse behavior is censored observation, not a negative observation.
- **Static-analysis limits:** Imports/exports and strings are incomplete for packed, obfuscated, dynamically resolved, or non-PE behavior. Text cleanup and English-word filtering also discard potentially discriminative non-English or encoded data.
- **Versioning:** The website is live and may add samples or revise metadata. Preserve the official URLs, access date, counts observed, raw/processed release names, local checksums, and preprocessing configuration with every result.

## Citation

```bibtex
@article{rands2026,
  title   = {RanDS: A large-Scale open dataset of raw binaries and extracted features for ransomware research},
  author  = {Saleh Alzahrani and Yang Xiao and Sultan Asiri},
  journal = {Computers \& Security},
  volume  = {167},
  pages   = {104909},
  year    = {2026},
  issn    = {0167-4048},
  doi     = {https://doi.org/10.1016/j.cose.2026.104909},
  url     = {https://www.sciencedirect.com/science/article/pii/S0167404826000854},
}
```

## Official References

- [RanDS home](https://ran-ds.com/home) - official corpus description, counts, collector, safety notice, and citation.
- [RanDS processed datasets](https://ran-ds.com/features) - official feature-extraction descriptions, archive layout, and download links.
- [RanDS ransomware table](https://ran-ds.com/ransomware) and [benign table](https://ran-ds.com/benigns) - searchable sample metadata and raw-sample access.
- [RanDS paper](https://doi.org/10.1016/j.cose.2026.104909) - dataset methodology and research context.
