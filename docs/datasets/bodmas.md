# BODMAS Malware Dataset

## Overview

**BODMAS** stands for **B**lue Hexagon **O**pen **D**ataset for **M**alware **A**nalysi**S**. It is a labelled, timestamped dataset of Windows Portable Executable (PE) files created by Blue Hexagon and the University of Illinois Urbana-Champaign (UIUC). It supports static malware detection, malware-family classification, and time-aware/concept-drift experiments.

The public feature release contains **134,435** samples collected from **August 2019 through September 2020**:

| Class | Samples |
| --- | ---: |
| Benign | 77,142 |
| Malicious | 57,293 |
| Total | 134,435 |

The malicious samples are annotated with **581 malware families**. The public BODMAS page also links optional malware-category information released in December 2021.

## Access, License, and Safety

The feature vectors and metadata are openly downloadable from the official BODMAS Google Drive. Original binaries are available for **malware only** and require a request to the maintainers; benign binaries cannot be released because of copyright considerations.

- Do not execute, upload, redistribute, or commit raw malware samples. Handle approved binary access only in an isolated malware-analysis environment, following the provider's sharing conditions.
- The dataset maintainers ask raw-binary requesters not to share the data beyond project co-authors. Requests should state the research plan and satisfy the affiliation/justification requirements on the official download page.
- The BODMAS code repository uses the BSD 2-Clause Simplified License. Confirm the terms presented with each downloaded data artifact before redistribution or publication.
- Store downloaded archives and extracted data outside version control. Restrict permissions for any raw-sample directory.

## Official Acquisition

There are two separate things to obtain:

1. **Dataset files**: open the [official BODMAS download page](https://whyisyoung.github.io/BODMAS/) and follow its Google Drive link for `bodmas.npz` and `bodmas_metadata.csv`. The feature bundle is about 250 MB and the metadata is about 12 MB, as stated by the maintainers.
2. **Experiment code** (optional): clone the official repository with HTTPS:

   ```bash
   git clone https://github.com/whyisyoung/BODMAS.git
   ```

   The upstream code was tested with Python 3.6.8 and contains cluster/Fabric-oriented scripts. Its installation instructions are:

   ```bash
   cd BODMAS/code
   python -m pip install -r requirements.txt
   python setup.py install
   ```

   Do not rely on the upstream orchestration scripts unchanged: several assume the clone is at `~/BODMAS`, hard-code host names, or are designed for multiple servers. For a new experiment, start by loading the public files directly as shown below.

For raw malware binaries, follow the current contact and eligibility instructions on the official download page rather than treating the repository or Google Drive feature link as binary access. The page was updated on 2023-10-09 to direct future requests to Pirouz Naghavi, with Gang Wang copied.

## Expected File Layout

Keep data local and untracked (for example, in a locally ignored directory). This project does not prescribe its exact location; the following is one safe convention:

```text
data/
  bodmas/
    bodmas.npz
    bodmas_metadata.csv
    raw-malware/                 # only if separately approved; never versioned
```

`bodmas.npz` is a NumPy compressed archive with these arrays:

| Key | Expected shape | Meaning |
| --- | --- | --- |
| `X` | `(134435, 2381)` | Static PE feature vectors |
| `y` | `(134435,)` | Binary label: `0` = benign, `1` = malicious |

`bodmas_metadata.csv` has one row per feature vector and three columns:

| Field | Meaning |
| --- | --- |
| SHA-256 | Sample identifier and join key for an approved raw-binary corpus |
| First-seen timestamp | Temporal ordering field |
| Malware family | Family name for malicious samples; empty for benign samples |

The maintainers state that both files are sorted by timestamp in ascending order and that feature row *i* corresponds to metadata row *i*. Preserve this ordering unless a deliberate split or shuffle is recorded. Read the actual CSV header after download rather than depending on a guessed column spelling.

## Feature Provenance

Each sample is represented by 2,381 static features extracted with LIEF 0.9.0, using the same feature design as the EMBER dataset. They describe properties derivable from a PE binary; they are not dynamic sandbox traces, byte sequences, disassembly, or source code.

Feature values are **not normalized**. Tree-based methods can generally consume them directly, while neural networks such as MLPs normally need scaling fitted on the training partition only. Never fit a scaler on validation or test data.

## Loading and Validating

```python
from pathlib import Path

import numpy as np
import pandas as pd

root = Path("data/bodmas")
archive = np.load(root / "bodmas.npz", allow_pickle=False)
X = archive["X"]
y = archive["y"]
metadata = pd.read_csv(root / "bodmas_metadata.csv")

assert X.shape == (134_435, 2_381)
assert y.shape == (134_435,)
assert len(metadata) == len(y)
assert set(np.unique(y)).issubset({0, 1})

# Confirm the public ordering contract before constructing temporal splits.
assert metadata.iloc[:, 1].is_monotonic_increasing
```

Before training, also record the downloaded archive checksum, inspect missing values and duplicate SHA-256 values, and confirm that an empty family value agrees with label `0`. If timestamps are parsed for splitting, explicitly convert the timestamp column and save the split boundaries with the experiment output.

## Recommended Use

### Binary Detection

Use `X` as input and `y` as the target. Report class-aware metrics such as ROC-AUC, precision-recall AUC, F1, and false-positive rate at a stated true-positive rate. Since the samples are in temporal order, a chronological train/validation/test partition best reflects future-sample generalization.

### Family Classification

Filter to rows where `y == 1` and use the non-empty family field as the target. The family distribution is long-tailed: only a subset of the 581 families has many examples. Define and publish the handling of rare families, unseen future families, and macro versus weighted metrics.

### Temporal Robustness

Use the first-seen timestamps to train on earlier samples and evaluate later samples. This is a core motivation for BODMAS, but it also means random splits can overstate real-world performance through temporal and family-distribution leakage.

## Important Caveats

- **Scope:** Results apply to the dataset's 2019-2020 Windows PE collection; they should not be generalized without validation to current malware, non-PE formats, mobile binaries, scripts, documents, or network traffic.
- **Static-only view:** The public vectors omit behavior observable only during execution. A model can miss packed, evasive, or behaviorally malicious files whose static representation is insufficient.
- **Leakage control:** Split before fitting normalization, feature selection, target encoding, resampling, or hyperparameter choices. Avoid allowing identical hashes, near duplicates, or closely related family variants to cross evaluation boundaries when the research question requires novelty robustness.
- **Time semantics:** The timestamp is a first-seen field, not necessarily a sample creation time or a ground-truth onset time. Treat it as the dataset's temporal index.
- **Labels and families:** Family labels are curated but remain operational malware taxonomy labels. Normalization, family aliases, and category mappings should be described and versioned if changed.
- **Reproducibility:** Record the retrieval date, checksum, preprocessing code, split strategy, random seed, LIEF/feature implementation version, and the exact data edition. Do not claim raw-binary reproducibility if only public feature vectors were used.

## Citation

Please cite the dataset paper when using BODMAS:

```bibtex
@inproceedings{bodmas,
  title = {BODMAS: An Open Dataset for Learning based Temporal Analysis of PE Malware},
  author = {Yang, Limin and Ciptadi, Arridhana and Laziuk, Ihar and Ahmadzadeh, Ali and Wang, Gang},
  booktitle = {4th Deep Learning and Security Workshop},
  year = {2021}
}
```

## Official Resources

- [BODMAS project and download page](https://whyisyoung.github.io/BODMAS/) - access conditions, feature/metadata downloads, binary-request process, and category-label link.
- [Official BODMAS code repository](https://github.com/whyisyoung/BODMAS) - paper citation, baseline/temporal-analysis code, and upstream installation notes.
- [Dataset paper (PDF)](https://liminyang.web.illinois.edu/data/DLS21_BODMAS.pdf) - collection and experimental methodology.
- [EMBER feature implementation](https://github.com/elastic/ember/blob/master/ember/features.py) - the feature design referenced by the BODMAS maintainers.
- [LIEF project](https://lief.re/) - PE parsing library used for feature extraction (BODMAS specifies version 0.9.0).
