# SOREL-20M Malware Dataset

## Overview

**SOREL-20M** (Sophos-ReversingLabs 20 Million) is a large benchmark for static Windows Portable Executable (PE) malware detection. Released by Sophos and ReversingLabs in December 2020, it provides nearly 20 million labelled PE records, pre-extracted EMBER v2 features, PE metadata, vendor-derived behavioral tags, baseline models, and approximately 9.92 million disarmed malware binaries.

It is suited to large-scale binary classification, multi-task learning with behavior-like tags, and time-aware evaluation. It is not a current threat feed: the data was collected from **2017-01-01 through 2019-04-10**.

| Item | Quantity |
| --- | ---: |
| Total labelled PE records | 19,389,877 |
| Malware records / disarmed malware binaries | 9,919,251 |
| Benign records | 9,470,626 |
| Raw benign binaries released | 0 |
| Behavioral tag targets | 11 |

The benchmark paper and the official `meta.db` index are authoritative for the exact local record count. The supplied class counts sum to 19,389,877; the paper describes the corpus as "nearly 20 million."

## Access, License, and Safety

Read the [official terms of use](https://github.com/sophos-ai/SOREL-20M/blob/master/Terms%20and%20Conditions%20of%20Use.pdf) before accessing any data. The terms grant a limited, non-exclusive, non-transferable, non-sublicensable license solely for legitimate security research in malware detection and analysis.

- Do **not** republish, upload, transmit, resell, distribute, or otherwise share any dataset content, portions of it, or derivative works based on it with third parties.
- Do not use the data for malicious or unlawful purposes. The terms require that users have the skills to handle malware safely and include export-control and sanctions obligations.
- The repository code is Apache-2.0 licensed, but that does **not** replace the separate terms governing the data.
- The raw binaries are malicious samples, even though their execution headers were disarmed. Never execute them; store them outside version control in an isolated analysis environment with restricted access.
- Benign binaries are not distributed because of intellectual-property concerns. The binary release alone is therefore not a complete raw-file malware/benign corpus.

## Official Resources and Retrieval

The data bucket is public and no AWS credentials are required. The release root is:

```text
s3://sorel-20m/09-DEC-2020/
```

Clone the official code separately from the data:

```bash
git clone https://github.com/sophos-ai/SOREL-20M.git
cd SOREL-20M
conda env create -f environment.yml
conda activate sorel
```

The upstream code targets Python 3.6+ and uses Conda. It links a SQLite metadata index to LMDB feature stores and includes baseline training/evaluation scripts. Modern environments may need dependency adjustments; record any deviation from the supplied `environment.yml`.

Use the AWS CLI to retrieve only the artifacts needed. `--no-sign-request` makes the intended anonymous access explicit:

```bash
mkdir -p data/sorel-20m/processed-data/ember_features
aws s3 cp --no-sign-request \
  s3://sorel-20m/09-DEC-2020/processed-data/meta.db \
  data/sorel-20m/processed-data/meta.db
aws s3 sync --no-sign-request \
  s3://sorel-20m/09-DEC-2020/processed-data/ember_features/ \
  data/sorel-20m/processed-data/ember_features/
```

Set `db_path` in the cloned repository's `config.py` to the directory containing `meta.db`; use a local checkpoint directory rather than the upstream example path.

## Release Layout and Storage Planning

Do not download the whole S3 prefix by default. The complete release is roughly **8 TB**, mostly compressed malware binaries.

```text
09-DEC-2020/
  Terms and Conditions of Use.pdf
  baselines/
    checkpoints/                 # FFNN and LightGBM checkpoints for five seeds
    results/                     # result JSON and per-seed outputs
  binaries/                      # ~8 TB, zlib-compressed disarmed malware binaries
  lightGBM-features/
    train-features.npz           # ~113 GB
    validation-features.npz      # ~22 GB
    test-features.npz            # ~37 GB
  processed-data/
    meta.db                      # SQLite metadata index, ~3.5 GB
    ember_features/              # LMDB: EMBER v2 feature vectors, ~72 GB
    pe_metadata/                 # LMDB: PE metadata dumps, ~480 GB
```

For the supplied neural-network baseline, `meta.db` plus `ember_features/` needs about **78 GB**. The complete `processed-data/` hierarchy needs about **552 GB**. The prebuilt LightGBM NPZ files total about **172 GB**, while training LightGBM needs approximately **175 GB RAM** according to the maintainers.

LMDB values are serialized with MessagePack and compressed with zlib. The official Python loader decompresses and deserializes them; use it or faithfully reproduce that format rather than attempting to read values as NumPy files.

## Data Model

All components join on `sha256`:

- In `meta.db`, `meta.sha256` is the primary identifier.
- In the `ember_features` and `pe_metadata` LMDBs, the key is the ASCII SHA-256 string.
- For a raw malware binary, its filename is the SHA-256 of the **original, pre-disarming file**. It will not equal the digest computed from the released disarmed bytes.

### `meta.db`

The `meta` table indexes labels and timestamps. Inspect the exact schema from the downloaded release before writing queries:

```python
from pathlib import Path
import sqlite3

db_path = Path("data/sorel-20m/processed-data/meta.db")
with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as connection:
    columns = connection.execute("PRAGMA table_info(meta)").fetchall()
    print(columns)
```

The official loader uses these fields:

| Field | Meaning |
| --- | --- |
| `sha256` | Identifier of the original file; LMDB key and raw-malware filename |
| `is_malware` | Binary target label |
| `rl_fs_t` | First-seen timestamp used for the recommended temporal split |
| `rl_ls_const_positives` | Detection/count target used by the baseline multi-task model |
| `adware`, `flooder`, `ransomware`, `dropper`, `spyware`, `packed`, `crypto_miner`, `file_infector`, `installer`, `worm`, `downloader` | Behavioral tag-count fields |

The tag values are **counts**, not calibrated probabilities or binary labels. The upstream loader binarizes them as `count != 0`; retain counts only when the modelling question justifies it. The paper also describes first- and last-seen times in the metadata.

### Feature and Metadata LMDBs

`ember_features/` holds EMBER v2 static PE features. Each record is a MessagePack object whose key `0` contains a one-dimensional feature vector; the official loader converts it to `float32` and applies a signed-log transform:

```python
import numpy as np

# x is a NumPy array of EMBER features (float32)
x[x < 0] = -np.log(1 - x[x < 0])
x[x > 0] = np.log(1 + x[x > 0])
```

Fit no additional preprocessing on validation or test data. If reproducing the provided neural baseline, use the upstream loader so this transform and missing-feature handling match the reference implementation.

`pe_metadata/` holds detailed PE structure dumps produced with `pefile.dump_dict()`, such as headers, sections, imports, resources, directories, and hashes. It is metadata, not a replacement for raw bytes, and is much larger than the feature-only store.

### LightGBM NPZ Files

The prebuilt `lightGBM-features/*.npz` files contain the same EMBER-feature representation in flattened NumPy arrays for the default timestamp splits. They contain only the binary malware labels, not count or tag labels.

```python
import numpy as np

bundle = np.load("data/sorel-20m/lightGBM-features/train-features.npz")
print(bundle.files)  # expected: arr_0 (features), arr_1 (binary labels)
X = bundle["arr_0"]
y = bundle["arr_1"]
assert len(X) == len(y)
```

This key order matches the upstream `build_numpy_arrays_for_lightgbm.py` and `train.py`. Check the downloaded archive's keys and shapes before allocating a full in-memory training job.

## Recommended Temporal Splits

Use the supplied time boundaries for a benchmark-comparable experiment:

| Partition | `rl_fs_t` range | Date boundary (UTC) | Malware | Benign |
| --- | --- | --- | ---: | ---: |
| Train | `< 1543542570` | before 2018-11-30 01:49:30 | 7,596,407 | 5,102,606 |
| Validation | `>= 1543542570` and `< 1547279640` | 2018-11-30 01:49:30 to 2019-01-12 07:54:00 | 962,222 | 1,533,579 |
| Test | `>= 1547279640` | from 2019-01-12 07:54:00 | 1,360,622 | 2,834,441 |

The upstream `config.py` defines these epoch timestamps. The paper's stated validation/test totals and its class-count table differ by 21 records; derive definitive local split counts with a `meta.db` query and record the result. Do not randomly split the dataset if reporting results against the SOREL baseline, because that loses the intended temporal evaluation.

```sql
SELECT
  CASE
    WHEN rl_fs_t < 1543542570 THEN 'train'
    WHEN rl_fs_t < 1547279640 THEN 'validation'
    ELSE 'test'
  END AS split,
  is_malware,
  COUNT(*) AS samples
FROM meta
GROUP BY split, is_malware
ORDER BY split, is_malware;
```

## Training and Evaluation

The official repository provides:

| Component | Purpose |
| --- | --- |
| `dataset.py` and `generators.py` | SQLite/LMDB loading and PyTorch `DataLoader` creation |
| `train.py` | Feed-forward neural-network and LightGBM training |
| `evaluate.py` | Model evaluation and result CSV output |
| `plot.py` | Baseline/result ROC plotting |
| `nets.py` | The reference feed-forward neural-network architecture |
| `shas_missing_ember_features.json` | SHA-256 values without EMBER v2 feature records |

For the feature-LMDB baseline, the upstream commands are:

```bash
python train.py train_network \
  --remove_missing_features=shas_missing_ember_features.json
python evaluate.py evaluate_network RESULTS_DIR CHECKPOINT_PATH
```

Pass `shas_missing_ember_features.json` to training and evaluation. Without it, a missing LMDB feature can fail data loading; the slower upstream alternative is `--remove_missing_features=scan`.

For prebuilt arrays, train LightGBM with the upstream interface:

```bash
python train.py train_lightGBM \
  --train_npz_file=data/sorel-20m/lightGBM-features/train-features.npz \
  --validation_npz_file=data/sorel-20m/lightGBM-features/validation-features.npz \
  --model_configuration_file=lightgbm_config.json \
  --checkpoint_dir=CHECKPOINT_DIR
```

The official baselines use five random seeds. Report seed variation, the exact split, feature source, missing-feature policy, and metrics at low false-positive rates; ROC-AUC alone hides performance at operationally relevant thresholds.

## Raw Malware Binaries

The `binaries/` prefix contains only malware, compressed individually with zlib. Sophos set `OptionalHeader.Subsystem` and `FileHeader.Machine` to `0` before release to inhibit accidental execution.

- This is a safety measure, not a license to handle the samples casually. Do not attempt to restore/re-arm them; Sophos explicitly declines to provide re-arming assistance or original samples.
- Raw samples cannot be hashed to validate against their filenames because filenames retain the original-file SHA-256.
- Use a dedicated, isolated analysis environment for static feature work. If a research protocol requires dynamic analysis, obtain institutional approval and use disposable, network-restricted infrastructure.
- Do not infer a raw benign counterpart exists in the bucket; it does not.

## Important Caveats

- **Age and scope:** The corpus covers 2017-2019 Windows PEs. Validate separately for current malware, other operating systems, scripts, documents, Android packages, or network traffic.
- **Labels:** Malware/benign labels combine non-public internal information with static rules and analyses. Treat them as high-quality benchmark labels, not absolute forensic ground truth.
- **Feature provenance:** EMBER v2 is a static feature representation. It does not encode runtime behavior and can miss evasive, packed, or behaviorally malicious files.
- **Feature availability:** Some samples have no extracted EMBER v2 record. Filter them consistently before fitting preprocessors or constructing partitions.
- **Leakage:** Fit normalization, feature selection, resampling, and all tuning only on the training partition. Preserve timestamp ordering and prevent hash/near-duplicate leakage when adding external data.
- **Tag interpretation:** Tags arise from vendor threat-feed token extraction. A nonzero count is evidence from that process, not a probability, a complete behavior ontology, or an independently verified label.
- **No raw benign bytes:** Feature-only benign records support static-feature models, but byte-level malware-vs-benign research needs a legally compatible benign binary source and a documented construction policy.
- **Resource needs:** Disk I/O is a baseline bottleneck; the maintainers recommend high-IOPS storage and note that large worker counts may require higher open-file and shared-memory limits.

## Citation

```bibtex
@misc{harang2020sorel20m,
  title={SOREL-20M: A Large Scale Benchmark Dataset for Malicious PE Detection},
  author={Richard Harang and Ethan M. Rudd},
  year={2020},
  eprint={2012.07634},
  archivePrefix={arXiv},
  primaryClass={cs.CR},
  url={https://arxiv.org/abs/2012.07634}
}
```

## Official Resources

- [SOREL-20M code repository](https://github.com/sophos-ai/SOREL-20M) - official loader, baselines, configuration, and data paths.
- [Terms and conditions of use](https://github.com/sophos-ai/SOREL-20M/blob/master/Terms%20and%20Conditions%20of%20Use.pdf) - binding data-use, handling, redistribution, and export-control restrictions.
- [SOREL-20M paper](https://arxiv.org/abs/2012.07634) - dataset composition, release design, temporal benchmark, and baseline methodology.
- [Sophos release post](https://ai.sophos.com/2020/12/14/sophos-reversinglabs-sorel-20-million-sample-malware-dataset/) - rationale and disarmed-malware discussion.
- [EMBER feature implementation](https://github.com/elastic/ember/blob/master/ember/features.py) - feature extractor referenced by the SOREL maintainers.
