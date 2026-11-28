"""Canonical S3 keys for the published PE datasets."""

import os
import re

from malweave.data.storage_io import DataError

DATASET_SLUGS = {
    "rands": "rands",
    "vera": "vera",
    "rawmal": "rawmal-tf",
    "assemblage": "assemblage",
}
RAW_PREFIX = "representations/raw"
EXE_PREFIX = "representations/exe"
EXE_MANIFEST = f"{EXE_PREFIX}/manifest.csv"
METADATA_PREFIX = "metadata"
EXPERIMENTS_PREFIX = "experiments"
RANDS_BENIGN = f"{METADATA_PREFIX}/Benign.csv"
RANDS_RANSOMWARE = f"{METADATA_PREFIX}/Ransomware.csv"
DATASET_RECEIPT = "dataset.json"
INVENTORY = "inventory.csv"
RAWMAL_LABELS = f"{METADATA_PREFIX}/labels/rawmal-task-labels.csv"


def account_id() -> str:
    owner = os.environ.get("MALWEAVE_S3_ACCOUNT_ID", "")
    if not re.fullmatch(r"[0-9]{12}", owner):
        raise DataError("Set MALWEAVE_S3_ACCOUNT_ID to the dataset bucket owner's AWS account ID.")
    return owner


def dataset_bucket(dataset: str, owner: str) -> str:
    return f"malweave-{DATASET_SLUGS[dataset]}-{owner}"


def sharded_key(prefix: str, digest: str) -> str:
    return f"{prefix}/{digest[:2]}/{digest}"
