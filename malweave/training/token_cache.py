"""Bounded-memory, checksummed token cache; full EXE arrays stay in the input store."""

from __future__ import annotations

from array import array
import json
import os
from pathlib import Path
from typing import Any

import torch
from torch.utils.data import DataLoader, Dataset

from malweave.data.byte_inputs import collate_exe_tokens
from malweave.data.rands_training import Progress, RandsTrainingError, atomic_json, file_digest


class TokenCache(Dataset):
    def __init__(self, path: Path, index: dict[str, Any]):
        self.offsets = index["offsets"]
        self.labels = index["labels"]
        self.values = torch.from_file(str(path), size=self.offsets[-1], dtype=torch.int32)
        self.stats = index["stats"]

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, index):
        return self.values[self.offsets[index] : self.offsets[index + 1]].long(), self.labels[
            index
        ]


def token_cache(
    source: Dataset,
    root: Path,
    name: str,
    identity: dict[str, Any],
    config: dict[str, Any],
    progress: Progress,
) -> TokenCache:
    root.mkdir(exist_ok=True)
    path = root / (name + ".tokens")
    metadata = root / (name + ".json")
    if metadata.exists():
        saved = json.loads(metadata.read_text())
        if saved["identity"] != identity or saved["sha256"] != file_digest(path):
            raise RandsTrainingError(
                "Token cache changed; preserve the run and remove/rebuild only its cache directory."
            )
        return TokenCache(path, saved)
    progress.emit(phase="tokenize_" + name, completed=0, total=len(source))
    temporary = path.with_suffix(".tmp")
    offsets, labels = [0], []
    loader = DataLoader(
        source,
        batch_size=32,
        num_workers=config["runtime"]["dataloader_workers"],
        collate_fn=collate_exe_tokens,
        generator=torch.Generator().manual_seed(0),
    )
    lengths = []
    with temporary.open("wb") as handle:
        for batch in loader:
            for ids, mask, label in zip(
                batch["input_ids"], batch["attention_mask"], batch["labels"], strict=True
            ):
                tokens = ids[mask.bool()].tolist()
                array("i", tokens).tofile(handle)
                offsets.append(offsets[-1] + len(tokens))
                lengths.append(len(tokens))
                labels.append(int(label))
            if len(labels) % 1024 == 0 or len(labels) == len(source):
                progress.emit(phase="tokenize_" + name, completed=len(labels), total=len(source))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    saved = {
        "identity": identity,
        "sha256": file_digest(path),
        "offsets": offsets,
        "labels": labels,
        "stats": {
            "samples": len(labels),
            "tokens": offsets[-1],
            "min_tokens": min(lengths),
            "max_tokens": max(lengths),
            "mean_tokens": sum(lengths) / len(lengths),
            "filled_context_samples": sum(
                length == config["model"]["max_tokens"] for length in lengths
            ),
        },
    }
    atomic_json(metadata, saved)
    return TokenCache(path, saved)
