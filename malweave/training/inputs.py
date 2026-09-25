"""Representation-specific fitting and encoding for the shared training loop."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from torch import Tensor

from malweave.data.byte_inputs import (
    collate_exe_tokens,
    collate_raw_byte_ids,
    encode_exe_tokens,
    raw_bytes_to_ids,
    train_exe_bpe_tokenizer,
)
from malweave.training.manifest import TrainingSample
from malweave.training.sources import VerifiedByteSource


class InputAdapter(Protocol):
    tokenizer: Any | None

    def fit(self, train_samples: list[TrainingSample], source: VerifiedByteSource) -> None: ...

    def encode(self, content: bytes) -> Tensor: ...

    def collate(self, examples: Sequence[tuple[Tensor, int]]) -> dict[str, Tensor]: ...


class RawInputAdapter:
    """RAW byte IDs require no fitted transform."""

    tokenizer = None

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes

    def fit(self, train_samples: list[TrainingSample], source: VerifiedByteSource) -> None:
        del train_samples, source

    def encode(self, content: bytes) -> Tensor:
        return raw_bytes_to_ids(content, self.max_bytes)

    def collate(self, examples: Sequence[tuple[Tensor, int]]) -> dict[str, Tensor]:
        return collate_raw_byte_ids(examples)


class ExeInputAdapter:
    """Fit BPE only on frozen training rows, then encode any split."""

    def __init__(self, max_tokens: int, vocab_size: int) -> None:
        self.max_tokens = max_tokens
        self.vocab_size = vocab_size
        self.tokenizer: Any | None = None

    def fit(self, train_samples: list[TrainingSample], source: VerifiedByteSource) -> None:
        self.tokenizer = train_exe_bpe_tokenizer(
            (source.read(sample) for sample in train_samples), vocab_size=self.vocab_size
        )

    def encode(self, content: bytes) -> Tensor:
        if self.tokenizer is None:
            raise ValueError("EXE adapter must fit on the training split before encoding.")
        return encode_exe_tokens(self.tokenizer, content, self.max_tokens)

    def collate(self, examples: Sequence[tuple[Tensor, int]]) -> dict[str, Tensor]:
        return collate_exe_tokens(examples)
