"""Byte adapters and train-partition-only EXE BPE tokenizer utilities."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from hashlib import sha256
from pathlib import Path

from tokenizers import Tokenizer, models, pre_tokenizers, processors, trainers
import torch

from malweave.config import PROJECT_ROOT

RAW_PAD_TOKEN_ID = 0
RAW_VOCAB_SIZE = 257
EXE_WORD_BYTES = 16
SPECIAL_TOKENS = {
    "pad": "<pad>",
    "unk": "<unk>",
    "mask": "<msk>",
    "bos": "<bos>",
    "eos": "<eos>",
    "cls": "<cls>",
    "sep": "<sep>",
}
SPECIAL_TOKEN_ORDER = tuple(SPECIAL_TOKENS.values())


class LmlmInputError(ValueError):
    """Raised when an adapter or tokenizer would violate its declared contract."""


def raw_bytes_to_ids(content: bytes, max_bytes: int = 2_097_152) -> torch.Tensor:
    """Map each byte reversibly to 1..256 so padding remains distinct at ID zero."""
    if max_bytes <= 0:
        raise LmlmInputError("max_bytes must be positive.")
    return torch.tensor([value + 1 for value in content[:max_bytes]], dtype=torch.long)


def collate_raw_byte_ids(
    examples: Sequence[tuple[torch.Tensor, int]], pad_token_id: int = RAW_PAD_TOKEN_ID
) -> dict[str, torch.Tensor]:
    """Prefix-pad no samples; only batch padding is added after the frozen truncation policy."""
    if not examples:
        raise LmlmInputError("Cannot collate an empty batch.")
    if any(ids.ndim != 1 for ids, _ in examples):
        raise LmlmInputError("RAW input IDs must be one-dimensional tensors.")
    max_length = max(ids.numel() for ids, _ in examples)
    input_ids = torch.full((len(examples), max_length), pad_token_id, dtype=torch.long)
    labels = torch.empty(len(examples), dtype=torch.long)
    for index, (ids, label) in enumerate(examples):
        input_ids[index, : ids.numel()] = ids
        labels[index] = label
    return {"input_ids": input_ids, "labels": labels}


def exe_words_to_text(content: bytes, word_bytes: int = EXE_WORD_BYTES) -> str:
    """Render non-overlapping byte words with the upstream byte-to-Unicode mapping."""
    if word_bytes <= 0:
        raise LmlmInputError("word_bytes must be positive.")
    return " ".join(
        "".join(chr(value + 10_752) for value in content[start : start + word_bytes])
        for start in range(0, len(content), word_bytes)
    )


def train_exe_bpe_tokenizer(
    train_contents: Iterable[bytes], vocab_size: int = 16_384
) -> Tokenizer:
    """Fit BPE exclusively from the already-frozen training partition's EXE bytes."""
    if vocab_size < len(SPECIAL_TOKEN_ORDER):
        raise LmlmInputError("vocab_size cannot be smaller than the special-token vocabulary.")
    tokenizer = Tokenizer(models.BPE(unk_token=SPECIAL_TOKENS["unk"]))
    tokenizer.pre_tokenizer = pre_tokenizers.WhitespaceSplit()
    trainer = trainers.BpeTrainer(
        vocab_size=vocab_size,
        special_tokens=list(SPECIAL_TOKEN_ORDER),
        show_progress=False,
    )

    seen = 0

    def text_stream() -> Iterable[str]:
        nonlocal seen
        for content in train_contents:
            if not isinstance(content, bytes):
                raise LmlmInputError("EXE tokenizer training inputs must be bytes.")
            seen += 1
            yield exe_words_to_text(content)

    tokenizer.train_from_iterator(text_stream(), trainer=trainer)
    if seen == 0:
        raise LmlmInputError("Cannot fit an EXE tokenizer without training examples.")
    tokenizer.post_processor = processors.TemplateProcessing(
        single=f"{SPECIAL_TOKENS['bos']} $A {SPECIAL_TOKENS['eos']}",
        pair=(
            f"{SPECIAL_TOKENS['bos']} $A {SPECIAL_TOKENS['eos']} "
            f"{SPECIAL_TOKENS['sep']} {SPECIAL_TOKENS['bos']}:1 $B:1 {SPECIAL_TOKENS['eos']}:1"
        ),
        special_tokens=[(token, index) for index, token in enumerate(SPECIAL_TOKEN_ORDER)],
    )
    return tokenizer


def encode_exe_tokens(
    tokenizer: Tokenizer, content: bytes, max_tokens: int = 4_096
) -> torch.Tensor:
    """Encode a prefix while retaining both boundary tokens required by bidirectional Mamba."""
    if max_tokens < 2:
        raise LmlmInputError("max_tokens must reserve space for BOS and EOS.")
    ids = tokenizer.encode(exe_words_to_text(content)).ids
    if len(ids) > max_tokens:
        ids = [*ids[: max_tokens - 1], tokenizer.token_to_id(SPECIAL_TOKENS["eos"])]
    return torch.tensor(ids, dtype=torch.long)


def collate_exe_tokens(
    examples: Sequence[tuple[torch.Tensor, int]], pad_token_id: int = 0
) -> dict[str, torch.Tensor]:
    """Pad encoded EXE sequences and return an attention mask for HRRFormer only."""
    if not examples:
        raise LmlmInputError("Cannot collate an empty batch.")
    if any(ids.ndim != 1 for ids, _ in examples):
        raise LmlmInputError("EXE input IDs must be one-dimensional tensors.")
    max_length = max(ids.numel() for ids, _ in examples)
    input_ids = torch.full((len(examples), max_length), pad_token_id, dtype=torch.long)
    labels = torch.empty(len(examples), dtype=torch.long)
    for index, (ids, label) in enumerate(examples):
        input_ids[index, : ids.numel()] = ids
        labels[index] = label
    return {
        "input_ids": input_ids,
        "attention_mask": input_ids.ne(pad_token_id).to(dtype=torch.long),
        "labels": labels,
    }


def write_private_tokenizer(tokenizer: Tokenizer, path: Path) -> str:
    """Persist a tokenizer only in a private artifact location and return its content digest."""
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        pass
    else:
        if tuple(relative.parts[:2]) != ("data", "processed"):
            raise LmlmInputError(
                "Tokenizer artifacts inside the repository must be under data/processed."
            )
    payload = tokenizer.to_str(pretty=True).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return sha256(payload).hexdigest()
