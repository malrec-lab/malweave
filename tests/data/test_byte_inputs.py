"""Synthetic tests for byte input adapters; no real PE data is used."""

from __future__ import annotations

from pathlib import Path

import pytest

from malweave.data.byte_inputs import (
    RAW_PAD_TOKEN_ID,
    RAW_VOCAB_SIZE,
    SPECIAL_TOKEN_ORDER,
    SPECIAL_TOKENS,
    LmlmInputError,
    collate_exe_tokens,
    collate_raw_byte_ids,
    encode_exe_tokens,
    exe_words_to_text,
    raw_bytes_to_ids,
    train_exe_bpe_tokenizer,
    write_private_tokenizer,
)


def test_raw_byte_adapter_keeps_zero_byte_distinct_from_padding() -> None:
    ids = raw_bytes_to_ids(bytes([0, 1, 255]), max_bytes=2)

    assert ids.tolist() == [1, 2]
    assert RAW_PAD_TOKEN_ID not in ids.tolist()
    assert RAW_VOCAB_SIZE == 257
    batch = collate_raw_byte_ids([(ids, 1), (raw_bytes_to_ids(b"\xff"), 0)])
    assert batch["input_ids"].tolist() == [[1, 2], [256, 0]]
    assert batch["labels"].tolist() == [1, 0]


def test_exe_words_are_lossless_non_overlapping_and_bpe_keeps_special_mapping() -> None:
    content = bytes(range(20))
    text = exe_words_to_text(content)
    words = text.split(" ")
    assert [len(word) for word in words] == [16, 4]
    assert [ord(character) - 10_752 for word in words for character in word] == list(range(20))

    tokenizer = train_exe_bpe_tokenizer([content, bytes(range(16, 32))], vocab_size=32)
    assert [tokenizer.token_to_id(token) for token in SPECIAL_TOKEN_ORDER] == list(range(7))
    encoded = encode_exe_tokens(tokenizer, content, max_tokens=3)
    assert encoded.tolist()[0] == tokenizer.token_to_id(SPECIAL_TOKENS["bos"])
    assert encoded.tolist()[-1] == tokenizer.token_to_id(SPECIAL_TOKENS["eos"])
    assert len(encoded) == 3


def test_exe_collator_and_private_tokenizer_contract(tmp_path: Path) -> None:
    tokenizer = train_exe_bpe_tokenizer([b"a" * 16 + b"b" * 16, b"a" * 16], vocab_size=32)
    first = encode_exe_tokens(tokenizer, b"a" * 16 + b"b" * 16)
    second = encode_exe_tokens(tokenizer, b"a" * 16)
    batch = collate_exe_tokens([(first, 1), (second, 0)])

    assert batch["input_ids"].shape[0] == 2
    assert batch["attention_mask"].tolist()[1][-1] == 0
    assert batch["labels"].tolist() == [1, 0]
    digest = write_private_tokenizer(tokenizer, tmp_path / "tokenizer.json")
    assert len(digest) == 64
    with pytest.raises(LmlmInputError, match="Tokenizer artifacts inside"):
        write_private_tokenizer(tokenizer, Path.cwd() / "unsafe-tokenizer.json")


def test_tokenizer_rejects_empty_or_invalid_contract_inputs() -> None:
    with pytest.raises(LmlmInputError, match="without training examples"):
        train_exe_bpe_tokenizer([])
    with pytest.raises(LmlmInputError, match="reserve space"):
        encode_exe_tokens(train_exe_bpe_tokenizer([b"x"]), b"x", max_tokens=1)
    with pytest.raises(LmlmInputError, match="max_bytes"):
        raw_bytes_to_ids(b"x", max_bytes=0)
