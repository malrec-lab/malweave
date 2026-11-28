"""Released BPE/Unigram input parity, including truncation and special tokens."""

import json
from pathlib import Path

import pytest
from transformers import PreTrainedTokenizerFast

from malweave.data.byte_inputs import LmlmInputError, exe_words_to_text
from malweave.data.lmlm_inputs import ReleasedExeTokenizer
from tests.lmlm_fixtures import released_checkpoint


@pytest.mark.parametrize("algorithm", ["BPE", "Unigram"])
def test_released_adapter_matches_upstream_contiguous_tokenization(tmp_path: Path, algorithm: str):
    root = tmp_path / "checkpoint"
    released_checkpoint(root, algorithm)
    config = json.loads((root / "config.json").read_text())
    adapter = ReleasedExeTokenizer(root, config, max_tokens=12)
    reference = PreTrainedTokenizerFast.from_pretrained(root, local_files_only=True)
    for content in (b"", bytes(range(3)), bytes(range(32)), bytes(range(256)), b"\x90" * 127):
        expected = reference(
            "".join(chr(value + 10752) for value in content), truncation=True, max_length=12
        )["input_ids"]
        assert adapter.encode_bytes(content).tolist() == expected
        assert expected[0] == 3 and expected[-1] == 4
    assert adapter.tokenizer.get_vocab_size() == 263
    assert adapter.vocab_size == 264


def test_unigram_adapter_does_not_insert_unknown_spaces(tmp_path: Path):
    root = tmp_path / "checkpoint"
    released_checkpoint(root, "Unigram")
    config = json.loads((root / "config.json").read_text())
    adapter = ReleasedExeTokenizer(root, config, max_tokens=64)
    content = bytes(range(32))
    assert 1 not in adapter.encode_bytes(content).tolist()
    assert 1 in adapter.tokenizer.encode(exe_words_to_text(content)).ids


def test_adapter_rejects_mismatched_special_ids_and_vocab(tmp_path: Path):
    root = tmp_path / "checkpoint"
    released_checkpoint(root)
    config = json.loads((root / "config.json").read_text())
    with pytest.raises(LmlmInputError, match="special-token IDs"):
        ReleasedExeTokenizer(root, {**config, "eos_token_id": 5}, 8)
    with pytest.raises(LmlmInputError, match="embedding rows"):
        ReleasedExeTokenizer(root, {**config, "vocab_size": 128}, 8)


def test_byte_prefix_is_applied_before_subword_tokenization(tmp_path):
    root = tmp_path / "checkpoint"
    released_checkpoint(root)
    config = json.loads((root / "config.json").read_text())
    tokenizer = ReleasedExeTokenizer(root, config, max_tokens=64, max_bytes=3)
    assert tokenizer.encode_bytes(b"abcdef").tolist() == tokenizer.encode_bytes(b"abc").tolist()
    assert tokenizer.encode_bytes(b"abc").numel() == 5  # Three bytes plus BOS/EOS.
