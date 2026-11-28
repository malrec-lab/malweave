"""Released EXE tokenizer adapter matching RawByteClf inference, not tokenizer fitting.

Reference: lkurlandski/RawByteClf at 2502450e40ac00363e168106662aac29821d4a93,
src/learn/preprocessing.py and src/learn/bytes_to_str_utf8.pyx (MIT).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tokenizers import Tokenizer
import torch

from malweave.data.byte_inputs import LmlmInputError


def _special_content(value: Any) -> str:
    content = value.get("content") if isinstance(value, dict) else value
    if not isinstance(content, str):
        raise LmlmInputError("Invalid released special-token definition.")
    return content


class ReleasedExeTokenizer:
    """Use saved BPE/Unigram on contiguous Unicode bytes, with saved postprocessing."""

    def __init__(
        self, root: Path, config: dict[str, Any], max_tokens: int, max_bytes: int = 65536
    ) -> None:
        if type(max_tokens) is not int or max_tokens < 2:
            raise LmlmInputError("max_tokens must reserve space for BOS and EOS.")
        try:
            self.tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
        except Exception as error:
            # Tokenizers' Rust parser exposes a generic Exception, not a typed parse error.
            raise LmlmInputError(f"Could not parse released tokenizer.json: {error}") from error
        try:
            specials = json.loads((root / "special_tokens_map.json").read_text())
            settings = json.loads((root / "tokenizer_config.json").read_text())
            definition = json.loads(self.tokenizer.to_str())
            if definition["model"]["type"] not in {"BPE", "Unigram"}:
                raise LmlmInputError("Only released EXE BPE and Unigram tokenizers are supported.")
            self.special_ids = {}
            for name in ("pad", "unk", "mask", "bos", "eos", "cls", "sep"):
                key = name + "_token"
                token = _special_content(specials[key])
                if key in settings and _special_content(settings[key]) != token:
                    raise LmlmInputError(
                        "Released tokenizer metadata disagrees on special tokens."
                    )
                token_id = self.tokenizer.token_to_id(token)
                if token_id is None:
                    raise LmlmInputError(
                        "A released special token is missing from the vocabulary."
                    )
                self.special_ids[name] = token_id
            if len(set(self.special_ids.values())) != len(self.special_ids):
                raise LmlmInputError("Released special tokens must have distinct IDs.")
            for name in ("pad", "bos", "eos"):
                if config[name + "_token_id"] != self.special_ids[name]:
                    raise LmlmInputError("Checkpoint and tokenizer special-token IDs disagree.")
            self.vocab_size = config["vocab_size"]
            if max(self.tokenizer.get_vocab().values()) >= self.vocab_size:
                raise LmlmInputError("Tokenizer IDs exceed checkpoint embedding rows.")
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise LmlmInputError(f"Invalid released EXE tokenizer: {error}") from error
        if type(max_bytes) is not int or max_bytes < 1:
            raise LmlmInputError("max_bytes must be a positive integer.")
        self.max_bytes = max_bytes
        self.max_tokens = max_tokens
        self.pad_token_id = self.special_ids["pad"]
        # Inference truncation preserves the tokenizer's own BOS/EOS postprocessor.
        self.tokenizer.no_padding()
        self.tokenizer.enable_truncation(max_length=max_tokens, direction="right")
        self.encode_bytes(bytes(range(32)))

    def encode_bytes(self, content: bytes) -> torch.Tensor:
        text = "".join(chr(value + 10_752) for value in content[: self.max_bytes])
        ids = self.tokenizer.encode(text, add_special_tokens=True).ids
        if (
            len(ids) < 2
            or ids[0] != self.special_ids["bos"]
            or ids[-1] != self.special_ids["eos"]
            or self.pad_token_id in ids
            or max(ids) >= self.vocab_size
        ):
            raise LmlmInputError("Released tokenizer must produce unpadded BOS/content/EOS IDs.")
        return torch.tensor(ids, dtype=torch.long)
