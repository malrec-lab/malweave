"""Synthetic byte-boundary, integrity and E2 leakage audit checks."""

from hashlib import sha256
import json
from types import SimpleNamespace

import pytest
from tokenizers import Tokenizer, models
import torch
from transformers import DataCollatorWithPadding, PreTrainedTokenizerFast

from malweave.data.byte_inputs import collate_raw_byte_ids
from malweave.data.malconv_inputs import audit_e2_inputs, encode_e2_bytes, verified_prefix
from malweave.training.contracts import SupervisedTrainingError


def test_e2_wordlevel_mapping_matches_source_formula_for_all_bytes_and_boundaries():
    content = bytes(range(256))
    assert encode_e2_bytes(content, 258).tolist() == [3, *range(7, 263), 4]
    assert encode_e2_bytes(content, 4).tolist() == [3, 7, 8, 4]
    assert encode_e2_bytes(content, 2).tolist() == [3, 4]
    assert encode_e2_bytes(b"", 8).tolist() == [3, 4]
    assert encode_e2_bytes(content, 258).dtype == torch.long
    with pytest.raises(SupervisedTrainingError):
        encode_e2_bytes(content, 1)


@pytest.mark.parametrize("batch_size", [1, 64])
def test_e2_padding_matches_rawbyteclf_hf_collator(batch_size):
    tokenizer = PreTrainedTokenizerFast(
        tokenizer_object=Tokenizer(models.WordLevel({"<pad>": 0, "<unk>": 1})),
        pad_token="<pad>",
        unk_token="<unk>",
    )
    examples = [
        (encode_e2_bytes(bytes(range(index % 19)), 32), index % 2) for index in range(batch_size)
    ]
    reference = DataCollatorWithPadding(
        tokenizer, padding="longest", pad_to_multiple_of=8, max_length=32
    )([{"input_ids": ids.tolist(), "labels": label} for ids, label in examples])
    actual = collate_raw_byte_ids(examples, pad_to_multiple_of=8)
    assert actual["input_ids"].shape[1] % 8 == 0
    torch.testing.assert_close(actual["input_ids"], reference["input_ids"], rtol=0, atol=0)
    torch.testing.assert_close(actual["labels"], reference["labels"], rtol=0, atol=0)


def test_prefix_retention_verifies_bytes_beyond_the_visible_prefix(tmp_path):
    content = b"synthetic" * 1000
    path = tmp_path / "sample"
    path.write_bytes(content)
    prefix, size = verified_prefix(path, sha256(content).hexdigest(), 4)
    assert prefix == content[:4] and size == len(content)
    path.write_bytes(content[:-1] + b"!")
    with pytest.raises(SupervisedTrainingError, match="digest changed"):
        verified_prefix(path, sha256(content).hexdigest(), 4)


@pytest.mark.parametrize("failure", ["cross_split", "conflicting_label", "corrupt"])
def test_e2_audit_keeps_per_source_failures_and_blocks_prefix_collisions(tmp_path, failure):
    examples = []
    for index in range(2):
        content = b"same-prefix" + bytes([index])
        source = sha256(content).hexdigest()
        path = tmp_path / "raw/dataset" / source[:2] / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"corrupt" if failure == "corrupt" and index == 1 else content)
        examples.append(
            SimpleNamespace(
                source_sha256=source,
                split="test" if failure == "cross_split" and index else "train",
                label=index if failure == "conflicting_label" else 0,
            )
        )
    with pytest.raises(SupervisedTrainingError, match="audit failed"):
        audit_e2_inputs(examples, tmp_path / "raw", "dataset", 6, "synthetic", tmp_path / "audit")
    summary_path = next((tmp_path / "audit").glob("*/summary.json"))
    summary = json.loads(summary_path.read_text())
    if failure == "corrupt":
        assert summary["statuses"] == {"success": 1, "error": 1}
    else:
        assert summary["cross_split_or_conflicting_label_groups"] == 1
    assert len(examples) == 2
