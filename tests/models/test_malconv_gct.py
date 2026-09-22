"""Synthetic behavioral tests for the RawByteClf MalConvGCT port."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest
import torch

from malweave.models import MalConvGCTConfig, MalConvGCTForSequenceClassification


def _config() -> MalConvGCTConfig:
    return MalConvGCTConfig(
        vocab_size=257,
        embedding_size=3,
        channels=4,
        stride=1,
        kernel_size=2,
        layers=1,
        num_labels=2,
        chunk_size=5,
        min_chunk_size=2,
    )


def test_malconvgct_runs_low_memory_scan_and_backpropagates_both_branches() -> None:
    torch.manual_seed(7)
    model = MalConvGCTForSequenceClassification(_config())
    inputs = torch.tensor([[1, 2, 3, 4, 5, 6, 7], [8, 9, 10, 0, 0, 0, 0]])
    output = model(inputs, labels=torch.tensor([0, 1]))

    assert output.logits.shape == (2, 2)
    assert output.loss is not None
    output.loss.backward()
    assert model.malconv.embedding.weight.grad is not None
    assert model.malconv.context_net.embedding.weight.grad is not None


def test_malconvgct_state_dict_round_trip_preserves_logits() -> None:
    torch.manual_seed(11)
    first = MalConvGCTForSequenceClassification(_config()).eval()
    second = MalConvGCTForSequenceClassification(_config()).eval()
    inputs = torch.tensor([[1, 2, 3, 4, 5, 6, 7]])

    second.load_state_dict(first.state_dict())
    with torch.no_grad():
        expected = first(inputs).logits
        actual = second(inputs).logits
    torch.testing.assert_close(actual, expected)


def test_malconvgct_tiny_synthetic_batch_overfits() -> None:
    torch.manual_seed(19)
    model = MalConvGCTForSequenceClassification(_config())
    inputs = torch.tensor([[1, 2, 3, 4, 5, 6, 7], [7, 6, 5, 4, 3, 2, 1]])
    labels = torch.tensor([1, 1])
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.05)
    initial = model(inputs, labels=labels).loss
    assert initial is not None
    for _ in range(12):
        optimizer.zero_grad()
        output = model(inputs, labels=labels)
        assert output.loss is not None
        output.loss.backward()
        optimizer.step()
    final = model(inputs, labels=labels).loss
    assert final is not None
    assert final < initial


def test_malconvgct_matches_pinned_rawbyteclf_when_reference_checkout_is_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference_root = Path(__file__).resolve().parents[3] / "RawByteClf"
    if not reference_root.is_dir():
        pytest.skip("Pinned RawByteClf checkout is not available in this test environment.")
    monkeypatch.setenv("HF_HOME", str(tmp_path / "hf-home"))
    sys.path.insert(0, str(reference_root))
    try:
        from src.architectures.malconv2 import MalConv2Config, MalConv2ForSequenceClassification

        torch.manual_seed(4)
        reference = MalConv2ForSequenceClassification(
            MalConv2Config(
                mode="gcg",
                vocab_size=257,
                embedding_size=3,
                channels=4,
                stride=1,
                kernel_size=2,
                layers=1,
                pad_token_id=0,
                num_labels=2,
            )
        ).eval()
        port = MalConvGCTForSequenceClassification(_config()).eval()
        for module in (reference.malconv.malconv, reference.malconv.malconv.context_net):
            module.chunk_size = 5
            module.min_chunk_size = 2
        port.load_state_dict(
            {
                key.replace("malconv.malconv.", "malconv.").replace(".embd.", ".embedding."): value
                for key, value in reference.state_dict().items()
            }
        )
        inputs = torch.tensor([[1, 2, 3, 4, 5, 6, 7]])
        with torch.no_grad():
            expected = reference(inputs).logits
            actual = port(inputs).logits
        torch.testing.assert_close(actual, expected)
    finally:
        sys.path.remove(str(reference_root))
