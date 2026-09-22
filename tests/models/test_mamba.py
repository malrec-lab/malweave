"""Synthetic behavior tests for the bidirectional Mamba port."""

from __future__ import annotations

import pytest
import torch

from malweave.models import MambaConfig, MambaForSequenceClassification


def _config(**overrides: object) -> MambaConfig:
    values: dict[str, object] = {
        "vocab_size": 32,
        "hidden_size": 4,
        "num_hidden_layers": 1,
        "state_size": 2,
        "conv_kernel": 2,
        "time_step_rank": 1,
    }
    values.update(overrides)
    return MambaConfig(**values)  # type: ignore[arg-type]


def test_bidirectional_mamba_builds_upstream_reverse_input_and_trains() -> None:
    torch.manual_seed(5)
    model = MambaForSequenceClassification(_config())
    inputs = torch.tensor([[3, 8, 9, 4, 0, 0], [3, 10, 4, 0, 0, 0]])

    assert model.prepare_input_for_backward_model(inputs).tolist() == [
        [3, 9, 8, 4, 0, 0],
        [3, 10, 4, 0, 0, 0],
    ]
    output = model(inputs, labels=torch.tensor([0, 1]))
    assert output.logits.shape == (2, 2)
    assert output.loss is not None
    output.loss.backward()
    assert model.layers_forw[0].mixer.in_proj.weight.grad is not None
    assert model.layers_back[0].mixer.in_proj.weight.grad is not None


def test_bidirectional_mamba_rejects_attention_mask_and_keeps_special_ids_distinct() -> None:
    model = MambaForSequenceClassification(_config())
    inputs = torch.tensor([[3, 8, 4, 0]])
    with pytest.raises(NotImplementedError, match="attention_mask"):
        model(inputs, attention_mask=torch.ones_like(inputs))
    with pytest.raises(ValueError, match="distinct"):
        _config(bos_token_id=0)


def test_bidirectional_mamba_checkpoint_and_state_dict_round_trip() -> None:
    torch.manual_seed(13)
    first = MambaForSequenceClassification(_config(gradient_checkpointing=True))
    second = MambaForSequenceClassification(_config(gradient_checkpointing=True))
    second.load_state_dict(first.state_dict())
    inputs = torch.tensor([[3, 8, 9, 4, 0]])
    first.train()
    output = first(inputs, labels=torch.tensor([1]))
    assert output.loss is not None
    output.loss.backward()
    first.eval()
    second.eval()
    with torch.no_grad():
        torch.testing.assert_close(first(inputs).logits, second(inputs).logits)


def test_bidirectional_mamba_tiny_synthetic_batch_overfits() -> None:
    torch.manual_seed(23)
    model = MambaForSequenceClassification(_config())
    inputs = torch.tensor([[3, 8, 9, 4, 0], [3, 9, 8, 4, 0]])
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
