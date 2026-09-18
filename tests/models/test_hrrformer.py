"""Synthetic behavior tests for the bidirectional HRRFormer classifier port."""

from __future__ import annotations

import torch

from malweave.models import HRRFormerConfig, HRRFormerForSequenceClassification


def _config(**overrides: object) -> HRRFormerConfig:
    values: dict[str, object] = {
        "vocab_size": 32,
        "hidden_size": 4,
        "num_hidden_layers": 2,
        "num_attention_heads": 1,
        "intermediate_size": 8,
        "max_position_embeddings": 8,
        "hidden_dropout_prob": 0.0,
        "attention_probs_dropout_prob": 0.0,
    }
    values.update(overrides)
    return HRRFormerConfig(**values)  # type: ignore[arg-type]


def test_hrrformer_bidir_classifier_runs_fft_attention_and_backpropagates() -> None:
    torch.manual_seed(3)
    model = HRRFormerForSequenceClassification(_config())
    inputs = torch.tensor([[1, 2, 3, 0], [4, 5, 6, 7]])
    output = model(inputs, attention_mask=inputs.ne(0), labels=torch.tensor([0, 1]))

    assert output.logits.shape == (2, 2)
    assert output.loss is not None
    output.loss.backward()
    assert model.word_embeddings.weight.grad is not None
    assert model.layers[0].attention.query.weight.grad is not None


def test_hrrformer_bidir_pooling_matches_upstream_unmasked_mean() -> None:
    model = HRRFormerForSequenceClassification(_config(num_hidden_layers=0)).eval()
    inputs = torch.tensor([[1, 2, 0, 0]])
    with torch.no_grad():
        token_logits = model.classifier(model._embed(inputs, None))
        output = model(inputs, attention_mask=inputs.ne(0)).logits
    torch.testing.assert_close(output, token_logits.mean(dim=1))


def test_hrrformer_checkpoint_and_state_dict_round_trip() -> None:
    torch.manual_seed(9)
    first = HRRFormerForSequenceClassification(_config(gradient_checkpointing=True))
    second = HRRFormerForSequenceClassification(_config(gradient_checkpointing=True))
    second.load_state_dict(first.state_dict())
    inputs = torch.tensor([[1, 2, 3, 4]])
    first.train()
    output = first(inputs, labels=torch.tensor([1]))
    assert output.loss is not None
    output.loss.backward()
    first.eval()
    second.eval()
    with torch.no_grad():
        torch.testing.assert_close(first(inputs).logits, second(inputs).logits)


def test_hrrformer_tiny_synthetic_batch_overfits() -> None:
    torch.manual_seed(21)
    model = HRRFormerForSequenceClassification(_config())
    inputs = torch.tensor([[1, 2, 3, 4], [4, 3, 2, 1]])
    labels = torch.tensor([0, 0])
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
