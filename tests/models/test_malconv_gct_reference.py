"""Differential checks against reviewed RawByteClf source, using synthetic IDs only.

The LMLM profile reproduces detached context and a missing embedding padding
index. Compare initialization, gradients and optimizer updates as well as logits.
"""

from hashlib import sha256
from pathlib import Path

import pytest
import torch

from malweave.models import MalConvGCTConfig, MalConvGCTForSequenceClassification
from malweave.training.malconv_e2 import e2_optimizer_groups

SOURCE_SHA256 = "c61265e654094ec03e6db876b8c2e461861fca46b50f9427bf892eb58126fb64"


def port_name(name):
    return name.replace("malconv.malconv.", "malconv.").replace(".embd.", ".embedding.")


@pytest.fixture
def reference_classes(monkeypatch, tmp_path):
    root = Path(__file__).resolve().parents[3] / "RawByteClf"
    source = root / "src/architectures/malconv2.py"
    if not source.is_file():
        pytest.skip("Pinned RawByteClf checkout is required for differential verification.")
    assert sha256(source.read_bytes()).hexdigest() == SOURCE_SHA256
    monkeypatch.syspath_prepend(str(root))
    monkeypatch.setenv("HF_HOME", str(tmp_path / "hf-home"))
    from src.architectures.malconv2 import MalConv2Config, MalConv2ForSequenceClassification

    previous = torch.get_num_threads()
    torch.set_num_threads(1)
    yield MalConv2Config, MalConv2ForSequenceClassification
    torch.set_num_threads(previous)


def pair(reference_classes, *, channels=4, embedding_size=3, kernel=2, chunk=16):
    config_class, model_class = reference_classes
    kwargs = {
        "vocab_size": 264,
        "embedding_size": embedding_size,
        "channels": channels,
        "kernel_size": kernel,
        "stride": kernel,
        "layers": 1,
        "num_labels": 2,
        "pad_token_id": 0,
    }
    torch.manual_seed(0)
    reference = model_class(config_class(mode="gcg", **kwargs))
    for module in (reference.malconv.malconv, reference.malconv.malconv.context_net):
        module.chunk_size = chunk
        module.min_chunk_size = kernel
    torch.manual_seed(0)
    port = MalConvGCTForSequenceClassification(
        MalConvGCTConfig(**kwargs, chunk_size=chunk, min_chunk_size=kernel, implementation="lmlm")
    )
    # Initialization must agree without copying reference weights into the port.
    for name, value in reference.state_dict().items():
        torch.testing.assert_close(port.state_dict()[port_name(name)], value, rtol=0, atol=0)
    return reference, port


@pytest.mark.parametrize("batch_size,length", [(1, 3), (64, 3), (64, 37)])
def test_pinned_initialization_forward_gradients_and_adamw(reference_classes, batch_size, length):
    reference, port = pair(reference_classes)
    generator = torch.Generator().manual_seed(17)
    ids = torch.randint(7, 263, (batch_size, length), generator=generator)
    ids[0, -1] = 0
    labels = torch.arange(batch_size) % 2
    expected = reference(ids, labels=labels)
    actual = port(ids, labels=labels)
    torch.testing.assert_close(actual.logits, expected.logits, rtol=0, atol=0)
    torch.testing.assert_close(actual.loss, expected.loss, rtol=0, atol=0)
    expected.loss.backward()
    actual.loss.backward()
    parameters = dict(port.named_parameters())
    for name, parameter in reference.named_parameters():
        mapped = port_name(name)
        if parameter.grad is None:
            assert parameters[mapped].grad is None
        else:
            torch.testing.assert_close(parameters[mapped].grad, parameter.grad, rtol=0, atol=0)
    for model in (reference, port):
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer = torch.optim.AdamW(e2_optimizer_groups(model, 0.01), lr=0.001)
        optimizer.step()
    for name, value in reference.state_dict().items():
        torch.testing.assert_close(port.state_dict()[port_name(name)], value, rtol=0, atol=0)


def test_pinned_e2_architecture_batch64_forward(reference_classes):
    reference, port = pair(
        reference_classes, channels=256, embedding_size=8, kernel=64, chunk=65536
    )
    ids = torch.randint(7, 263, (64, 136), generator=torch.Generator().manual_seed(18))
    ids[::2, -8:] = 0
    labels = torch.arange(64) % 2
    with torch.no_grad():
        expected = reference(ids, labels=labels)
        actual = port(ids, labels=labels)
    torch.testing.assert_close(actual.logits, expected.logits, rtol=0, atol=0)
    torch.testing.assert_close(actual.loss, expected.loss, rtol=0, atol=0)


def test_pinned_checkpoint_function_detaches_context_branch(reference_classes):
    reference, port = pair(reference_classes)
    ids = torch.tensor([[3, 12, 13, 14, 15, 4, 0, 0]])
    labels = torch.tensor([1])
    reference(ids, labels=labels).loss.backward()
    port(ids, labels=labels).loss.backward()
    # The pinned custom autograd Function receives only integer IDs, not any
    # differentiable parameter, so its context output has no autograd connection.
    assert all(p.grad is None for p in reference.malconv.malconv.context_net.parameters())
    assert all(p.grad is None for p in port.malconv.context_net.parameters())


def test_pinned_config_constructor_loses_embedding_padding_index(reference_classes):
    config_class, model_class = reference_classes
    config = config_class(
        mode="gcg",
        vocab_size=264,
        embedding_size=3,
        channels=4,
        kernel_size=2,
        stride=2,
        pad_token_id=0,
    )
    assert config.pad_token_id is None
    model = model_class(config)
    assert model.malconv.malconv.embd.padding_idx is None
    assert torch.count_nonzero(model.malconv.malconv.embd.weight[0]).item() > 0
    _, port = pair(reference_classes)
    assert port.malconv.embedding.padding_idx is None
    assert torch.count_nonzero(port.malconv.embedding.weight[0]).item() > 0


def test_negative_activations_preserve_pinned_winner_sentinel(reference_classes):
    reference, port = pair(reference_classes, kernel=1, chunk=8)
    source_branch = reference.malconv.malconv.context_net
    port_branch = port.malconv.context_net

    def negative_features(ids):
        return ids[:, None, :].float() / 100 - 5

    # Isolate the actual upstream/ported scan and recompute algorithms. All
    # features are below -1: source keeps winner position zero even though the
    # largest observed feature is later in the sequence, in another chunk.
    source_branch.processRange = negative_features
    source_branch.receptive_field = 1
    source_branch.stride = 1
    source_branch.out_channels = 1
    port_branch.process_range = negative_features
    ids = torch.tensor([[7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 99, 18, 19, 20, 21, 22]])
    expected = source_branch.seq2fix(ids)
    actual = port_branch.seq2fix(ids)
    torch.testing.assert_close(expected, negative_features(ids[:, :1]).reshape(1, 1))
    torch.testing.assert_close(actual, expected, rtol=0, atol=0)
