"""Synthetic differential tests for original MalConv2 b5a8654 training behavior.

Set MALWEAVE_MALCONV2_REFERENCE to a reviewed checkout. Tests never download
source or data. Original training uses low_mem=False and padding_idx=0.
"""

from hashlib import sha256
import os
from pathlib import Path

import pytest
import torch

from malweave.models import MalConvGCTConfig, MalConvGCTForSequenceClassification

SOURCE_HASHES = {
    "MalConvGCT_nocat.py": "ffb921eeff87bef4203d45fcaf13f9a62bd00bb2649c581a94e5dd5c357928af",
    "MalConvML.py": "e9519161e4bdc634a11119950e7f31102f031555ba86109841af4c2f10b06bc7",
    "LowMemConv.py": "4fec954ba8ce86aecb30a4562ad28718273c9e22f34003988ec43f58cca04b32",
    "checkpoint.py": "7c303ba12dfa4a30c8939c9f3905cb0678a69067c64078c042918f90cebe71ad",
}


def test_original_full_architecture_physical_batch128(original_class):
    torch.manual_seed(0)
    reference = original_class(
        channels=256, window_size=256, stride=64, embd_size=8, low_mem=False
    )
    torch.manual_seed(0)
    port = MalConvGCTForSequenceClassification(MalConvGCTConfig(implementation="original"))
    ids = torch.randint(1, 257, (128, 256), generator=torch.Generator().manual_seed(12))
    ids[::2, -64:] = 0
    with torch.no_grad():
        torch.testing.assert_close(port(ids).logits, reference(ids)[0], rtol=0, atol=0)


@pytest.fixture
def original_class(monkeypatch):
    root = Path(
        os.environ.get(
            "MALWEAVE_MALCONV2_REFERENCE", str(Path(__file__).resolve().parents[3] / "MalConv2")
        )
    )
    if not (root / "MalConvGCT_nocat.py").is_file():
        pytest.skip("Reviewed original MalConv2 source is required for differential verification.")
    for name, digest in SOURCE_HASHES.items():
        assert sha256((root / name).read_bytes()).hexdigest() == digest
    monkeypatch.syspath_prepend(str(root))
    from MalConvGCT_nocat import MalConvGCT

    previous = torch.get_num_threads()
    torch.set_num_threads(1)
    yield MalConvGCT
    torch.set_num_threads(previous)


@pytest.mark.parametrize("batch_size,length", [(1, 3), (128, 37), (128, 33)])
def test_original_initialization_forward_gradients_and_adapted_adamw(
    original_class, batch_size, length
):
    torch.manual_seed(0)
    reference = original_class(channels=4, window_size=2, stride=2, embd_size=3, low_mem=False)
    for branch in (reference, reference.context_net):
        branch.chunk_size = 16
        branch.min_chunk_size = 2
    torch.manual_seed(0)
    port = MalConvGCTForSequenceClassification(
        MalConvGCTConfig(
            implementation="original",
            vocab_size=257,
            embedding_size=3,
            channels=4,
            kernel_size=2,
            stride=2,
            chunk_size=16,
            min_chunk_size=2,
        )
    )

    def mapped(name):
        return "malconv." + name.replace("embd.", "embedding.")

    for name, value in reference.state_dict().items():
        torch.testing.assert_close(port.state_dict()[mapped(name)], value, rtol=0, atol=0)
    ids = torch.randint(1, 257, (batch_size, length), generator=torch.Generator().manual_seed(4))
    ids[0, -1] = 0
    labels = torch.arange(batch_size) % 2
    expected_logits = reference(ids)[0]
    expected_loss = torch.nn.functional.cross_entropy(expected_logits, labels)
    actual = port(ids, labels=labels)
    torch.testing.assert_close(actual.logits, expected_logits, rtol=0, atol=0)
    torch.testing.assert_close(actual.loss, expected_loss, rtol=0, atol=0)
    expected_loss.backward()
    actual.loss.backward()
    assert port.malconv.context_net.embedding.weight.grad is not None
    assert torch.count_nonzero(port.malconv.embedding.weight.grad[0]) == 0
    parameters = dict(port.named_parameters())
    for name, parameter in reference.named_parameters():
        other = parameters[mapped(name)]
        if parameter.grad is None:
            assert other.grad is None
        else:
            torch.testing.assert_close(other.grad, parameter.grad, rtol=0, atol=0)
    # AdamW/WD=.01 is the approved RanDS adaptation, not the original train
    # script's Adam. Apply it to both models to verify the port under that policy.
    for model in (reference, port):
        optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=0.01)
        optimizer.step()
    for name, value in reference.state_dict().items():
        torch.testing.assert_close(port.state_dict()[mapped(name)], value, rtol=0, atol=0)
