"""The A loader must keep the original classifier, not initialize C's new head."""

import json

import pytest
from safetensors.torch import load_file, save_file
from tests.lmlm_fixtures import released_checkpoint
import torch

from malweave.training.contracts import SupervisedTrainingError
from malweave.training.lmlm_detector import load_released_detector


def detector_checkpoint(root):
    original = released_checkpoint(root)
    path = root / "config.json"
    config = json.loads(path.read_text())
    config.update(
        architectures=["MambaForSequenceClassification"],
        label2id={"ben": 0, "mal": 1},
        id2label={"0": "ben", "1": "mal"},
        _name_or_path="/synthetic/lift_level--raw/task--mlm/checkpoint-799",
        head_num_hidden_layers=0,
        head_hidden_size=0,
    )
    path.write_text(json.dumps(config))
    tensors = {}
    for name, value in original.state_dict().items():
        source = (
            "head_clf.final_layer." + name.removeprefix("classifier.")
            if name.startswith("classifier.")
            else "backbone." + name
        )
        tensors[source] = value.detach().clone()
    save_file(tensors, str(root / "model.safetensors"))
    (root / "trainer_state.json").write_text(
        json.dumps(
            {
                "global_step": 1923,
                "best_model_checkpoint": "/synthetic/checkpoint-768",
            }
        )
    )
    return original.eval()


def test_all_weights_logits_rng_and_freezing_are_preserved(tmp_path):
    original = detector_checkpoint(tmp_path / "detector")
    state = torch.get_rng_state().clone()
    loaded = load_released_detector(tmp_path / "detector", max_bytes=32, max_tokens=12)
    assert torch.equal(state, torch.get_rng_state())
    assert not loaded.model.training
    assert not any(p.requires_grad for p in loaded.model.parameters())
    for key, value in original.state_dict().items():
        torch.testing.assert_close(loaded.model.state_dict()[key], value, atol=0, rtol=0)
    tokens = loaded.inputs.encode_bytes(b"synthetic").unsqueeze(0)
    with torch.inference_mode():
        torch.testing.assert_close(
            loaded.model(tokens).logits, original(tokens).logits, atol=0, rtol=0
        )
    assert loaded.provenance["head_tensors_loaded"] == 2
    assert loaded.provenance["source_best_checkpoint"] == "checkpoint-768"


@pytest.mark.parametrize("fault", ["missing_head", "extra", "shape", "nan", "dtype", "alias"])
def test_detector_rejects_any_invalid_weight(tmp_path, fault):
    root = tmp_path / "detector"
    detector_checkpoint(root)
    path = root / "model.safetensors"
    tensors = load_file(str(path))
    key = "head_clf.final_layer.weight"
    if fault == "missing_head":
        tensors.pop(key)
    elif fault == "extra":
        tensors["head_mlm.final_layer.weight"] = torch.zeros(1)
    elif fault == "shape":
        tensors[key] = torch.zeros(2, 1)
    elif fault == "nan":
        tensors[key][0, 0] = float("nan")
    elif fault == "dtype":
        tensors[key] = tensors[key].half()
    else:
        tensors["backbone.embedding.weight"] = tensors["backbone.embeddings.weight"].clone()
    save_file(tensors, str(path))
    with pytest.raises(SupervisedTrainingError, match="detector rejected"):
        load_released_detector(root)


@pytest.mark.parametrize(
    "override",
    [
        {"architectures": ["MambaForMaskedLM"]},
        {"_name_or_path": None},
        {"label2id": {"ben": 1, "mal": 0}},
        {"is_decoder": True},
        {"bi_tie_directions": True},
        {"bi_mix_directions": True},
        {"bi_add_directions": False},
        {"head_num_hidden_layers": 1},
    ],
)
def test_source_protocol_cannot_silently_change(tmp_path, override):
    root = tmp_path / "detector"
    detector_checkpoint(root)
    path = root / "config.json"
    path.write_text(json.dumps({**json.loads(path.read_text()), **override}))
    with pytest.raises(SupervisedTrainingError, match="detector rejected"):
        load_released_detector(root)
