"""Tiny generated author-style artifacts; no released weights or real malware bytes."""

from dataclasses import asdict
import json
from pathlib import Path

from safetensors.torch import save_file
from tokenizers import Tokenizer, models, processors
import torch

from malweave.data.byte_inputs import SPECIAL_TOKEN_ORDER
from malweave.models.mamba import MambaConfig, MambaForSequenceClassification


def released_checkpoint(root: Path, algorithm: str = "BPE") -> MambaForSequenceClassification:
    root.mkdir(parents=True)
    vocab = {token: index for index, token in enumerate(SPECIAL_TOKEN_ORDER)}
    vocab.update({chr(value + 10752): value + 7 for value in range(256)})
    backend = (
        models.BPE(vocab=vocab, merges=[])
        if algorithm == "BPE"
        else models.Unigram([(token, -1.0) for token in vocab], unk_id=1)
    )
    tokenizer = Tokenizer(backend)
    tokenizer.add_special_tokens(list(SPECIAL_TOKEN_ORDER))
    tokenizer.post_processor = processors.TemplateProcessing(
        single="<bos> $A <eos>", special_tokens=[("<bos>", 3), ("<eos>", 4)]
    )
    tokenizer.save(str(root / "tokenizer.json"))
    names = ("pad", "unk", "mask", "bos", "eos", "cls", "sep")
    specials = {name + "_token": token for name, token in zip(names, SPECIAL_TOKEN_ORDER)}
    (root / "special_tokens_map.json").write_text(json.dumps(specials))
    (root / "tokenizer_config.json").write_text(
        json.dumps(
            {
                **specials,
                "tokenizer_class": "PreTrainedTokenizerFast",
                "model_max_length": 64,
            }
        )
    )
    torch.manual_seed(7)
    config = MambaConfig(
        vocab_size=264,
        hidden_size=8,
        num_hidden_layers=2,
        state_size=2,
        conv_kernel=2,
        time_step_rank=1,
    )
    model = MambaForSequenceClassification(config)
    metadata = {
        **asdict(config),
        "model_type": "mamba",
        "architectures": ["MambaForMaskedLM"],
        "initializer_range": 0.02,
    }
    (root / "config.json").write_text(json.dumps(metadata))
    tensors = {
        "backbone." + key: value.detach().clone()
        for key, value in model.state_dict().items()
        if not key.startswith("classifier.")
    }
    tensors["head_mlm.final_layer.weight"] = torch.zeros(config.vocab_size, config.hidden_size)
    tensors["head_mlm.final_layer.bias"] = torch.zeros(config.vocab_size)
    save_file(tensors, str(root / "model.safetensors"))
    return model
