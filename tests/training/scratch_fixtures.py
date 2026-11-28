"""Shared synthetic scratch experiment setup; contains no real sample data."""

from pathlib import Path

import yaml

from malweave.config import CONFIGS_DIR
from malweave.data.rands_training import load_config
from malweave.training.scratch_smoke import synthetic_inputs


def fixture(tmp_path: Path) -> tuple[Path, Path]:
    data = tmp_path / "data"
    count = synthetic_inputs(data)
    config = load_config(CONFIGS_DIR / "experiments/rands-exe-scratch.yaml")
    config["data"]["expected_exe_files"] = count
    config["tokenizer"].update(vocab_size=272, max_train_files=16, max_bytes_per_file=64)
    config["model"].update(
        name="hrrformer",
        max_tokens=16,
        architecture={
            "hidden_size": 8,
            "num_hidden_layers": 1,
            "num_attention_heads": 2,
            "intermediate_size": 16,
            "hidden_dropout_prob": 0.1,
            "attention_probs_dropout_prob": 0.1,
            "mask_padding": True,
        },
    )
    config["training"].update(
        epochs=2,
        batch_size=3,
        gradient_accumulation_steps=3,
        precision="fp32",
        gradient_checkpointing=False,
    )
    config["runtime"].update(cpu_threads=1, dataloader_workers=0, checkpoint_updates=1)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False))
    return data, path
