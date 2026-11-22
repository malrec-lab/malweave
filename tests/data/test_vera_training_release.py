import csv
from hashlib import sha256
import json
import struct

import pytest
import yaml

from malweave.data.lmlm_inputs import ReleasedExeTokenizer
from malweave.data.vera_training_release import stage_ratio_release, stage_ratio_releases
from malweave.training.supervised import load_supervised_split
from tests.lmlm_fixtures import released_checkpoint


@pytest.mark.parametrize("fault", [None, "bytes", "tokens", "ratio", "state"])
def test_stage_verified_loader_manifest(tmp_path, fault, monkeypatch):
    checkpoint = tmp_path / "checkpoint"
    released_checkpoint(checkpoint)
    tokenizer = ReleasedExeTokenizer(
        checkpoint, json.loads((checkpoint / "config.json").read_text()), 12, 32
    )
    config = {
        "experiment": {"protocol": "vera_active_latent_ratios"},
        "finetuning": {"initialization": "original_mlm"},
        "inputs": {"exe": {"truncation": {"max_tokens": 12, "max_bytes": 32}}},
        "cohort": {"approval_status": "approved_frozen", "active_percentage": 50},
    }
    exe_root = tmp_path / "exe"
    rows = []
    for split in ("train", "validation", "test"):
        for state in ("Active", "Latent", "benign", "benign"):
            payload = bytes([len(rows) + 1]) * 10
            digest = sha256(payload).hexdigest()
            dataset = "assemblage" if state == "benign" else "vera"
            path = exe_root / dataset / digest
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            ids = tokenizer.encode_bytes(payload).tolist()
            token = sha256(
                struct.pack("<Q", len(ids)) + struct.pack(f"<{len(ids)}I", *ids)
            ).hexdigest()
            rows.append(
                {
                    "split": split,
                    "state": state,
                    "dataset": dataset,
                    "label": "benign" if state == "benign" else "ransomware",
                    "source_sha256": sha256(b"source" + payload).hexdigest(),
                    "exe_sha256": digest,
                    "exe_bytes": len(payload),
                    "model_input_sha256": token,
                }
            )
    if fault == "bytes":
        path.write_bytes(b"wrong")
    elif fault == "tokens":
        rows[0]["model_input_sha256"] = "f" * 64
    elif fault == "ratio":
        config["cohort"]["active_percentage"] = 30
    elif fault == "state":
        rows[0]["state"] = "benign"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))
    membership = tmp_path / "membership.csv"
    with membership.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    output = tmp_path / "release"
    if fault:
        with pytest.raises(ValueError):
            stage_ratio_release(membership, config_path, checkpoint, exe_root, output)
        assert not output.exists()
    else:
        summary = stage_ratio_release(membership, config_path, checkpoint, exe_root, output)
        assert summary["model_input_audit"]["verified_sources"] == 12
        loaded = load_supervised_split(output / "split.csv")
        assert len(loaded) == 12
        assert loaded[0].state == "Active"
        calls = []
        original = ReleasedExeTokenizer.encode_bytes

        def counted(self, payload):
            if len(payload) == 10:
                calls.append(sha256(payload).hexdigest())
            return original(self, payload)

        monkeypatch.setattr(ReleasedExeTokenizer, "encode_bytes", counted)
        outputs = [tmp_path / "batch-a", tmp_path / "batch-b"]
        summaries = stage_ratio_releases(
            [(membership, config_path, destination) for destination in outputs],
            checkpoint,
            exe_root,
        )
        assert len(calls) == len(set(calls)) == 12
        assert len(summaries) == 2
        assert (
            outputs[0].joinpath("split.csv").read_bytes()
            == output.joinpath("split.csv").read_bytes()
        )
        assert (
            outputs[1].joinpath("split.csv").read_bytes()
            == output.joinpath("split.csv").read_bytes()
        )

        # A cached result cannot hide a changed expected token digest.
        bad_membership = tmp_path / "bad-membership.csv"
        rows[0]["model_input_sha256"] = "f" * 64
        with bad_membership.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        with pytest.raises(ValueError, match="final-token digest"):
            stage_ratio_releases(
                [
                    (membership, config_path, tmp_path / "cache-first"),
                    (bad_membership, config_path, tmp_path / "cache-rejected"),
                ],
                checkpoint,
                exe_root,
            )
        assert not (tmp_path / "cache-rejected").exists()
