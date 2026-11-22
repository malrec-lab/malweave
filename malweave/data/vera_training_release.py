"""Stage ratio membership as verified supervised inputs without authorizing training."""

import csv
from hashlib import sha256
import json
from pathlib import Path
import struct

import yaml

from malweave.config import PROJECT_ROOT
from malweave.data.lmlm_inputs import ReleasedExeTokenizer
from malweave.experiments.rands_comparison import SPLIT_FIELDS


def stage_ratio_release(
    membership: Path,
    config_path: Path,
    checkpoint: Path,
    exe_root: Path,
    output: Path,
    *,
    _verified_tokens: dict | None = None,
) -> dict:
    """Verify local EXE bytes and exact tokens, then bind the loader manifest to policy.

    Files must be staged as exe_root/dataset/exe_sha256. No implicit download,
    approval, seed selection or recovery of missing admission evidence occurs here.
    """
    config = yaml.safe_load(config_path.read_text())
    if (
        config["experiment"].get("protocol") != "vera_active_latent_ratios"
        or config["finetuning"].get("initialization") != "original_mlm"
        or config["cohort"].get("approval_status") != "approved_frozen"
    ):
        raise ValueError("Explicit original-MLM frozen ratio policy required")
    limits = config["inputs"]["exe"]["truncation"]
    identity = {
        "tokenizer_sha256": sha256((checkpoint / "tokenizer.json").read_bytes()).hexdigest(),
        "checkpoint_config_sha256": sha256((checkpoint / "config.json").read_bytes()).hexdigest(),
        "production_adapter_sha256": sha256(
            (PROJECT_ROOT / "malweave/data/lmlm_inputs.py").read_bytes()
        ).hexdigest(),
        "max_bytes": limits["max_bytes"],
        "max_tokens_including_bos_eos": limits["max_tokens"],
    }
    cache_identity = json.dumps(identity, sort_keys=True)
    verified_tokens = {} if _verified_tokens is None else _verified_tokens
    tokenizer = ReleasedExeTokenizer(
        checkpoint,
        json.loads((checkpoint / "config.json").read_text()),
        max_tokens=limits["max_tokens"],
        max_bytes=limits["max_bytes"],
    )
    with membership.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError("Empty ratio membership")
    seen = {key: set() for key in ("source_sha256", "exe_sha256", "model_input_sha256")}
    staged = []
    for row in rows:
        for key, values in seen.items():
            digest = row[key]
            if (
                len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
                or digest in values
            ):
                raise ValueError("Malformed or duplicate source/EXE/token membership")
            values.add(digest)
        if row["dataset"] not in {"vera", "assemblage"} or row["split"] not in {
            "train",
            "validation",
            "test",
        }:
            raise ValueError("Invalid dataset/split membership")
        if (row["label"], row["state"], row["dataset"]) not in {
            ("benign", "benign", "assemblage"),
            ("ransomware", "Active", "vera"),
            ("ransomware", "Latent", "vera"),
        }:
            raise ValueError("Invalid class/state/source membership")
        relative = Path(row["dataset"]) / row["exe_sha256"]
        payload = (exe_root / relative).read_bytes()
        if (
            len(payload) != int(row["exe_bytes"])
            or sha256(payload).hexdigest() != row["exe_sha256"]
        ):
            raise ValueError("Staged EXE digest/size mismatch")
        cache_key = (cache_identity, row["exe_sha256"])
        digest = verified_tokens.get(cache_key)
        if digest is None:
            ids = tokenizer.encode_bytes(payload).tolist()
            digest = sha256(
                struct.pack("<Q", len(ids)) + struct.pack(f"<{len(ids)}I", *ids)
            ).hexdigest()
        if digest != row["model_input_sha256"]:
            raise ValueError("Staged final-token digest mismatch")
        verified_tokens[cache_key] = digest
        staged.append(
            {
                **dict.fromkeys(SPLIT_FIELDS, ""),
                "split": row["split"],
                "source_sha256": row["source_sha256"],
                "label": row["label"],
                "exe_representation_sha256": row["exe_sha256"],
                "exe_relative_path": relative.as_posix(),
                "exe_size": len(payload),
                "active_leakage_group_sha256": digest,
                "state": row["state"],
            }
        )
    for split in ("train", "validation", "test"):
        counts = {
            state: sum(r["split"] == split and r["state"] == state for r in staged)
            for state in ("benign", "Active", "Latent")
        }
        ransomware = counts["Active"] + counts["Latent"]
        if ransomware == 0 or counts["benign"] != ransomware:
            raise ValueError("Unbalanced/empty binary split")
        if split == "train":
            if counts["Active"] * 100 != ransomware * config["cohort"]["active_percentage"]:
                raise ValueError("Train ratio does not match frozen policy")
        elif counts["Active"] != counts["Latent"]:
            raise ValueError("Unbalanced holdout states")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    split_path = output / "split.csv"
    with split_path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=[*SPLIT_FIELDS, "state"])
        writer.writeheader()
        writer.writerows(staged)
    split_path.chmod(0o600)
    summary = {
        "status": "verified_staged_inputs_not_training_authorization",
        "policy": config["cohort"],
        "membership_sha256": sha256(membership.read_bytes()).hexdigest(),
        "output_sha256": {"split.csv": sha256(split_path.read_bytes()).hexdigest()},
        "model_input_audit": {"identity": identity, "verified_sources": len(staged)},
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def stage_ratio_releases(
    runs: list[tuple[Path, Path, Path]], checkpoint: Path, exe_root: Path
) -> list[dict]:
    """Stage memberships with one token audit per unique EXE/input contract.

    Each tuple contains membership, config and output paths. The cache is created
    here, never imported from caller claims. Every membership still checks file
    bytes, expected token digest, class, split and ratio independently. No token
    arrays or payloads are retained in the shared cache.
    """
    verified_tokens: dict = {}
    return [
        stage_ratio_release(
            membership,
            config,
            checkpoint,
            exe_root,
            output,
            _verified_tokens=verified_tokens,
        )
        for membership, config, output in runs
    ]
