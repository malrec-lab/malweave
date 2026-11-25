"""Static original/LMLM byte encodings and durable input-integrity audits.

Source: RawByteClf 2502450e40ac00363e168106662aac29821d4a93,
src/learn/preprocessing.py:bytes_to_input_ids and src/tokenization/__init__.py.
The source WORDLEVEL path shifts bytes by seven, prepends BOS, truncates, then
reserves the final position for EOS. No author Python needs to be executed.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys
import time

import torch

from malweave.training.contracts import SupervisedTrainingError

E2_ENCODING = {"byte_offset": 7, "bos_token_id": 3, "eos_token_id": 4, "pad_token_id": 0}
E1_ENCODING = {"byte_offset": 1, "bos_token_id": None, "eos_token_id": None, "pad_token_id": 0}


def encode_e1_bytes(content: bytes) -> torch.Tensor:
    """Original binaryLoader byte+1 encoding, with no truncation or BOS/EOS."""
    if not content:
        return torch.empty(0, dtype=torch.long)
    return torch.frombuffer(bytearray(content), dtype=torch.uint8).long() + 1


def encode_e2_bytes(content: bytes, max_tokens: int) -> torch.Tensor:
    """Keep at most max_tokens-2 bytes, with source-compatible BOS/EOS."""
    if type(max_tokens) is not int or max_tokens < 2:
        raise SupervisedTrainingError("E2 max_tokens must reserve BOS and EOS.")
    prefix = content[: max_tokens - 2]
    values = (
        torch.frombuffer(bytearray(prefix), dtype=torch.uint8).long()
        if prefix
        else torch.empty(0, dtype=torch.long)
    )
    return torch.cat((torch.tensor([3]), values + 7, torch.tensor([4])))


def raw_sample_path(root: Path, samples_dir: str, source: str) -> Path:
    path = root / samples_dir / source[:2] / source
    if not path.resolve().is_relative_to(root.resolve()):
        raise SupervisedTrainingError("RAW sample path escapes its declared root.")
    return path


def verified_prefix(path: Path, expected_sha256: str, max_bytes: int | None) -> tuple[bytes, int]:
    """Hash the original; retain a bounded prefix, or the entire input with None."""
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 0):
        raise SupervisedTrainingError("max_bytes must be nonnegative or None for full input.")
    digest = sha256()
    prefix = bytearray()
    size = 0
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
                size += len(block)
                remaining = len(block) if max_bytes is None else max_bytes - len(prefix)
                if remaining > 0:
                    prefix.extend(block[:remaining])
    except OSError as error:
        raise SupervisedTrainingError("Could not read required RAW representation.") from error
    if digest.hexdigest() != expected_sha256:
        raise SupervisedTrainingError("RAW representation digest changed; aborting run.")
    return bytes(prefix), size


def audit_e2_inputs(examples, raw_root, samples_dir, max_tokens, split_digest, audit_root):
    return audit_malconv_inputs(
        examples, raw_root, samples_dir, max_tokens, split_digest, audit_root, protocol="lmlm_e2"
    )


def audit_malconv_inputs(
    examples, raw_root, samples_dir, max_tokens, split_digest, audit_root, *, protocol
):
    """Durable static audit; never change the frozen cohort to resolve collisions.

    E1 uses the full verified source digest; E2 uses its retained prefix digest.
    These injective encodings preserve input equality. Only digests/aggregates
    are retained, never bytes.
    Completed rows can be reused; the training reader independently verifies each
    original source hash again before consuming it.
    """
    if protocol not in {"lmlm_e2", "malconvgct_e1"}:
        raise SupervisedTrainingError("Unknown MalConv input audit protocol.")
    full_file = protocol == "malconvgct_e1"
    if full_file and max_tokens is not None:
        raise SupervisedTrainingError("E1 full-input audit cannot have a token limit.")
    if not full_file and (type(max_tokens) is not int or max_tokens < 2):
        raise SupervisedTrainingError("E2 audit requires a token limit including BOS/EOS.")
    identity = {
        "protocol": protocol,
        "split_sha256": split_digest,
        "max_tokens": max_tokens,
        "encoding": E1_ENCODING if full_file else E2_ENCODING,
        "adapter_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    key = sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    directory = audit_root / key
    directory.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    last_log = started
    with sqlite3.connect(directory / "state.sqlite3") as connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("CREATE TABLE IF NOT EXISTS identity (value TEXT NOT NULL)")
        encoded = json.dumps(identity, sort_keys=True)
        previous = connection.execute("SELECT value FROM identity").fetchone()
        if previous and previous[0] != encoded:
            raise SupervisedTrainingError("MalConv audit identity changed.")
        if previous is None:
            connection.execute("INSERT INTO identity VALUES (?)", (encoded,))
        connection.execute(
            "CREATE TABLE IF NOT EXISTS source (sha TEXT PRIMARY KEY, split TEXT, label INTEGER, "
            "prefix_sha TEXT, raw_size INTEGER, prefix_size INTEGER, status TEXT, error TEXT)"
        )
        connection.commit()
        completed = {
            row[0] for row in connection.execute("SELECT sha FROM source WHERE status='success'")
        }
        for row in examples:
            if row.source_sha256 in completed:
                continue
            try:
                path = raw_sample_path(raw_root, samples_dir, row.source_sha256)
                # Full-input identity is the verified original digest: audit it
                # without retaining the entire file in memory.
                prefix, size = verified_prefix(
                    path, row.source_sha256, 0 if full_file else max_tokens - 2
                )
                result = (
                    row.source_sha256 if full_file else sha256(prefix).hexdigest(),
                    size,
                    size if full_file else len(prefix),
                    "success",
                    None,
                )
            except SupervisedTrainingError as error:
                result = (None, 0, 0, "error", str(error))
            connection.execute(
                "INSERT OR REPLACE INTO source VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (row.source_sha256, row.split, row.label, *result),
            )
            connection.commit()
            if time.perf_counter() - last_log >= 5:
                progress = {
                    "phase": "e1_input_audit" if full_file else "e2_input_audit",
                    "total": len(examples),
                    "processed": connection.execute("SELECT count(*) FROM source").fetchone()[0],
                    "elapsed_seconds": time.perf_counter() - started,
                }
                temporary = directory / "progress.json.tmp"
                temporary.write_text(json.dumps(progress, sort_keys=True) + "\n")
                temporary.replace(directory / "progress.json")
                print(json.dumps(progress), file=sys.stderr, flush=True)
                last_log = time.perf_counter()
        statuses = dict(connection.execute("SELECT status, count(*) FROM source GROUP BY status"))
        by_class = {
            str(label): dict(
                Counter(
                    status
                    for (status,) in connection.execute(
                        "SELECT status FROM source WHERE label=?", (label,)
                    )
                )
            )
            for label in (0, 1)
        }
        collisions = connection.execute(
            "SELECT count(*) FROM (SELECT prefix_sha FROM source WHERE status='success' "
            "GROUP BY prefix_sha HAVING count(DISTINCT split)>1 OR count(DISTINCT label)>1)"
        ).fetchone()[0]
        sizes = connection.execute(
            "SELECT coalesce(sum(raw_size),0), coalesce(sum(prefix_size),0) FROM source"
        ).fetchone()
    summary = {
        "identity": identity,
        "total": len(examples),
        "statuses": statuses,
        "by_class": by_class,
        "cross_split_or_conflicting_label_groups": collisions,
        "raw_bytes": sizes[0],
        "retained_bytes": sizes[1],
        "elapsed_seconds": time.perf_counter() - started,
    }
    temporary = directory / "summary.json.tmp"
    temporary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    temporary.replace(directory / "summary.json")
    if statuses.get("success", 0) != len(examples) or collisions:
        raise SupervisedTrainingError(
            "MalConv input audit failed; inspect private audit summary. Frozen split is unchanged."
        )
    return summary
