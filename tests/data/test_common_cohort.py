"""Synthetic checks for paired evaluation balancing; never read sample bytes."""

import csv
from hashlib import sha256
import json

import pytest

from malweave.config import CONFIGS_DIR
from malweave.data.common_cohort import CommonCohortError, freeze_balanced_common_cohort
from malweave.training.manifest import TrainingManifestError, load_training_manifest


def _inputs(tmp_path):
    raw, exe = [], []
    for split, year, counts in (
        ("train", 2022, (2, 2)),
        ("validation", 2023, (1, 3)),
        ("test", 2024, (3, 2)),
    ):
        for label, count in zip(("benign", "ransomware"), counts):
            for index in range(count):
                source = sha256(f"{split}-{label}-{index}".encode()).hexdigest()
                row = {
                    "source_sha256": source,
                    "split": split,
                    "label": label,
                    "year": str(year),
                    "snapshot": "2026-09-02",
                    "group_id": source,
                    "object_size": "10",
                    "object_key": f"raw/{source}",
                    "object_etag": "synthetic",
                }
                raw.append(row)
                digest = sha256(f"exe-{source}".encode()).hexdigest()
                exe.append(
                    {
                        **row,
                        "representation": "exe",
                        "group_id": digest,
                        "representation_sha256": digest,
                        "object_key": f"exe/{source}",
                        "relative_path": f"exe/{source}.bin",
                    }
                )

    def write(name, rows):
        path = tmp_path / f"{name}.csv"
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        audit = tmp_path / f"{name}.json"
        audit.write_text(
            json.dumps(
                {
                    "inventory_audit_passed": True,
                    "manifest": {
                        "rows": len(rows),
                        "sha256": sha256(path.read_bytes()).hexdigest(),
                    },
                }
            )
        )
        return path, audit

    r, ra = write("raw", raw)
    e, ea = write("exe", exe)
    return r, e, ra, ea, CONFIGS_DIR / "datasets/rands-common-balanced.yaml"


def test_balance_preserves_pairing_train_years_and_provenance(tmp_path):
    inputs = _inputs(tmp_path)
    out = tmp_path / "balanced"
    report = freeze_balanced_common_cohort(*inputs, out)
    assert report["after"] == {
        "train": {"benign": 2, "ransomware": 2},
        "validation": {"benign": 1, "ransomware": 1},
        "test": {"benign": 2, "ransomware": 2},
    }
    raw = load_training_manifest(out / "raw-split.csv", "raw")
    exe = load_training_manifest(out / "exe-split.csv", "exe")
    assert [(r.source_sha256, r.split, r.label, r.group_id) for r in raw] == [
        (r.source_sha256, r.split, r.label, r.group_id) for r in exe
    ]
    original = load_training_manifest(inputs[0], "raw")
    assert {r.source_sha256 for r in raw if r.split == "train"} == {
        r.source_sha256 for r in original if r.split == "train"
    }
    assert len(list(csv.DictReader((out / "excluded.csv").open()))) == 3
    for name in ("raw", "exe"):
        audit = json.loads((out / f"{name}-summary.json").read_text())
        assert (
            audit["manifest"]["sha256"]
            == sha256((out / f"{name}-split.csv").read_bytes()).hexdigest()
        )
        assert audit["staging_required"] is True
        assert "output_root" not in audit  # Cannot masquerade as a staging report.
    assert not (out / "staging-summary.json").exists()
    other = tmp_path / "repeat"
    freeze_balanced_common_cohort(*inputs, other)
    assert (out / "raw-split.csv").read_bytes() == (other / "raw-split.csv").read_bytes()
    assert (out / "exe-split.csv").read_bytes() == (other / "exe-split.csv").read_bytes()
    with pytest.raises(CommonCohortError, match="already exists"):
        freeze_balanced_common_cohort(*inputs, out)


@pytest.mark.parametrize(
    "mutation",
    ["mismatch", "leakage", "missing_class", "bad_year", "bad_audit", "duplicate", "missing_raw"],
)
def test_invalid_inputs_fail_before_publication(tmp_path, mutation):
    inputs = list(_inputs(tmp_path))
    path = inputs[1]
    rows = list(csv.DictReader(path.open()))
    if mutation == "mismatch":
        rows[0]["label"] = "ransomware"
    elif mutation == "leakage":
        rows[-1]["group_id"] = rows[0]["group_id"]
    elif mutation == "missing_class":
        rows = [r for r in rows if not (r["split"] == "validation" and r["label"] == "benign")]
    elif mutation == "bad_year":
        rows[0]["year"] = "2024"
    elif mutation == "duplicate":
        rows.append(rows[0])
    elif mutation == "missing_raw":
        rows[0]["source_sha256"] = "f" * 64
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    audit = json.loads(inputs[3].read_text())
    audit["manifest"] = {"rows": len(rows), "sha256": sha256(path.read_bytes()).hexdigest()}
    if mutation == "bad_audit":
        audit["inventory_audit_passed"] = False
    inputs[3].write_text(json.dumps(audit))
    out = tmp_path / "balanced"
    with pytest.raises((CommonCohortError, TrainingManifestError)):
        freeze_balanced_common_cohort(*inputs, out)
    assert not out.exists()


def test_cli_freezes_balanced_common(tmp_path, capsys):
    from malweave.cli import main

    raw, exe, ra, ea, cfg = _inputs(tmp_path)
    assert (
        main(
            [
                "experiment",
                "freeze-balanced-common",
                "--raw-manifest",
                str(raw),
                "--exe-manifest",
                str(exe),
                "--raw-audit",
                str(ra),
                "--exe-audit",
                str(ea),
                "--config",
                str(cfg),
                "--output-dir",
                str(tmp_path / "out"),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["staging_required"] is True
