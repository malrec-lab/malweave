import csv

import pytest

from malweave.data.vera_presplit import export_presplit


def test_ordered_dedup_preserves_states_and_blocks_unknown_packing(tmp_path):
    def write(name, rows):
        path = tmp_path / name
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return path

    rows = [
        {
            "dataset": "synthetic",
            "source_sha256": s,
            "state": state,
            "label": label,
            "exe_sha256": exe,
        }
        for s, state, label, exe in (
            ("a", "Active", "ransomware", "x"),
            ("b", "Latent", "ransomware", "x"),
            ("c", "Latent", "ransomware", "y"),
            ("d", "benign", "benign", "z"),
            ("e", "benign", "benign", "w"),
        )
    ]
    manifest = write("manifest.csv", rows)
    evidence = write(
        "eligibility.csv",
        [
            {
                "dataset": "synthetic",
                "source_sha256": r["source_sha256"],
                "arch": "I386",
                "packed": "unknown" if r["source_sha256"] == "e" else "false",
                "timestamp_utc": "2020-01-01T00:00:00+00:00",
                "evidence_reference": "synthetic",
            }
            for r in rows
        ],
    )
    tokens = write(
        "tokens.csv",
        [
            {"exe_sha256": e, "status": "success", "token_sha256": d * 64}
            for e, d in (("x", "1"), ("y", "1"), ("z", "2"))
        ],
    )
    out = tmp_path / "out"
    result = export_presplit(manifest, evidence, tokens, out)
    assert result["selected"] == 2
    assert result["excluded_by_reason"] == {
        "packing_unknown": 1,
        "same_label_exe_duplicate": 1,
        "same_label_model_input_duplicate": 1,
    }
    with (out / "membership.csv").open() as stream:
        members = list(csv.DictReader(stream))
    assert {r["state"] for r in members if r["representative_source"] == "a"} == {
        "Active",
        "Latent",
    }
    assert not (out / "split.csv").exists()


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"arch": "AMD64"}, "architecture_not_i386"),
        ({"arch": ""}, "architecture_unknown"),
        ({"packed": "true", "packing_state": "obfuscated"}, "packing_obfuscated"),
        ({"packed": ""}, "packing_unknown"),
        ({"assessment_status": "failed", "arch": ""}, "assessment_failed"),
        ({"admission_evidence_valid": "false"}, "admission_evidence_invalid"),
    ],
)
def test_admission_exclusion_reasons(tmp_path, changes, reason):
    def write(name, rows):
        path = tmp_path / name
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return path

    manifest = write(
        "manifest.csv",
        [{"dataset": "synthetic", "source_sha256": "a", "exe_sha256": "b"}],
    )
    eligibility = write(
        "eligibility.csv",
        [
            {
                "dataset": "synthetic",
                "source_sha256": "a",
                "evidence_reference": "fixture",
                "arch": "I386",
                "packed": "false",
                **changes,
            }
        ],
    )
    tokens = write("tokens.csv", [{"exe_sha256": "b", "status": "failed"}])
    result = export_presplit(manifest, eligibility, tokens, tmp_path / "out", non_temporal=True)
    assert result["excluded_by_reason"] == {reason: 1}
    assert result["selected"] == 0
