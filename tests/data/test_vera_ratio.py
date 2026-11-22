import csv

from malweave.data.vera_ratio import export_ratio_splits


def test_shared_holdouts_exact_ratios_and_no_overlap(tmp_path):
    candidates, membership = [], []
    for state in ("Active", "Latent", "benign"):
        for i in range(40 if state != "benign" else 100):
            source = f"{state}-{i}"
            candidates.append(
                {
                    "source_sha256": source,
                    "exe_sha256": source,
                    "model_input_sha256": source,
                    "label": "benign" if state == "benign" else "ransomware",
                    "state": state,
                }
            )
            membership.append({"model_input_sha256": source, "state": state})

    def write(name, rows):
        path = tmp_path / name
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return path

    out = tmp_path / "out"
    summary = export_ratio_splits(
        write("candidates.csv", candidates), write("membership.csv", membership), out, [0, 1, 2], 0
    )
    assert summary["train_ransomware"] == 30
    assert summary["validation_total"] == 16
    holdout = None
    benign = {}
    for seed in (0, 1, 2):
        for pct in (0, 10, 30, 50, 70, 90, 100):
            with (out / f"seed-{seed}" / f"active-{pct:03d}" / "split.csv").open() as f:
                rows = list(csv.DictReader(f))
            train = [r for r in rows if r["split"] == "train"]
            current = {(r["source_sha256"], r["split"]) for r in rows if r["split"] != "train"}
            if holdout is None:
                holdout = current
            assert current == holdout
            assert len({r["source_sha256"] for r in rows}) == len(rows)
            assert sum(r["state"] == "Active" for r in train) == 30 * pct // 100
            b = {r["source_sha256"] for r in train if r["state"] == "benign"}
            assert benign.setdefault(seed, b) == b
