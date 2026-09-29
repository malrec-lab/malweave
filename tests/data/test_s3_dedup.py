"""Dedup policies use synthetic metadata only."""

from malweave.data.s3.dedup import deduplicate_temporal_rows


def row(source, digest, split, label, year):
    return {
        "source_sha256": source,
        "representation_sha256": digest,
        "split": split,
        "label": label,
        "year": str(year),
    }


def test_earliest_keeps_original_split_and_uses_stable_tie_break():
    rows = [
        row("z", "x", "test", "benign", 2024),
        row("b", "x", "train", "benign", 2021),
        row("a", "x", "train", "benign", 2021),
        row("v", "y", "validation", "ransomware", 2023),
        row("t", "y", "test", "ransomware", 2024),
    ]
    kept, removed, report = deduplicate_temporal_rows(rows)
    assert [(r["source_sha256"], r["split"]) for r in kept] == [
        ("a", "train"),
        ("v", "validation"),
    ]
    assert report["removed_by_reason"] == {"duplicate_same_split": 1, "duplicate_later_split": 2}
    assert report["source_objects_deleted"] == 0
    assert deduplicate_temporal_rows(list(reversed(rows))) == (kept, removed, report)


def test_conflicting_labels_remove_entire_group_even_across_time():
    rows = [
        row("a", "x", "train", "benign", 2020),
        row("b", "x", "test", "ransomware", 2024),
        row("c", "y", "test", "benign", 2024),
    ]
    kept, removed, report = deduplicate_temporal_rows(rows)
    assert [r["source_sha256"] for r in kept] == ["c"]
    assert report["removed_by_reason"] == {"conflicting_labels": 2}
    assert all(not r["retained_source_sha256"] for r in removed)
