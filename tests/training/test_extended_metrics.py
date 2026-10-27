"""Check strict empirical FPR caps in the offline reporting script."""

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "extended_metrics", Path(__file__).resolve().parents[2] / "scripts/extended_metrics.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_low_fpr_does_not_force_one_false_positive():
    result = module._tpr_at_fpr([0.9, 0.8, 0.7, 0.1], [1, 0, 1, 0], 1e-4)
    assert result["false_positives"] == 0
    assert result["achieved_fpr"] == 0
    assert result["tpr"] == 0.5


def test_low_fpr_preserves_ties():
    result = module._tpr_at_fpr([0.9, 0.9, 0.9, 0.1], [1, 0, 0, 1], 0.5)
    assert result["false_positives"] == 0
    assert result["tpr"] == 0


@pytest.mark.parametrize("cap", [0, 0.01, 0.1, 0.5, 1])
def test_empirical_fpr_is_always_bounded(cap):
    scores = [0.9, 0.8, 0.8, 0.6, 0.3, 0.1]
    labels = [1, 0, 1, 0, 1, 0]
    result = module._tpr_at_fpr(scores, labels, cap)
    assert result["achieved_fpr"] <= cap
    assert result["false_positives"] == sum(
        p >= result["threshold"] and y == 0 for p, y in zip(scores, labels)
    )
