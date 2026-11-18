"""Tests for the metric helpers."""

from __future__ import annotations

from evaluation.metrics import confusion, metrics


def test_confusion_matrix() -> None:
    result = confusion([1, 1, 0, 0], [1, 0, 1, 0])
    assert result == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}


def test_metrics_values() -> None:
    result = metrics([1, 1, 1, 0, 0], [1, 1, 0, 0, 1])
    assert result["tp"] == 2
    assert result["fn"] == 1
    assert result["tn"] == 1
    assert result["fp"] == 1
    assert result["precision"] == 0.6667
    assert result["recall"] == 0.6667
    assert result["fpr"] == 0.5


def test_metrics_empty_inputs_do_not_divide_by_zero() -> None:
    result = metrics([], [])
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
    assert result["f1"] == 0.0
    assert result["fpr"] == 0.0
