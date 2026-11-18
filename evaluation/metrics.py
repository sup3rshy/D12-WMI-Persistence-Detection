"""Binary classification metrics for scenario-level detector evaluation."""

from __future__ import annotations

from typing import Iterable


def confusion(labels: Iterable[int], predicted: Iterable[int]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for label, pred in zip(labels, predicted):
        if label == 1 and pred == 1:
            tp += 1
        elif label == 0 and pred == 1:
            fp += 1
        elif label == 0 and pred == 0:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def metrics(labels: Iterable[int], predicted: Iterable[int]) -> dict[str, float | int]:
    labels = list(labels)
    predicted = list(predicted)
    cm = confusion(labels, predicted)
    tp, fp, tn, fn = cm["tp"], cm["fp"], cm["tn"], cm["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / len(labels) if labels else 0.0
    return {
        **cm,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(accuracy, 4),
        "support": len(labels),
    }


def format_metrics(result: dict[str, float | int]) -> str:
    return (
        f"TP={result['tp']} FP={result['fp']} TN={result['tn']} FN={result['fn']} | "
        f"precision={result['precision']:.3f} recall={result['recall']:.3f} "
        f"f1={result['f1']:.3f} fpr={result['fpr']:.3f}"
    )
