"""Evaluate the detector on the labelled scenario dataset.

Writes:
  reports/metrics.json
  reports/per_scenario.csv
  reports/confusion_matrix.csv
  reports/alerts.json
  reports/threshold_sensitivity.csv
  reports/evaluation-report.md
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from detector.parser import load_scenario
from detector.scoring import DEFAULT_THRESHOLDS, analyze_bundle, load_allowlist
from evaluation.metrics import metrics


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _scenario_dirs(dataset: Path) -> list[Path]:
    return sorted(
        path
        for path in dataset.iterdir()
        if path.is_dir() and (path / "ground_truth.json").exists()
    )


def _markdown(report: dict) -> str:
    strict = report["metrics"]["strict"]
    triage = report["metrics"]["triage"]
    lines = [
        "# D12 detector - evaluation report",
        "",
        f"- Dataset: `{report['dataset']}`",
        f"- Scenarios: {report['summary']['scenarios']} "
        f"({report['summary']['benign']} benign / {report['summary']['malicious']} malicious)",
        f"- Malicious threshold: score >= {report['thresholds']['malicious']}",
        f"- Suspicious threshold: score >= {report['thresholds']['suspicious']}",
        "",
        "## Scenario-level results",
        "",
        "| Scenario | Label | Score | Verdict | Top evidence |",
        "|---|---:|---:|---|---|",
    ]
    for item in report["results"]:
        rules = [
            evidence["rule"]
            for sub in item["subscriptions"]
            for evidence in sub["evidence"]
            if evidence["weight"] > 0
        ]
        lines.append(
            f"| `{item['scenario_id']}` | {item['label']} | {item['score']} | "
            f"{item['verdict']} | {', '.join(rules[:4]) or '-'} |"
        )
    lines += [
        "",
        "## Metrics",
        "",
        "| Operating point | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, value in (("strict (malicious only)", strict), ("triage (suspicious+malicious)", triage)):
        lines.append(
            f"| {name} | {value['tp']} | {value['fp']} | {value['tn']} | {value['fn']} | "
            f"{value['precision']:.3f} | {value['recall']:.3f} | {value['f1']:.3f} | {value['fpr']:.3f} |"
        )
    lines += [
        "",
        "## Threshold sensitivity",
        "",
        "| Malicious threshold | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["threshold_sensitivity"]:
        lines.append(
            f"| {row['threshold']} | {row['tp']} | {row['fp']} | {row['tn']} | {row['fn']} | "
            f"{row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} | {row['fpr']:.3f} |"
        )
    lines += [
        "",
        "## Per-scenario evidence",
        "",
    ]
    for item in report["results"]:
        lines.append(f"### `{item['scenario_id']}` ({item['category']})")
        lines.append("")
        lines.append(item["description"])
        lines.append("")
        for sub in item["subscriptions"]:
            lines.append(
                f"- score **{sub['score']}** / verdict **{sub['verdict']}** - "
                f"`{sub['filter']['name']}` -> `{sub['consumer']['class']}:{sub['consumer']['name']}`"
            )
            for evidence in sub["evidence"]:
                lines.append(
                    f"  - `{evidence['rule']}` (+{evidence['weight']}) {evidence['title']}: {evidence['detail']}"
                )
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("data/scenarios"))
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    parser.add_argument("--malicious-threshold", type=int, default=DEFAULT_THRESHOLDS["malicious"])
    parser.add_argument("--suspicious-threshold", type=int, default=DEFAULT_THRESHOLDS["suspicious"])
    parser.add_argument("--allowlist", type=Path, default=None)
    args = parser.parse_args()

    thresholds = {
        "malicious": args.malicious_threshold,
        "suspicious": args.suspicious_threshold,
    }
    allowlist = load_allowlist(args.allowlist)
    directories = _scenario_dirs(args.dataset)
    if not directories:
        raise SystemExit(f"no scenarios in {args.dataset}; run simulator.generate_dataset first")

    results = []
    for directory in directories:
        bundle = load_scenario(directory)
        result = analyze_bundle(bundle, allowlist=allowlist, thresholds=thresholds)
        result["directory"] = str(directory)
        results.append(result)

    labels = [item["label"] for item in results]
    strict_pred = [1 if item["verdict"] == "malicious" else 0 for item in results]
    triage_pred = [1 if item["verdict"] in {"malicious", "suspicious"} else 0 for item in results]

    strict = metrics(labels, strict_pred)
    triage = metrics(labels, triage_pred)

    sensitivity = []
    for threshold in range(20, 101, 5):
        pred = [1 if item["score"] >= threshold else 0 for item in results]
        row = metrics(labels, pred)
        sensitivity.append({"threshold": threshold, **row})

    report = {
        "dataset": str(args.dataset),
        "thresholds": thresholds,
        "summary": {
            "scenarios": len(results),
            "benign": labels.count(0),
            "malicious": labels.count(1),
        },
        "metrics": {"strict": strict, "triage": triage},
        "threshold_sensitivity": sensitivity,
        "results": results,
    }

    args.reports.mkdir(parents=True, exist_ok=True)
    _write_json(args.reports / "metrics.json", report)
    _write_json(
        args.reports / "alerts.json",
        {
            "thresholds": thresholds,
            "alerts": [
                item
                for item in results
                if item["verdict"] in {"malicious", "suspicious"}
            ],
        },
    )

    with (args.reports / "per_scenario.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["scenario_id", "label", "category", "score", "verdict", "predicted", "correct"])
        for item in results:
            writer.writerow(
                [
                    item["scenario_id"],
                    item["label"],
                    item["category"],
                    item["score"],
                    item["verdict"],
                    item["predicted"],
                    int(item["predicted"] == item["label"]),
                ]
            )

    with (args.reports / "confusion_matrix.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["operating_point", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "fpr"])
        for name, value in (("strict", strict), ("triage", triage)):
            writer.writerow(
                [
                    name,
                    value["tp"],
                    value["fp"],
                    value["tn"],
                    value["fn"],
                    value["precision"],
                    value["recall"],
                    value["f1"],
                    value["fpr"],
                ]
            )

    with (args.reports / "threshold_sensitivity.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["threshold", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "fpr"])
        for row in sensitivity:
            writer.writerow(
                [
                    row["threshold"],
                    row["tp"],
                    row["fp"],
                    row["tn"],
                    row["fn"],
                    row["precision"],
                    row["recall"],
                    row["f1"],
                    row["fpr"],
                ]
            )

    (args.reports / "evaluation-report.md").write_text(_markdown(report), encoding="utf-8")

    print(f"{'scenario':<38} {'label':>5} {'score':>5}  verdict")
    print("-" * 62)
    for item in results:
        print(f"{item['scenario_id']:<38} {item['label']:>5} {item['score']:>5}  {item['verdict']}")
    print("-" * 62)
    print(f"strict: TP={strict['tp']} FP={strict['fp']} TN={strict['tn']} FN={strict['fn']} "
          f"precision={strict['precision']:.3f} recall={strict['recall']:.3f} "
          f"f1={strict['f1']:.3f} fpr={strict['fpr']:.3f}")
    print(f"triage: TP={triage['tp']} FP={triage['fp']} TN={triage['tn']} FN={triage['fn']} "
          f"precision={triage['precision']:.3f} recall={triage['recall']:.3f} "
          f"f1={triage['f1']:.3f} fpr={triage['fpr']:.3f}")
    print(f"reports -> {args.reports}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
