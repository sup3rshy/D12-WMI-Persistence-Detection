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
from evaluation.validation import build_validation_report


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
    validation = report.get("validation")
    if validation:
        lines += [
            "",
            "## Bootstrap 95% confidence intervals",
            "",
            f"Resampling: {validation['bootstrap']['resamples']} draws, "
            f"seed `{validation['bootstrap']['seed']}`. A metric is omitted from a "
            "resample when its denominator is zero.",
            "",
            "| Operating point | Metric | 95% CI | Usable resamples |",
            "|---|---|---|---:|",
        ]
        for point in ("strict", "triage"):
            for metric in ("precision", "recall", "f1", "fpr"):
                interval = validation["bootstrap"][point][metric]
                lines.append(
                    f"| {point} | {metric} | {interval['low']:.3f}-{interval['high']:.3f} "
                    f"| {interval['n']} |"
                )

        lines += [
            "",
            "## Rule ablation",
            "",
            "Score impact of disabling one rule at a time (baseline: strict recall "
            f"{validation['ablation']['baseline']['strict']['recall']:.3f}, triage recall "
            f"{validation['ablation']['baseline']['triage']['recall']:.3f}).",
            "",
            "| Rule | Strict recall | Triage recall | Strict recall drop | Triage recall drop |",
            "|---|---:|---:|---:|---:|",
        ]
        for row in validation["ablation"]["rules"]:
            lines.append(
                f"| {row['rule']} | {row['strict_recall']:.3f} | "
                f"{row['triage_recall']:.3f} | {row['strict_recall_drop']:.3f} | "
                f"{row['triage_recall_drop']:.3f} |"
            )

        lines += [
            "",
            "## Perturbation robustness",
            "",
            "Deterministic mutations of the catalogue, evaluated but never used to "
            "choose weights: neutral object names, relocated payload paths, switched "
            "principal, changed polling interval, moved namespace and dropped "
            "activation telemetry.",
            "",
            "| Family | Malicious | Strict recall | Triage recall | Benign | Strict FPR | Triage FPR |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for family, summary in validation["perturbation"]["summary"].items():
            lines.append(
                f"| {family} | {summary['malicious']} | {summary['strict_recall']:.3f} | "
                f"{summary['triage_recall']:.3f} | {summary['benign']} | "
                f"{summary['strict_fpr']:.3f} | {summary['triage_fpr']:.3f} |"
            )
        strict_failures = sorted(
            {
                item
                for summary in validation["perturbation"]["summary"].values()
                for item in summary["strict_failures"]
            }
        )
        if strict_failures:
            lines += [
                "",
                "Strict-threshold misses after mutation: "
                + ", ".join(f"`{item}`" for item in strict_failures)
                + ".",
            ]

        lines += [
            "",
            "## External validation",
            "",
            "Data that was not part of the labelled scenario set.",
            "",
            "| Sample | Provenance | Expected | Score | Verdict | Correct |",
            "|---|---|---:|---:|---|---:|",
        ]
        for row in validation["external"]["samples"]:
            lines.append(
                f"| `{row['name']}` | {row['provenance']} | {row['expected']} | "
                f"{row['score']} | {row['verdict']} | {row['correct']} |"
            )
        external = validation["external"]["summary"]
        lines += [
            "",
            f"External confusion matrix: TP={external['tp']} FP={external['fp']} "
            f"TN={external['tn']} FN={external['fn']}.",
        ]

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("data/scenarios"))
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    parser.add_argument("--malicious-threshold", type=int, default=DEFAULT_THRESHOLDS["malicious"])
    parser.add_argument("--suspicious-threshold", type=int, default=DEFAULT_THRESHOLDS["suspicious"])
    parser.add_argument("--allowlist", type=Path, default=None)
    args = parser.parse_args(argv)

    thresholds = {
        "malicious": args.malicious_threshold,
        "suspicious": args.suspicious_threshold,
    }
    allowlist = load_allowlist(args.allowlist)
    directories = _scenario_dirs(args.dataset)
    if not directories:
        raise SystemExit(f"no scenarios in {args.dataset}; run simulator.generate_dataset first")

    results = []
    bundles = []
    for directory in directories:
        bundle = load_scenario(directory)
        bundles.append(bundle)
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

    validation = build_validation_report(bundles, allowlist, thresholds)

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
        "validation": validation,
        "results": results,
    }

    args.reports.mkdir(parents=True, exist_ok=True)
    _write_json(args.reports / "metrics.json", report)
    _write_json(args.reports / "validation.json", validation)
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
        writer = csv.writer(handle, lineterminator="\n")
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
        writer = csv.writer(handle, lineterminator="\n")
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
        writer = csv.writer(handle, lineterminator="\n")
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

    with (args.reports / "rule_ablation.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "rule",
                "strict_tp",
                "strict_fn",
                "strict_fp",
                "strict_recall",
                "strict_fpr",
                "triage_tp",
                "triage_fn",
                "triage_fp",
                "triage_recall",
                "triage_fpr",
                "strict_recall_drop",
                "triage_recall_drop",
            ]
        )
        for row in validation["ablation"]["rules"]:
            writer.writerow(
                [
                    row["rule"],
                    row["strict_tp"],
                    row["strict_fn"],
                    row["strict_fp"],
                    row["strict_recall"],
                    row["strict_fpr"],
                    row["triage_tp"],
                    row["triage_fn"],
                    row["triage_fp"],
                    row["triage_recall"],
                    row["triage_fpr"],
                    row["strict_recall_drop"],
                    row["triage_recall_drop"],
                ]
            )

    with (args.reports / "robustness.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "family",
                "base_scenario",
                "label",
                "score",
                "verdict",
                "strict_predicted",
                "triage_predicted",
            ]
        )
        for row in validation["perturbation"]["rows"]:
            writer.writerow(
                [
                    row["family"],
                    row["base_scenario"],
                    row["label"],
                    row["score"],
                    row["verdict"],
                    row["strict_predicted"],
                    row["triage_predicted"],
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
