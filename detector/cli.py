"""Command line interface for the D12 detector.

Examples
--------
# one scenario / live collection folder
python -m detector.cli scan --scenario data/live

# whole labelled dataset
python -m detector.cli scan --dataset data/scenarios --json-out reports/alerts.json

# reconstruct subscriptions from 5861 event logs only
python -m detector.cli scan --scenario data/live --source events
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

from .parser import load_scenario
from .scoring import DEFAULT_THRESHOLDS, analyze_bundle, load_allowlist

VERDICT_ORDER = {"malicious": 3, "suspicious": 2, "benign": 1}


def _print_bundle(result: dict[str, Any]) -> None:
    print("=" * 78)
    print(f"scenario : {result['scenario_id']}  (label={result['label']})")
    print(f"category : {result['category']}")
    print(f"verdict  : {result['verdict'].upper()}   score={result['score']}/100")
    print(f"truth    : {result['description']}".rstrip())
    print("-" * 78)
    for assessment in result["subscriptions"]:
        sub = assessment["consumer"]
        filt = assessment["filter"]
        print(
            f"[{assessment['verdict']:>10}] {assessment['score']:>3}  "
            f"{filt['name']} -> {sub['class']}:{sub['name']}"
        )
        print(
            f"             namespace={filt['namespace']}  "
            f"event_ns={filt['event_namespace']}  "
            f"creator={assessment['creator']['sid'] or 'unknown'}"
        )
        print(f"             query={filt['query']}")
        for item in assessment["evidence"]:
            print(
                f"             +{item['weight']:<3} {item['rule']} "
                f"{item['title']} :: {item['detail']}"
            )
    print()


def _iter_scenarios(dataset: Path) -> list[Path]:
    return sorted(
        path
        for path in dataset.iterdir()
        if path.is_dir() and (path / "ground_truth.json").exists()
    )


def _write_csv(path: Path, results: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "scenario_id",
                "label",
                "category",
                "score",
                "verdict",
                "predicted",
                "correct",
                "top_rule",
            ]
        )
        for result in results:
            rules = [
                item["rule"]
                for assessment in result["subscriptions"]
                for item in assessment["evidence"]
                if item["weight"] > 0
            ]
            writer.writerow(
                [
                    result["scenario_id"],
                    result["label"],
                    result["category"],
                    result["score"],
                    result["verdict"],
                    result["predicted"],
                    int(result["predicted"] == result["label"]),
                    rules[0] if rules else "",
                ]
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T1546.003 WMI persistence detector")
    parser.add_argument(
        "command",
        nargs="?",
        default="scan",
        choices=["scan"],
        help="scan (default)",
    )
    parser.add_argument(
        "--scenario", type=Path, help="single scenario / collection folder"
    )
    parser.add_argument(
        "--dataset", type=Path, help="folder containing scenario sub-folders"
    )
    parser.add_argument(
        "--source",
        choices=["auto", "repository", "events"],
        default="auto",
        help="where subscriptions come from",
    )
    parser.add_argument(
        "--allowlist", type=Path, default=None, help="baseline allow-list JSON"
    )
    parser.add_argument(
        "--malicious-threshold", type=int, default=DEFAULT_THRESHOLDS["malicious"]
    )
    parser.add_argument(
        "--suspicious-threshold", type=int, default=DEFAULT_THRESHOLDS["suspicious"]
    )
    parser.add_argument("--json-out", type=Path, help="write full JSON report")
    parser.add_argument("--csv-out", type=Path, help="write per-scenario CSV")
    parser.add_argument(
        "--fail-on-malicious",
        action="store_true",
        help="exit code 2 when at least one malicious verdict is produced",
    )
    args = parser.parse_args(argv)

    if not args.scenario and not args.dataset:
        parser.error("provide --scenario or --dataset")

    thresholds = {
        "malicious": args.malicious_threshold,
        "suspicious": args.suspicious_threshold,
    }
    allowlist = load_allowlist(args.allowlist)

    directories: list[Path]
    if args.dataset:
        directories = _iter_scenarios(args.dataset)
    else:
        directories = [args.scenario]
    if not directories:
        print(f"no scenarios found in {args.dataset}", file=sys.stderr)
        return 1

    results: list[dict[str, Any]] = []
    for directory in directories:
        bundle = load_scenario(directory, source=args.source)
        result = analyze_bundle(bundle, allowlist=allowlist, thresholds=thresholds)
        result["directory"] = str(directory)
        results.append(result)
        _print_bundle(result)

    if args.dataset:
        correct = sum(1 for item in results if item["predicted"] == item["label"])
        print(
            f"summary: {correct}/{len(results)} scenarios classified correctly "
            f"(threshold malicious>={thresholds['malicious']})"
        )

    payload = {
        "thresholds": thresholds,
        "results": results,
        "summary": {
            "scenarios": len(results),
            "malicious": sum(1 for item in results if item["verdict"] == "malicious"),
            "suspicious": sum(1 for item in results if item["verdict"] == "suspicious"),
            "benign": sum(1 for item in results if item["verdict"] == "benign"),
        },
    }
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"json report -> {args.json_out}")
    if args.csv_out:
        _write_csv(args.csv_out, results)
        print(f"csv report  -> {args.csv_out}")

    if args.fail_on_malicious and any(
        item["verdict"] == "malicious" for item in results
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
