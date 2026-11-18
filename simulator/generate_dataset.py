"""Generate the labelled T1546.003 scenario dataset.

The generated files mirror exactly what collector/Collect-WmiSubscriptions.ps1
and collector/Collect-WmiActivityLog.ps1 write on a real Windows host, so the
same detector path is used for simulated and live telemetry.

Usage:
    python3 -m simulator.generate_dataset --out data/scenarios
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path

from .scenario_catalog import build_scenarios


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def generate(out: Path) -> list[dict]:
    scenarios = build_scenarios()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    rows: list[dict] = []
    for scenario in scenarios:
        directory = out / scenario["scenario_id"]
        directory.mkdir()
        _write_json(directory / "repository.json", scenario["repository"])
        _write_jsonl(directory / "wmi_activity.jsonl", scenario["events"])
        _write_jsonl(directory / "process_events.jsonl", scenario["processes"])
        truth = {
            "scenario_id": scenario["scenario_id"],
            "label": scenario["label"],
            "category": scenario["category"],
            "variant": scenario["variant"],
            "description": scenario["description"],
            "tags": scenario["tags"],
            "safety": "Inert marker strings only; no payload was executed.",
            "host": scenario["repository"]["host"],
        }
        _write_json(directory / "ground_truth.json", truth)
        rows.append(truth)

    _write_json(
        out.parent / "manifest.json",
        {
            "schema_version": "1.0",
            "generated_by": "simulator.generate_dataset",
            "scenarios": len(rows),
            "benign": sum(1 for row in rows if row["label"] == 0),
            "malicious": sum(1 for row in rows if row["label"] == 1),
            "variants": sorted({row["variant"] for row in rows if row["label"] == 1}),
            "items": rows,
        },
    )

    csv_path = out.parent / "ground_truth.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["scenario_id", "label", "category", "variant", "description"])
        for row in rows:
            writer.writerow(
                [row["scenario_id"], row["label"], row["category"], row["variant"], row["description"]]
            )

    print(f"generated {len(rows)} scenarios in {out}")
    print(f"benign={sum(1 for r in rows if r['label'] == 0)} malicious={sum(1 for r in rows if r['label'] == 1)}")
    for row in rows:
        print(f"  {row['scenario_id']:<38} label={row['label']}  variant={row['variant']}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("data/scenarios"))
    args = parser.parse_args()
    generate(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
