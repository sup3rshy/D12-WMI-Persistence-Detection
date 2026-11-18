"""Bridge PoC dry-run evidence into detector input.

This closes the loop without executing the PoC: it reads the variant
configuration emitted by ``poc/Invoke-WmiSubscription.ps1 -DryRun`` and renders
the repository snapshot plus 5861 event that the same objects would produce.
The detector is then run on that data.

Usage:
    python3 -m poc.export_variant_repository \
        --input reports/poc-dryrun --out reports/poc-to-detector
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from simulator.scenario_catalog import (
    HOST,
    SID_STUDENT,
    USER_STUDENT,
    event_5861,
)


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def variant_to_scenario(variant: dict) -> dict:
    config = variant["config"]
    namespace = config["Namespace"]
    filter_name = config["FilterName"]
    consumer_name = config["ConsumerName"]
    consumer_class = config["ConsumerClass"]
    props = {str(k): str(v) for k, v in config.get("ConsumerProperties", {}).items()}

    repository = {
        "schema_version": "1.0",
        "collected_at": "2026-11-17T10:00:00Z",
        "collector": "poc.export_variant_repository",
        "host": HOST,
        "scope": sorted({namespace}),
        "filters": [
            {
                "name": filter_name,
                "namespace": namespace,
                "event_namespace": config["EventNamespace"],
                "query": config["Query"],
                "query_language": "WQL",
                "creator_sid": SID_STUDENT,
                "creator_user": USER_STUDENT,
            }
        ],
        "consumers": [
            {
                "name": consumer_name,
                "namespace": namespace,
                "class": consumer_class,
                "properties": props,
                "creator_sid": SID_STUDENT,
                "creator_user": USER_STUDENT,
            }
        ],
        "bindings": [
            {
                "filter_name": filter_name,
                "filter_namespace": namespace,
                "consumer_name": consumer_name,
                "consumer_namespace": namespace,
                "creator_sid": SID_STUDENT,
            }
        ],
    }

    event = event_5861(
        filter_name=filter_name,
        consumer_class=consumer_class,
        consumer_name=consumer_name,
        event_namespace=config["EventNamespace"],
        query=config["Query"],
        consumer_props=props,
        creator_sid=SID_STUDENT,
        user=USER_STUDENT,
        binding_namespace=namespace,
    )

    return {
        "repository": repository,
        "event": event,
        "truth": {
            "scenario_id": f"POC_{variant['variant']}",
            "label": 1,
            "category": "malicious",
            "variant": variant["variant"],
            "description": (
                f"Rendered from the dry-run configuration of PoC variant "
                f"{variant['variant']} ({consumer_class})."
            ),
            "tags": ["poc-bridge"],
            "safety": "Configuration only; no WMI object was created and no payload ran.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("reports/poc-dryrun"))
    parser.add_argument("--out", type=Path, default=Path("reports/poc-to-detector"))
    args = parser.parse_args()

    files = sorted(args.input.glob("V*.json"))
    if not files:
        raise SystemExit(f"no dry-run evidence in {args.input}")

    if args.out.exists():
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True)

    for path in files:
        variant = json.loads(path.read_text(encoding="utf-8"))
        scenario = variant_to_scenario(variant)
        directory = args.out / scenario["truth"]["scenario_id"]
        directory.mkdir()
        _write_json(directory / "repository.json", scenario["repository"])
        with (directory / "wmi_activity.jsonl").open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(scenario["event"], ensure_ascii=False) + "\n")
        (directory / "process_events.jsonl").write_text("", encoding="utf-8")
        _write_json(directory / "ground_truth.json", scenario["truth"])
        print(f"rendered {scenario['truth']['scenario_id']} -> {directory}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
