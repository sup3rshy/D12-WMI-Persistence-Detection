"""CLI smoke tests."""

from __future__ import annotations

import json
from pathlib import Path

from detector.cli import main
from simulator.generate_dataset import generate


def test_cli_dataset_report(tmp_path: Path) -> None:
    dataset = tmp_path / "scenarios"
    generate(dataset)
    json_out = tmp_path / "alerts.json"
    csv_out = tmp_path / "per_scenario.csv"

    code = main(
        [
            "scan",
            "--dataset",
            str(dataset),
            "--json-out",
            str(json_out),
            "--csv-out",
            str(csv_out),
        ]
    )
    assert code == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["summary"]["scenarios"] == 15
    assert payload["summary"]["malicious"] == 8
    assert payload["summary"]["suspicious"] == 1
    assert payload["summary"]["benign"] == 6
    assert csv_out.exists()


def test_cli_fail_on_malicious(tmp_path: Path) -> None:
    dataset = tmp_path / "scenarios"
    generate(dataset)
    code = main(["scan", "--dataset", str(dataset), "--fail-on-malicious"])
    assert code == 2


def test_cli_single_scenario_events_source(tmp_path: Path) -> None:
    dataset = tmp_path / "scenarios"
    generate(dataset)
    out = tmp_path / "m2.json"
    code = main(
        [
            "scan",
            "--scenario",
            str(dataset / "M2_activescript_masquerade"),
            "--source",
            "events",
            "--json-out",
            str(out),
        ]
    )
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["results"][0]["verdict"] == "malicious"
