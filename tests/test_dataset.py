"""Dataset quality and safety invariants."""

from __future__ import annotations

import json
import re
from pathlib import Path

from simulator.scenario_catalog import build_scenarios


def _catalog() -> list[dict]:
    return build_scenarios()


def test_ids_are_unique() -> None:
    ids = [scenario["scenario_id"] for scenario in _catalog()]
    assert len(ids) == len(set(ids))


def test_every_malicious_scenario_has_activation_evidence() -> None:
    for scenario in _catalog():
        if scenario["label"] != 1:
            continue
        assert scenario["events"], scenario["scenario_id"]
        assert any(event["EventId"] == 5861 for event in scenario["events"])
        assert scenario["repository"]["bindings"], scenario["scenario_id"]


def test_variant_coverage() -> None:
    scenarios = [item for item in _catalog() if item["label"] == 1]
    classes = {item["repository"]["consumers"][0]["class"] for item in scenarios}
    namespaces = {
        item["repository"]["filters"][0]["namespace"] for item in scenarios
    }
    queries = " ".join(item["repository"]["filters"][0]["query"] for item in scenarios)
    assert "CommandLineEventConsumer" in classes
    assert "ActiveScriptEventConsumer" in classes
    assert any(ns != "root\\subscription" for ns in namespaces)
    assert "__TimerEvent" in queries
    assert "__InstanceCreationEvent" in queries


def test_payloads_are_inert_text_only() -> None:
    forbidden = re.compile(
        r"(mimikatz|meterpreter|cobaltstrike|\\\\?pipe\\\\|sekurlsa|lsass|"
        r"vssadmin\s+delete|bcdedit\s+/set|net\s+user\s+\S+\s+\S+\s+/add)",
        re.I,
    )
    for scenario in _catalog():
        blob = json.dumps(scenario)
        assert not forbidden.search(blob), scenario["scenario_id"]


def test_network_targets_are_test_net_only() -> None:
    allowed_hosts = {"198.51.100.23"}
    for scenario in _catalog():
        blob = json.dumps(scenario)
        for host in re.findall(r"https?://([^/\"\s]+)", blob):
            assert host in allowed_hosts, (scenario["scenario_id"], host)


def test_generated_dataset_matches_catalog(tmp_path: Path) -> None:
    from simulator.generate_dataset import generate

    generate(tmp_path / "scenarios")
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["scenarios"] == len(_catalog())
    assert manifest["benign"] >= 3
    assert manifest["malicious"] >= 3
    assert len(manifest["variants"]) >= 3
