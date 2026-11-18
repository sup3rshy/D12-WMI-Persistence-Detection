"""PoC configuration -> detector integration test."""

from __future__ import annotations

from detector.parser import subscriptions_from_repository
from detector.scoring import analyze_bundle, load_allowlist
from poc.export_variant_repository import variant_to_scenario


def _variant(name: str, filter_name: str, query: str, command: str) -> dict:
    return {
        "variant": name,
        "config": {
            "Namespace": "root\\subscription",
            "FilterName": filter_name,
            "ConsumerName": f"{filter_name}_Consumer",
            "ConsumerClass": "CommandLineEventConsumer",
            "ConsumerProperties": {"CommandLineTemplate": command},
            "EventNamespace": "root\\cimv2",
            "Query": query,
            "TimerId": None,
            "TimerIntervalMs": 0,
        },
    }


def test_poc_config_is_detected_as_malicious() -> None:
    variant = _variant(
        "V1",
        "NT230_D12_V1_Filter",
        "SELECT * FROM __TimerEvent WHERE TimerID = 'T' AND NumEvents = 1",
        'cmd.exe /c echo NT230-D12-MARKER > "%PUBLIC%\\marker.txt"',
    )
    scenario = variant_to_scenario(variant)
    subscriptions = subscriptions_from_repository(scenario["repository"])
    bundle = {
        "scenario_id": "POC_TEST",
        "label": 1,
        "category": "malicious",
        "description": "test",
        "subscriptions": subscriptions,
        "events": [scenario["event"]],
        "processes": [],
    }
    result = analyze_bundle(bundle, allowlist=load_allowlist())
    assert result["verdict"] == "malicious"
    assert result["score"] >= 60


def test_poc_masquerade_adds_evidence() -> None:
    variant = _variant(
        "V2",
        "NT230_D12_V2_Windows Update Monitor",
        "SELECT * FROM __InstanceCreationEvent WITHIN 3 "
        "WHERE TargetInstance ISA 'Win32_Process'",
        'cmd.exe /c echo NT230-D12-MARKER > "%PUBLIC%\\marker.txt"',
    )
    scenario = variant_to_scenario(variant)
    bundle = {
        "scenario_id": "POC_TEST_V2",
        "label": 1,
        "category": "malicious",
        "description": "test",
        "subscriptions": subscriptions_from_repository(scenario["repository"]),
        "events": [scenario["event"]],
        "processes": [],
    }
    result = analyze_bundle(bundle, allowlist=load_allowlist())
    rules = {
        evidence["rule"]
        for sub in result["subscriptions"]
        for evidence in sub["evidence"]
    }
    assert result["verdict"] == "malicious"
    assert "R10" in rules
    assert "R07" in rules
