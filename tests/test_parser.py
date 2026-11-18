"""Tests for parsing repository snapshots and 5861 event messages."""

from __future__ import annotations

import json
from pathlib import Path

from detector.parser import (
    load_scenario,
    parse_5861,
    sid_from_bytes,
    subscriptions_from_repository,
)
from simulator.scenario_catalog import (
    SID_STUDENT,
    SID_SYSTEM,
    build_scenarios,
    event_5861,
    sid_to_bytes,
)


def test_sid_roundtrip_system() -> None:
    assert sid_from_bytes(sid_to_bytes(SID_SYSTEM)) == SID_SYSTEM


def test_sid_roundtrip_user() -> None:
    assert sid_from_bytes(sid_to_bytes(SID_STUDENT)) == SID_STUDENT


def test_parse_5861_full_definition() -> None:
    scenario = next(s for s in build_scenarios() if s["scenario_id"] == "M2_activescript_masquerade")
    message = scenario["events"][0]["Message"]
    subscriptions = parse_5861(message)
    assert len(subscriptions) == 1
    sub = subscriptions[0]
    assert sub.filter_name == "SCM Event Log Filter"
    assert sub.consumer_class == "ActiveScriptEventConsumer"
    assert sub.consumer_name == "SCM Event Log Consumer"
    assert "__InstanceCreationEvent" in sub.query
    assert "NT230-D12-MARKER" in sub.consumer_properties["ScriptText"]
    assert sub.creator_sid == SID_STUDENT


def test_parse_5861_multiline_script_preserved() -> None:
    scenario = next(s for s in build_scenarios() if s["scenario_id"] == "M5_network_activescript")
    sub = parse_5861(scenario["events"][0]["Message"])[0]
    script = sub.consumer_properties["ScriptText"]
    assert script.count("\n") >= 3
    assert "MSXML2.XMLHTTP" in script


def test_parse_5861_garbage_returns_empty() -> None:
    assert parse_5861("") == []
    assert parse_5861("not an event message") == []


def test_repository_join_and_dangling_filter() -> None:
    repo = {
        "namespace": "root\\subscription",
        "filters": [
            {"name": "F1", "query": "SELECT * FROM __TimerEvent", "event_namespace": "root\\cimv2"}
        ],
        "consumers": [],
        "bindings": [],
    }
    subs = subscriptions_from_repository(repo)
    assert len(subs) == 1
    assert subs[0].filter_name == "F1"
    assert subs[0].binding_present is False


def test_binding_path_form_supported() -> None:
    repo = {
        "filters": [{"name": "F1", "query": "q", "namespace": "root\\subscription"}],
        "consumers": [
            {"name": "C1", "class": "CommandLineEventConsumer", "namespace": "root\\subscription"}
        ],
        "bindings": [
            {
                "filter_name": '__EventFilter (Name = "F1")',
                "consumer_name": 'CommandLineEventConsumer (Name = "C1")',
                "filter_namespace": "root\\subscription",
                "consumer_namespace": "root\\subscription",
            }
        ],
    }
    subs = subscriptions_from_repository(repo)
    assert len(subs) == 1
    assert subs[0].filter_name == "F1"
    assert subs[0].consumer_name == "C1"


def test_load_live_snapshot_if_available() -> None:
    live = Path("data/live")
    if not (live / "repository.json").exists():
        return
    bundle = load_scenario(live)
    assert bundle["subscriptions"], "live snapshot should contain at least one subscription"
    names = {sub.consumer_name for sub in bundle["subscriptions"]}
    assert "SCM Event Log Consumer" in names
