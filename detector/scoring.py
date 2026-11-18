"""Score aggregation, allow-listing and batch analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import Assessment, Evidence, Subscription
from .rules import evaluate_rules

DEFAULT_THRESHOLDS = {"suspicious": 40, "malicious": 60}
DEFAULT_ALLOWLIST = Path(__file__).with_name("baseline_allowlist.json")


def load_allowlist(path: Path | None = None) -> list[dict[str, Any]]:
    path = Path(path) if path else DEFAULT_ALLOWLIST
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    return list(data.get("entries", []))


def _allowlist_match(sub: Subscription, entries: list[dict[str, Any]]) -> str:
    fields = {
        "filter_name": sub.filter_name,
        "consumer_name": sub.consumer_name,
        "consumer_class": sub.consumer_class,
        "query": sub.query,
        "event_namespace": sub.event_namespace,
    }
    for entry in entries:
        matched = True
        for field, actual in fields.items():
            expected = entry.get(field)
            if expected is None:
                continue
            if str(expected).strip().lower() != str(actual).strip().lower():
                matched = False
                break
        expected_sid = entry.get("creator_sid")
        if matched and expected_sid:
            # A missing CreatorSID must not silently satisfy the allow-list.
            matched = bool(sub.creator_sid) and (
                sub.creator_sid.upper() == str(expected_sid).upper()
            )
        if matched:
            return str(entry.get("id") or "allowlist")
    return ""


def assess_subscription(
    sub: Subscription,
    events: list[dict[str, Any]] | None = None,
    processes: list[dict[str, Any]] | None = None,
    allowlist: list[dict[str, Any]] | None = None,
    thresholds: dict[str, int] | None = None,
) -> Assessment:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    evidence = evaluate_rules(sub, events, processes)

    allow_id = _allowlist_match(sub, allowlist or [])
    strong = [item for item in evidence if item.weight >= 20]
    if allow_id and not strong:
        return Assessment(
            subscription=sub,
            score=0,
            verdict="benign",
            evidence=[
                Evidence(
                    "R00",
                    "Matched signed baseline allow-list",
                    0,
                    f"Object matches known-good entry '{allow_id}'. Exact query, "
                    "class and namespace were required for the match.",
                )
            ],
            allowlisted=True,
            matched_allowlist=allow_id,
        )

    score = min(100, sum(item.weight for item in evidence))
    if score >= thresholds["malicious"]:
        verdict = "malicious"
    elif score >= thresholds["suspicious"]:
        verdict = "suspicious"
    else:
        verdict = "benign"

    evidence.sort(key=lambda item: (-item.weight, item.rule_id))
    return Assessment(subscription=sub, score=score, verdict=verdict, evidence=evidence)


def analyze_bundle(
    bundle: dict[str, Any],
    allowlist: list[dict[str, Any]] | None = None,
    thresholds: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Analyse one scenario bundle produced by parser.load_scenario()."""
    assessments = [
        assess_subscription(
            sub,
            events=bundle.get("events"),
            processes=bundle.get("processes"),
            allowlist=allowlist,
            thresholds=thresholds,
        )
        for sub in bundle.get("subscriptions", [])
    ]
    top = max((item.score for item in assessments), default=0)
    verdict = "benign"
    if any(item.verdict == "malicious" for item in assessments):
        verdict = "malicious"
    elif any(item.verdict == "suspicious" for item in assessments):
        verdict = "suspicious"

    return {
        "scenario_id": bundle.get("scenario_id"),
        "label": bundle.get("label"),
        "category": bundle.get("category"),
        "description": bundle.get("description"),
        "score": top,
        "verdict": verdict,
        "predicted": 1 if verdict == "malicious" else 0,
        "subscriptions": [item.as_dict() for item in assessments],
    }
