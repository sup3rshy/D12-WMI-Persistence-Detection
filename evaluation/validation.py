"""Validation beyond the headline confusion matrix.

The scenario dataset is small and the rule weights are hand-set, so a single
P/R/F1 table is not enough. This module adds four checks that a reviewer can
re-run:

* bootstrap confidence intervals for the operating points;
* leave-one-rule-out ablation (which rules actually carry the detection?);
* a deterministic perturbation suite (rename, relocate, change principal,
  change polling, move namespace, drop telemetry) that is *not* part of
  ``data/scenarios`` and therefore not used to tune the weights;
* external validation on the real Windows VM run and the read-only host
  snapshot shipped with the project.

Everything here is deterministic (fixed bootstrap seed) and writes no state;
``evaluation.evaluate`` persists the results under ``reports/``.
"""

from __future__ import annotations

import copy
import random
import re
from pathlib import Path
from typing import Any, Callable

from detector.parser import load_scenario, subscriptions_from_repository
from detector.rules import ALL_RULE_IDS
from detector.scoring import analyze_bundle, load_allowlist
from evaluation.metrics import metrics
from simulator.scenario_catalog import (
    SID_STUDENT,
    SID_SYSTEM,
    USER_STUDENT,
    USER_SYSTEM,
    build_scenarios,
    event_5861,
)

# --------------------------------------------------------------------------- #
# bootstrap confidence intervals
# --------------------------------------------------------------------------- #


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def bootstrap_ci(
    labels: list[int],
    predictions: list[int],
    n_boot: int = 2000,
    seed: int = 1234,
    alpha: float = 0.05,
) -> dict[str, dict[str, float | int]]:
    """Percentile bootstrap CI, resampling scenarios with replacement.

    A metric is only recorded for a resample where its denominator is
    non-zero (e.g. recall is skipped when a resample contains no malicious
    scenario). The number of usable resamples is reported as ``n``.
    """
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have the same length")
    rng = random.Random(seed)
    buckets: dict[str, list[float]] = {
        "precision": [],
        "recall": [],
        "f1": [],
        "fpr": [],
    }
    for _ in range(n_boot):
        indices = [rng.randrange(len(labels)) for _ in labels]
        sample_labels = [labels[i] for i in indices]
        sample_pred = [predictions[i] for i in indices]
        tp = fp = tn = fn = 0
        for label, pred in zip(sample_labels, sample_pred):
            if label == 1 and pred == 1:
                tp += 1
            elif label == 0 and pred == 1:
                fp += 1
            elif label == 0 and pred == 0:
                tn += 1
            else:
                fn += 1
        if tp + fp:
            buckets["precision"].append(tp / (tp + fp))
        if tp + fn:
            buckets["recall"].append(tp / (tp + fn))
        if tp + fp + fn:
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fn) if tp + fn else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if precision + recall
                else 0.0
            )
            buckets["f1"].append(f1)
        if fp + tn:
            buckets["fpr"].append(fp / (fp + tn))

    result: dict[str, dict[str, float | int]] = {}
    for name, values in buckets.items():
        result[name] = {
            "low": round(_percentile(values, alpha / 2), 4),
            "high": round(_percentile(values, 1 - alpha / 2), 4),
            "n": len(values),
        }
    return result


# --------------------------------------------------------------------------- #
# rule ablation
# --------------------------------------------------------------------------- #


def _predictions(
    bundles: list[dict[str, Any]],
    allowlist: list[dict[str, Any]],
    thresholds: dict[str, int],
    exclude_rules: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[int], list[int], list[int]]:
    results = [
        analyze_bundle(
            bundle,
            allowlist=allowlist,
            thresholds=thresholds,
            exclude_rules=exclude_rules,
        )
        for bundle in bundles
    ]
    labels = [int(item["label"]) for item in results]
    strict = [1 if item["verdict"] == "malicious" else 0 for item in results]
    triage = [
        1 if item["verdict"] in {"malicious", "suspicious"} else 0 for item in results
    ]
    return results, labels, strict, triage


def rule_ablation(
    bundles: list[dict[str, Any]],
    allowlist: list[dict[str, Any]],
    thresholds: dict[str, int],
) -> dict[str, Any]:
    _, labels, strict, triage = _predictions(bundles, allowlist, thresholds)
    base_strict = metrics(labels, strict)
    base_triage = metrics(labels, triage)

    rows: list[dict[str, Any]] = []
    for rule_id in ALL_RULE_IDS:
        _, _, ablated_strict, ablated_triage = _predictions(
            bundles, allowlist, thresholds, exclude_rules={rule_id}
        )
        strict_m = metrics(labels, ablated_strict)
        triage_m = metrics(labels, ablated_triage)
        rows.append(
            {
                "rule": rule_id,
                "strict_tp": strict_m["tp"],
                "strict_fn": strict_m["fn"],
                "strict_fp": strict_m["fp"],
                "strict_recall": strict_m["recall"],
                "strict_fpr": strict_m["fpr"],
                "triage_tp": triage_m["tp"],
                "triage_fn": triage_m["fn"],
                "triage_fp": triage_m["fp"],
                "triage_recall": triage_m["recall"],
                "triage_fpr": triage_m["fpr"],
                "strict_recall_drop": round(
                    base_strict["recall"] - strict_m["recall"], 4
                ),
                "triage_recall_drop": round(
                    base_triage["recall"] - triage_m["recall"], 4
                ),
            }
        )
    rows.sort(
        key=lambda row: (
            -row["strict_recall_drop"],
            -row["triage_recall_drop"],
            row["rule"],
        )
    )
    return {
        "baseline": {"strict": base_strict, "triage": base_triage},
        "rules": rows,
    }


# --------------------------------------------------------------------------- #
# perturbation suite
# --------------------------------------------------------------------------- #

_TRANSFORM_NAMES = (
    "rename_neutral",
    "path_relocate",
    "sid_switch",
    "polling_change",
    "namespace_move",
    "telemetry_gap",
)

_PATH_PAIRS = (
    (r"%PUBLIC%", r"%TEMP%"),
    (r"C:\Users\Public", r"C:\Windows\Temp"),
    (r"C:\ProgramData", r"C:\Windows\Temp"),
    (r"%APPDATA%", r"%TEMP%"),
)


def _rebuild_event(scenario: dict[str, Any]) -> None:
    repo = scenario["repository"]
    filters = repo.get("filters") or []
    consumers = repo.get("consumers") or []
    bindings = repo.get("bindings") or []
    if not filters or not consumers:
        return
    filt = filters[0]
    consumer = consumers[0]
    binding = bindings[0] if bindings else {}
    scenario["events"] = [
        event_5861(
            filt["name"],
            consumer["class"],
            consumer["name"],
            filt.get("event_namespace", "root\\cimv2"),
            filt.get("query", ""),
            consumer.get("properties", {}),
            consumer.get("creator_sid") or filt.get("creator_sid") or SID_SYSTEM,
            consumer.get("creator_user")
            or filt.get("creator_user")
            or USER_SYSTEM,
            binding_namespace=binding.get("filter_namespace")
            or filt.get("namespace")
            or "root\\subscription",
        )
    ]


def _rename_neutral(scenario: dict[str, Any]) -> dict[str, Any]:
    repo = scenario["repository"]
    filter_map: dict[str, str] = {}
    consumer_map: dict[str, str] = {}
    for index, item in enumerate(repo.get("filters") or []):
        filter_map[item["name"]] = f"Perturb{index}Filter"
        item["name"] = filter_map[item["name"]]
    for index, item in enumerate(repo.get("consumers") or []):
        consumer_map[item["name"]] = f"Perturb{index}Consumer"
        item["name"] = consumer_map[item["name"]]
    for binding in repo.get("bindings") or []:
        binding["filter_name"] = filter_map.get(
            binding.get("filter_name"), binding.get("filter_name")
        )
        binding["consumer_name"] = consumer_map.get(
            binding.get("consumer_name"), binding.get("consumer_name")
        )
    _rebuild_event(scenario)
    return scenario


def _path_relocate(scenario: dict[str, Any]) -> dict[str, Any] | None:
    changed = False
    for consumer in scenario["repository"].get("consumers") or []:
        props = consumer.get("properties") or {}
        for key, value in list(props.items()):
            text = str(value)
            for old, new in _PATH_PAIRS:
                text = text.replace(old, new)
            if text != str(value):
                props[key] = text
                changed = True
    if not changed:
        return None
    _rebuild_event(scenario)
    return scenario


def _sid_switch(scenario: dict[str, Any]) -> dict[str, Any]:
    repo = scenario["repository"]
    for item in (repo.get("filters") or []) + (repo.get("consumers") or []):
        sid = str(item.get("creator_sid") or "")
        if sid.upper() in {SID_SYSTEM, "S-1-5-19", "S-1-5-20"}:
            item["creator_sid"] = SID_STUDENT
            item["creator_user"] = USER_STUDENT
        else:
            item["creator_sid"] = SID_SYSTEM
            item["creator_user"] = USER_SYSTEM
    _rebuild_event(scenario)
    return scenario


def _polling_change(scenario: dict[str, Any]) -> dict[str, Any] | None:
    changed = False
    for filt in scenario["repository"].get("filters") or []:
        query = str(filt.get("query") or "")
        match = re.search(r"WITHIN\s+(\d+)", query, re.I)
        if not match:
            continue
        value = 300 if int(match.group(1)) <= 5 else 1
        filt["query"] = re.sub(
            r"WITHIN\s+\d+", f"WITHIN {value}", query, count=1, flags=re.I
        )
        changed = True
    if not changed:
        return None
    _rebuild_event(scenario)
    return scenario


def _namespace_move(scenario: dict[str, Any]) -> dict[str, Any]:
    repo = scenario["repository"]
    target = "root\\PerturbLab"
    for item in (repo.get("filters") or []) + (repo.get("consumers") or []):
        item["namespace"] = target
    for binding in repo.get("bindings") or []:
        binding["filter_namespace"] = target
        binding["consumer_namespace"] = target
    _rebuild_event(scenario)
    return scenario


def _telemetry_gap(scenario: dict[str, Any]) -> dict[str, Any]:
    scenario["events"] = []
    scenario["processes"] = []
    return scenario


_TRANSFORMS: dict[str, Callable[[dict[str, Any]], dict[str, Any] | None]] = {
    "rename_neutral": _rename_neutral,
    "path_relocate": _path_relocate,
    "sid_switch": _sid_switch,
    "polling_change": _polling_change,
    "namespace_move": _namespace_move,
    "telemetry_gap": _telemetry_gap,
}


def _bundle_from_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    repo = scenario["repository"]
    return {
        "scenario_id": scenario["scenario_id"],
        "label": int(scenario["label"]),
        "category": scenario["category"],
        "description": scenario["description"],
        "repository": repo,
        "events": scenario.get("events", []),
        "processes": scenario.get("processes", []),
        "subscriptions": subscriptions_from_repository(repo),
        "ground_truth": {
            "scenario_id": scenario["scenario_id"],
            "label": int(scenario["label"]),
            "category": scenario["category"],
        },
    }


def perturbation_suite(
    allowlist: list[dict[str, Any]],
    thresholds: dict[str, int],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for base in build_scenarios():
        for family in _TRANSFORM_NAMES:
            transform = _TRANSFORMS[family]
            mutated = transform(copy.deepcopy(base))
            if mutated is None:
                continue
            bundle = _bundle_from_scenario(mutated)
            result = analyze_bundle(bundle, allowlist=allowlist, thresholds=thresholds)
            verdict = result["verdict"]
            rows.append(
                {
                    "family": family,
                    "base_scenario": base["scenario_id"],
                    "label": int(base["label"]),
                    "score": result["score"],
                    "verdict": verdict,
                    "strict_predicted": 1 if verdict == "malicious" else 0,
                    "triage_predicted": 1
                    if verdict in {"malicious", "suspicious"}
                    else 0,
                }
            )

    summary: dict[str, dict[str, Any]] = {}
    for family in _TRANSFORM_NAMES:
        family_rows = [row for row in rows if row["family"] == family]
        malicious = [row for row in family_rows if row["label"] == 1]
        benign = [row for row in family_rows if row["label"] == 0]
        summary[family] = {
            "malicious": len(malicious),
            "strict_recall": round(
                sum(row["strict_predicted"] for row in malicious) / len(malicious), 4
            )
            if malicious
            else 0.0,
            "triage_recall": round(
                sum(row["triage_predicted"] for row in malicious) / len(malicious), 4
            )
            if malicious
            else 0.0,
            "benign": len(benign),
            "strict_fpr": round(
                sum(row["strict_predicted"] for row in benign) / len(benign), 4
            )
            if benign
            else 0.0,
            "triage_fpr": round(
                sum(row["triage_predicted"] for row in benign) / len(benign), 4
            )
            if benign
            else 0.0,
            "strict_failures": [
                row["base_scenario"]
                for row in malicious
                if row["strict_predicted"] == 0
            ],
            "triage_failures": [
                row["base_scenario"]
                for row in malicious
                if row["triage_predicted"] == 0
            ],
        }
    return {"rows": rows, "summary": summary}


# --------------------------------------------------------------------------- #
# external validation
# --------------------------------------------------------------------------- #


def external_validation(
    allowlist: list[dict[str, Any]],
    thresholds: dict[str, int],
) -> dict[str, Any]:
    samples: list[tuple[str, Path, int, str]] = [
        ("vm-live-v1", Path("reports/vm-live/out"), 1, "real VirtualBox run"),
        (
            "vm-live-reboot",
            Path("reports/vm-live/reboot"),
            1,
            "real reboot-persistence run",
        ),
        ("host-live-scm", Path("data/live"), 0, "read-only host snapshot"),
    ]
    poc_root = Path("reports/poc-to-detector")
    if poc_root.exists():
        for directory in sorted(path for path in poc_root.iterdir() if path.is_dir()):
            samples.append((f"poc-{directory.name}", directory, 1, "PoC dry-run render"))

    rows: list[dict[str, Any]] = []
    for name, directory, expected, provenance in samples:
        if not (directory / "repository.json").exists():
            continue
        bundle = load_scenario(directory)
        result = analyze_bundle(bundle, allowlist=allowlist, thresholds=thresholds)
        predicted = 1 if result["verdict"] == "malicious" else 0
        rows.append(
            {
                "name": name,
                "provenance": provenance,
                "expected": expected,
                "score": result["score"],
                "verdict": result["verdict"],
                "predicted": predicted,
                "correct": int(predicted == expected),
            }
        )
    labels = [row["expected"] for row in rows]
    preds = [row["predicted"] for row in rows]
    summary = metrics(labels, preds)
    return {"samples": rows, "summary": summary}


# --------------------------------------------------------------------------- #
# aggregate
# --------------------------------------------------------------------------- #


def build_validation_report(
    bundles: list[dict[str, Any]],
    allowlist: list[dict[str, Any]],
    thresholds: dict[str, int],
) -> dict[str, Any]:
    _, labels, strict, triage = _predictions(bundles, allowlist, thresholds)
    return {
        "bootstrap": {
            "strict": bootstrap_ci(labels, strict),
            "triage": bootstrap_ci(labels, triage),
            "resamples": 2000,
            "seed": 1234,
        },
        "ablation": rule_ablation(bundles, allowlist, thresholds),
        "perturbation": perturbation_suite(allowlist, thresholds),
        "external": external_validation(allowlist, thresholds),
    }
