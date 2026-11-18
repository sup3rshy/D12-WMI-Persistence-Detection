"""Explainable detection rules for T1546.003.

Every rule returns zero or one :class:`Evidence`. Weights are additive and
were calibrated on the labelled scenario set (see docs/03-detection-design.md).
The detector intentionally stays rule based so that each alert can be
justified to an analyst; the score is not a probability.
"""

from __future__ import annotations

import re
from typing import Any

from .model import (
    HIGH_RISK_CONSUMERS,
    MEDIUM_RISK_CONSUMERS,
    SYSTEM_SIDS,
    Evidence,
    Subscription,
)

# --------------------------------------------------------------------------- #
# patterns
# --------------------------------------------------------------------------- #

RE_ENCODED = re.compile(
    r"(-enc\b|-encodedcommand|frombase64string|\[convert\]::frombase64|"
    r"\[char\[\]\]|\[char\]\[|base64string)",
    re.I,
)
RE_NETWORK = re.compile(
    r"(https?://|invoke-webrequest|downloadstring|net\.webclient|"
    r"start-bitstransfer|bitsadmin\s+/transfer|\bcurl\b|\bwget\b|"
    r"invoke-restmethod)",
    re.I,
)
RE_LOLBIN = re.compile(
    r"(\bpowershell(?:\.exe)?\b|\bpwsh(?:\.exe)?\b|\bcmd(?:\.exe)?\s*/c\b|"
    r"\bmshta(?:\.exe)?\b|\brundll32(?:\.exe)?\b|\bregsvr32(?:\.exe)?\b|"
    r"\bwscript\.exe\b|\bcscript\.exe\b|\bcertutil(?:\.exe)?\b|"
    r"\bbitsadmin(?:\.exe)?\b)",
    re.I,
)
RE_USER_WRITABLE = re.compile(
    r"(%temp%|%appdata%|%localappdata%|%public%|%userprofile%|"
    r"\\users\\public\\|\\appdata\\|\\downloads\\|\\programdata\\|"
    r"\\windows\\temp\\|/tmp/)",
    re.I,
)
RE_SCRIPT_ABUSE = re.compile(
    r"(wscript\.shell|scripting\.filesystemobject|shell\.application|"
    r"adodb\.stream|new-object\s+-comobject|invoke-expression|\biex\b|"
    r"msxml2\.xmlhttp)",
    re.I,
)
RE_INSTANCE_EVENT = re.compile(
    r"(__instancecreationevent|__instancemodificationevent|"
    r"__instancedeletionevent)",
    re.I,
)
RE_SENSITIVE_TARGET = re.compile(
    r"(win32_process|win32_service|win32_logonsession|win32_computersystem|"
    r"win32_startupcommand|registry|msft_scmeventlogevent)",
    re.I,
)
RE_WITHIN = re.compile(r"within\s+(\d+)", re.I)
RE_MASQUERADE = re.compile(
    r"(scm event log|windows update|microsoft|defender|windows security|"
    r"system center|windows telemetry|service control manager)",
    re.I,
)

ALLOWED_EVENT_NAMESPACES = {
    "root\\cimv2",
    "root\\default",
    "root\\subscription",
    "root\\wmi",
}


def _norm(value: str) -> str:
    return value.replace("/", "\\").strip().lower()


def _is_system(sid: str) -> bool:
    return sid.upper() in SYSTEM_SIDS


# --------------------------------------------------------------------------- #
# independent rules
# --------------------------------------------------------------------------- #


def rule_consumer_class(sub: Subscription) -> list[Evidence]:
    weight = HIGH_RISK_CONSUMERS.get(sub.consumer_class)
    if weight:
        return [
            Evidence(
                "R01",
                "High-risk permanent consumer class",
                weight,
                f"{sub.consumer_class} executes an action automatically when the "
                "filter fires; it is the preferred T1546.003 consumer type.",
            )
        ]
    weight = MEDIUM_RISK_CONSUMERS.get(sub.consumer_class)
    if weight:
        return [
            Evidence(
                "R01",
                "Permanent consumer registered",
                weight,
                f"{sub.consumer_class} is a permanent consumer and needs an "
                "explicit business justification.",
            )
        ]
    return []


def rule_encoded_payload(sub: Subscription) -> list[Evidence]:
    text = sub.action_text
    if RE_ENCODED.search(text):
        return [
            Evidence(
                "R02",
                "Encoded or obfuscated action",
                25,
                "Consumer action contains an encoding/obfuscation primitive "
                "(-EncodedCommand, FromBase64String, [char[]] ...).",
            )
        ]
    return []


def rule_network_indicator(sub: Subscription) -> list[Evidence]:
    text = sub.action_text
    match = RE_NETWORK.search(text)
    if match:
        return [
            Evidence(
                "R03",
                "Network retrieval in consumer action",
                30,
                f"Action references remote content ({match.group(0)}); "
                "a permanent subscription must not be a download cradle.",
            )
        ]
    return []


def rule_lolbin(sub: Subscription) -> list[Evidence]:
    text = sub.action_text
    match = RE_LOLBIN.search(text)
    if match:
        return [
            Evidence(
                "R04",
                "Command interpreter or LOLBin launch",
                15,
                f"Action starts {match.group(0).strip()}, which is typical for "
                "scripted execution but uncommon for monitoring consumers.",
            )
        ]
    return []


def rule_writable_path(sub: Subscription) -> list[Evidence]:
    text = sub.action_text
    match = RE_USER_WRITABLE.search(text)
    if match:
        return [
            Evidence(
                "R05",
                "User-writable target path",
                10,
                f"Action references {match.group(0)}, a location writable by "
                "non-privileged users (staging/marker location).",
            )
        ]
    return []


def rule_script_abuse(sub: Subscription) -> list[Evidence]:
    text = sub.action_text
    match = RE_SCRIPT_ABUSE.search(text)
    if match:
        return [
            Evidence(
                "R06",
                "Scripting host abuse in inline script",
                15,
                f"Inline script uses {match.group(0)} to create processes or "
                "write files, the usual ActiveScriptEventConsumer payload.",
            )
        ]
    return []


def rule_wql_target(sub: Subscription) -> list[Evidence]:
    query = sub.query
    if RE_INSTANCE_EVENT.search(query) and RE_SENSITIVE_TARGET.search(query):
        return [
            Evidence(
                "R07",
                "WQL watches a security-sensitive class",
                15,
                "Filter subscribes to instance create/modify/delete events on a "
                "process, service, logon, registry or SCM class.",
            )
        ]
    return []


def rule_polling_interval(sub: Subscription) -> list[Evidence]:
    match = RE_WITHIN.search(sub.query)
    if not match:
        return []
    seconds = int(match.group(1))
    if seconds <= 5:
        weight, detail = 10, f"WITHIN {seconds}s causes very high-frequency polling."
    elif seconds <= 60:
        weight, detail = 6, f"WITHIN {seconds}s is a short polling interval."
    else:
        return []
    return [Evidence("R08", "High-frequency WQL polling", weight, detail)]


def rule_principal(sub: Subscription) -> list[Evidence]:
    sid = sub.creator_sid.strip()
    user = sub.creator_user.strip()
    if sid and not _is_system(sid):
        return [
            Evidence(
                "R09",
                "Subscription created by a non-SYSTEM principal",
                10,
                f"CreatorSID {sid} ({user or 'unknown user'}) is not LOCAL SYSTEM; "
                "WMI persistence is normally installed by an interactive user "
                "or attacker context.",
            )
        ]
    return []


def rule_masquerade(sub: Subscription) -> list[Evidence]:
    text = f"{sub.filter_name} {sub.consumer_name}"
    match = RE_MASQUERADE.search(text)
    if match:
        return [
            Evidence(
                "R10",
                "Name masquerades as a trusted component",
                15,
                f"Subscription name contains '{match.group(0)}', a common "
                "masquerading pattern for T1546.003.",
            )
        ]
    return []


def rule_namespace(sub: Subscription) -> list[Evidence]:
    findings: list[str] = []
    weight = 0
    if sub.filter_namespace and _norm(sub.filter_namespace) != "root\\subscription":
        findings.append(f"filter/consumer stored in {sub.filter_namespace}")
        weight += 6
    if sub.event_namespace and _norm(sub.event_namespace) not in ALLOWED_EVENT_NAMESPACES:
        findings.append(f"events consumed from {sub.event_namespace}")
        weight += 6
    if not findings:
        return []
    return [
        Evidence(
            "R11",
            "Non-default WMI namespace",
            weight,
            "; ".join(findings) + ". Custom namespaces hide subscriptions from "
            "the usual root\\subscription triage.",
        )
    ]


def rule_binding_integrity(sub: Subscription) -> list[Evidence]:
    if not sub.binding_present:
        return [
            Evidence(
                "R12",
                "Dangling filter/consumer without binding",
                10,
                "A permanent object exists without a __FilterToConsumerBinding. "
                "It may be a leftover or an attempt to hide the chain.",
            )
        ]
    if sub.has_multiple_consumers:
        return [
            Evidence(
                "R12",
                "Filter bound to multiple consumers",
                5,
                "Several consumers share one filter; legitimate deployments "
                "usually have a 1:1 binding.",
            )
        ]
    return []


def rule_activation_context(
    sub: Subscription, events: list[dict[str, Any]]
) -> list[Evidence]:
    activations = [
        event
        for event in events
        if int(event.get("EventId") or event.get("Id") or 0) == 5861
        and sub.filter_name
        and sub.filter_name.lower() in str(event.get("Message") or "").lower()
    ]
    if activations:
        for event in activations:
            user = str(event.get("User") or event.get("UserName") or "").strip()
            if user and "system" not in user.lower():
                return [
                    Evidence(
                        "R13",
                        "Activation logged under a user account",
                        10,
                        f"Event 5861 for '{sub.filter_name}' records user "
                        f"'{user}' rather than SYSTEM.",
                    )
                ]
        return []
    if sub.source == "repository" and sub.binding_present:
        return [
            Evidence(
                "R13",
                "No 5861 activation record for repository object",
                4,
                "Subscription is present in the WMI repository but no "
                "corresponding WMI-Activity 5861 event was collected; verify "
                "logging coverage or log tampering.",
            )
        ]
    return []


def rule_wmiprvse_children(
    sub: Subscription, processes: list[dict[str, Any]]
) -> list[Evidence]:
    if sub.consumer_class not in HIGH_RISK_CONSUMERS:
        return []
    suspicious: list[str] = []
    for proc in processes:
        parent = str(proc.get("ParentImage") or "").lower()
        if "wmiprvse.exe" not in parent:
            continue
        command = str(proc.get("CommandLine") or "")
        image = str(proc.get("Image") or "")
        if (
            RE_ENCODED.search(command)
            or RE_NETWORK.search(command)
            or RE_USER_WRITABLE.search(command)
            or RE_USER_WRITABLE.search(image)
        ):
            suspicious.append(command or image)
    if suspicious:
        return [
            Evidence(
                "R14",
                "WmiPrvSE spawned a suspicious child process",
                20,
                "Consumer execution produced: "
                + " | ".join(suspicious[:3]),
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #


def evaluate_rules(
    sub: Subscription,
    events: list[dict[str, Any]] | None = None,
    processes: list[dict[str, Any]] | None = None,
) -> list[Evidence]:
    events = events or []
    processes = processes or []
    collectors = (
        rule_consumer_class,
        rule_encoded_payload,
        rule_network_indicator,
        rule_lolbin,
        rule_writable_path,
        rule_script_abuse,
        rule_wql_target,
        rule_polling_interval,
        rule_principal,
        rule_masquerade,
        rule_namespace,
        rule_binding_integrity,
    )
    evidence: list[Evidence] = []
    for collector in collectors:
        evidence.extend(collector(sub))
    evidence.extend(rule_activation_context(sub, events))
    evidence.extend(rule_wmiprvse_children(sub, processes))
    return evidence
