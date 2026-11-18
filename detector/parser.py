"""Parsing and normalisation of WMI subscription evidence.

Supported inputs
----------------
* repository.json      - output of collector/Collect-WmiSubscriptions.ps1
* wmi_activity.jsonl   - output of collector/Collect-WmiActivityLog.ps1
* process_events.jsonl - Sysmon-style process creation events (optional)
* raw 5861 messages    - the WMI-Activity event contains the full object
                         definition, so the detector can work from logs alone.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Iterable

from .model import Subscription

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# generic helpers
# ---------------------------------------------------------------------------


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _prop(props: dict[str, Any], name: str) -> str:
    """Case-insensitive property lookup, returns '' when absent."""
    if not isinstance(props, dict):
        return ""
    lowered = name.lower()
    for key, value in props.items():
        if str(key).lower() == lowered and value is not None:
            return str(value)
    return ""


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # A truncated write must not take down an incident triage run.
                LOGGER.warning(
                    "skipping malformed JSONL line in %s: %s", path, line[:120]
                )
    return records


def _tail_name(path_value: str) -> str:
    """Extract the object name from a WMI object path.

    ``__EventFilter.Name="X"`` -> ``X``
    ``\\\\HOST\\root\\subscription:__EventFilter.Name="X"`` -> ``X``
    """
    if not path_value:
        return ""
    match = re.search(r'Name\s*=\s*"([^"]+)"', path_value, re.I)
    if match:
        return match.group(1)
    return path_value


# ---------------------------------------------------------------------------
# SID handling
# ---------------------------------------------------------------------------


def sid_from_bytes(values: Iterable[int]) -> str:
    """Convert a WMI CreatorSID byte array into SDDL string form."""
    vals = [int(value) for value in _as_list(values)]
    if len(vals) < 8:
        return ""
    revision = vals[0]
    count = vals[1]
    authority = int.from_bytes(bytes(vals[2:8]), "big")
    subs: list[int] = []
    offset = 8
    for _ in range(count):
        chunk = vals[offset : offset + 4]
        if len(chunk) < 4:
            break
        subs.append(int.from_bytes(bytes(chunk), "little"))
        offset += 4
    sid = f"S-{revision}-{authority}"
    if subs:
        sid += "-" + "-".join(str(item) for item in subs)
    return sid


# ---------------------------------------------------------------------------
# repository -> Subscription objects
# ---------------------------------------------------------------------------


def subscriptions_from_repository(repo: dict[str, Any]) -> list[Subscription]:
    filters = _as_list(repo.get("filters"))
    consumers = _as_list(repo.get("consumers"))
    bindings = _as_list(repo.get("bindings"))

    filter_index: dict[tuple[str, str], dict[str, Any]] = {}
    for item in filters:
        ns = str(item.get("namespace") or repo.get("namespace") or "root\\subscription")
        filter_index[(ns.lower(), str(item.get("name") or "").lower())] = item

    consumer_index: dict[tuple[str, str], dict[str, Any]] = {}
    for item in consumers:
        ns = str(item.get("namespace") or repo.get("namespace") or "root\\subscription")
        consumer_index[(ns.lower(), str(item.get("name") or "").lower())] = item

    results: list[Subscription] = []
    seen_filter_keys: set[tuple[str, str]] = set()
    consumers_per_filter: dict[tuple[str, str], int] = {}

    for binding in bindings:
        filter_ns = str(
            binding.get("filter_namespace")
            or binding.get("namespace")
            or repo.get("namespace")
            or "root\\subscription"
        )
        consumer_ns = str(
            binding.get("consumer_namespace")
            or binding.get("namespace")
            or repo.get("namespace")
            or "root\\subscription"
        )
        filter_name = _tail_name(
            str(binding.get("filter_name") or binding.get("filter", ""))
        )
        consumer_name = _tail_name(
            str(binding.get("consumer_name") or binding.get("consumer", ""))
        )
        fkey = (filter_ns.lower(), filter_name.lower())
        ckey = (consumer_ns.lower(), consumer_name.lower())
        consumers_per_filter[fkey] = consumers_per_filter.get(fkey, 0) + 1
        seen_filter_keys.add(fkey)

        filt = filter_index.get(fkey, {})
        cons = consumer_index.get(ckey, {})
        results.append(_build_subscription(filt, cons, filter_ns, consumer_ns, True, repo))

    # Orphan filters (persistence object created but binding deleted) are
    # still forensic artefacts and are reported as dangling.
    for key, filt in filter_index.items():
        if key in seen_filter_keys:
            continue
        results.append(_build_subscription(filt, {}, key[0], "", False, repo))

    # Orphan consumers are suspicious: a consumer without a filter has no
    # legitimate reason to be registered permanently.
    for key, cons in consumer_index.items():
        if any(
            str(item.consumer_name).lower() == key[1]
            and str(item.filter_namespace).lower() == key[0]
            for item in results
        ):
            continue
        results.append(_build_subscription({}, cons, "", key[0], False, repo))

    for sub in results:
        fkey = (sub.filter_namespace.lower(), sub.filter_name.lower())
        sub.has_multiple_consumers = consumers_per_filter.get(fkey, 0) > 1
    return results


def _build_subscription(
    filt: dict[str, Any],
    cons: dict[str, Any],
    filter_ns: str,
    consumer_ns: str,
    binding_present: bool,
    repo: dict[str, Any],
) -> Subscription:
    props = cons.get("properties") if isinstance(cons.get("properties"), dict) else {}
    # tolerate flat consumer objects as well
    if not props:
        props = {
            key: value
            for key, value in cons.items()
            if key
            not in {
                "name",
                "namespace",
                "class",
                "creator_sid",
                "creator_user",
                "properties",
            }
        }

    creator_sid = str(cons.get("creator_sid") or filt.get("creator_sid") or "")
    if isinstance(creator_sid, list):
        creator_sid = sid_from_bytes(creator_sid)

    return Subscription(
        filter_name=str(filt.get("name") or ""),
        filter_namespace=filter_ns or "root\\subscription",
        event_namespace=str(filt.get("event_namespace") or "root\\cimv2"),
        query=str(filt.get("query") or ""),
        query_language=str(filt.get("query_language") or "WQL"),
        consumer_name=str(cons.get("name") or ""),
        consumer_class=str(cons.get("class") or cons.get("__CLASS") or ""),
        consumer_properties={str(k): str(v) for k, v in props.items() if v is not None},
        creator_sid=creator_sid,
        creator_user=str(cons.get("creator_user") or filt.get("creator_user") or ""),
        binding_present=binding_present,
        source="repository",
        extra={"consumer_namespace": consumer_ns or "root\\subscription"},
    )


# ---------------------------------------------------------------------------
# WMI-Activity 5861 parsing
# ---------------------------------------------------------------------------

_RE_NAMESPACE = re.compile(r"Namespace\s*=\s*//[^/]*/(?P<ns>[^;\n]+)")
_RE_FILTER = re.compile(r"Eventfilter\s*=\s*(?P<name>.+?)\s*\(refer to", re.I)
_RE_CONSUMER = re.compile(r'Consumer\s*=\s*(?P<cls>\w+)\s*=\s*"(?P<name>[^"]*)"', re.I)
_RE_INSTANCE = re.compile(
    r"instance of (?P<cls>\w+)\s*\{(?P<body>.*?)\n\s*\};", re.S | re.I
)
_RE_PROPERTY = re.compile(
    r'^\s*(?P<key>\w+)\s*=\s*(?P<value>"(?:[^"\\]|\\.)*"|\{[^}]*\}|[^;]*);',
    re.M,
)


def _unescape(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
        value = value.replace('\\"', '"').replace("\\\\", "\\")
    return value


def _parse_instance(block: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for match in _RE_PROPERTY.finditer(block):
        props[match.group("key")] = _unescape(match.group("value"))
    return props


def parse_5861(message: str) -> list[Subscription]:
    """Parse a 5861 message into one subscription (or [] if unparseable).

    The event text embeds two CIM instances (filter and consumer), which is
    enough to reconstruct the persistence chain without querying the
    repository.
    """
    if not message:
        return []

    ns_match = _RE_NAMESPACE.search(message)
    binding_ns = ns_match.group("ns").strip() if ns_match else "root/subscription"
    binding_ns = binding_ns.replace("/", "\\")

    filter_match = _RE_FILTER.search(message)
    consumer_match = _RE_CONSUMER.search(message)
    event_filter_name = filter_match.group("name").strip() if filter_match else ""
    consumer_class = consumer_match.group("cls") if consumer_match else ""
    consumer_name = consumer_match.group("name") if consumer_match else ""

    blocks = list(_RE_INSTANCE.finditer(message))
    filter_props: dict[str, str] = {}
    consumer_props: dict[str, str] = {}

    for block in blocks:
        cls = block.group("cls")
        props = _parse_instance(block.group("body"))
        if "Query" in props or cls == "__EventFilter":
            filter_props = props
        elif cls == consumer_class or "CreatorSID" in props:
            consumer_props = props
        elif not consumer_props:
            consumer_props = props

    if not filter_props and not consumer_props:
        return []

    def _name(props: dict[str, str], fallback: str) -> str:
        return props.get("Name") or fallback

    creator_sid = consumer_props.get("CreatorSID", "") or filter_props.get("CreatorSID", "")
    if creator_sid.startswith("{"):
        numbers = re.findall(r"\d+", creator_sid)
        creator_sid = sid_from_bytes(numbers)

    return [
        Subscription(
            filter_name=_name(filter_props, event_filter_name),
            filter_namespace=binding_ns,
            event_namespace=filter_props.get("EventNamespace", "root\\cimv2"),
            query=filter_props.get("Query", ""),
            query_language=filter_props.get("QueryLanguage", "WQL"),
            consumer_name=_name(consumer_props, consumer_name),
            consumer_class=consumer_class or str(consumer_props.get("__CLASS", "")),
            consumer_properties=consumer_props,
            creator_sid=creator_sid,
            creator_user="",
            binding_present=True,
            source="eventlog-5861",
            extra={"consumer_namespace": binding_ns},
        )
    ]


def subscriptions_from_events(events: list[dict[str, Any]]) -> list[Subscription]:
    """Reconstruct subscriptions from 5861 records, one entry per chain.

    A subscription may be activated several times (service restart, log
    replay); the activation count is kept as evidence instead of emitting
    duplicate findings.
    """
    results: dict[str, Subscription] = {}
    for event in events:
        if int(event.get("EventId") or event.get("Id") or 0) != 5861:
            continue
        message = str(event.get("Message") or "")
        for sub in parse_5861(message):
            # 5861 "User" is the account that activated the consumer, not the
            # CreatorSID owner. Keep the two concepts separate so R09 does not
            # claim that the student SID belongs to SYSTEM.
            sub.extra["activation_user"] = str(
                event.get("User") or event.get("UserName") or ""
            )
            sub.extra["event_time"] = str(event.get("TimeCreated") or "")
            sub.extra["record_id"] = event.get("RecordId")
            existing = results.get(sub.key)
            if existing is None:
                sub.extra["activation_count"] = 1
                results[sub.key] = sub
            else:
                existing.extra["activation_count"] = int(
                    existing.extra.get("activation_count", 1)
                ) + 1
    return list(results.values())


# ---------------------------------------------------------------------------
# scenario loading
# ---------------------------------------------------------------------------


def load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.suffix.lower() == ".jsonl":
        return _read_jsonl(path)
    data = _read_json(path)
    return data if isinstance(data, list) else [data]


def load_scenario(directory: Path, source: str = "auto") -> dict[str, Any]:
    """Load one scenario folder into a normalised bundle.

    ``source`` is ``auto`` (repository first, event log fallback),
    ``repository`` or ``events`` (5861 parsing only).
    """
    directory = Path(directory)
    repo_path = directory / "repository.json"
    events_path = directory / "wmi_activity.jsonl"
    process_path = directory / "process_events.jsonl"
    truth_path = directory / "ground_truth.json"

    repo = _read_json(repo_path) if repo_path.exists() else {}
    events = load_events(events_path)
    processes = load_events(process_path)
    truth = _read_json(truth_path) if truth_path.exists() else {}

    if source == "events":
        subscriptions = subscriptions_from_events(events)
    elif source == "repository":
        subscriptions = subscriptions_from_repository(repo) if repo else []
    else:
        subscriptions = subscriptions_from_repository(repo) if repo else []
        if not subscriptions:
            subscriptions = subscriptions_from_events(events)

    return {
        "directory": str(directory),
        "scenario_id": truth.get("scenario_id") or directory.name,
        "label": int(truth.get("label", 0)),
        "category": truth.get("category", "unknown"),
        "description": truth.get("description", ""),
        "repository": repo,
        "events": events,
        "processes": processes,
        "subscriptions": subscriptions,
        "ground_truth": truth,
    }
