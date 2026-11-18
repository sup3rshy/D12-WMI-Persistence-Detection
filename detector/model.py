"""Data model shared by the collector output and the detector."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Well known security principals
SYSTEM_SIDS = {
    "S-1-5-18",  # LOCAL SYSTEM
    "S-1-5-19",  # LOCAL SERVICE
    "S-1-5-20",  # NETWORK SERVICE
}

HIGH_RISK_CONSUMERS = {
    "CommandLineEventConsumer": 25,
    "ActiveScriptEventConsumer": 25,
}

MEDIUM_RISK_CONSUMERS = {
    "LogFileEventConsumer": 8,
    "SMTPEventConsumer": 10,
    "NTEventLogEventConsumer": 5,
}


@dataclass
class Evidence:
    """One explainable reason contributing to a risk score."""

    rule_id: str
    title: str
    weight: int
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule_id,
            "title": self.title,
            "weight": self.weight,
            "detail": self.detail,
        }


@dataclass
class Subscription:
    """A joined filter -> binding -> consumer chain."""

    filter_name: str
    filter_namespace: str
    event_namespace: str
    query: str
    query_language: str
    consumer_name: str
    consumer_class: str
    consumer_properties: dict[str, str] = field(default_factory=dict)
    creator_sid: str = ""
    creator_user: str = ""
    binding_present: bool = True
    has_multiple_consumers: bool = False
    source: str = "repository"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.filter_namespace}::{self.filter_name}->{self.consumer_name}"

    @property
    def action_text(self) -> str:
        """All consumer-controlled strings, concatenated for content rules."""
        interesting = (
            "CommandLineTemplate",
            "ExecutablePath",
            "ScriptText",
            "ScriptFileName",
            "ScriptingEngine",
            "LogFilePath",
            "SourceName",
            "Subject",
            "Message",
            "Name",
        )
        parts: list[str] = []
        for name in interesting:
            value = self.consumer_properties.get(name)
            if value:
                parts.append(str(value))
        return "\n".join(parts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "filter_name": self.filter_name,
            "filter_namespace": self.filter_namespace,
            "event_namespace": self.event_namespace,
            "query": self.query,
            "query_language": self.query_language,
            "consumer_name": self.consumer_name,
            "consumer_class": self.consumer_class,
            "consumer_properties": self.consumer_properties,
            "creator_sid": self.creator_sid,
            "creator_user": self.creator_user,
            "binding_present": self.binding_present,
            "has_multiple_consumers": self.has_multiple_consumers,
            "source": self.source,
        }


@dataclass
class Assessment:
    """Detector verdict for one subscription."""

    subscription: Subscription
    score: int
    verdict: str
    evidence: list[Evidence] = field(default_factory=list)
    allowlisted: bool = False
    matched_allowlist: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.subscription.key,
            "score": self.score,
            "verdict": self.verdict,
            "allowlisted": self.allowlisted,
            "matched_allowlist": self.matched_allowlist,
            "filter": {
                "name": self.subscription.filter_name,
                "namespace": self.subscription.filter_namespace,
                "event_namespace": self.subscription.event_namespace,
                "query": self.subscription.query,
            },
            "consumer": {
                "name": self.subscription.consumer_name,
                "class": self.subscription.consumer_class,
                "properties": self.subscription.consumer_properties,
            },
            "creator": {
                "sid": self.subscription.creator_sid,
                "user": self.subscription.creator_user,
            },
            "evidence": [item.as_dict() for item in self.evidence],
        }

    def to_alert(self) -> dict[str, Any]:
        return self.as_dict()
