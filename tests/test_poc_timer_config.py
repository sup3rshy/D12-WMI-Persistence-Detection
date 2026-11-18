"""Regression tests for the WMI timer configuration bug found in the lab VM.

The first real run in a Windows 10 VirtualBox VM exposed two issues that the
synthetic dry-run did not catch:

* ``__TimerEvent`` is delivered from ``root\\default``; a filter with
  ``EventNamespace = root\\cimv2`` never receives it.
* ``NumEvents = 1`` in the WQL query is too strict for the first delivery.

These tests read the PoC script so the bug cannot silently return.
"""
from __future__ import annotations

from pathlib import Path

POC = Path(__file__).resolve().parents[1] / "poc" / "Invoke-WmiSubscription.ps1"


def test_timer_variants_use_root_default_event_namespace() -> None:
    text = POC.read_text(encoding="utf-8")
    # V1 and V4 are the two timer variants.
    assert text.count("$common.EventNamespace = 'root\\default'") >= 2
    # Intrinsic-event variants keep the default root\cimv2 namespace.
    assert "EventNamespace     = 'root\\cimv2'" in text


def test_timer_queries_do_not_require_numevents_one() -> None:
    text = POC.read_text(encoding="utf-8")
    assert "NumEvents = 1" not in text
