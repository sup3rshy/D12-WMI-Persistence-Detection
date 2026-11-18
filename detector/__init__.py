"""D12 - WMI Event Subscription Persistence Detector.

A layered, explainable detector for MITRE ATT&CK T1546.003
(Event Triggered Execution: WMI Event Subscription).

Layers
------
1. Repository layer  : __EventFilter / __EventConsumer / __FilterToConsumerBinding
2. Content layer     : consumer action (command line, script, log path)
3. WQL layer         : event class, target class, polling interval
4. Identity layer    : CreatorSID, namespace, name masquerading
5. Telemetry layer   : Microsoft-Windows-WMI-Activity 5861/5859/5860 events
6. Behaviour layer   : WmiPrvSE.exe child processes (Sysmon-style)
"""

__version__ = "1.0.0"
