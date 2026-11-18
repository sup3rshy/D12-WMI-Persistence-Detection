# D12 detector - evaluation report

- Dataset: `data/scenarios`
- Scenarios: 9 (3 benign / 6 malicious)
- Malicious threshold: score >= 60
- Suspicious threshold: score >= 40

## Scenario-level results

| Scenario | Label | Score | Verdict | Top evidence |
|---|---:|---:|---|---|
| `B1_builtin_scm` | 0 | 0 | benign | - |
| `B2_it_logfile_monitor` | 0 | 33 | benign | R07, R05, R01 |
| `B3_service_state_audit` | 0 | 26 | benign | R07, R08, R01 |
| `M1_cmd_marker_timer` | 1 | 100 | malicious | R01, R14, R04, R10 |
| `M2_activescript_masquerade` | 1 | 100 | malicious | R01, R06, R07, R10 |
| `M3_encoded_powershell` | 1 | 100 | malicious | R01, R02, R14, R04 |
| `M4_delayed_custom_namespace` | 1 | 71 | malicious | R01, R04, R10, R05 |
| `M5_network_activescript` | 1 | 100 | malicious | R03, R01, R06, R07 |
| `M6_stealth_low_noise` | 1 | 50 | suspicious | R01, R04, R05 |

## Metrics

| Operating point | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| strict (malicious only) | 5 | 0 | 3 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| triage (suspicious+malicious) | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |

## Threshold sensitivity

| Malicious threshold | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 | 6 | 2 | 1 | 0 | 0.750 | 1.000 | 0.857 | 0.667 |
| 25 | 6 | 2 | 1 | 0 | 0.750 | 1.000 | 0.857 | 0.667 |
| 30 | 6 | 1 | 2 | 0 | 0.857 | 1.000 | 0.923 | 0.333 |
| 35 | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 40 | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 45 | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 50 | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 55 | 5 | 0 | 3 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| 60 | 5 | 0 | 3 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| 65 | 5 | 0 | 3 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| 70 | 5 | 0 | 3 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| 75 | 4 | 0 | 3 | 2 | 1.000 | 0.667 | 0.800 | 0.000 |
| 80 | 4 | 0 | 3 | 2 | 1.000 | 0.667 | 0.800 | 0.000 |
| 85 | 4 | 0 | 3 | 2 | 1.000 | 0.667 | 0.800 | 0.000 |
| 90 | 4 | 0 | 3 | 2 | 1.000 | 0.667 | 0.800 | 0.000 |
| 95 | 4 | 0 | 3 | 2 | 1.000 | 0.667 | 0.800 | 0.000 |
| 100 | 4 | 0 | 3 | 2 | 1.000 | 0.667 | 0.800 | 0.000 |

## Per-scenario evidence

### `B1_builtin_scm` (benign)

Windows built-in SCM Event Log Filter/Consumer (real baseline, exported from the lab host).

- score **0** / verdict **benign** - `SCM Event Log Filter` -> `NTEventLogEventConsumer:SCM Event Log Consumer`
  - `R00` (+0) Matched signed baseline allow-list: Object matches known-good entry 'builtin-scm-eventlog'. Exact query, class and namespace were required for the match.

### `B2_it_logfile_monitor` (benign)

Approved IT monitoring: LogFileEventConsumer writes service-state changes to a log file.

- score **33** / verdict **benign** - `IT Health Log Filter` -> `LogFileEventConsumer:IT Health Log Writer`
  - `R07` (+15) WQL watches a security-sensitive class: Filter subscribes to instance create/modify/delete events on a process, service, logon, registry or SCM class.
  - `R05` (+10) User-writable target path: Action references \ProgramData\, a location writable by non-privileged users (staging/marker location).
  - `R01` (+8) Permanent consumer registered: LogFileEventConsumer is a permanent consumer and needs an explicit business justification.

### `B3_service_state_audit` (benign)

Event-log audit of stopped services; benign use of a permanent WMI subscription.

- score **26** / verdict **benign** - `Service State Audit` -> `NTEventLogEventConsumer:Service State EventLog Writer`
  - `R07` (+15) WQL watches a security-sensitive class: Filter subscribes to instance create/modify/delete events on a process, service, logon, registry or SCM class.
  - `R08` (+6) High-frequency WQL polling: WITHIN 60s is a short polling interval.
  - `R01` (+5) Permanent consumer registered: NTEventLogEventConsumer is a permanent consumer and needs an explicit business justification.

### `M1_cmd_marker_timer` (malicious)

V1 baseline: CommandLineEventConsumer triggered by __TimerEvent writes a marker once.

- score **100** / verdict **malicious** - `Windows Update Monitor` -> `CommandLineEventConsumer:Windows Update Monitor Consumer`
  - `R01` (+25) High-risk permanent consumer class: CommandLineEventConsumer executes an action automatically when the filter fires; it is the preferred T1546.003 consumer type.
  - `R14` (+20) WmiPrvSE spawned a suspicious child process: Consumer execution produced: cmd.exe /c echo NT230-D12-MARKER > "C:\Users\Public\nt230_d12_marker.txt"
  - `R04` (+15) Command interpreter or LOLBin launch: Action starts cmd.exe /c, which is typical for scripted execution but uncommon for monitoring consumers.
  - `R10` (+15) Name masquerades as a trusted component: Subscription name contains 'Windows Update', a common masquerading pattern for T1546.003.
  - `R05` (+10) User-writable target path: Action references %PUBLIC%, a location writable by non-privileged users (staging/marker location).
  - `R09` (+10) Subscription created by a non-SYSTEM principal: CreatorSID S-1-5-21-1004336348-1177238915-682003330-1001 (NT230LAB\student) is not LOCAL SYSTEM; WMI persistence is normally installed by an interactive user or attacker context.
  - `R13` (+10) Activation logged under a user account: Event 5861 for 'Windows Update Monitor' records user 'NT230LAB\student' rather than SYSTEM.

### `M2_activescript_masquerade` (malicious)

V2 filter + name variation: process-creation WQL (WITHIN 5) and a masqueraded ActiveScript consumer.

- score **100** / verdict **malicious** - `SCM Event Log Filter` -> `ActiveScriptEventConsumer:SCM Event Log Consumer`
  - `R01` (+25) High-risk permanent consumer class: ActiveScriptEventConsumer executes an action automatically when the filter fires; it is the preferred T1546.003 consumer type.
  - `R06` (+15) Scripting host abuse in inline script: Inline script uses Scripting.FileSystemObject to create processes or write files, the usual ActiveScriptEventConsumer payload.
  - `R07` (+15) WQL watches a security-sensitive class: Filter subscribes to instance create/modify/delete events on a process, service, logon, registry or SCM class.
  - `R10` (+15) Name masquerades as a trusted component: Subscription name contains 'SCM Event Log', a common masquerading pattern for T1546.003.
  - `R05` (+10) User-writable target path: Action references \Users\Public\, a location writable by non-privileged users (staging/marker location).
  - `R08` (+10) High-frequency WQL polling: WITHIN 5s causes very high-frequency polling.
  - `R09` (+10) Subscription created by a non-SYSTEM principal: CreatorSID S-1-5-21-1004336348-1177238915-682003330-1001 (NT230LAB\student) is not LOCAL SYSTEM; WMI persistence is normally installed by an interactive user or attacker context.
  - `R13` (+10) Activation logged under a user account: Event 5861 for 'SCM Event Log Filter' records user 'NT230LAB\student' rather than SYSTEM.

### `M3_encoded_powershell` (malicious)

V3 consumer variation: encoded PowerShell action with 2-second polling on chrome.exe.

- score **100** / verdict **malicious** - `SessionSync_8f2a` -> `CommandLineEventConsumer:SessionSync_8f2a_Action`
  - `R01` (+25) High-risk permanent consumer class: CommandLineEventConsumer executes an action automatically when the filter fires; it is the preferred T1546.003 consumer type.
  - `R02` (+25) Encoded or obfuscated action: Consumer action contains an encoding/obfuscation primitive (-EncodedCommand, FromBase64String, [char[]] ...).
  - `R14` (+20) WmiPrvSE spawned a suspicious child process: Consumer execution produced: powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAE4AVAAyADMAMAAtAEQAMQAyAC0ATQBBAFIASwBFAFIAIgAgAHwAIABPAHUAdAAtAEYAaQBsAGUAIAAtAEYAaQBsAGUAUABhAHQAaAAgACIAJABlAG4AdgA6AFAAVQBCAEwASQBDAFwAbgB0ADIAMwAwAF8AZAAxADIAXwBtAGEAcgBrAGUAcgAuAHQAeAB0ACIA
  - `R04` (+15) Command interpreter or LOLBin launch: Action starts powershell.exe, which is typical for scripted execution but uncommon for monitoring consumers.
  - `R07` (+15) WQL watches a security-sensitive class: Filter subscribes to instance create/modify/delete events on a process, service, logon, registry or SCM class.
  - `R08` (+10) High-frequency WQL polling: WITHIN 2s causes very high-frequency polling.
  - `R09` (+10) Subscription created by a non-SYSTEM principal: CreatorSID S-1-5-21-1004336348-1177238915-682003330-1001 (NT230LAB\student) is not LOCAL SYSTEM; WMI persistence is normally installed by an interactive user or attacker context.
  - `R13` (+10) Activation logged under a user account: Event 5861 for 'SessionSync_8f2a' records user 'NT230LAB\student' rather than SYSTEM.

### `M4_delayed_custom_namespace` (malicious)

V4 namespace + trigger-delay variation: subscription in root\NT230Lab, 300 s timer, no process telemetry.

- score **71** / verdict **malicious** - `Windows Defender Cache` -> `CommandLineEventConsumer:DefenderCacheConsumer`
  - `R01` (+25) High-risk permanent consumer class: CommandLineEventConsumer executes an action automatically when the filter fires; it is the preferred T1546.003 consumer type.
  - `R04` (+15) Command interpreter or LOLBin launch: Action starts cmd.exe /c, which is typical for scripted execution but uncommon for monitoring consumers.
  - `R10` (+15) Name masquerades as a trusted component: Subscription name contains 'Defender', a common masquerading pattern for T1546.003.
  - `R05` (+10) User-writable target path: Action references %APPDATA%, a location writable by non-privileged users (staging/marker location).
  - `R11` (+6) Non-default WMI namespace: filter/consumer stored in root\NT230Lab. Custom namespaces hide subscriptions from the usual root\subscription triage.

### `M5_network_activescript` (malicious)

V5 consumer variation: JScript consumer with a network retrieval primitive (inert TEST-NET-2 URL).

- score **100** / verdict **malicious** - `Windows Telemetry Collector` -> `ActiveScriptEventConsumer:Windows Telemetry Consumer`
  - `R03` (+30) Network retrieval in consumer action: Action references remote content (http://); a permanent subscription must not be a download cradle.
  - `R01` (+25) High-risk permanent consumer class: ActiveScriptEventConsumer executes an action automatically when the filter fires; it is the preferred T1546.003 consumer type.
  - `R06` (+15) Scripting host abuse in inline script: Inline script uses WScript.Shell to create processes or write files, the usual ActiveScriptEventConsumer payload.
  - `R07` (+15) WQL watches a security-sensitive class: Filter subscribes to instance create/modify/delete events on a process, service, logon, registry or SCM class.
  - `R10` (+15) Name masquerades as a trusted component: Subscription name contains 'Windows Telemetry', a common masquerading pattern for T1546.003.
  - `R09` (+10) Subscription created by a non-SYSTEM principal: CreatorSID S-1-5-21-1004336348-1177238915-682003330-1001 (NT230LAB\student) is not LOCAL SYSTEM; WMI persistence is normally installed by an interactive user or attacker context.
  - `R13` (+10) Activation logged under a user account: Event 5861 for 'Windows Telemetry Collector' records user 'NT230LAB\student' rather than SYSTEM.
  - `R08` (+6) High-frequency WQL polling: WITHIN 30s is a short polling interval.

### `M6_stealth_low_noise` (malicious)

V6 low-noise evasion: SYSTEM principal, neutral names, Windows\Temp target and no WmiPrvSE child telemetry.

- score **50** / verdict **suspicious** - `Inventory Sync` -> `CommandLineEventConsumer:Inventory Sync Action`
  - `R01` (+25) High-risk permanent consumer class: CommandLineEventConsumer executes an action automatically when the filter fires; it is the preferred T1546.003 consumer type.
  - `R04` (+15) Command interpreter or LOLBin launch: Action starts cmd.exe /c, which is typical for scripted execution but uncommon for monitoring consumers.
  - `R05` (+10) User-writable target path: Action references \Windows\Temp\, a location writable by non-privileged users (staging/marker location).

