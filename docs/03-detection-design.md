# 03 - Thiết kế detector

Detector là một package Python thuần, không phụ thuộc thư viện ngoài. Mục tiêu
không phải là tối đa hóa accuracy trên dataset nhỏ, mà là tạo ra **chuỗi bằng
chứng giải thích được** cho từng quyết định.

---

## 1. Kiến trúc

```
collector/*.ps1                 data/*.json(l)
      |                              |
      v                              v
+---------------------------------------------------+
| detector.parser                                   |
|  - subscriptions_from_repository()                |
|  - parse_5861() / subscriptions_from_events()     |
|  - load_scenario()                                |
+-------------------------+-------------------------+
                          |
                          v
+---------------------------------------------------+
| detector.rules  (R01 - R14)                       |
|  repository | content | WQL | identity | telemetry|
|  | behaviour                                      |
+-------------------------+-------------------------+
                          |
                          v
+---------------------------------------------------+
| detector.scoring                                  |
|  - allow-list exact match                         |
|  - weighted sum, cap 100                          |
|  - verdict: benign < 40 <= suspicious < 60 <= malicious |
+-------------------------+-------------------------+
                          |
                          v
              CLI / reports / alerts.json
```

Điểm quan trọng: **detector không import hay gọi PoC**. Hai phần chỉ chia sẻ
schema dữ liệu. Điều này đáp ứng yêu cầu "detector độc lập với PoC" của rubric.

---

## 2. Input schema

### 2.1 `repository.json`

```json
{
  "schema_version": "1.0",
  "collected_at": "2026-11-17T09:05:00Z",
  "host": {"hostname": "NT230-LAB", "os": "Windows 10 22H2", "model": "VMware"},
  "scope": ["root\\subscription", "root\\NT230Lab"],
  "filters": [
    {
      "name": "Windows Update Monitor",
      "namespace": "root\\subscription",
      "event_namespace": "root\\cimv2",
      "query": "SELECT * FROM __TimerEvent WHERE TimerID = 'X' AND NumEvents > 0",
      "query_language": "WQL",
      "creator_sid": "S-1-5-21-...-1001",
      "creator_user": "NT230LAB\\student"
    }
  ],
  "consumers": [
    {
      "name": "Windows Update Monitor Consumer",
      "namespace": "root\\subscription",
      "class": "CommandLineEventConsumer",
      "properties": {"CommandLineTemplate": "cmd.exe /c ..."},
      "creator_sid": "S-1-5-21-...-1001",
      "creator_user": "NT230LAB\\student"
    }
  ],
  "bindings": [
    {
      "filter_name": "Windows Update Monitor",
      "filter_namespace": "root\\subscription",
      "consumer_name": "Windows Update Monitor Consumer",
      "consumer_namespace": "root\\subscription"
    }
  ]
}
```

Collector chấp nhận cả hai dạng path của WMI:

- `\\HOST\root\subscription:__EventFilter.Name="X"`
- `__EventFilter (Name = "X")`

### 2.2 `wmi_activity.jsonl`

Mỗi dòng là một event, tối thiểu có `EventId`, `TimeCreated`, `User`, `Message`.
Trường `Message` của 5861 chứa nguyên CIM instance nên parser tái tạo được
subscription ngay cả khi repository không truy cập được.

### 2.3 `process_events.jsonl` (tùy chọn)

Sysmon EID 1 hoặc EDR tương đương:

```json
{"Image":"C:\\Windows\\System32\\cmd.exe",
 "ParentImage":"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
 "CommandLine":"cmd.exe /c echo NT230-D12-MARKER > ...",
 "User":"NT230LAB\\student"}
```

---

## 3. Bảng rule

| ID | Tên | Trọng số | Tín hiệu | Vì sao |
|---|---|---:|---|---|
| R01 | High-risk permanent consumer class | 25 (`CommandLine`, `ActiveScript`), 8 (`LogFile`), 10 (`SMTP`), 5 (`NTEventLog`) | `consumer_class` | Đây là loại consumer thực thi hành động; mức rủi ro khác nhau theo khả năng thực thi |
| R02 | Encoded/obfuscated action | 25 | `-EncodedCommand`, `FromBase64String`, `[char[]]` | Obfuscation làm giảm khả năng đọc/giám sát của analyst |
| R03 | Network retrieval | 30 | `http(s)://`, `Invoke-WebRequest`, `DownloadString`, `bitsadmin /transfer` | Permanent subscription không nên là download cradle |
| R04 | Command interpreter/LOLBin | 15 | `powershell`, `cmd /c`, `mshta`, `rundll32`, `regsvr32`, `certutil` | Thực thi qua binary hợp pháp, phổ biến trong T1546.003 |
| R05 | User-writable target path | 10 | `%TEMP%`, `%APPDATA%`, `\Users\Public\`, `\ProgramData\`, `\Windows\Temp\`, `\Downloads\` | Nơi attacker thường ghi marker/payload |
| R06 | Scripting host abuse | 15 | `WScript.Shell`, `Scripting.FileSystemObject`, `Shell.Application`, `MSXML2.XMLHTTP` | Payload ActiveScript điển hình |
| R07 | Sensitive WQL target | 15 | `__Instance*Event` / `RegistryKeyChangeEvent` / `Win32_ProcessStartTrace` + `Win32_Process`, `Win32_Service`, `Win32_LogonSession`, registry | Theo dõi hành vi nhạy cảm để kích hoạt |
| R08 | High-frequency polling | 10 nếu `WITHIN <= 5`, 6 nếu `<= 60` | `WITHIN n` | Polling dày tạo tải và cho thấy mục tiêu kích hoạt nhanh |
| R09 | Non-SYSTEM creator | 10 | `CreatorSID` khác `S-1-5-18/19/20` | Persistence thường do user/admin tạo, không phải service account |
| R10 | Name masquerade | 15 | `SCM Event Log`, `Windows Update`, `Microsoft`, `Defender`, `Windows Telemetry` | Giả mạo thành phần tin cậy |
| R11 | Non-default namespace | 6 + 6 | filter namespace khác `root\subscription`; event namespace lạ | Namespace tùy chỉnh né triage thông thường |
| R12 | Binding integrity | 10 orphan, 5 multi-consumer | thiếu binding hoặc một filter gắn nhiều consumer | Object mồ côi/misconfiguration |
| R13 | Activation context | 10 user thường; 4 thiếu 5861 | event 5861 `User` | Xác nhận subscription được đăng ký dưới context nào |
| R14 | WmiPrvSE suspicious child | 20 | process có `ParentImage` là `WmiPrvSE.exe` và command chứa encoded/network/user-writable | Bằng chứng động của consumer |

Tổng điểm bị chặn ở 100.

### 3.1 Vì sao không dùng ML?

- Dataset nhỏ, nhãn do nhóm tạo; ML sẽ overfit nặng và khó giải thích.
- Rubric yêu cầu "giải thích được feature và xử lý false positive".
- Rule-based cho phép analyst đọc lý do và điều chỉnh tại chỗ.
- Kiến trúc vẫn tách feature khỏi scoring, nên có thể thay bằng mô hình học máy
  sau này mà không đổi parser.

### 3.2 Chống trùng lặp

- Repository: một `Subscription` cho mỗi binding; filter mồ côi và consumer mồ
  côi được thêm một lần.
- Event log: nhiều 5861 cho cùng một chain được gộp theo `key`, lưu
  `activation_count` thay vì tạo nhiều alert.

---

## 4. Scoring và allow-list

```python
score = min(100, sum(evidence.weight))
if score >= 60: verdict = "malicious"
elif score >= 40: verdict = "suspicious"
else: verdict = "benign"
```

Allow-list (`detector/baseline_allowlist.json`) khớp **chính xác**:

- `filter_name` và `filter_namespace`
- `consumer_name`, `consumer_class` và `consumer_namespace`
- `query`
- `event_namespace`
- `creator_sid` (nếu có)

Nếu khớp và **không** có evidence nào có trọng số >= 20, object được coi là
benign với điểm 0. Nếu có evidence mạnh (encoded, network, LOLBin...), allow-list
bị vô hiệu. Điều này ngăn attacker chỉ cần copy tên built-in là né toàn bộ detector.

Entry duy nhất hiện tại là `SCM Event Log Filter` / `NTEventLogEventConsumer`,
lấy từ host thật.

---

## 5. CLI

```bash
# một scenario
python3 -m detector.cli scan --scenario data/scenarios/M4_delayed_custom_namespace

# toàn dataset, xuất JSON + CSV
python3 -m detector.cli scan --dataset data/scenarios \
  --json-out reports/alerts.json --csv-out reports/per_scenario.csv

# chỉ event log
python3 -m detector.cli scan --scenario data/live --source events

# đổi ngưỡng
python3 -m detector.cli scan --dataset data/scenarios --malicious-threshold 50

# dùng trong CI: exit 2 nếu có malicious
python3 -m detector.cli scan --dataset data/scenarios --fail-on-malicious
```

Output JSON của một subscription:

```json
{
  "key": "root\\\\subscription::Windows Update Monitor->Windows Update Monitor Consumer",
  "score": 100,
  "verdict": "malicious",
  "allowlisted": false,
  "filter": {"name": "...", "namespace": "root\\subscription", "query": "..."},
  "consumer": {"name": "...", "class": "CommandLineEventConsumer", "properties": {"CommandLineTemplate": "..."}},
  "creator": {"sid": "S-1-5-21-...", "user": "NT230LAB\\student"},
  "evidence": [
    {"rule": "R01", "title": "...", "weight": 25, "detail": "..."},
    {"rule": "R04", "title": "...", "weight": 15, "detail": "..."}
  ]
}
```

---

## 6. Coverage theo scenario

| Scenario | Score | Verdict | Rule khớp |
|---|---:|---|---|
| B1 builtin SCM | 0 | benign | allow-list |
| B2 IT log file | 33 | benign | R01, R05, R07 |
| B3 service audit | 26 | benign | R01, R07, R08 |
| B4 backup commandline | 35 | benign | R01, R05 |
| B5 disk alert SMTP | 10 | benign | R01 |
| B6 custom namespace ops | 39 | benign | R01, R05, R07, R11 |
| M1 cmd timer | 100 | malicious | R01, R04, R05, R09, R10, R13, R14 |
| M2 activescript masquerade | 100 | malicious | R01, R05, R06, R07, R08, R09, R10, R13 |
| M3 encoded PowerShell | 100 | malicious | R01, R02, R04, R07, R08, R09, R13, R14 |
| M4 custom namespace | 71 | malicious | R01, R04, R05, R10, R11 |
| M5 network JScript | 100 | malicious | R01, R03, R06, R07, R08, R09, R10, R13 |
| M6 low-noise | 50 | suspicious | R01, R04, R05 |
| M7 MOF random names | 91 | malicious | R01, R05, R06, R07, R08, R09, R13 |
| M8 allow-list clone | 100 | malicious | R01, R05, R06, R07, R08, R09, R10, R13 |
| M9 registry WQL | 85 | malicious | R01, R04, R05, R07, R09, R13 |

M6 cho thấy giới hạn của rule-based: nếu attacker dùng SYSTEM, tên trung tính,
đường dẫn ít bị chú ý và không có process telemetry, tổng điểm chỉ còn 50. Đây
là lý do detector có thêm ngưỡng triage 40. B6 (39 điểm) là hard negative sát
ngưỡng, nên 40 không phải ngưỡng tùy ý: hạ xuống 35 sẽ có 2 false positive
(B4 và B6).

Ghi chú: score = `min(100, tổng weight)`; M1/M2/M3/M5 có tổng thô lần lượt
105/110/130/126 nên đều hiển thị 100.

---

## 7. Hiệu năng

Đo trên máy phân tích (WSL2, Python 3.12.3):

```
elapsed≈1 s cho pipeline 15 scenario (generate + evaluate + validation)
maxrss≈30 MB (evaluate)
```

Detector không phụ thuộc network, không dùng model, nên có thể chạy trong CI hoặc
trên endpoint có Python.

---

## 8. Hạn chế thiết kế

1. Rule weight là chủ quan, được calibrate trên 15 scenario; cần review khi có
   dữ liệu thật. `reports/rule_ablation.csv` và perturbation suite giúp phát hiện
   rule nào thực sự đóng góp.
2. Parser 5861 dựa trên format text hiện tại của Windows 10/11; thay đổi format
   có thể làm hỏng parse (có test với message thật để phát hiện sớm).
3. Không đọc trực tiếp `OBJECTS.DATA`; nếu WMI service không chạy hoặc quyền bị
   chặn, collector thất bại.
4. Không phát hiện consumer dùng COM object không có chuỗi đặc trưng.
5. Rule R14 phụ thuộc Sysmon/EDR; môi trường không có telemetry này sẽ mất 20 điểm.
6. Allow-list exact match có thể gây khó chịu khi Windows cập nhật query built-in;
   cần quy trình review.
