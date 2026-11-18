# 04 - Đánh giá

Toàn bộ số liệu trong tài liệu này sinh từ:

```bash
python3 -m simulator.generate_dataset --out data/scenarios
python3 scripts/update_checksums.py
python3 -m evaluation.evaluate
```

Artefacts:

- `reports/metrics.json` - số liệu đầy đủ + evidence từng scenario
- `reports/per_scenario.csv` - score/verdict/nhãn
- `reports/confusion_matrix.csv` - strict và triage
- `reports/threshold_sensitivity.csv` - quét ngưỡng 20-100
- `reports/rule_ablation.csv` - bỏ từng rule, đo recall/FPR
- `reports/robustness.csv` - perturbation suite (không dùng để tune)
- `reports/validation.json` - bootstrap CI + ablation + perturbation + external
- `reports/evaluation-report.md` - báo cáo markdown
- `reports/alerts.json` - alert + lý do

---

## 1. Protocol

| Thành phần | Giá trị |
|---|---|
| Đơn vị đánh giá | 1 scenario = 1 permanent subscription chain |
| Số scenario | 15 (6 benign, 9 malicious) |
| Nhãn | `ground_truth.json` do nhóm gán theo hành vi, không theo tên |
| Ngưỡng strict | score >= 60 |
| Ngưỡng triage | score >= 40 |
| Metric | TP/FP/TN/FN, Precision, Recall, F1, FPR, accuracy |
| Test tự động | 56 pytest |
| Thời gian chạy | ~1 giây cho generate + evaluate + validation |

`predicted = 1` khi verdict là `malicious` (strict) hoặc `malicious|suspicious`
(triage). FPR = FP / (FP + TN).

---

## 2. Kết quả

### 2.1 Confusion matrix

| Operating point | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Strict (>= 60) | 8 | 0 | 6 | 1 | 1.000 | 0.889 | 0.941 | 0.000 |
| Triage (>= 40) | 9 | 0 | 6 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |

### 2.2 Từng scenario

| Scenario | Nhãn | Score | Verdict | Rule chính |
|---|---:|---:|---|---|
| B1_builtin_scm | 0 | 0 | benign | allow-list |
| B2_it_logfile_monitor | 0 | 33 | benign | R01, R05, R07 |
| B3_service_state_audit | 0 | 26 | benign | R01, R07, R08 |
| B4_backup_commandline | 0 | 35 | benign | R01, R05 |
| B5_disk_alert_smtp | 0 | 10 | benign | R01 |
| B6_custom_namespace_ops | 0 | 39 | benign | R01, R05, R07, R11 |
| M1_cmd_marker_timer | 1 | 100 | malicious | R01, R04, R05, R09, R10, R13, R14 |
| M2_activescript_masquerade | 1 | 100 | malicious | R01, R05, R06, R07, R08, R09, R10, R13 |
| M3_encoded_powershell | 1 | 100 | malicious | R01, R02, R04, R07, R08, R09, R13, R14 |
| M4_delayed_custom_namespace | 1 | 71 | malicious | R01, R04, R05, R10, R11 |
| M5_network_activescript | 1 | 100 | malicious | R01, R03, R06, R07, R08, R09, R10, R13 |
| M6_stealth_low_noise | 1 | 50 | suspicious | R01, R04, R05 |
| M7_mof_random_names | 1 | 91 | malicious | R01, R05, R06, R07, R08, R09, R13 |
| M8_allowlist_clone | 1 | 100 | malicious | R01, R05, R06, R07, R08, R09, R10, R13 |
| M9_registry_wql | 1 | 85 | malicious | R01, R04, R05, R07, R09, R13 |

Không có false positive ở cả hai operating point. False negative duy nhất ở
strict là M6, được thiết kế để kiểm tra giới hạn của detector.

> Điểm cuối là `min(100, tổng weight)`. Vì vậy các scenario 100 điểm có tổng
> weight thô lớn hơn 100.

---

## 3. Threshold sensitivity

| Ngưỡng | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 | 9 | 4 | 2 | 0 | 0.692 | 1.000 | 0.818 | 0.667 |
| 30 | 9 | 3 | 3 | 0 | 0.750 | 1.000 | 0.857 | 0.500 |
| 35 | 9 | 2 | 4 | 0 | 0.818 | 1.000 | 0.900 | 0.333 |
| 40 | 9 | 0 | 6 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 45 | 9 | 0 | 6 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 50 | 9 | 0 | 6 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 55 | 8 | 0 | 6 | 1 | 1.000 | 0.889 | 0.941 | 0.000 |
| 60 | 8 | 0 | 6 | 1 | 1.000 | 0.889 | 0.941 | 0.000 |
| 75 | 7 | 0 | 6 | 2 | 1.000 | 0.778 | 0.875 | 0.000 |
| 90 | 6 | 0 | 6 | 3 | 1.000 | 0.667 | 0.800 | 0.000 |

Diễn giải:

- **20-25:** B2 (33), B3 (26), B4 (35) và B6 (39) thành FP (4 FP).
- **30:** B2 (33), B4 (35) và B6 (39) thành FP (3 FP).
- **35:** B4 (35) và B6 (39) thành FP (2 FP); đây là lý do không chọn 35 dù recall đạt 1.0.
- **40-50:** vùng tối ưu trên dataset này; B6 (39) vẫn benign, M6 (50) được bắt.
- **55-70:** M6 rơi khỏi strict, recall giảm còn 0.889.
- **75+:** M4 (71) cũng rơi; **90+:** M9 (85) rơi.

Ngưỡng mặc định 60 là lựa chọn bảo thủ cho SOC: giảm alert rác, chấp nhận đẩy
M6 sang triage. Nếu ưu tiên recall, đặt 40-50; nếu ưu tiên precision tuyệt đối,
60 vẫn giữ FPR = 0.

---

## 4. Phân tích lỗi

### 4.1 False negative: M6 low-noise (score 50, strict)

M6 mô phỏng attacker có kiến thức về detector:

| Thay đổi | Rule bị mất | Điểm mất |
|---|---|---:|
| Chạy dưới SYSTEM | R09, R13 | 20 |
| Tên trung tính (`Inventory Sync`) | R10 | 15 |
| Không có process telemetry | R14 | 20 |
| Đường dẫn `C:\Windows\Temp` thay vì `%PUBLIC%` | vẫn khớp R05 | 0 |

Còn lại: R01 (25) + R04 (15) + R05 (10) = 50.

Kết luận: nếu attacker có quyền SYSTEM và chủ động né tên/đường dẫn/telemetry,
detector tĩnh chỉ đạt mức "suspicious". Đây là lý do cần:

- bật Sysmon/EDR để lấy lại R14;
- theo dõi 5861 với user context;
- review các subscription lạ trong `root\subscription` theo baseline;
- không chỉ dựa vào tên object.

Ở ngưỡng triage 40, M6 được đưa vào hàng đợi điều tra, đúng mục tiêu thiết kế.

### 4.2 Hard negative: B4 backup commandline (35)

`CommandLineEventConsumer` chạy `robocopy` là hợp lệ nhưng vẫn nhận R01 (25) vì
class consumer có khả năng thực thi, và R05 (10) vì log đích nằm trong
`C:\ProgramData`. Điểm 35 nằm dưới ngưỡng 40 nhưng trên 30: nếu hạ ngưỡng để bắt
M6, B4 sẽ thành false positive. Đây là trade-off định lượng, không phải giả định.

### 4.3 Hard negative: B6 custom namespace (39)

Operations probe dùng `LogFileEventConsumer` trong `root\OpsMonitoring`:
R01 (8) + R05 (10) + R07 (15) + R11 (6) = 39, chỉ dưới triage 1 điểm. Trường hợp
này chứng minh "custom namespace" một mình không đủ kết luận malicious, đồng thời
giải thích vì sao ngưỡng 40 được chọn thay vì 35.

### 4.4 B2/B3/B5

- B2: `LogFileEventConsumer` + `ProgramData` + `Win32_Service` = 33.
- B3: `NTEventLogEventConsumer` + `WITHIN 60` + `Win32_Service` = 26.
- B5: `SMTPEventConsumer` + `Win32_LogicalDisk` = 10.

Ba mẫu này giữ FPR = 0 ở ngưỡng 40 và cho thấy R07 một mình không đủ kết luận;
cần kết hợp consumer class và hành vi.

### 4.5 B1 built-in SCM (0)

Khớp allow-list chính xác. Đây là object thật lấy từ host phân tích, không phải
dữ liệu mô phỏng. Allow-list yêu cầu cả `filter_namespace` và
`consumer_namespace`, nên M8 (clone tên built-in nhưng khác class/query) không
được miễn trừ.

### 4.6 M8 allow-list clone

M8 dùng đúng tên `SCM Event Log Filter` / `SCM Event Log Consumer` nhưng
`ActiveScriptEventConsumer`, query process-creation và script ghi marker. Detector
chấm 100 và `allowlisted = false`, chứng minh allow-list không chỉ so tên.

---

## 5. Kiểm chứng trên host thật (read-only)

Chạy `scripts/run_live.sh` trên laptop Windows 11:

```
collector: filters=1 consumers=1 bindings=1
event log: ~1.2k events (5857/5858/5859/5860/5861)
detector (repository): BENIGN score=0
detector (events only): BENIGN score=0
```

Object duy nhất là `SCM Event Log Filter` / `SCM Event Log Consumer`, được
allow-list. Kết quả này xác nhận:

1. Collector đọc được repository thật và chuyển đúng schema.
2. Parser 5861 xử lý được message thật của Windows 11.
3. Detector không báo động với baseline hợp lệ.

Log: `reports/live-scan.txt`, `reports/live-scan.json`,
`data/live/repository.json`, `data/live/wmi_activity.jsonl`.

---

## 5b. Kiểm chứng PoC thật trong VM (held-out, không dùng để tune rule)

Sau khi hoàn tất detector, nhóm chạy PoC V1 thật trong VM Windows 10 22H2
(VirtualBox 7.0.26, snapshot `clean-baseline`) để lấy dữ liệu **held-out** -
không scenario nào trong bộ 15 mẫu được dùng lại.

```
VM            : NT230LAB, Windows 10 22H2 build 19045
Account       : NT230LAB\student (high integrity qua elevated console)
Object tạo    : __EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding
Namespace     : root\subscription, EventNamespace = root\default
Marker        : C:\Users\Public\nt230_d12_marker.txt = "NT230-D12-MARKER"
Thời gian     : marker xuất hiện ~23 giây sau khi tạo subscription
Event log     : 5861 ghi nhận binding; 5857/5858/5859/5860 cũng có
Detector      : MALICIOUS score=60/100 (R01 +25, R04 +15, R05 +10, R09 +10)
Kết luận      : true positive trên dữ liệu thật; built-in SCM filter vẫn benign
```

Điểm 60 thấp hơn 70 của bản render dry-run vì event 5861 thật ghi
`User = NT AUTHORITY\SYSTEM` (R13 không kích hoạt), trong khi dry-run gán user
`student`. Đây là khác biệt telemetry có thật, không phải lỗi detector; R09 vẫn
bắt được `CreatorSID` của `student`.

Bằng chứng: `reports/vm-live/` (`poc-v1.json`, `marker.txt`,
`repository.json`, `wmi_activity.jsonl`, `runner.log`, `detector-scan.txt`).

Lần chạy thật này cũng phát hiện một bug mà dry-run bỏ sót: filter timer phải
dùng `EventNamespace = root\default` và không nên đặt `NumEvents = 1`. Bug đã
được sửa trong `poc/Invoke-WmiSubscription.ps1` và có regression test
`tests/test_poc_timer_config.py`.

---

## 5c. Persistence qua reboot (held-out, mới)

Đây là bằng chứng cốt lõi của T1546.003: object phải nằm trong repository và
tiếp tục hoạt động sau khi OS khởi động lại.

| Bước | Bằng chứng |
|---|---|
| Tạo V1 với `-Keep`, timer 30 s, xóa marker trước reboot | `create.log`, `objects-before-reboot.txt` (1 filter / 1 consumer / 1 binding), `create-evidence.json` |
| Reboot guest | `shutdown /r /t 5 /f`; `LastBootUpTime = 2026-11-18T14:11:14Z` |
| Sau boot, object vẫn còn | `objects-after-reboot.txt` (1 / 1 / 1), `summary.json` |
| Timer tạo lại marker | `marker-after-reboot.txt` = `NT230-D12-MARKER`; `marker_created_utc = 2026-11-18T14:12:15Z` (sau boot) |
| Detector | `MALICIOUS 60/100` trên repository; `MALICIOUS 60/100` trên events-only |
| Cleanup | `removed=4`, remaining filters/consumers/bindings = 0/0/0 |
| Rollback | snapshot `clean-baseline` restore, VM poweroff |

Bằng chứng: `reports/vm-live/reboot/` (`summary.json`, `create.log`,
`verify.log`, `marker-after-reboot.txt`, `repository.json`,
`wmi_activity.jsonl`, `cleanup.txt`, `detector-scan*.txt`).

Harness tái lập: `scripts/vm/Reboot-Persistence-Test.ps1` (phase `Create` /
`Verify`) và `scripts/vm/run-create.cmd`, `run-verify.cmd`. Đây là script lab,
phải chạy elevated trong VM có snapshot; không dùng trên host vật lý.

---

## 6. Validation bổ sung (không dùng để chọn weight)

### 6.1 Bootstrap 95% CI

Resample 2000 lần, seed 1234:

| Operating point | Metric | 95% CI |
|---|---|---:|
| strict | precision | 1.000-1.000 |
| strict | recall | 0.625-1.000 |
| strict | F1 | 0.769-1.000 |
| strict | FPR | 0.000-0.000 |
| triage | precision / recall / F1 / FPR | 1.000 / 1.000 / 1.000 / 0.000 |

CI rộng phản ánh đúng N nhỏ; không nên đọc 1.000 của triage như bằng chứng tổng
quát hóa.

### 6.2 Rule ablation

Tắt từng rule và đo recall (baseline strict 0.889, triage 1.000):

| Rule | Strict recall | Triage recall | Strict recall drop |
|---|---:|---:|---:|
| R01 | 0.778 | 0.889 | 0.111 |
| R04 | 0.778 | 0.889 | 0.111 |
| R10 | 0.778 | 1.000 | 0.111 |
| R02/R03/R05/R06/R07/R08/R09/R11/R12/R13/R14 | 0.889 | 1.000 | 0.000 |

R01/R04/R10 là các rule "carry" M6 qua strict; các rule còn lại đóng góp vào
score nhưng không làm thay đổi quyết định ở operating point này. Đây là thông
tin cần thiết để tránh tưởng rằng 14 rule đều quan trọng như nhau.

### 6.3 Perturbation robustness

Các phép biến đổi deterministic trên catalogue, **không** nằm trong `data/scenarios`:

| Family | Malicious | Strict recall | Triage recall | Benign | Strict FPR | Triage FPR |
|---|---:|---:|---:|---:|---:|---:|
| rename_neutral | 9 | 0.778 | 1.000 | 6 | 0.000 | 0.000 |
| path_relocate | 5 | 1.000 | 1.000 | 3 | 0.000 | 0.000 |
| sid_switch | 9 | 1.000 | 1.000 | 6 | 0.000 | 0.667 |
| polling_change | 5 | 1.000 | 1.000 | 4 | 0.000 | 0.500 |
| namespace_move | 9 | 0.889 | 1.000 | 6 | 0.000 | 0.333 |
| telemetry_gap | 9 | 0.889 | 1.000 | 6 | 0.000 | 0.167 |

- Đổi tên trung tính làm M4/M6 rơi khỏi strict (mất R10/R09/R13), nhưng triage
  vẫn bắt 9/9.
- Đổi principal của benign subscription làm một số mẫu thành *suspicious* (triage
  FPR 0.667) nhưng **không** thành malicious (strict FPR 0).
- Đây là lý do triage phải là hàng đợi review, không phải auto-block.

### 6.4 External validation

| Sample | Nguồn | Expected | Score | Verdict | Correct |
|---|---|---:|---:|---|---:|
| vm-live-v1 | VM thật, lần chạy đầu | 1 | 60 | malicious | 1 |
| vm-live-reboot | VM thật, sau reboot | 1 | 60 | malicious | 1 |
| host-live-scm | host thật, read-only | 0 | 0 | benign | 1 |
| poc-POC_V1..V5 | PoC dry-run render | 1 | 70/100/100/91/95 | malicious | 5 |

External: TP=7, FP=0, TN=1, FN=0. Đây là các mẫu không tham gia chọn weight.

---

## 7. Threats to validity

| Loại | Vấn đề | Giảm thiểu |
|---|---|---|
| Internal validity | Rule weight được chọn sau khi xem scenario, có nguy cơ overfit | Công bố toàn bộ weight; ablation; threshold sensitivity; perturbation suite không dùng để tune |
| Construct validity | "Malicious" trong dataset là nhãn do nhóm gán, không phải malware thật | Label guide rõ ràng; mọi payload chỉ ghi marker |
| External validity | 15 scenario, 1 phiên bản Windows, không có drift | Nêu rõ giới hạn; external validation trên VM/host thật |
| Reliability | Format 5861 có thể thay đổi | Test với message thật; parser fallback repository; test malformed JSONL |
| Telemetry bias | Sysmon chỉ có ở một số scenario | Báo cáo điểm có/không R14; M4/M6 là static-only |
| Label leakage | Không có train/test split riêng | Tất cả là test; weight không học tự động; perturbation/external held-out |
| Selection bias | B1 lấy từ host thật, B2-B6 do nhóm tạo | Ghi rõ provenance trong dataset card |
| Small sample | CI rộng, không đủ power thống kê | Bootstrap CI + N nhỏ được báo cáo thay vì che giấu |

---

## 8. So sánh với rubric

| Yêu cầu | Kết quả |
|---|---|
| >= 3 benign + >= 3 PoC/biến thể | 6 benign + 9 malicious (V1-V9) |
| Precision/Recall/F1/FPR | Có, ở 2 operating point + threshold sweep |
| Log/telemetry | Repository JSON, WMI-Activity JSONL, process JSONL, live export, VM reboot |
| Hướng dẫn tái lập | `docs/05-reproduction.md`, `scripts/run_all.sh`, `scripts/update_checksums.py --check`, CI |
| Phân tích lỗi | M6 FN, B4/B6 hard negative, threshold sweep, perturbation |
| An toàn | VM guard, không chạy PoC trên host vật lý, marker-only, snapshot rollback |
