# 04 - Đánh giá

Toàn bộ số liệu trong tài liệu này sinh từ:

```bash
python3 -m simulator.generate_dataset --out data/scenarios
python3 -m evaluation.evaluate
```

Artefacts:

- `reports/metrics.json` - số liệu đầy đủ + evidence từng scenario
- `reports/per_scenario.csv` - score/verdict/nhãn
- `reports/confusion_matrix.csv` - strict và triage
- `reports/threshold_sensitivity.csv` - quét ngưỡng 20-100
- `reports/evaluation-report.md` - báo cáo markdown
- `reports/alerts.json` - alert + lý do

---

## 1. Protocol

| Thành phần | Giá trị |
|---|---|
| Đơn vị đánh giá | 1 scenario = 1 permanent subscription chain |
| Số scenario | 9 (3 benign, 6 malicious) |
| Nhãn | `ground_truth.json` do nhóm gán theo hành vi, không theo tên |
| Ngưỡng strict | score >= 60 |
| Ngưỡng triage | score >= 40 |
| Metric | TP/FP/TN/FN, Precision, Recall, F1, FPR |
| Test tự động | 33 pytest |
| Thời gian chạy | ~1 giây cho generate + evaluate |

`predicted = 1` khi verdict là `malicious` (strict) hoặc `malicious|suspicious`
(triage). FPR = FP / (FP + TN).

---

## 2. Kết quả

### 2.1 Confusion matrix

| Operating point | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Strict (>= 60) | 5 | 0 | 3 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| Triage (>= 40) | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |

### 2.2 Từng scenario

| Scenario | Nhãn | Score | Verdict | Rule chính |
|---|---:|---:|---|---|
| B1_builtin_scm | 0 | 0 | benign | allow-list |
| B2_it_logfile_monitor | 0 | 33 | benign | R01, R05, R07 |
| B3_service_state_audit | 0 | 26 | benign | R01, R07, R08 |
| M1_cmd_marker_timer | 1 | 100 | malicious | R01, R04, R05, R09, R10, R13, R14 |
| M2_activescript_masquerade | 1 | 100 | malicious | R01, R05, R06, R07, R08, R09, R10, R13 |
| M3_encoded_powershell | 1 | 100 | malicious | R01, R02, R04, R07, R08, R09, R13, R14 |
| M4_delayed_custom_namespace | 1 | 71 | malicious | R01, R04, R05, R10, R11 |
| M5_network_activescript | 1 | 100 | malicious | R01, R03, R06, R07, R08, R09, R10, R13 |
| M6_stealth_low_noise | 1 | 50 | suspicious | R01, R04, R05 |

Không có false positive ở cả hai operating point. False negative duy nhất ở
strict là M6, được thiết kế để kiểm tra giới hạn của detector.

> Điểm cuối là `min(100, tổng weight)`. Vì vậy các scenario 100 điểm có tổng
> weight thô lớn hơn 100: M1=105, M2=110, M3=130, M5=126. Bảng 4.1 tính "điểm
> mất" trên tổng thô 105 của M1 (105 - 55 = 50).

---

## 3. Threshold sensitivity

| Ngưỡng | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 30 | 6 | 1 | 2 | 0 | 0.857 | 1.000 | 0.923 | 0.333 |
| 35 | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 40 | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 50 | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| 55 | 5 | 0 | 3 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| 60 | 5 | 0 | 3 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| 75 | 4 | 0 | 3 | 2 | 1.000 | 0.667 | 0.800 | 0.000 |

Diễn giải:

- **30:** B2 (33 điểm) bị coi là alert -> 1 FP. Đây là lý do không chọn ngưỡng 30.
- **35-50:** vùng tối ưu trên dataset này; M6 (50 điểm) vẫn được bắt.
- **55-70:** M6 rơi khỏi strict, recall giảm còn 0.833.
- **75+:** M4 (71 điểm) cũng rơi, recall còn 0.667.

Ngưỡng mặc định 60 là lựa chọn bảo thủ cho SOC: giảm alert rác, chấp nhận đẩy
M6 sang triage. Nếu ưu tiên recall, đặt 40-50.

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

### 4.2 Hard negative: B2 IT log file (score 33)

B2 là monitoring hợp lệ nhưng dùng `LogFileEventConsumer` + `ProgramData` +
`Win32_Service`, nên khớp R01 (8) + R05 (10) + R07 (15) = 33. Nếu hạ ngưỡng
suspicious xuống 30, B2 thành false positive. Đây là trade-off rõ ràng giữa
recall và false alarm; ngưỡng 40 được chọn để giữ FPR = 0.

### 4.3 B3 service audit (score 26)

`NTEventLogEventConsumer` + `WITHIN 60` + `Win32_Service`: 5 + 6 + 15 = 26. Đây
là ví dụ cho thấy R07 một mình không đủ kết luận; cần kết hợp consumer class và
hành vi.

### 4.4 B1 built-in SCM (score 0)

Khớp allow-list chính xác. Đây là object thật lấy từ host phân tích, không phải
dữ liệu mô phỏng.

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
không scenario nào trong bộ 9 mẫu được dùng lại.

```
VM            : NT230LAB, Windows 10 22H2 build 19041
Account       : NT230LAB\student (high integrity qua scheduled task)
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

## 6. Threats to validity

| Loại | Vấn đề | Giảm thiểu |
|---|---|---|
| Internal validity | Rule weight được chọn sau khi xem scenario, có nguy cơ overfit | Công bố toàn bộ weight; threshold sensitivity; test case riêng cho M6 |
| Construct validity | "Malicious" trong dataset là nhãn do nhóm gán, không phải malware thật | Label guide rõ ràng; mọi payload chỉ ghi marker |
| External validity | 9 scenario, 1 phiên bản Windows, không có drift | Nêu rõ giới hạn; đề xuất thu thập thêm từ lab |
| Reliability | Format 5861 có thể thay đổi | Test với message thật; parser có fallback repository |
| Telemetry bias | Sysmon chỉ có ở một số scenario | Báo cáo điểm có/không R14; M4/M6 là static-only |
| Label leakage | Không có train/test split riêng | Tất cả là test; weight không học tự động |
| Selection bias | B1 lấy từ host thật, B2/B3 do nhóm tạo | Ghi rõ provenance trong dataset card |

---

## 7. So sánh với rubric

| Yêu cầu | Kết quả |
|---|---|
| >= 3 benign + >= 3 PoC/biến thể | 3 benign + 6 malicious (V1-V6) |
| Precision/Recall/F1/FPR | Có, ở 2 operating point |
| Log/telemetry | Repository JSON, WMI-Activity JSONL, process JSONL, live export |
| Hướng dẫn tái lập | `docs/05-reproduction.md`, `scripts/run_all.sh` |
| Phân tích lỗi | M6 FN, B2 hard negative, threshold sweep |
| An toàn | VM guard, không chạy PoC trên host vật lý, marker-only |
