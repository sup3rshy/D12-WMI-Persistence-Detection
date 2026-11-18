# D12 - WMI Event Subscription Persistence Detection

**Môn học:** NT230 - Cơ chế hoạt động của mã độc  
**DEV Track - đề tài D12:** WMI Event Subscription Persistence Detection  
**MITRE ATT&CK:** [T1546.003 - Event Triggered Execution: WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)  
**Mức độ:** Trung bình - Khá

Dự án gồm 4 phần chạy được độc lập:

1. **PoC vô hại** tạo permanent WMI subscription trong VM, dùng `CommandLineEventConsumer` / `ActiveScriptEventConsumer` để ghi một marker text.
2. **Detector nhiều lớp** đọc WMI repository, event log `Microsoft-Windows-WMI-Activity/Operational` và process telemetry; liên kết filter-consumer và giải thích từng điểm rủi ro.
3. **Dataset có nhãn** gồm 3 mẫu benign và 6 biến thể malicious (V1-V6), sinh từ đúng schema của collector.
4. **Đánh giá định lượng** với Precision / Recall / F1 / FPR, phân tích ngưỡng, false positive/negative và hướng dẫn tái lập.

---

## Kết quả chính

| Operating point | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Strict (score >= 60) | 5 | 0 | 3 | 1 | 1.000 | 0.833 | 0.909 | 0.000 |
| Triage (score >= 40) | 6 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |

- Biến thể V6 được thiết kế "low-noise" (SYSTEM, tên trung tính, không có process telemetry) nên chỉ đạt 50 điểm. Ở ngưỡng strict 60, V6 là **false negative** và được đẩy sang hàng đợi triage; ở ngưỡng 40 detector bắt đủ 6/6.
- Trên máy thật, detector đọc **1 permanent subscription hợp lệ** của Windows (`SCM Event Log Filter`) và **không** báo động (allow-list khớp chính xác tên, class, query, namespace, CreatorSID).
- 5/5 cấu hình PoC (V1-V5) khi chuyển thành repository/5861 đều bị detector chấm `MALICIOUS` (70-100 điểm), xác nhận PoC và detector khớp nhau về mặt dữ liệu.
- **Đã chạy PoC thật trong VM**: Windows 10 22H2 (VirtualBox 7.0.26, snapshot `clean-baseline`), V1 tạo filter/consumer/binding, marker `NT230-D12-MARKER` xuất hiện sau ~23 giây; detector chấm dữ liệu thật `MALICIOUS 60/100`; sau đó PoC xóa 4 object và VM được rollback snapshot. Bằng chứng: [`reports/vm-live/`](reports/vm-live/).
- Lần chạy thật phát hiện và sửa một lỗi cấu hình mà dry-run không thấy: `__TimerEvent` phải dùng `EventNamespace = root\default` (không phải `root\cimv2`), và bỏ điều kiện quá chặt `NumEvents = 1`.
- 33 test tự động pass; pipeline offline (sinh dataset + đánh giá) chạy khoảng **1 giây**.

Báo cáo đầy đủ: [`reports/evaluation-report.md`](reports/evaluation-report.md)  
Demo transcript: [`reports/demo.txt`](reports/demo.txt)  
Cấu hình PoC V1-V5 (dry-run, không tạo object): [`reports/poc-dryrun/summary.md`](reports/poc-dryrun/summary.md)

---

## Quick start

```bash
# 1. Sinh dataset + đánh giá + test (offline, không cần Windows)
./scripts/run_all.sh

# 2. Chỉ chạy detector trên toàn dataset
python3 -m evaluation.evaluate

# 3. Quét một thư mục collection hoặc một scenario
python3 -m detector.cli scan --scenario data/scenarios/M2_activescript_masquerade

# 4. Chỉ dùng event log 5861 (khi không query được repository)
python3 -m detector.cli scan --scenario data/live --source events

# 5. Chuyển cấu hình PoC dry-run thành telemetry và quét lại (PoC -> detector)
python3 -m poc.export_variant_repository
python3 -m detector.cli scan --dataset reports/poc-to-detector
```

Thu thập read-only trên Windows (không tạo object nào):

```powershell
.\collector\Collect-WmiSubscriptions.ps1
.\collector\Collect-WmiActivityLog.ps1 -MaxEvents 5000 -SinceDays 30
```

PoC chỉ chạy trong VM có snapshot:

```powershell
# PowerShell elevated, trong VM
.\poc\Invoke-WmiSubscription.ps1 -Variant V1 -WaitForMarker -EvidencePath ..\reports\poc-v1.json
.\poc\Invoke-WmiSubscription.ps1 -Action Remove -Variant V1
```

> **Trạng thái thực thi:** máy phân tích là laptop vật lý (Acer Nitro AN515-44),
> nên nhóm **không tạo permanent subscription thật** trên máy này; chỉ chạy
> collector read-only và các biến thể ở chế độ `-DryRun`. Script PoC có VM guard và
> từ chối chạy khi phát hiện host vật lý. PoC sau đó được chạy thật **một lần**
> trong VM Windows 10 22H2 (VirtualBox, snapshot `clean-baseline`): V1 tạo đủ
> filter/consumer/binding, marker xuất hiện sau ~23 giây, detector chấm
> `MALICIOUS 60/100`, rồi object được xóa và VM rollback. Bằng chứng:
> [`reports/vm-live/`](reports/vm-live/). Chi tiết an toàn:
> [`docs/06-safety.md`](docs/06-safety.md).

---

## Cấu trúc dự án

```
D12-WMI-Persistence-Detection/
├── detector/                 # detector Python (package)
│   ├── model.py              # dataclass Subscription / Evidence / Assessment
│   ├── parser.py             # repository JSON, 5861 message, scenario loader
│   ├── rules.py              # 14 rule giải thích được
│   ├── scoring.py            # cộng điểm, allow-list, batch analysis
│   ├── baseline_allowlist.json
│   └── cli.py                # giao diện dòng lệnh
├── simulator/
│   ├── scenario_catalog.py   # 9 scenario có nhãn (3 benign, 6 malicious)
│   └── generate_dataset.py   # sinh data/scenarios + manifest + ground truth
├── evaluation/
│   ├── metrics.py            # confusion matrix, P/R/F1/FPR
│   └── evaluate.py           # sinh toàn bộ báo cáo trong reports/
├── collector/
│   ├── Collect-WmiSubscriptions.ps1   # read-only repository snapshot
│   └── Collect-WmiActivityLog.ps1     # read-only WMI-Activity export
├── poc/
│   ├── Invoke-WmiSubscription.ps1     # V1-V5, có VM guard + auto cleanup
│   └── benign/New-BenignSubscription.ps1
├── tests/                    # 33 test pytest
├── data/                     # dataset sinh ra + live snapshot
├── reports/                  # metrics, CSV, markdown, live scan, vm-live, test log
├── docs/                     # threat model, cơ chế, thiết kế, đánh giá, an toàn
└── scripts/                  # run_all.sh, run_live.sh
```

---

## Detector hoạt động như thế nào

Detector không phụ thuộc vào PoC. Nó nhận 3 nguồn dữ liệu độc lập:

| Lớp | Nguồn | Tín hiệu |
|---|---|---|
| 1. Repository | `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding` | consumer class, WQL query, namespace, CreatorSID, binding treo |
| 2. Nội dung consumer | `CommandLineTemplate`, `ScriptText`, `ScriptFilePath`, `LogFilePath` | LOLBin, encoded command, download cradle, scripting host, đường dẫn user-writable |
| 3. WQL | `Query` | `__InstanceCreationEvent` trên `Win32_Process`/`Win32_Service`/registry, `WITHIN` polling |
| 4. Identity | `CreatorSID`, event `User` | non-SYSTEM principal, tên masquerade |
| 5. Event log | WMI-Activity 5861 / 5859 / 5860 | filter-consumer chain, user activation, thiếu telemetry |
| 6. Behaviour | Sysmon-style process events | `WmiPrvSE.exe` sinh child process đáng ngờ |

14 rule được mô tả trong [`docs/03-detection-design.md`](docs/03-detection-design.md).
Mỗi alert trả về danh sách `evidence` gồm `rule`, `weight`, `detail`, nên analyst
có thể giải thích vì sao bị chấm điểm mà không cần mô hình hộp đen.

---

## Dataset

| Nhóm | Scenario | Mô tả ngắn |
|---|---|---|
| Benign | B1 | `SCM Event Log Filter` thật của Windows (export từ host) |
| Benign | B2 | IT monitoring dùng `LogFileEventConsumer`, hard negative |
| Benign | B3 | Audit service state dùng `NTEventLogEventConsumer` |
| Malicious | M1 / V1 | `__TimerEvent` + `CommandLineEventConsumer` ghi marker |
| Malicious | M2 / V2 | WQL process creation + tên masquerade + `ActiveScriptEventConsumer` |
| Malicious | M3 / V3 | encoded PowerShell, polling 2 giây |
| Malicious | M4 / V4 | namespace `root\NT230Lab`, timer 300 giây, không có process telemetry |
| Malicious | M5 / V5 | JScript consumer chứa network primitive (URL TEST-NET-2, không thực thi) |
| Malicious | M6 / V6 | low-noise evasion: SYSTEM, tên trung tính, `C:\Windows\Temp`, mất telemetry |

Nguồn, schema và giới hạn: [`docs/07-dataset-card.md`](docs/07-dataset-card.md).

---

## Đối chiếu rubric DEV Track

| Hạng mục | Điểm | Minh chứng trong repo |
|---|---:|---|
| A. Hiểu cơ chế và thiết kế PoC | 3.0 | `docs/02-mechanism.md`, `poc/Invoke-WmiSubscription.ps1`, dry-run V1-V5 trong `reports/poc-dryrun/`, lần chạy thật trong `reports/vm-live/` |
| B. Thực nghiệm biến thể/evasion có kiểm soát | 2.0 | 6 biến thể V1-V6 + 3 benign, bảng scenario trong `data/ground_truth.csv`, so sánh điểm trong `reports/per_scenario.csv` |
| C. Detector và kỹ thuật phát hiện | 4.0 | `detector/` với 14 rule, 6 lớp tín hiệu, 5861 parser, allow-list, CLI |
| D. Đánh giá, tái lập và an toàn | 1.0 | `reports/metrics.json`, `reports/confusion_matrix.csv`, `reports/vm-live/`, `docs/05-reproduction.md`, `docs/06-safety.md`, 33 test |

Chi tiết từng tiêu chí: [`docs/rubric-mapping.md`](docs/rubric-mapping.md).

---

## Tài liệu

- [`docs/01-threat-model.md`](docs/01-threat-model.md) - threat model, tài sản, trust boundary
- [`docs/02-mechanism.md`](docs/02-mechanism.md) - kiến trúc WMI eventing, vòng đời subscription, event ID
- [`docs/03-detection-design.md`](docs/03-detection-design.md) - thiết kế detector, bảng rule, scoring
- [`docs/04-evaluation.md`](docs/04-evaluation.md) - protocol, kết quả, error analysis, threats to validity
- [`docs/05-reproduction.md`](docs/05-reproduction.md) - các bước tái lập trong VM
- [`docs/06-safety.md`](docs/06-safety.md) - ràng buộc an toàn, VM guard và lần chạy thật có rollback
- [`docs/07-dataset-card.md`](docs/07-dataset-card.md) - data card

---

## Giới hạn đã biết

- Dataset nhỏ (9 scenario) và do nhóm thiết kế; rule weight được calibrate trên chính tập này nên có nguy cơ overfit. Kết quả 1.000 ở ngưỡng triage **không** đại diện cho môi trường thật.
- Chưa có temporal drift, chưa có nhiều phiên bản Windows, chưa có subscription do attacker tạo bằng MOF/`mofcomp` với object name ngẫu nhiên.
- Detector chỉ đọc được namespace được truyền vào collector. Mặc định `root\subscription`; cần thêm namespace tùy chỉnh khi hunt.
- Nếu WMI-Activity Operational log bị tắt hoặc bị xóa, lớp 5 mất tín hiệu; detector vẫn chạy bằng repository nhưng giảm khả năng xác nhận.
- Allow-list khớp chính xác; attacker copy nguyên tên + query của built-in sẽ không bị allow-list che nếu có evidence mạnh, nhưng đây vẫn là bề mặt bypass cần review định kỳ.

## License và phạm vi sử dụng

Chỉ dùng cho học phần NT230 và lab cô lập. Không chứa malware thật, không có C2,
không có credential theft hay exfiltration. Xem [`docs/06-safety.md`](docs/06-safety.md).
