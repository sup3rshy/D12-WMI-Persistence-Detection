# D12 - WMI Event Subscription Persistence Detection

**Môn học:** NT230 - Cơ chế hoạt động của mã độc  
**DEV Track - đề tài D12:** WMI Event Subscription Persistence Detection  
**MITRE ATT&CK:** [T1546.003 - Event Triggered Execution: WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)  
**Mức độ:** Trung bình - Khá

Dự án gồm 4 phần chạy được độc lập:

1. **PoC vô hại** tạo permanent WMI subscription trong VM, dùng `CommandLineEventConsumer` / `ActiveScriptEventConsumer` để ghi một marker text.
2. **Detector nhiều lớp** đọc WMI repository, event log `Microsoft-Windows-WMI-Activity/Operational` và process telemetry; liên kết filter-consumer và giải thích từng điểm rủi ro.
3. **Dataset có nhãn** gồm 6 mẫu benign và 9 biến thể malicious (V1-V9), sinh từ đúng schema của collector.
4. **Đánh giá định lượng** với Precision / Recall / F1 / FPR, bootstrap confidence interval, rule ablation, perturbation suite, external validation và hướng dẫn tái lập.

---

## Kết quả chính

| Operating point | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Strict (score >= 60) | 8 | 0 | 6 | 1 | 1.000 | 0.889 | 0.941 | 0.000 |
| Triage (score >= 40) | 9 | 0 | 6 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |

- Dataset có **15 scenario**: 6 benign (B1-B6) và 9 malicious (M1-M9/V1-V9). B4-B6 là hard negative thực tế (backup `robocopy`, SMTP disk alert, operations probe trong namespace riêng); B6 đạt 39 điểm, chỉ dưới ngưỡng triage 1 điểm, nên ngưỡng 40 là lựa chọn có bằng chứng thay vì cảm tính.
- Biến thể V6 "low-noise" (SYSTEM, tên trung tính, không process telemetry) đạt 50 điểm: **false negative ở strict**, được đẩy sang triage; ở ngưỡng 40 detector bắt đủ 9/9. V7-V9 bổ sung MOF + tên GUID, allow-list clone và registry WQL.
- Trên máy thật, detector đọc **1 permanent subscription hợp lệ** của Windows (`SCM Event Log Filter`) và **không** báo động (allow-list khớp chính xác tên, namespace, class, query, CreatorSID).
- 5/5 cấu hình PoC (V1-V5) khi chuyển thành repository/5861 đều bị detector chấm `MALICIOUS` (70-100 điểm), xác nhận PoC và detector khớp nhau về mặt dữ liệu.
- **Đã chạy PoC thật trong VM**: Windows 10 22H2 (VirtualBox 7.0.26, snapshot `clean-baseline`), V1 tạo filter/consumer/binding, marker `NT230-D12-MARKER` xuất hiện sau ~23 giây; detector chấm dữ liệu thật `MALICIOUS 60/100`; sau đó PoC xóa 4 object và VM được rollback snapshot. Bằng chứng: [`reports/vm-live/`](reports/vm-live/).
- **Đã kiểm chứng persistence qua reboot**: V1 được tạo với `-Keep`, marker bị xóa trước khi reboot; sau khi VM boot lại (`LastBootUpTime = 2026-11-18T14:11:14Z`), repository vẫn còn 1 filter/1 consumer/1 binding và timer tạo lại marker lúc `14:12:15Z`. Cleanup xóa `removed=4`, snapshot `clean-baseline` được restore. Bằng chứng: [`reports/vm-live/reboot/`](reports/vm-live/reboot/).
- Lần chạy thật phát hiện và sửa hai lỗi mà dry-run không thấy: `__TimerEvent` phải dùng `EventNamespace = root\default` (không phải `root\cimv2`), bỏ điều kiện quá chặt `NumEvents = 1`; và log-only mode từng lẫn *activation user* với *CreatorSID owner*.
- **56 test tự động pass**; pipeline offline (sinh dataset + checksum + evaluate + validation + test) chạy khoảng **3 giây**.
- **Tái lập được**: dataset/report sinh deterministic, có `.gitattributes` LF, `scripts/update_checksums.py --check`, test `tests/test_reproducibility.py` và GitHub Actions (`.github/workflows/ci.yml`).

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

# 3. Kiểm tra checksum và tính tái lập của artefact
python3 scripts/update_checksums.py --check
python3 -m pytest -q tests/test_reproducibility.py

# 4. Quét một thư mục collection hoặc một scenario
python3 -m detector.cli scan --scenario data/scenarios/M2_activescript_masquerade

# 5. Chỉ dùng event log 5861 (khi không query được repository)
python3 -m detector.cli scan --scenario data/live --source events

# 6. Chuyển cấu hình PoC dry-run thành telemetry và quét lại (PoC -> detector)
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
│   ├── scenario_catalog.py   # 15 scenario có nhãn (6 benign, 9 malicious)
│   └── generate_dataset.py   # sinh data/scenarios + manifest + ground truth
├── evaluation/
│   ├── metrics.py            # confusion matrix, P/R/F1/FPR
│   ├── validation.py         # bootstrap CI, ablation, perturbation, external
│   └── evaluate.py           # sinh toàn bộ báo cáo trong reports/
├── collector/
│   ├── Collect-WmiSubscriptions.ps1   # read-only repository snapshot
│   └── Collect-WmiActivityLog.ps1     # read-only WMI-Activity export
├── poc/
│   ├── Invoke-WmiSubscription.ps1     # V1-V5, có VM guard + auto cleanup
│   └── benign/New-BenignSubscription.ps1
├── scripts/
│   ├── run_all.sh / run_live.sh       # pipeline offline / live read-only
│   ├── update_checksums.py            # checksum dataset telemetry
│   └── vm/                            # harness reboot-persistence (lab-only)
├── tests/                    # 56 test pytest (unit + integration + repro)
├── data/                     # dataset sinh ra + live snapshot + checksums
├── reports/                  # metrics, CSV, validation, live/vm evidence
├── docs/                     # threat model, cơ chế, thiết kế, đánh giá, an toàn
└── .github/workflows/ci.yml  # pytest + reproducibility + detector smoke test
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
| Benign | B4 | Backup `robocopy` hợp lệ dùng `CommandLineEventConsumer`, hard negative |
| Benign | B5 | Capacity alert dùng `SMTPEventConsumer` trên `Win32_LogicalDisk` |
| Benign | B6 | Operations probe trong `root\OpsMonitoring`, 39 điểm (dưới triage 1 điểm) |
| Malicious | M1 / V1 | `__TimerEvent` + `CommandLineEventConsumer` ghi marker |
| Malicious | M2 / V2 | WQL process creation + tên masquerade + `ActiveScriptEventConsumer` |
| Malicious | M3 / V3 | encoded PowerShell, polling 2 giây |
| Malicious | M4 / V4 | namespace `root\NT230Lab`, timer 300 giây, không có process telemetry |
| Malicious | M5 / V5 | JScript consumer chứa network primitive (URL TEST-NET-2, không thực thi) |
| Malicious | M6 / V6 | low-noise evasion: SYSTEM, tên trung tính, `C:\Windows\Temp`, mất telemetry |
| Malicious | M7 / V7 | MOF-style: tên GUID, process WQL, inline VBScript dropper |
| Malicious | M8 / V8 | allow-list clone: tên built-in nhưng khác class/query/payload |
| Malicious | M9 / V9 | registry key-change WQL, command-line marker write |

Nguồn, schema và giới hạn: [`docs/07-dataset-card.md`](docs/07-dataset-card.md).

---

## Đối chiếu rubric DEV Track

| Hạng mục | Điểm | Minh chứng trong repo |
|---|---:|---|
| A. Hiểu cơ chế và thiết kế PoC | 3.0 | `docs/02-mechanism.md`, `poc/Invoke-WmiSubscription.ps1`, dry-run V1-V5 trong `reports/poc-dryrun/`, lần chạy thật trong `reports/vm-live/`, **persistence qua reboot** trong `reports/vm-live/reboot/` |
| B. Thực nghiệm biến thể/evasion có kiểm soát | 2.0 | 9 biến thể V1-V9 + 6 benign, bảng scenario trong `data/ground_truth.csv`, so sánh điểm trong `reports/per_scenario.csv`, threshold sweep |
| C. Detector và kỹ thuật phát hiện | 4.0 | `detector/` với 14 rule, 6 lớp tín hiệu, 5861 parser, allow-list chặt, CLI; `reports/rule_ablation.csv` định lượng đóng góp từng rule |
| D. Đánh giá, tái lập và an toàn | 1.0 | `reports/metrics.json`, bootstrap CI, `reports/robustness.csv`, `reports/validation.json`, `reports/vm-live/`, `docs/05-reproduction.md`, `docs/06-safety.md`, 56 test, CI, checksum/reproducibility guard |

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

- Dataset vẫn nhỏ (15 scenario) và do nhóm thiết kế; rule weight được chọn thủ công nên có nguy cơ overfit. Kết quả 1.000 ở ngưỡng triage **không** đại diện cho môi trường thật. Bootstrap 95% CI cho strict recall là 0.625-1.000, cho thấy độ bất định cao với N=15.
- Chưa có temporal drift, chưa có nhiều phiên bản Windows/Server, và M7 chỉ **mô phỏng** MOF deployment; nhóm chưa chạy `mofcomp` thật.
- Perturbation suite cho thấy khi đổi principal của một benign subscription (SYSTEM -> user), một số mẫu rơi vào hàng đợi *suspicious* (triage FPR 0.667); strict FPR vẫn 0. Đây là lý do "suspicious" phải là hàng đợi review, không phải auto-block.
- Detector chỉ đọc được namespace được truyền vào collector. Mặc định `root\subscription`; cần thêm namespace tùy chỉnh khi hunt.
- Nếu WMI-Activity Operational log bị tắt hoặc bị xóa, lớp 5 mất tín hiệu; detector vẫn chạy bằng repository nhưng giảm khả năng xác nhận.
- Allow-list khớp chính xác cả namespace; attacker copy nguyên tên + query + namespace của built-in sẽ không bị allow-list che nếu có evidence mạnh, nhưng đây vẫn là bề mặt bypass cần review định kỳ.
- Mới kiểm chứng persistence qua reboot trên **một** VM Windows 10 22H2; chưa có video và chưa test Windows 11/Server.

## License và phạm vi sử dụng

Chỉ dùng cho học phần NT230 và lab cô lập. Không chứa malware thật, không có C2,
không có credential theft hay exfiltration. Xem [`docs/06-safety.md`](docs/06-safety.md).
