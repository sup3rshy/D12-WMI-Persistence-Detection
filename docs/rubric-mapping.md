# Đối chiếu rubric DEV Track

Rubric: `DEV Track - Rubric` trong file đề tài. Tổng 10 điểm.
Số liệu lấy từ `reports/metrics.json` và `reports/validation.json` (sinh ngày
2026-11-18, dataset 15 scenario).

---

## A. Hiểu cơ chế và thiết kế PoC - 3.0 điểm

**Yêu cầu:** giải thích đúng nguyên lý, luồng thực thi, điều kiện cần và giới hạn;
PoC chạy được trong lab.

| Minh chứng | Vị trí |
|---|---|
| Giải thích WMI eventing, filter/consumer/binding, vòng đời, event ID | `docs/02-mechanism.md` |
| Threat model, điều kiện tiên quyết, trust boundary | `docs/01-threat-model.md` |
| PoC 5 biến thể, có VM guard, auto-cleanup, evidence JSON | `poc/Invoke-WmiSubscription.ps1` |
| Benign control | `poc/benign/New-BenignSubscription.ps1` |
| Dry-run chứng minh cấu hình V1-V5 hợp lệ | `reports/poc-dryrun/V1.json` ... `V5.json` |
| **Chạy Create thật trong VM snapshot** | `reports/vm-live/out/poc-v1.json`, `marker.txt` |
| **Persistence qua reboot trong VM** | `reports/vm-live/reboot/summary.json`, `marker-after-reboot.txt` |
| Harness reboot tái lập được | `scripts/vm/Reboot-Persistence-Test.ps1` |
| PowerShell syntax check | 4/4 file `OK` (xem log bên dưới) |

**Giới hạn đã nêu:** PoC **không** chạy `Create` trên host vật lý; lý do và bằng
chứng VM guard ở `docs/06-safety.md`.

**Lần chạy thật:** VM Windows 10 22H2 (VirtualBox 7.0.26, snapshot
`clean-baseline`), V1 tạo đủ filter/consumer/binding, marker
`NT230-D12-MARKER` xuất hiện sau ~23 giây, detector chấm `MALICIOUS 60/100`,
sau đó object được xóa và VM rollback.

**Lần reboot (mới):** tạo V1 `-Keep` với timer 30 s, xóa marker trước reboot.
Sau khi boot lại (`LastBootUpTime = 2026-11-18T14:11:14Z`), repository vẫn còn
1 filter / 1 consumer / 1 binding; timer tạo lại marker lúc `14:12:15Z`; cleanup
`removed=4`; snapshot restore + VM poweroff. Kết luận `verdict=persisted`.

**Cách kiểm tra nhanh:**

```bash
powershell.exe -NoProfile -Command '
  $t=$null;$e=$null
  [System.Management.Automation.Language.Parser]::ParseFile(
    "D:\NT230\D12-WMI-Persistence-Detection\poc\Invoke-WmiSubscription.ps1",
    [ref]$t,[ref]$e) | Out-Null
  "errors=" + $e.Count'
python3 -m detector.cli scan --scenario reports/vm-live/reboot
```

Chưa quay video; đây là hạn chế trình bày, không phải hạn chế kỹ thuật.

---

## B. Thực nghiệm biến thể/evasion có kiểm soát - 2.0 điểm

**Yêu cầu:** ít nhất 3 biến thể + đối chứng benign; mô tả thay đổi và ảnh hưởng
đến detector; đo trade-off giữa thay đổi, khả năng quan sát và tỷ lệ phát hiện.

| Biến thể | Thay đổi | Điểm | Kết quả |
|---|---|---:|---|
| V1 | Timer + CommandLine | 100 | malicious |
| V2 | Process WQL + masquerade + ActiveScript | 100 | malicious |
| V3 | Encoded PowerShell + polling 2s | 100 | malicious |
| V4 | Namespace riêng + delay 300s, không process telemetry | 71 | malicious |
| V5 | JScript + network primitive | 100 | malicious |
| V6 | SYSTEM + tên trung tính + `C:\Windows\Temp` + mất telemetry | 50 | suspicious (FN strict) |
| V7 | Tên GUID + process WQL + VBScript dropper (MOF-style) | 91 | malicious |
| V8 | Tên built-in + class/query/payload khác (allow-list clone) | 100 | malicious |
| V9 | Registry key-change WQL + command-line marker | 85 | malicious |
| B1 | Built-in SCM thật | 0 | benign |
| B2 | IT LogFile monitoring | 33 | benign |
| B3 | NTEventLog service audit | 26 | benign |
| B4 | Backup `robocopy` dùng CommandLine | 35 | benign |
| B5 | SMTP disk alert | 10 | benign |
| B6 | Operations probe trong namespace riêng | 39 | benign |

**Trade-off đo được:**

- Bỏ process telemetry + đổi namespace: V1 (100) -> V4 (71).
- Thêm SYSTEM + tên trung tính: V6 (50), false negative ở strict.
- Tăng ngưỡng 40 -> 60: recall 1.000 -> 0.889 (M6 rơi).
- Hạ ngưỡng 40 -> 35: FPR 0.000 -> 0.333 (B4 35 và B6 39 thành FP).
- Perturbation: đổi tên trung tính làm strict recall 0.778 nhưng triage recall
  1.000; đổi principal của benign làm triage FPR 0.667 nhưng strict FPR 0.000.

Bảng chi tiết: `reports/per_scenario.csv`, `reports/threshold_sensitivity.csv`,
`reports/robustness.csv`, `docs/04-evaluation.md`.

**Đối chứng benign:** B1 (built-in thật), B2 (LogFile), B3 (NTEventLog audit),
B4 (CommandLine backup), B5 (SMTP), B6 (custom namespace). B2/B4/B6 là hard
negative vì khớp nhiều rule nhưng vẫn dưới ngưỡng.

---

## C. Detector và kỹ thuật phát hiện - 4.0 điểm

**Yêu cầu:** detector độc lập với PoC, phát hiện bằng static/dynamic/memory/graph
features phù hợp; nhiều lớp, giải thích feature, xử lý false positive.

| Yêu cầu | Minh chứng |
|---|---|
| Độc lập với PoC | `detector/` không import `poc/`; chỉ đọc schema |
| Static | Repository layer: filter/consumer/binding, WQL, namespace, CreatorSID |
| Content | Command line, ScriptText, path analysis (R02-R06) |
| Dynamic | WMI-Activity 5861/5859/5860 (R13) |
| Behaviour | WmiPrvSE child process (R14) |
| Graph | Liên kết filter-consumer-binding, phát hiện orphan/multi-consumer (R12) |
| Nhiều lớp | 6 lớp, 14 rule |
| Giải thích feature | Mỗi alert có `evidence.rule/weight/detail` |
| False positive | Allow-list chính xác cả namespace + ngưỡng 40/60 + phân tích B2-B6 |
| Rule/model | `detector/rules.py`, `detector/baseline_allowlist.json` |
| Telemetry | `collector/*.ps1`, `data/live/`, `reports/vm-live/`, `reports/vm-live/reboot/` |
| Kiểm chứng dữ liệu thật | PoC V1 trong VM -> `MALICIOUS 60/100`; sau reboot vẫn `60/100`; SCM built-in vẫn benign |
| Đo đóng góp rule | `reports/rule_ablation.csv` (R01/R04/R10 là rule carry M6) |
| Báo cáo lỗi | M6 FN, B4/B6 hard negative, threshold sweep, timer namespace bug, log-only creator/activation bug |

**Cách kiểm tra:**

```bash
python3 -m detector.cli scan --scenario data/scenarios/M2_activescript_masquerade
python3 -m detector.cli scan --scenario data/live
python3 -m detector.cli scan --scenario data/live --source events
python3 -m detector.cli scan --scenario reports/vm-live/reboot --source events
```

**Điểm mạnh:** mỗi quyết định đều truy vết được; allow-list không che evidence
mạnh (M8); parser 5861 hoạt động với message thật; có ablation/perturbation.

**Điểm yếu đã nêu:** rule weight chủ quan; dataset vẫn nhỏ (15); R14 phụ thuộc
Sysmon; không đọc trực tiếp `OBJECTS.DATA`; M6 cho thấy giới hạn của static-only;
M7 chỉ mô phỏng MOF.

---

## D. Đánh giá, tái lập và an toàn - 1.0 điểm

**Yêu cầu:** Precision/Recall/F1/FPR hoặc latency; hướng dẫn tái lập; tuân thủ lab
cô lập; phân tích giới hạn, threat model, khả năng tổng quát, rủi ro triển khai.

| Yêu cầu | Minh chứng |
|---|---|
| Precision/Recall/F1/FPR | `reports/metrics.json`, `reports/confusion_matrix.csv` |
| Kết quả | strict: P=1.000 R=0.889 F1=0.941 FPR=0.000; triage: 1.000/1.000/1.000/0.000 |
| Uncertainty | bootstrap 95% CI trong `reports/validation.json` |
| Rule ablation | `reports/rule_ablation.csv` |
| Perturbation | `reports/robustness.csv` (6 family, không dùng tune) |
| External validation | VM thật + host thật + PoC render: TP=7 FP=0 TN=1 FN=0 |
| Latency | ~1s evaluate 15 scenario + validation (`docs/03-detection-design.md`) |
| Hướng dẫn tái lập | `docs/05-reproduction.md`, `scripts/run_all.sh`, `scripts/run_live.sh` |
| Test tái chạy | `reports/test-results.txt` (56 passed) |
| Chống report drift | `tests/test_reproducibility.py`, `.gitattributes`, `scripts/update_checksums.py --check` |
| CI | `.github/workflows/ci.yml` (pytest 3.11/3.12, reproducibility, detector smoke) |
| Cấu hình môi trường | Python 3.12.3, PowerShell 5.1, Windows 10 22H2 (VM), Windows 11 (host) |
| Checklist an toàn | `docs/06-safety.md` |
| Snapshot/rollback | bắt buộc trong `docs/05-reproduction.md`; đã restore sau PoC và reboot |
| Giới hạn/threat model | `docs/01-threat-model.md`, `docs/04-evaluation.md` mục 7 |
| Rủi ro triển khai | allow-list bypass, log disabled, namespace coverage, overfit, small-sample CI |

**Bằng chứng chạy thực tế:**

| Bước | Kết quả | File |
|---|---|---|
| `pytest` | 56 passed | `reports/test-results.txt` |
| Evaluate | 15 scenario | `reports/evaluation-report.md` |
| Validation | bootstrap + ablation + perturbation + external | `reports/validation.json` |
| Live repository | 1 sub, benign | `reports/live-scan.txt` |
| Live event log | ~1.2k events | `data/live/wmi_activity.jsonl` |
| VM guard | từ chối host vật lý | `reports/safety-guard.txt` |
| PoC dry-run | 5/5 hợp lệ | `reports/poc-dryrun/` |
| **PoC thật trong VM** | filter/consumer/binding + marker sau ~23 giây | `reports/vm-live/out/` |
| **Detector trên dữ liệu thật** | `MALICIOUS 60/100` | `reports/vm-live/detector-scan.txt` |
| **Persistence qua reboot** | object 1/1/1, marker tạo lại sau boot | `reports/vm-live/reboot/summary.json` |
| **Rollback VM** | restore `clean-baseline`, poweroff | `docs/06-safety.md` mục 1c |

---

## Tự đánh giá

| Hạng mục | Điểm tối đa | Tự đánh giá | Lý do |
|---|---:|---:|---|
| A | 3.0 | 3.0 | Hiểu cơ chế; PoC chạy thật trong VM; persistence qua reboot có bằng chứng; còn thiếu video |
| B | 2.0 | 2.0 | 9 biến thể + 6 benign, đo trade-off, threshold, perturbation |
| C | 4.0 | 3.8 | 14 rule, 6 lớp, giải thích được, ablation/perturbation, kiểm chứng dữ liệu thật; dataset còn nhỏ và weight chủ quan |
| D | 1.0 | 1.0 | Metric đầy đủ + CI, tái lập có test/CI, an toàn, phân tích giới hạn |
| **Tổng** | **10.0** | **9.8** | |

Điểm A có thể đạt tối đa khi quay video marker + reboot; điểm C có thể tăng khi
có thêm benign thật (SCCM/AV/backup agent) và test trên nhiều phiên bản Windows.
