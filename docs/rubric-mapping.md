# Đối chiếu rubric DEV Track

Rubric: `DEV Track - Rubric` trong file đề tài. Tổng 10 điểm.

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
| PowerShell syntax check | 4/4 file `OK` (xem log bên dưới) |

**Giới hạn đã nêu:** PoC **không** chạy `Create` trên host vật lý; lý do và bằng
chứng VM guard ở `docs/06-safety.md`. PoC đã chạy thật trong VM Windows 10 22H2
(VirtualBox, snapshot `clean-baseline`): V1 tạo đủ filter/consumer/binding, marker
`NT230-D12-MARKER` xuất hiện sau ~23 giây, sau đó object được xóa và VM rollback.
Chưa quay video và chưa test lại persistence qua reboot trong lần chạy này; quy
trình được mô tả ở `docs/05-reproduction.md`.

**Cách kiểm tra nhanh:**

```bash
powershell.exe -NoProfile -Command '
  $t=$null;$e=$null
  [System.Management.Automation.Language.Parser]::ParseFile(
    "D:\NT230\D12-WMI-Persistence-Detection\poc\Invoke-WmiSubscription.ps1",
    [ref]$t,[ref]$e) | Out-Null
  "errors=" + $e.Count'
```

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
| V6 | SYSTEM + tên trung tính + `C:\Windows\Temp` + mất telemetry | 50 | suspicious |
| B1-B3 | 3 benign controls | 0/33/26 | benign |

**Trade-off đo được:**

- Bỏ process telemetry: V1 (100) -> V4 (71) nếu đồng thời đổi namespace; V6 (50)
  khi thêm SYSTEM + tên trung tính.
- Tăng ngưỡng 40 -> 60: recall 1.000 -> 0.833 (M6 rơi).
- Hạ ngưỡng 40 -> 30: FPR 0.000 -> 0.333 (B2 false positive).

Bảng chi tiết: `reports/per_scenario.csv`, `reports/threshold_sensitivity.csv`,
`docs/04-evaluation.md`.

**Đối chứng benign:** B1 (built-in thật), B2 (LogFile monitoring), B3
(NTEventLog audit). B2 là hard negative vì khớp R01+R05+R07 nhưng vẫn dưới ngưỡng.

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
| False positive | Allow-list chính xác + ngưỡng 40/60 + phân tích B2/B3 |
| Rule/model | `detector/rules.py`, `detector/baseline_allowlist.json` |
| Telemetry | `collector/*.ps1`, `data/live/`, `reports/vm-live/` |
| Kiểm chứng dữ liệu thật | PoC V1 trong VM -> detector `MALICIOUS 60/100`; SCM built-in vẫn benign |
| Báo cáo lỗi | M6 FN, B2 hard negative, threshold sweep, timer namespace bug |

**Cách kiểm tra:**

```bash
python3 -m detector.cli scan --scenario data/scenarios/M2_activescript_masquerade
python3 -m detector.cli scan --scenario data/live
python3 -m detector.cli scan --scenario data/live --source events
```

**Điểm mạnh:** mỗi quyết định đều truy vết được; allow-list không che evidence
mạnh; parser 5861 hoạt động với message thật.

**Điểm yếu đã nêu:** rule weight chủ quan; dataset nhỏ; R14 phụ thuộc Sysmon;
không đọc trực tiếp `OBJECTS.DATA`; M6 cho thấy giới hạn của static-only.

---

## D. Đánh giá, tái lập và an toàn - 1.0 điểm

**Yêu cầu:** Precision/Recall/F1/FPR hoặc latency; hướng dẫn tái lập; tuân thủ lab
cô lập; phân tích giới hạn, threat model, khả năng tổng quát, rủi ro triển khai.

| Yêu cầu | Minh chứng |
|---|---|
| Precision/Recall/F1/FPR | `reports/metrics.json`, `reports/confusion_matrix.csv` |
| Kết quả | strict: P=1.000 R=0.833 F1=0.909 FPR=0.000; triage: 1.000/1.000/1.000/0.000 |
| Latency | ~0.5s evaluate 9 scenario; ~0.9s generate + evaluate (`docs/03-detection-design.md`) |
| Hướng dẫn tái lập | `docs/05-reproduction.md`, `scripts/run_all.sh`, `scripts/run_live.sh` |
| Test tái chạy | `reports/test-results.txt` (33 passed) |
| Cấu hình môi trường | Python 3.12.3, PowerShell 5.1, Windows 11 26300 |
| Checklist an toàn | `docs/06-safety.md` |
| Snapshot/rollback | bắt buộc trong `docs/05-reproduction.md` |
| Giới hạn/threat model | `docs/01-threat-model.md`, `docs/04-evaluation.md` mục 6 |
| Rủi ro triển khai | allow-list bypass, log disabled, namespace coverage, overfit |

**Bằng chứng chạy thực tế:**

| Bước | Kết quả | File |
|---|---|---|
| `pytest` | 33 passed | `reports/test-results.txt` |
| Evaluate | 9 scenario | `reports/evaluation-report.md` |
| Live repository | 1 sub, benign | `reports/live-scan.txt` |
| Live event log | ~1.2k events | `data/live/wmi_activity.jsonl` |
| VM guard | từ chối host vật lý | `reports/safety-guard.txt` |
| PoC dry-run | 5/5 hợp lệ | `reports/poc-dryrun/` |
| **PoC thật trong VM** | filter/consumer/binding + marker sau ~23 giây | `reports/vm-live/out/` |
| **Detector trên dữ liệu thật** | `MALICIOUS 60/100` | `reports/vm-live/detector-scan.txt` |
| **Rollback VM** | restore `clean-baseline`, poweroff | `docs/06-safety.md` mục 1b |

---

## Tự đánh giá

| Hạng mục | Điểm tối đa | Tự đánh giá | Lý do |
|---|---:|---:|---|
| A | 3.0 | 2.8 | Hiểu cơ chế, PoC chạy thật trong VM và marker quan sát được; chưa có video và chưa test persistence qua reboot |
| B | 2.0 | 2.0 | 6 biến thể + 3 benign, đo trade-off và threshold |
| C | 4.0 | 3.6 | 14 rule, 6 lớp, giải thích được, kiểm chứng trên dữ liệu VM thật; dataset nhỏ và rule weight chủ quan |
| D | 1.0 | 1.0 | Metric đầy đủ, tái lập, an toàn, phân tích giới hạn |
| **Tổng** | **10.0** | **9.4** | |

Điểm A có thể đạt tối đa khi quay video marker + reboot persistence trong VM.
Điểm C có thể tăng khi có thêm benign thật và test trên nhiều phiên bản Windows.
