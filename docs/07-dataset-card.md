# 07 - Dataset card

**Tên:** NT230 D12 WMI Event Subscription dataset
**Phiên bản:** 1.2
**Ngày:** 2026-11-18
**Người tạo:** nhóm đồ án NT230 (DEV Track D12)
**Loại:** telemetry mô phỏng + baseline thật + 2 lần chạy PoC thật trong VM (lần đầu + reboot)
**License:** dùng cho học phần NT230; không chứa malware thật

---

## 1. Nguồn gốc (provenance)

| Nguồn | Sử dụng |
|---|---|
| Host phân tích Windows 11 (Acer Nitro) | B1: export read-only `SCM Event Log Filter` + 5861 thật |
| VM Windows 10 22H2 (VirtualBox, snapshot) | Held-out validation: PoC V1 thật + persistence qua reboot, không dùng để tune rule |
| `simulator/scenario_catalog.py` | B2-B6, M1-M9: dựng theo đúng schema của collector |
| `simulator/generate_dataset.py` | Sinh file deterministic, không random |

B1 không phải dữ liệu mô phỏng: nó được tạo bằng
`collector/Collect-WmiSubscriptions.ps1` và `Collect-WmiActivityLog.ps1` trên host
thật, sau đó đưa vào catalog. Điều này đảm bảo parser được kiểm tra với format thật.

Ngoài bộ 15 scenario, nhóm còn các mẫu **held-out** lấy từ PoC chạy thật trong VM:
`reports/vm-live/out/` (lần chạy đầu) và `reports/vm-live/reboot/` (sau reboot).
Các mẫu này không nằm trong `data/scenarios`, không được dùng để chọn
rule/weight, và chỉ dùng để kiểm chứng detector có hoạt động trên telemetry thật
hay không. Kết quả: `MALICIOUS 60/100` (R01/R04/R05/R09) cho cả hai, trong khi
built-in SCM filter vẫn benign.

Các scenario còn lại được thiết kế để bao phủ biến thể:

| Variant | Thay đổi so với baseline | Mục đích |
|---|---|---|
| V1 | Timer + CommandLine | Baseline persistence |
| V2 | Process WQL + tên masquerade + ActiveScript | Filter/name/consumer variation |
| V3 | Encoded PowerShell + polling 2s | Obfuscation |
| V4 | Namespace `root\NT230Lab` + delay 300s | Namespace/trigger delay, static-only |
| V5 | JScript + network primitive (inert) | Content detection |
| V6 | SYSTEM + tên trung tính + `C:\Windows\Temp` + không process telemetry | Low-noise evasion |
| V7 | Tên GUID, process WQL, VBScript dropper | MOF-style/random name |
| V8 | Tên built-in + class/query/payload khác | Allow-list bypass |
| V9 | Registry key-change WQL + command-line marker | Registry trigger |

Các benign control cũng được mở rộng: B4 backup `robocopy`, B5 SMTP disk alert,
B6 operations probe trong namespace riêng (39 điểm, sát ngưỡng triage).

---

## 2. Thành phần

```
data/
├── scenarios/
│   ├── B1_builtin_scm/
│   │   ├── repository.json
│   │   ├── wmi_activity.jsonl
│   │   ├── process_events.jsonl
│   │   └── ground_truth.json
│   ├── B2_it_logfile_monitor/ ... B6_custom_namespace_ops/
│   ├── ...
│   └── M9_registry_wql/
├── live/                     # export read-only từ host phân tích
│   ├── repository.json
│   └── wmi_activity.jsonl
├── ground_truth.csv
└── manifest.json
```

| File | Schema | Ghi chú |
|---|---|---|
| `repository.json` | filters/consumers/bindings | output của collector |
| `wmi_activity.jsonl` | EventId, TimeCreated, User, Message | 5861 chứa definition |
| `process_events.jsonl` | Image, ParentImage, CommandLine, User | Sysmon-style, có thể rỗng |
| `ground_truth.json` | scenario_id, label, category, variant, tags | nhãn |
| `manifest.json` | counts, variants, items | tổng hợp |

---

## 3. Thống kê

| Chỉ số | Giá trị |
|---|---|
| Tổng scenario | 15 |
| Benign | 6 (B1-B6) |
| Malicious | 9 (M1-M9) |
| Số variant malicious | 9 (V1-V9) |
| Consumer class | CommandLine, ActiveScript, LogFile, NTEventLog, SMTP |
| Namespace | `root\subscription`, `root\NT230Lab`, `root\OpsMonitoring` |
| Có process telemetry | 2/15 (M1, M3) |
| Có 5861 | 15/15 |
| Kích thước `data/scenarios` | ~45 KB (45,966 bytes) |
| Toàn bộ `data/` (kèm live export) | ~750 KiB |
| Mẫu held-out ngoài bộ chính | 2 (PoC V1 chạy thật + reboot) |

Phân bố này vẫn nhỏ nhưng đã có đủ benign control và biến thể để đo trade-off.
Ưu tiên chất lượng, provenance và khả năng tái lập hơn số lượng; bootstrap CI
trong `reports/validation.json` cho thấy độ bất định còn lớn với N=15.

---

## 4. Label guide

### Benign

Một subscription được gán `label=0` khi:

- consumer không thực thi command/script tùy ý, **hoặc**
- là thành phần built-in của Windows, **và**
- có mục đích vận hành rõ ràng (monitoring, audit), **và**
- không có dấu hiệu obfuscation/network/user-writable path.

### Malicious

`label=1` khi hội đủ:

- có permanent subscription trong repository, **và**
- consumer thực thi hành động (command/script), **và**
- hành động ghi marker ra vị trí người dùng ghi được, **và**
- không có phê duyệt vận hành (không nằm trong allow-list).

Nhãn dựa trên **hành vi và ngữ cảnh**, không dựa trên tên object. Ví dụ M2 dùng
tên `SCM Event Log Filter` nhưng vẫn là malicious vì consumer là ActiveScript ghi
file.

---

## 5. Cách tái sinh

```bash
python3 -m simulator.generate_dataset --out data/scenarios
```

Deterministic: không dùng random, không phụ thuộc thời gian thực (timestamp cố
định trong catalog). Chạy lại cho cùng nội dung.

Kiểm tra:

```bash
sha256sum data/scenarios/*/repository.json | sort
python3 -m pytest tests/test_dataset.py -q
```

### 5b. Held-out collection từ VM (không tái sinh bằng generator)

```text
reports/vm-live/out/repository.json        # filter/consumer/binding thật
reports/vm-live/out/wmi_activity.jsonl     # 5861/5859/5860 thật
reports/vm-live/out/marker.txt             # NT230-D12-MARKER
reports/vm-live/out/poc-v1.json            # timeline + verdict

reports/vm-live/reboot/summary.json        # verdict=persisted, marker sau boot
reports/vm-live/reboot/marker-after-reboot.txt
reports/vm-live/reboot/objects-after-reboot.txt
reports/vm-live/reboot/repository.json     # object sau reboot
reports/vm-live/reboot/wmi_activity.jsonl
```

Các file này **không** nằm trong `data/checksums.txt` và không được generator
sinh lại; chúng là bằng chứng của các lần chạy có kiểm soát trong VM
`NT230-D12-WinLab`, đã rollback snapshot sau khi thu thập. `data/checksums.txt`
chỉ cover telemetry của dataset + live snapshot và được kiểm tra bởi
`tests/test_checksums.py`.

---

## 6. An toàn

- Không có binary, shellcode, malware thật.
- Không có network call; URL duy nhất là `198.51.100.23` (TEST-NET-2).
- Không có credential/token/PII.
- Marker chỉ là text.
- B1 chứa tên host thật; làm sạch trước khi công bố ngoài lớp.

---

## 7. Giới hạn

1. **Quy mô nhỏ:** 15 scenario vẫn không đủ để kết luận thống kê; bootstrap 95% CI
   cho strict recall là 0.625-1.000.
2. **Thiếu đa dạng môi trường:** 1 phiên bản Windows, 1 cấu hình.
3. **Nhãn do nhóm tạo:** không có chuyên gia độc lập, không có inter-rater agreement.
4. **Không có temporal split:** tất cả dùng để evaluate, không có train/test riêng.
5. **Mô phỏng:** hành vi thật của attacker có thể khác (random name, MOF, xóa dấu vết).
6. **Negative đã đa dạng hơn nhưng vẫn hạn chế:** 6 benign, chưa có subscription
   thật của SCCM/AV/monitoring agent; B4-B6 do nhóm thiết kế.
7. **5861 format:** phụ thuộc phiên bản Windows; cần test thêm trên Windows Server.

---

## 8. Hướng mở rộng

- Thêm benign từ SCCM, monitoring agent, backup agent thật.
- Chạy `mofcomp` thật thay vì mô phỏng M7; thêm namespace ngẫu nhiên và
  `SMTPEventConsumer` bị lạm dụng.
- Thu thập trên Windows 10/11/Server 2019/2022.
- Thêm temporal split và drift analysis.
- Ký số/checksum cho từng file và publish kèm data card.
