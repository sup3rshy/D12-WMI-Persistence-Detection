# 05 - Hướng dẫn tái lập

Có 3 chế độ:

| Chế độ | Cần gì | Tạo persistence? | Mục đích |
|---|---|---|---|
| Offline pipeline | Python 3.11+ | Không | Sinh dataset, chạy detector, test |
| Live read-only | Windows + quyền đọc WMI/event log | Không | Kiểm chứng collector/parser trên máy thật |
| VM PoC | Windows VM có snapshot | Có, tự xóa | Chạy T1546.003 thật, kiểm chứng end-to-end |

---

## 0. Chuẩn bị

### 0.1 Offline (Linux/WSL)

```bash
cd D12-WMI-Persistence-Detection
python3 --version          # 3.11+
python3 -m pytest -q       # 33 passed
./scripts/run_all.sh
```

Kỳ vọng:

```
generated 9 scenarios ...
strict: TP=5 FP=0 TN=3 FN=1 precision=1.000 recall=0.833 f1=0.909 fpr=0.000
triage: TP=6 FP=0 TN=3 FN=0 precision=1.000 recall=1.000 f1=1.000 fpr=0.000
33 passed
```

### 0.2 VM PoC

- Windows 10/11 VM (VMware/VirtualBox/Hyper-V/QEMU).
- **Snapshot sạch trước khi bắt đầu.**
- PowerShell 5.1 chạy **elevated** (Administrator).
- Copy thư mục dự án vào VM, ví dụ `C:\NT230\D12-WMI-Persistence-Detection`.
- Bật WMI-Activity log (mặc định đã bật trên Windows 10/11):

```powershell
wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true
Get-WinEvent -ListLog Microsoft-Windows-WMI-Activity/Operational |
  Select-Object LogName, IsEnabled, RecordCount
```

---

## 1. Chạy PoC trong VM

Mỗi variant tạo subscription, chờ marker, rồi tự xóa (trừ khi `-Keep`).

### V1 - baseline timer + CommandLine

```powershell
cd C:\NT230\D12-WMI-Persistence-Detection
.\poc\Invoke-WmiSubscription.ps1 -Variant V1 -WaitForMarker `
  -EvidencePath .\reports\poc-v1.json
```

Kỳ vọng:

- `C:\Users\Public\nt230_d12_marker.txt` xuất hiện, nội dung `NT230-D12-MARKER`.
- Evidence JSON ghi `marker_seen: true`, timeline `subscription-created` ->
  `marker-check` -> `cleanup`.
- Sau khi script kết thúc, không còn object `NT230_D12_*`.

### V2 - process creation + tên masquerade

```powershell
.\poc\Invoke-WmiSubscription.ps1 -Variant V2 -WaitForMarker `
  -EvidencePath .\reports\poc-v2.json
```

Script tự mở `notepad.exe` để kích hoạt filter rồi tắt process. Marker xuất hiện
trong vòng vài giây.

### V3 - encoded PowerShell

```powershell
.\poc\Invoke-WmiSubscription.ps1 -Variant V3 -WaitForMarker `
  -EvidencePath .\reports\poc-v3.json
```

Command line chứa `-EncodedCommand`; nội dung decode là lệnh ghi marker, không có
network hay payload khác.

### V4 - namespace tùy chỉnh + delay

```powershell
# delay mặc định 300 giây; có thể rút ngắn để demo
.\poc\Invoke-WmiSubscription.ps1 -Variant V4 -TriggerDelaySeconds 20 `
  -TimeoutSeconds 60 -WaitForMarker -EvidencePath .\reports\poc-v4.json
```

Tạo namespace `root\NT230Lab`, timer 20 giây, consumer nằm trong namespace đó.
Cleanup xóa namespace cùng các object con.

### V5 - ActiveScript consumer

```powershell
.\poc\Invoke-WmiSubscription.ps1 -Variant V5 -WaitForMarker `
  -EvidencePath .\reports\poc-v5.json
```

VBScript chạy trong `WmiPrvSE.exe`, ghi marker. Không có process con, nên đây là
case để kiểm tra lớp nội dung script.

### Kiểm tra thủ công (tùy chọn)

```powershell
# giữ object lại để xem
.\poc\Invoke-WmiSubscription.ps1 -Variant V2 -Keep

# liệt kê object của lab
.\poc\Invoke-WmiSubscription.ps1 -Variant V2 -Action Status

# xem filter/consumer/binding
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Where-Object Name -like 'NT230_D12_*' | Format-List Name, Query, EventNamespace, CreatorSID

Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
  Format-List Filter, Consumer
```

### Cleanup

```powershell
.\poc\Invoke-WmiSubscription.ps1 -Variant V1 -Action Remove
.\poc\Invoke-WmiSubscription.ps1 -Variant V2 -Action Remove
.\poc\Invoke-WmiSubscription.ps1 -Variant V3 -Action Remove
.\poc\Invoke-WmiSubscription.ps1 -Variant V4 -Action Remove
.\poc\Invoke-WmiSubscription.ps1 -Variant V5 -Action Remove
```

Xác nhận không còn sót:

```powershell
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Where-Object Name -like 'NT230_D12_*'
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
  Where-Object Name -like 'NT230_D12_*'
Get-CimInstance -Namespace root -ClassName __Namespace |
  Where-Object Name -eq 'NT230Lab'
```

Cả ba lệnh phải trả về rỗng. Nếu không, rollback snapshot.

---

## 2. Kiểm chứng persistence qua reboot (trong VM)

Đây là bằng chứng cốt lõi của T1546.003.

```powershell
# 1. Tạo subscription nhưng không xóa
.\poc\Invoke-WmiSubscription.ps1 -Variant V1 -Keep

# 2. Reboot VM
Restart-Computer -Force
```

Sau reboot, đăng nhập lại:

```powershell
# 3. Object vẫn còn?
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Where-Object Name -like 'NT230_D12_*' | Format-List Name, Query

# 4. Marker cũ đã bị xóa trước khi reboot; xóa để quan sát lần chạy mới
Remove-Item C:\Users\Public\nt230_d12_marker.txt -ErrorAction SilentlyContinue

# 5. Chờ timer (15 giây) rồi kiểm tra marker
Start-Sleep -Seconds 20
Get-Content C:\Users\Public\nt230_d12_marker.txt
```

Kỳ vọng: object vẫn tồn tại sau reboot và marker được tạo lại, chứng minh
subscription nằm trong repository chứ không phụ thuộc process.

Cleanup sau bước này:

```powershell
.\poc\Invoke-WmiSubscription.ps1 -Variant V1 -Action Remove
```

---

## 3. Chạy collector + detector trên kết quả PoC

Trong VM, khi subscription còn tồn tại (`-Keep`):

```powershell
.\collector\Collect-WmiSubscriptions.ps1 `
  -OutputPath .\data\live\repository.json `
  -Namespace root\subscription,root\NT230Lab

.\collector\Collect-WmiActivityLog.ps1 `
  -OutputPath .\data\live\wmi_activity.jsonl `
  -MaxEvents 5000 -SinceDays 1

python -m detector.cli scan --scenario data\live --json-out reports\vm-scan.json
```

Kỳ vọng với V1: verdict `MALICIOUS`, score >= 60, evidence có R01/R04/R05/R09;
có thể thêm R10 nếu tên masquerade và R14 nếu Sysmon bật. Lần chạy thật trong VM
đạt đúng 60 điểm với R01/R04/R05/R09 (tên `NT230_D12_V1_Filter` không masquerade
nên không có R10).

Với V4: cần truyền thêm `root\NT230Lab` vào `-Namespace`, nếu không collector sẽ
không thấy object (đây là hành vi đúng, thể hiện giới hạn coverage).

### 3b. Run thật đã thực hiện (Windows 10 22H2 + VirtualBox 7.0.26)

Đây là cấu hình đã dùng để sinh bằng chứng trong `reports/vm-live/`:

```text
Host      : Acer Nitro AN515-44, VirtualBox 7.0.26
VM        : NT230-D12-WinLab, Windows 10 22H2 build 19041
Snapshot  : clean-baseline (chụp trước khi chạy PoC)
Account   : NT230LAB\student
```

Trình tự:

1. Bật WMI-Activity log và kiểm tra VM guard:

```powershell
wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true
Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model
```

2. Chạy PoC V1 với `-WaitForMarker -Keep` để collector còn thấy object. Trong
   lab này quyền elevated có được bằng scheduled task (batch logon token chạy ở
   High Mandatory Level), không cần bật UAC:

```cmd
schtasks /Create /TN NT230_D12_PoC /TR C:\NT230\run-poc.cmd /SC ONCE /ST 23:59 ^
  /RU student /RP "<password>" /F
schtasks /Run /TN NT230_D12_PoC
```

3. Kết quả thật (xem `reports/vm-live/out/runner.log`):

```text
[07:50:17] running V1 Create -WaitForMarker -Keep
[07:50:40] V1 completed; marker_exists=True
[07:50:40] marker content: NT230-D12-MARKER
[07:50:41] repository collected
[07:50:42] events collected
[07:50:42] cleanup complete
```

4. Chạy detector trên dữ liệu thật:

```bash
python3 -m detector.cli scan --scenario reports/vm-live/out \
  --json-out reports/vm-live/detector.json
```

Kết quả: `MALICIOUS score=60/100` với R01 (+25), R04 (+15), R05 (+10), R09
(+10); built-in `SCM Event Log Filter` vẫn benign nhờ allow-list.

5. Rollback:

```bash
VBoxManage snapshot "NT230-D12-WinLab" restore clean-baseline
VBoxManage controlvm "NT230-D12-WinLab" poweroff
```

**Bài học cấu hình (đã sửa trong `poc/Invoke-WmiSubscription.ps1`):**

| Triệu chứng | Nguyên nhân | Sửa |
|---|---|---|
| Filter tạo được, 5861 có, nhưng marker không bao giờ xuất hiện | `__TimerEvent` được phát từ `root\default`, không phải `root\cimv2` | Đặt `EventNamespace = 'root\default'` cho V1/V4 |
| Timer event bị bỏ qua lần đầu | Query `NumEvents = 1` quá chặt | Bỏ điều kiện `NumEvents` khỏi query timer |

Regression test: `tests/test_poc_timer_config.py`.

---

## 4. Benign control

```powershell
.\poc\benign\New-BenignSubscription.ps1 -WaitForLog `
  -EvidencePath .\reports\benign-control.json
```

Script tạo `LogFileEventConsumer` ghi service state vào
`C:\ProgramData\IT\logs\service-state.log`, restart Spooler để sinh event, rồi xóa
subscription. Detector phải cho score < 40 (benign).

---

## 5. Live read-only trên máy phân tích

Không tạo object nào:

```bash
./scripts/run_live.sh
```

Script gọi:

```powershell
.\collector\Collect-WmiSubscriptions.ps1
.\collector\Collect-WmiActivityLog.ps1 -MaxEvents 5000 -SinceDays 30
```

rồi chạy detector ở cả hai chế độ (`repository` và `events`).

---

## 6. Troubleshooting

| Lỗi | Nguyên nhân | Cách xử lý |
|---|---|---|
| `VM guard: this host does not look like a virtual machine` | Đang chạy trên host vật lý | Chuyển vào VM; không dùng `-Force` trên máy thật |
| `Access denied` khi tạo object | PowerShell không elevated | Chạy as Administrator |
| Marker không xuất hiện | Filter chưa match / timer chưa tới | Tăng `-TimeoutSeconds`; kiểm tra `Get-CimInstance`; xem event 5859/5860 |
| Timer filter tạo được nhưng không bao giờ fire | `__TimerEvent` nằm ở `root\default`, không phải `root\cimv2` | Đặt `EventNamespace = 'root\default'`; xem mục 3b |
| `Cannot read __EventFilter` | Namespace sai hoặc WMI service lỗi | Kiểm tra `Get-Service Winmgmt`; thêm đúng `-Namespace` |
| 5861 không có | Log bị tắt hoặc chưa có activation | `wevtutil sl ... /e:true`; restart WMI service trong VM |
| Detector không thấy V4 | Chưa scan `root\NT230Lab` | Thêm namespace vào collector |
| `Remove` không xóa hết | Object tạo bởi script khác | Kiểm tra theo prefix `NT230_D12_`; rollback snapshot |

---

## 7. Bằng chứng đã chạy trong môi trường hiện tại

| Bước | Kết quả | File |
|---|---|---|
| Offline pipeline | 9 scenario, strict F1 0.909, triage F1 1.000 | `reports/metrics.json` |
| Pytest | 33 passed | `reports/test-results.txt` |
| Live read-only repository | 1 filter/1 consumer/1 binding | `data/live/repository.json` |
| Live event log | ~1.2k events | `data/live/wmi_activity.jsonl` |
| Live detector | BENIGN score 0, allow-list | `reports/live-scan.txt` |
| PoC dry-run V1-V5 | cấu hình hợp lệ, không tạo object | `reports/poc-dryrun/V*.json` |
| PoC create trên host vật lý | bị VM guard từ chối (đúng thiết kế) | `docs/06-safety.md` |
| **PoC V1 thật trong VM Windows 10** | filter/consumer/binding tạo được, marker sau ~23 giây | `reports/vm-live/out/poc-v1.json` |
| **Detector trên dữ liệu VM thật** | `MALICIOUS 60/100` (R01/R04/R05/R09) | `reports/vm-live/detector-scan.txt` |
| **Cleanup + rollback** | 4 object bị xóa, VM restore `clean-baseline` | `reports/vm-live/out/cleanup.txt` |
