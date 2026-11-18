# 06 - An toàn và phạm vi lab

Đề tài D12 yêu cầu PoC persistence trong VM có snapshot, payload vô hại, không C2,
không credential theft, không exfiltration, không phát tán mẫu. Tài liệu này ghi
lại các kiểm soát đã triển khai và quyết định **không chạy PoC trên máy phân tích**.

---

## 1. Quyết định quan trọng: không tạo persistence trên host vật lý

Máy phân tích hiện tại:

```
Manufacturer      : Acer
Model             : Nitro AN515-44
HypervisorPresent : True   (do WSL2/Hyper-V, không đủ để coi là VM lab)
```

Đây là **laptop vật lý**, không phải VM có snapshot. Mặc dù `HypervisorPresent`
là `True` (WSL2), đây không phải bằng chứng của một lab VM. Vì vậy nhóm:

1. **Không chạy** `Invoke-WmiSubscription.ps1 -Action Create` trên máy này.
2. Chỉ chạy collector **read-only** để kiểm chứng schema/parser.
3. Chạy PoC ở chế độ `-DryRun` để kiểm tra cấu hình V1-V5.
4. Thử `-Action Create` một lần để chứng minh VM guard từ chối (không tạo object).

Bằng chứng: [`reports/safety-guard.txt`](../reports/safety-guard.txt)

```
=== VM guard test (Create must refuse) ===
VM guard: this host does not look like a virtual machine. ...
=== no lab objects created ===
"vm_detected": false,
"objects": []
```

Đây là hành vi đúng theo rubric: "Vi phạm an toàn nghiêm trọng: không đạt phần D".

---

## 1b. Ngoại lệ có kiểm soát: chạy PoC thật trong VM snapshot

Sau khi hoàn tất phần offline, nhóm chạy **một** PoC thật (V1) trong VM chuyên
dụng để lấy bằng chứng end-to-end. Việc này không thay đổi quyết định ở mục 1:
máy vật lý vẫn không bao giờ tạo object.

| Kiểm soát | Giá trị |
|---|---|
| Hypervisor | VirtualBox 7.0.26, VM `NT230-D12-WinLab` |
| Guest | Windows 10 22H2 build 19041, 6 GB RAM, 4 vCPU, NAT |
| Snapshot trước khi chạy | `clean-baseline` (UUID `2a91413f-...`) |
| Tài khoản | `NT230LAB\student` (local, trong VM) |
| Object tạo ra | 1 filter + 1 consumer + 1 binding, prefix `NT230_D12_` |
| Payload | `cmd.exe /c echo NT230-D12-MARKER > C:\Users\Public\nt230_d12_marker.txt` |
| Thời gian sống | ~30 giây (tạo, chờ marker, thu evidence, xóa) |
| Cleanup | `-Action Remove` xóa 4 object; sau đó VM restore snapshot và poweroff |

Điểm cần lưu ý: để có quyền tạo object, nhóm dùng scheduled task chạy dưới
account `student` (batch logon token ở High Mandatory Level) thay vì bật UAC.
Cách này **chỉ dùng trong VM lab**, không phải kỹ thuật né bảo vệ và không được
đưa vào hướng dẫn chạy trên máy thật.

Bằng chứng: `reports/vm-live/out/runner.log`, `poc-v1.json`, `marker.txt`,
`repository.json`, `wmi_activity.jsonl`, `cleanup.txt`;
detector: `reports/vm-live/detector-scan.txt`.

---

## 2. VM guard hoạt động thế nào

`poc/Invoke-WmiSubscription.ps1` kiểm tra:

```powershell
$identity = "$($cs.Manufacturer) $($cs.Model) $($bios.SerialNumber)".ToLower()
$isVm = $identity -match 'vmware|virtualbox|virtual machine|hyper-v|qemu|xen|parallels|bochs|innotek'
```

Nếu không phải VM và không có `-Force`, script `throw` **trước khi** gọi bất kỳ
`Set-WmiInstance` nào. `-Force` chỉ dành cho VM dùng một lần; tài liệu không khuyến
khích dùng trên máy thật.

`New-BenignSubscription.ps1` cũng có guard tương tự, vì benign control vẫn tạo
permanent subscription.

---

## 3. Thiết kế payload vô hại

| Thành phần | Giá trị | Ghi chú |
|---|---|---|
| Marker | `NT230-D12-MARKER` | Chỉ là text |
| Đường dẫn | `%PUBLIC%\nt230_d12_marker.txt`, `%APPDATA%\cache.dat`, `C:\Windows\Temp\...` | Không ghi đè file hệ thống |
| Command | `cmd.exe /c echo ... > marker` | Không download, không exec payload |
| PowerShell | `Write-Output ... | Out-File` | Encode chỉ để mô phỏng obfuscation |
| VBScript | `FileSystemObject.CreateTextFile` | Không gọi network, không registry |
| JScript (dataset) | URL `http://198.51.100.23/...` | TEST-NET-2, **không được thực thi** |
| Network | Không có | Không C2, không exfil |
| Credential | Không có | Không LSASS, không token theft |
| Persistence | Chỉ WMI subscription trong phạm vi đề tài | Không service/Run key/scheduled task |

V5 trong **dataset** chứa network primitive dạng chuỗi để kiểm tra rule R03; đây
là dữ liệu tĩnh, không có script nào chạy nó. PoC V5 dùng VBScript ghi marker,
không có network.

---

## 4. Auto-cleanup

Mọi nhánh `Create` (trừ `-Keep`) đều gọi `Remove-LabObjects` trong `try/finally`:

- xóa binding khớp `FilterName`/`ConsumerName`
- xóa filter, consumer
- xóa `__IntervalTimerInstruction`
- xóa namespace `root\NT230Lab` nếu script tạo
- nếu creation throw giữa chừng, `catch` rollback trước khi rethrow
- chỉ xóa object có prefix `NT230_D12_` (không đụng subscription thật)
- `-Action Remove` cho phép dọn thủ công
- `-Action Status` liệt kê object còn sót

Kiểm tra sau cleanup:

```powershell
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Where-Object Name -like 'NT230_D12_*'
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
  Where-Object Name -like 'NT230_D12_*'
Get-CimInstance -Namespace root -ClassName __Namespace |
  Where-Object Name -eq 'NT230Lab'
```

Phải rỗng. Nếu không, rollback snapshot VM.

---

## 5. Dữ liệu và mẫu

- Không có malware thật, không có binary độc hại.
- Dataset là JSON/JSONL mô tả object và event; có thể chia sẻ công khai.
- B1 lấy từ host thật nhưng chỉ chứa tên/query built-in, không có dữ liệu cá nhân.
- Live export chứa tên máy (`LAPTOP-224O4NK2`) và SID hệ thống; nếu công bố ngoài
  phạm vi lớp, cần làm sạch (xóa `host.hostname`, `Computer`, `UserSid`).
- Bằng chứng VM trong `reports/vm-live/` chứa tên máy lab (`NT230LAB`), tài khoản
  `student` và SID của tài khoản đó. Đây là môi trường lab dùng một lần; trước khi
  công bố ra ngoài lớp nên thay bằng placeholder.
- Không có credential, token, hash hay nội dung file người dùng. Mật khẩu VM
  không được ghi trong tài liệu nộp bài (chỉ dùng trong lúc chạy lab).

---

## 6. Tuân thủ rubric

| Ràng buộc | Cách đáp ứng | Bằng chứng |
|---|---|---|
| Chỉ VM có snapshot/rollback | VM guard + không chạy Create trên host vật lý; lần chạy thật diễn ra trong VirtualBox với snapshot `clean-baseline` và đã rollback | `reports/safety-guard.txt`, `reports/vm-live/` |
| Payload vô hại | Marker text, không network/credential | `poc/`, `docs/06-safety.md` |
| Không C2 Internet | Không có kết nối mạng; URL TEST-NET-2 chỉ là chuỗi | `simulator/scenario_catalog.py` |
| Không credential theft/exfiltration | Không có code liên quan | test `test_payloads_are_inert_text_only` |
| Không persistence ngoài phạm vi | Chỉ WMI subscription, auto-cleanup, prefix riêng | `poc/Invoke-WmiSubscription.ps1` |
| Không phát tán mẫu | Dataset JSON/JSONL, không binary | `docs/07-dataset-card.md` |
| Không vô hiệu hóa bảo vệ | Không đụng Defender/AMSI/ETW | không có code |
| Snapshot/rollback | Hướng dẫn bắt buộc trước khi chạy; VM lab đã restore `clean-baseline` sau PoC | `docs/05-reproduction.md`, `reports/vm-live/` |

---

## 7. Nếu phát hiện object sót trên máy thật

1. **Không** reboot tiếp tục demo.
2. Chạy `-Action Remove` cho từng variant.
3. Kiểm tra 3 lệnh ở mục 4.
4. Nếu vẫn còn, dùng `Get-CimInstance` xác định `__PATH` rồi `Remove-CimInstance`.
5. Kiểm tra event log 5861 để biết object nào đã được đăng ký.
6. Ghi lại incident, rollback snapshot nếu là VM.

Không dùng `-Force` để chạy PoC trên máy thật chỉ vì "cần demo".
