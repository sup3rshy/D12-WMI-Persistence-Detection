# Bằng chứng chạy PoC thật trong VM

Thư mục này chứa bằng chứng của **một lần chạy PoC V1 thật** trong VM Windows 10
22H2, dùng để kiểm chứng end-to-end rằng PoC tạo được T1546.003 và detector phát
hiện được telemetry thật.

## Môi trường

| Thành phần | Giá trị |
|---|---|
| Hypervisor | VirtualBox 7.0.26 |
| VM | `NT230-D12-WinLab` |
| Guest | Windows 10 22H2 build 19041, 6 GB RAM, 4 vCPU, NAT |
| Guest Additions | 7.0.26 |
| Snapshot trước khi chạy | `clean-baseline` |
| Account | `NT230LAB\student` (high integrity qua scheduled task) |
| Thời điểm | 2026-11-17 07:50 UTC |

## Kết quả

```text
[07:50:17] timer-created          NT230D12TimerV1 interval=15000ms
[07:50:17] subscription-created   NT230_D12_V1_Filter -> CommandLineEventConsumer:NT230_D12_V1_Consumer
[07:50:40] marker-check           C:\Users\Public\nt230_d12_marker.txt seen=True

runner.log
[07:50:40] V1 completed; marker_exists=True
[07:50:40] marker content: NT230-D12-MARKER
[07:50:41] repository collected
[07:50:42] events collected
[07:50:42] cleanup complete
```

- Marker xuất hiện **~23 giây** sau khi tạo subscription.
- Repository có 2 filter / 2 consumer / 2 binding: object của lab và built-in
  `SCM Event Log Filter`.
- `wmi_activity.jsonl` có 5861 ghi đúng filter/consumer/binding và
  `CreatorSID` của `student`.
- Detector: `MALICIOUS 60/100` (R01 +25, R04 +15, R05 +10, R09 +10).
- Built-in SCM subscription vẫn được allow-list và **không** báo động.
- Cleanup: `removed=4` object; sau đó VM restore snapshot `clean-baseline` và
  poweroff.

Điểm 60 thấp hơn bản render dry-run (70) vì event 5861 thật ghi user
`NT AUTHORITY\SYSTEM`, nên R13 không kích hoạt; R09 vẫn bắt `CreatorSID` của
`student`. Đây là khác biệt telemetry có thật, không phải lỗi detector.

## Danh sách file

| File | Nội dung |
|---|---|
| `out/runner.log` | log tuần tự của lần chạy |
| `out/poc-v1.json` | evidence JSON: variant, timeline, `marker_seen`, verdict |
| `out/marker.txt` | nội dung marker `NT230-D12-MARKER` |
| `out/repository.json` | filter/consumer/binding thu từ `root\subscription` |
| `out/wmi_activity.jsonl` | event 5857/5858/5859/5860/5861 |
| `out/status.txt` | 3 object còn tồn tại trước cleanup |
| `out/cleanup.txt` | kết quả `-Action Remove`, `removed=4` |
| `out/whoami-groups.txt` | chứng minh token High Mandatory Level trong VM |
| `out/host.txt` | xác nhận VM (VirtualBox) |
| `out/poc-v1-transcript.txt` | output PowerShell của PoC |
| `detector-scan.txt` | detector CLI trên dữ liệu thật |
| `detector.json` | alert/evidence dạng JSON |

## Rollback

```bash
VBoxManage snapshot "NT230-D12-WinLab" restore clean-baseline
VBoxManage controlvm "NT230-D12-WinLab" poweroff
```

Object đã được xóa trước khi rollback; snapshot là lớp bảo hiểm thứ hai.

## Ghi chú an toàn / quyền riêng tư

- Đây là VM lab dùng một lần, không phải máy thật.
- Payload chỉ ghi text marker; không network, không credential, không payload thứ hai.
- File chứa tên máy lab (`NT230LAB`), account `student` và SID tương ứng. Nếu công
  bố ngoài phạm vi lớp, thay bằng placeholder.
- Không có mật khẩu nào được lưu trong thư mục này.
