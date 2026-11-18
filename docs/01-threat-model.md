# 01 - Threat model

**Kỹ thuật:** T1546.003 - Event Triggered Execution: WMI Event Subscription  
**Đối tượng:** Windows 10/11, WMI service (`Winmgmt`), namespace `root\subscription`  
**Mục tiêu phòng thủ:** phát hiện permanent WMI subscription được tạo để duy trì
thực thi qua reboot/logon, kể cả khi attacker thay đổi namespace, filter, consumer
hoặc thời điểm kích hoạt.

---

## 1. Câu hỏi nghiên cứu

> Với telemetry chỉ gồm WMI repository, WMI-Activity Operational log và process
> creation events, có thể phát hiện một permanent WMI subscription độc hại với
> precision/recall chấp nhận được, đồng thời giải thích được lý do cảnh báo và
> không tạo false positive với các subscription monitoring hợp lệ hay không?

Giả thuyết:

- **H1:** Chuỗi filter-consumer-binding trong repository đủ để phát hiện các biến
  thể tĩnh (V1, V5, V6) ngay cả khi không có process telemetry.
- **H2:** Nội dung consumer (command line/script) và WQL query tạo ra tín hiệu
  phân biệt mạnh hơn tên object.
- **H3:** Event 5861 bổ sung ngữ cảnh user và xác nhận activation, nhưng không
  cần thiết cho mọi quyết định.

---

## 2. Tài sản và mục tiêu của attacker

| Tài sản | Mô tả | Tác động nếu bị chiếm |
|---|---|---|
| Tính toàn vẹn của WMI repository | `OBJECTS.DATA`, các object filter/consumer/binding | Persistence sống qua reboot, khó thấy bằng autorun thông thường |
| Quyền thực thi SYSTEM | WmiPrvSE thường chạy dưới SYSTEM | Leo thang đặc quyền, thực thi payload ngay cả khi user không đăng nhập |
| Credential/process context | Consumer chạy trong context của WMI service | Có thể đọc file, tạo process, gọi network dưới quyền cao |
| Audit trail | WMI-Activity log | Attacker có thể xóa log để giảm khả năng phát hiện |

---

## 3. Attacker model

**Điều kiện tiên quyết:** local administrator hoặc SYSTEM. Đây là đặc điểm thực
tế của T1546.003: ghi object vào `root\subscription` yêu cầu quyền cao.

**Năng lực giả định:**

- Tạo/xóa `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`.
- Chọn namespace tùy ý (`root\subscription`, `root\NT230Lab`, ...).
- Chọn consumer class: `CommandLineEventConsumer`, `ActiveScriptEventConsumer`,
  `LogFileEventConsumer`, `NTEventLogEventConsumer`, `SMTPEventConsumer`.
- Chọn WQL: timer, instance creation/modification/deletion, interval polling.
- Chọn thời điểm kích hoạt (ngay, sau 300 giây, khi user logon, khi process chạy).
- Đặt tên giả mạo thành phần tin cậy (SCM, Windows Update, Defender, Telemetry).
- Xóa subscription sau khi dùng để giảm dấu vết.

**Không giả định:**

- Không có kernel driver hay BYOVD.
- Không patch WMI service.
- Không có khả năng sửa detector.
- Không tấn công mạng thật trong lab.

---

## 4. Đường tấn công

```
Initial access / admin shell
        |
        v
[1] Tạo __EventFilter (WQL)          -> "khi nào chạy"
        |
        v
[2] Tạo __EventConsumer              -> "chạy cái gì"
        |
        v
[3] Tạo __FilterToConsumerBinding    -> nối filter với consumer
        |
        v
[4] WMI service lưu object vào repository, đăng ký permanent subscription
        |
        v
[5] Reboot / logon / timer / process event
        |
        v
[6] WmiPrvSE.exe kích hoạt consumer -> cmd.exe / powershell / script host
        |
        v
[7] Marker file / payload / C2 (trong lab: chỉ marker text)
```

Điểm quan trọng: **không có service, registry Run key hay scheduled task** nào
được tạo. Vì vậy các công cụ chỉ quét autorun truyền thống sẽ bỏ sót.

---

## 5. Trust boundary và bề mặt quan sát

```
+--------------------------- VM / host ---------------------------+
| user session            | WMI service (Winmgmt)                 |
|  |                      |   |                                   |
|  | admin token -------->|   +--> repository (OBJECTS.DATA)      |
|  |                      |   +--> permanent subscription table   |
|  |                      |   +--> WmiPrvSE.exe (SYSTEM)          |
|  |                      |          |                            |
|  +-- process events ----|----------+--> child process          |
|                         |                                       |
|  event log <------------+---- WMI-Activity 5857..5861           |
+-----------------------------------------------------------------+
```

| Bề mặt | Ví dụ | Ai tạo ra | Độ tin cậy |
|---|---|---|---|
| WMI repository | `__EventFilter.Query`, `__EventConsumer.CommandLineTemplate` | WMI service | Cao, nhưng cần quyền đọc namespace |
| Event log | 5861 chứa nguyên definition của filter và consumer | WMI provider | Cao, phụ thuộc log enabled |
| Process telemetry | `WmiPrvSE.exe` -> `cmd.exe` | Sysmon/EDR | Trung bình, có thể mất nếu consumer chạy trong process |
| File system | marker file | Consumer | Thấp, chỉ là hệ quả |

---

## 6. Giả định phát hiện và điều kiện thất bại

| Giả định | Nếu sai |
|---|---|
| Collector đọc được namespace chứa subscription | Subscription trong namespace lạ sẽ bị bỏ sót |
| WMI-Activity Operational log được bật | Mất bằng chứng activation và user context |
| Tên built-in/allow-list được review định kỳ | Attacker copy tên hợp lệ có thể giảm điểm |
| Process telemetry có parent là `WmiPrvSE.exe` | Mất lớp behaviour, giảm điểm V1/V3 |
| Consumer dùng command/script có thể đọc tĩnh | Consumer mã hóa mạnh hoặc chỉ gọi API nội bộ có thể né rule nội dung |

---

## 7. Ngoài phạm vi

- Không đánh giá khả năng chống lại attacker có quyền kernel.
- Không phân tích memory forensics của `WmiPrvSE.exe`.
- Không phát hiện subscription được tạo rồi xóa hoàn toàn trước khi collector chạy
  (trừ khi còn event 5861/5859/5860).
- Không đánh giá WMI provider độc hại tự viết.
- Không thực thi payload thật, không kết nối C2, không thu thập credential.

---

## 8. Liên kết với rubric

| Yêu cầu rubric | Được xử lý ở đâu |
|---|---|
| Hiểu đối tượng, hành vi, bề mặt quan sát | tài liệu này + `02-mechanism.md` |
| Threat model và điều kiện kích hoạt | mục 3-6 |
| Benign vs malicious | `07-dataset-card.md` (label guide) |
| Điểm có thể gây nhầm lẫn | B2/B3 hard negatives, M6 low-noise, mục 6 |
