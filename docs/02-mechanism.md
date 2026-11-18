# 02 - Cơ chế WMI Event Subscription

Tài liệu này giải thích **vì sao** kỹ thuật hoạt động và **telemetry nào** được
sinh ra, làm cơ sở cho thiết kế detector.

---

## 1. WMI eventing trong một đoạn

WMI là implementation của WBEM/CIM trên Windows. Thành phần chính:

| Thành phần | Vai trò |
|---|---|
| `Winmgmt` service | Chủ sở hữu repository, điều phối provider và event subsystem |
| `WmiPrvSE.exe` | Host process cho provider và consumer, thường chạy dưới SYSTEM |
| Namespace | Không gian tên logic, ví dụ `root\cimv2`, `root\subscription`, `root\default` |
| Repository | File nhị phân `%SystemRoot%\System32\wbem\Repository\OBJECTS.DATA` + index |
| Event provider | Sinh event intrinsic (instance change) hoặc extrinsic (provider tự định nghĩa) |

Có hai loại subscription:

1. **Temporary** - đăng ký trong process (ví dụ `Register-CimIndicationEvent`),
   mất khi process kết thúc.
2. **Permanent** - lưu thành object trong repository, do `Winmgmt` quản lý, tồn
   tại qua reboot và logon. Đây là cơ chế của **T1546.003**.

---

## 2. Bộ ba object của permanent subscription

### 2.1 `__EventFilter` - "khi nào chạy"

```powershell
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name           = 'NT230_D12_V1_Filter'
    EventNamespace = 'root\cimv2'
    QueryLanguage  = 'WQL'
    Query          = "SELECT * FROM __TimerEvent WHERE TimerID = 'NT230D12TimerV1' AND NumEvents = 1"
}
```

Các thuộc tính quan trọng:

| Thuộc tính | Ý nghĩa | Giá trị đáng ngờ |
|---|---|---|
| `Name` | Định danh filter | Giả mạo SCM/Windows Update/Defender |
| `EventNamespace` | Namespace sinh event | Namespace lạ ngoài `root\cimv2` |
| `Query` | WQL chọn event | `__InstanceCreationEvent` trên `Win32_Process`, `Win32_Service`, registry |
| `QueryLanguage` | Thường là `WQL` | Giá trị khác WQL hiếm gặp |
| `CreatorSID` | SID người tạo | User thường thay vì SYSTEM |

### 2.2 `__EventConsumer` - "chạy cái gì"

`__EventConsumer` là abstract class. Các subclass phổ biến:

| Class | Hành vi | Mức rủi ro |
|---|---|---|
| `CommandLineEventConsumer` | Chạy command line | Cao: thực thi tùy ý |
| `ActiveScriptEventConsumer` | Chạy VBScript/JScript trong `WmiPrvSE` | Cao: không cần file thực thi |
| `LogFileEventConsumer` | Ghi text vào file | Trung bình: có thể là monitoring hợp lệ |
| `NTEventLogEventConsumer` | Ghi Windows Event Log | Trung bình: thường là built-in |
| `SMTPEventConsumer` | Gửi email | Trung bình, ít dùng |
| `ScriptEventConsumer` | Chạy script (legacy) | Cao, ít gặp |

Ví dụ:

```powershell
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name                = 'NT230_D12_V1_Consumer'
    CommandLineTemplate = 'cmd.exe /c echo NT230-D12-MARKER > "C:\Users\Public\nt230_d12_marker.txt"'
}
```

`ActiveScriptEventConsumer` không tạo process con; script chạy ngay trong
`WmiPrvSE.exe`. Vì vậy process telemetry có thể **không** thấy payload, và detector
phải dựa vào nội dung `ScriptText`.

### 2.3 `__FilterToConsumerBinding` - nối hai object

```powershell
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter   = $filter
    Consumer = $consumer
}
```

Đây là object quyết định persistence có hiệu lực. Nếu binding bị xóa, filter và
consumer còn lại chỉ là object mồ côi (orphan), không tự chạy. Detector vẫn báo
orphan vì đó là dấu vết forensics, nhưng mức điểm thấp hơn.

---

## 3. Các loại trigger

### 3.1 Timer

```sql
SELECT * FROM __TimerEvent
WHERE TimerID = 'NT230D12TimerV1' AND NumEvents = 1
```

Cần một object `__IntervalTimerInstruction` trong `root\default`:

```powershell
Set-WmiInstance -Namespace root\default -Class __IntervalTimerInstruction -Arguments @{
    TimerID              = 'NT230D12TimerV1'
    IntervalBetweenEvents = 15000
    SkipIfPassed          = $false
}
```

- `NumEvents = 1` làm subscription chỉ chạy một lần.
- `IntervalBetweenEvents` tính bằng milliseconds.
- Trigger delay dài (300 giây) làm giảm khả năng quan sát động.

### 3.2 Instance change (intrinsic event)

```sql
SELECT * FROM __InstanceCreationEvent WITHIN 5
WHERE TargetInstance ISA 'Win32_Process'
  AND TargetInstance.Name = 'notepad.exe'
```

- `WITHIN n` là chu kỳ polling của WMI (giây). `WITHIN 1..5` tạo tải cao và là
  tín hiệu đáng ngờ.
- Các class nhạy cảm: `Win32_Process`, `Win32_Service`, `Win32_LogonSession`,
  `Win32_ComputerSystem`, registry provider classes.
- Có thể dùng `__InstanceModificationEvent`, `__InstanceDeletionEvent`.

### 3.3 Extrinsic event

Provider tự định nghĩa event class (ví dụ `MSFT_SCMEventLogEvent`). Built-in
`SCM Event Log Filter` dùng loại này, nên query của nó trông "lành" và cần
allow-list riêng.

---

## 4. Vòng đời và thời điểm quan sát

```
T0  attacker tạo filter/consumer/binding
T1  Winmgmt ghi object vào repository
T2  WMI-Activity ghi 5861 (kèm nguyên definition)
T3  subscription được đăng ký lại mỗi khi WMI service khởi động
T4  event xảy ra -> filter match -> consumer chạy trong WmiPrvSE
T5  5859/5860 ghi nhận filter/consumer được kích hoạt
T6  attacker xóa binding/filter/consumer (dấu vết còn trong log)
```

Điểm mấu chốt: **T1-T2 xảy ra ngay cả khi payload chưa chạy**. Detector có thể
phát hiện trước khi marker/payload xuất hiện, miễn là thu thập được repository
hoặc event log.

---

## 5. Event ID liên quan

Log: `Microsoft-Windows-WMI-Activity/Operational`

| ID | Nội dung | Giá trị điều tra |
|---|---|---|
| 5857 | Provider started | Baseline provider, ít liên quan trực tiếp |
| 5858 | WMI operation | Chứa namespace, client, đôi khi WQL; hữu ích để hunt |
| 5859 | Permanent event filter activated | Xác nhận filter được nạp |
| 5860 | Permanent event consumer activated | Xác nhận consumer được nạp |
| 5861 | Permanent subscription registered | **Quan trọng nhất**: chứa cả filter và consumer definition |

Ví dụ thật từ host phân tích (rút gọn):

```
Namespace = //./root/subscription; Eventfilter = SCM Event Log Filter
(refer to its activate eventid:5859); Consumer = NTEventLogEventConsumer="SCM Event Log Consumer";
PossibleCause = Binding EventFilter:
instance of __EventFilter
{
    CreatorSID = {1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0};
    EventNamespace = "root\cimv2";
    Name = "SCM Event Log Filter";
    Query = "select * from MSFT_SCMEventLogEvent";
    QueryLanguage = "WQL";
};
Perm. Consumer:
instance of NTEventLogEventConsumer
{
    ...
    Name = "SCM Event Log Consumer";
    SourceName = "Service Control Manager";
};
```

Detector parse trực tiếp format này (`detector/parser.py::parse_5861`) nên có thể
làm việc chỉ với log, không cần query repository.

---

## 6. Vì sao khó phát hiện bằng công cụ thông thường

1. Không có file thực thi, service, Run key hay scheduled task.
2. Tên object có thể giả mạo thành phần hợp lệ.
3. `ActiveScriptEventConsumer` chạy trong `WmiPrvSE`, không tạo process con.
4. Subscription có thể nằm trong namespace tùy chỉnh, ngoài `root\subscription`.
5. Trigger delay dài khiến hành vi không xuất hiện trong thời gian quan sát ngắn.
6. Attacker có thể xóa object sau khi dùng; chỉ còn event log.

---

## 7. Liên hệ với PoC và detector

| Cơ chế | PoC | Detector |
|---|---|---|
| Timer one-shot | V1, V4 | Rule R01/R04/R05/R10/R11 |
| Process-creation WQL | V2, V3, V5 | Rule R07/R08 |
| CommandLine consumer | V1-V4, V6 | Rule R01/R02/R04/R05 |
| ActiveScript consumer | V5 | Rule R01/R06 |
| Namespace tùy chỉnh | V4 | Rule R11 |
| Trigger delay | V4 | Không chấm điểm riêng; làm mất lớp R14 |
| Masquerade name | V1, V2, V4, V5 | Rule R10 |
| WmiPrvSE child process | V1, V3 | Rule R14 |

Chi tiết trọng số: [`03-detection-design.md`](03-detection-design.md).
