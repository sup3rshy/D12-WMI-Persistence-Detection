# Dataset samples

Thư mục này chỉ chứa mô tả. Dataset thực tế nằm ở:

- `../data/scenarios/` - 15 scenario có nhãn (6 benign, 9 malicious), sinh bởi
  `simulator/generate_dataset.py`.
- `../data/manifest.json` - thống kê và danh sách scenario.
- `../data/ground_truth.csv` - nhãn dạng bảng.
- `../data/live/` - snapshot read-only từ host phân tích (1 subscription built-in
  `SCM Event Log Filter`, ~1.2k event WMI-Activity).

Mỗi scenario gồm:

```
<scenario_id>/
├── repository.json        # filters / consumers / bindings
├── wmi_activity.jsonl     # 5857-5861 events, 5861 chứa full definition
├── process_events.jsonl   # Sysmon-style, có thể rỗng
└── ground_truth.json      # label, category, variant, tags
```

Xem `../docs/07-dataset-card.md` để biết provenance, label guide và giới hạn.
