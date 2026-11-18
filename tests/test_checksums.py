"""The committed telemetry checksums must match the committed files."""

from __future__ import annotations

from scripts.update_checksums import CHECKSUM_FILE, compute_checksums


def test_checksums_are_current() -> None:
    assert CHECKSUM_FILE.read_text(encoding="utf-8") == compute_checksums()


def test_checksums_cover_every_scenario() -> None:
    text = CHECKSUM_FILE.read_text(encoding="utf-8")
    scenario_dirs = sorted(
        path.name for path in (CHECKSUM_FILE.parent / "scenarios").iterdir() if path.is_dir()
    )
    assert len(scenario_dirs) == 15
    for name in scenario_dirs:
        assert f"data/scenarios/{name}/repository.json" in text
        assert f"data/scenarios/{name}/wmi_activity.jsonl" in text
