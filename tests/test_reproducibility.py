"""The committed dataset and reports must be regenerable byte-for-byte.

This is the guard against "report drift": if someone edits a report by hand or
changes a generator without re-running it, CI fails.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from evaluation import evaluate
from simulator.generate_dataset import generate

ROOT = Path(__file__).resolve().parents[1]


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_dataset_regenerates_byte_identical(tmp_path: Path) -> None:
    generate(tmp_path / "scenarios")
    generated_root = tmp_path
    committed_root = ROOT / "data"
    for name in ("manifest.json", "ground_truth.csv"):
        assert (generated_root / name).read_bytes() == (committed_root / name).read_bytes(), name
    for generated in sorted((generated_root / "scenarios").rglob("*")):
        if not generated.is_file():
            continue
        relative = generated.relative_to(generated_root)
        committed = committed_root / relative
        assert committed.exists(), relative
        assert generated.read_bytes() == committed.read_bytes(), relative


def test_evaluation_regenerates_committed_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    generate(tmp_path / "scenarios")
    reports = tmp_path / "reports"
    with contextlib.redirect_stdout(io.StringIO()):
        code = evaluate.main(
            [
                "--dataset",
                str(tmp_path / "scenarios"),
                "--reports",
                str(reports),
            ]
        )
    assert code == 0

    for name in (
        "per_scenario.csv",
        "confusion_matrix.csv",
        "threshold_sensitivity.csv",
        "rule_ablation.csv",
        "robustness.csv",
        "validation.json",
    ):
        assert (reports / name).read_bytes() == (ROOT / "reports" / name).read_bytes(), name

    fresh = _read_json(reports / "metrics.json")
    committed = _read_json(ROOT / "reports" / "metrics.json")
    fresh.pop("dataset", None)
    committed.pop("dataset", None)
    for item in fresh["results"]:
        item.pop("directory", None)
    for item in committed["results"]:
        item.pop("directory", None)
    assert fresh == committed

    fresh_md = (reports / "evaluation-report.md").read_text(encoding="utf-8")
    fresh_md = fresh_md.replace(str(tmp_path / "scenarios"), "data/scenarios")
    assert fresh_md == (ROOT / "reports" / "evaluation-report.md").read_text(encoding="utf-8")
