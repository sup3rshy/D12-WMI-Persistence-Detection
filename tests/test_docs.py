"""Documentation must not drift from the generated metrics or break local links."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _markdown_files() -> list[Path]:
    return (
        [ROOT / "README.md"]
        + sorted((ROOT / "docs").glob("*.md"))
        + [ROOT / "reports" / "vm-live" / "README.md", ROOT / "dataset" / "samples" / "README.md"]
    )


def test_local_markdown_links_exist() -> None:
    broken: list[str] = []
    for path in _markdown_files():
        in_code = False
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                continue
            for match in LINK.finditer(line):
                target = match.group(1).strip()
                if target.startswith(("http://", "https://", "#", "mailto:")):
                    continue
                target = target.split("#", 1)[0]
                if not target:
                    continue
                if not (path.parent / target).resolve().exists():
                    broken.append(f"{path.relative_to(ROOT)}:{line_number} -> {target}")
    assert not broken, "broken local links:\n" + "\n".join(broken)


def test_readme_headline_metrics_match_report() -> None:
    report = json.loads((ROOT / "reports" / "metrics.json").read_text(encoding="utf-8"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for name, score in (("Strict (score >= 60)", 60), ("Triage (score >= 40)", 40)):
        row = report["metrics"]["strict" if score == 60 else "triage"]
        expected = (
            f"| {name} | {row['tp']} | {row['fp']} | {row['tn']} | {row['fn']} | "
            f"{row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} | {row['fpr']:.3f} |"
        )
        assert expected in readme, expected
