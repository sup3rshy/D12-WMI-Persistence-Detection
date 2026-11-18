"""Regenerate data/checksums.txt for the committed telemetry artefacts.

The checksum file lets a reviewer detect silent edits to the labelled dataset
or to the live snapshot without re-reading every file. It is deliberately
small: only the telemetry that the detector actually consumes is covered.

Usage:
    python3 scripts/update_checksums.py          # rewrite data/checksums.txt
    python3 scripts/update_checksums.py --check  # exit 1 if it is stale
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKSUM_FILE = ROOT / "data" / "checksums.txt"


def _targets() -> list[Path]:
    paths = sorted(
        (ROOT / "data" / "scenarios").glob("*/repository.json")
    ) + sorted((ROOT / "data" / "scenarios").glob("*/wmi_activity.jsonl"))
    paths += [
        ROOT / "data" / "live" / "repository.json",
        ROOT / "data" / "live" / "wmi_activity.jsonl",
    ]
    return [path for path in paths if path.exists()]


def compute_checksums() -> str:
    lines = []
    for path in _targets():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(ROOT).as_posix()}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the file instead of rewriting it",
    )
    args = parser.parse_args(argv)

    expected = compute_checksums()
    if args.check:
        actual = CHECKSUM_FILE.read_text(encoding="utf-8") if CHECKSUM_FILE.exists() else ""
        if actual != expected:
            print("data/checksums.txt is stale; run scripts/update_checksums.py", file=sys.stderr)
            return 1
        print(f"checksums ok ({len(_targets())} files)")
        return 0

    CHECKSUM_FILE.parent.mkdir(parents=True, exist_ok=True)
    CHECKSUM_FILE.write_text(expected, encoding="utf-8", newline="\n")
    print(f"wrote {len(_targets())} checksums to {CHECKSUM_FILE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
