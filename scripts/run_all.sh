#!/usr/bin/env bash
# Full offline pipeline: dataset -> checksums -> evaluation -> tests.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/5] generating labelled dataset"
python3 -m simulator.generate_dataset --out data/scenarios

echo "[2/5] refreshing telemetry checksums"
python3 scripts/update_checksums.py

echo "[3/5] evaluating detector + validation suite"
python3 -m evaluation.evaluate

echo "[4/5] running tests"
python3 -m pytest -q

echo "[5/5] artefacts"
ls -1 reports/

echo "done. open reports/evaluation-report.md"
