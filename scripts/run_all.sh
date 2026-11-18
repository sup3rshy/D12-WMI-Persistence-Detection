#!/usr/bin/env bash
# Full offline pipeline: dataset -> evaluation -> tests.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/4] generating labelled dataset"
python3 -m simulator.generate_dataset --out data/scenarios

echo "[2/4] evaluating detector"
python3 -m evaluation.evaluate

echo "[3/4] running tests"
python3 -m pytest -q

echo "[4/4] artefacts"
ls -1 reports/

echo "done. open reports/evaluation-report.md"
