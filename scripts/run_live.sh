#!/usr/bin/env bash
# Read-only live collection on a Windows host through WSL interop.
# Creates no WMI objects; safe to run on the analysis workstation.
set -euo pipefail
cd "$(dirname "$0")/.."

WIN_ROOT=$(wslpath -w "$PWD")

powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File "collector\\Collect-WmiSubscriptions.ps1" \
  -OutputPath "$WIN_ROOT\\data\\live\\repository.json"

powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File "collector\\Collect-WmiActivityLog.ps1" \
  -MaxEvents 5000 -SinceDays 30 \
  -OutputPath "$WIN_ROOT\\data\\live\\wmi_activity.jsonl"

echo "--- repository scan ---"
python3 -m detector.cli scan --scenario data/live --json-out reports/live-scan.json

echo "--- event-log-only reconstruction ---"
python3 -m detector.cli scan --scenario data/live --source events
