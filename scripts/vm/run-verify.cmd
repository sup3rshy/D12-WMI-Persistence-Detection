@echo off
if not exist C:\NT230\reboot-evidence mkdir C:\NT230\reboot-evidence
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\NT230\Reboot-Persistence-Test.ps1 -Phase Verify > C:\NT230\reboot-evidence\verify-console.txt 2>&1
