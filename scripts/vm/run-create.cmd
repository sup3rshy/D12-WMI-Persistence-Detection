@echo off
if not exist C:\NT230\reboot-evidence mkdir C:\NT230\reboot-evidence
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\NT230\Reboot-Persistence-Test.ps1 -Phase Create > C:\NT230\reboot-evidence\create-console.txt 2>&1
