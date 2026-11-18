<#
.SYNOPSIS
    Read-only export of Microsoft-Windows-WMI-Activity/Operational events.

.DESCRIPTION
    Exports the event IDs relevant to permanent WMI subscriptions:
      5857 - WMI provider started
      5858 - WMI operation (query/exec) with namespace and client
      5859 - permanent event filter activated
      5860 - permanent event consumer activated
      5861 - permanent subscription registered (contains the full filter and
             consumer CIM instances)

    The script only reads the event log and writes JSONL for detector/parser.py.

.PARAMETER OutputPath
    Destination .jsonl file. Default data/live/wmi_activity.jsonl

.PARAMETER MaxEvents
    Maximum number of events to export. Default 5000.

.PARAMETER SinceDays
    Only export events newer than N days. Default 30.

.EXAMPLE
    .\Collect-WmiActivityLog.ps1 -MaxEvents 2000
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [int]$MaxEvents = 5000,
    [int]$SinceDays = 30,
    [int[]]$EventId = @(5857, 5858, 5859, 5860, 5861)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) {
    $OutputPath = Join-Path $root 'data/live/wmi_activity.jsonl'
}

$logName = 'Microsoft-Windows-WMI-Activity/Operational'
$startTime = (Get-Date).AddDays(-1 * [Math]::Abs($SinceDays))

function Convert-SidToAccount {
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return '' }
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate(
            [System.Security.Principal.NTAccount]).Value
    }
    catch {
        return $Sid
    }
}

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = $logName
        Id        = $EventId
        StartTime = $startTime
    } -MaxEvents $MaxEvents -ErrorAction Stop
}
catch {
    Write-Warning "Cannot read ${logName}: $($_.Exception.Message)"
    $events = @()
}

$directory = Split-Path -Parent $OutputPath
if ($directory -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

$writer = New-Object System.IO.StreamWriter(
    $OutputPath, $false, (New-Object System.Text.UTF8Encoding($false)))
try {
    foreach ($event in $events) {
        $userSid = ''
        if ($event.UserId) { $userSid = $event.UserId.Value }
        $record = [ordered]@{
            EventId     = [int]$event.Id
            Channel     = $event.LogName
            Provider    = $event.ProviderName
            TimeCreated = $event.TimeCreated.ToUniversalTime().ToString('o')
            Level       = $event.LevelDisplayName
            UserSid     = $userSid
            User        = (Convert-SidToAccount $userSid)
            Computer    = $event.MachineName
            RecordId    = [int]$event.RecordId
            Message     = $event.Message
        }
        $writer.WriteLine(($record | ConvertTo-Json -Depth 4 -Compress))
    }
}
finally {
    $writer.Dispose()
}

Write-Host ("exported {0} WMI-Activity events -> {1}" -f $events.Count, $OutputPath)
