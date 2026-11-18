<#
.SYNOPSIS
    Benign control for the D12 lab: a legitimate monitoring subscription.

.DESCRIPTION
    Creates a LogFileEventConsumer that records Win32_Service state changes to
    a text file, waits (optionally) for evidence, and removes the subscription.
    This is the operational counterpart used to measure false positives.

    Run only in a snapshot VM. Use -Keep to inspect the objects manually.
#>
[CmdletBinding()]
param(
    [string]$LogPath,
    [int]$TimeoutSeconds = 20,
    [switch]$WaitForLog,
    [switch]$Keep,
    [switch]$Force,
    [string]$EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $LogPath) {
    $LogPath = Join-Path $env:ProgramData 'IT\logs\service-state.log'
}

$filterName = 'NT230_D12_Benign_ServiceAudit'
$consumerName = 'NT230_D12_Benign_LogWriter'

function Test-LabVirtualMachine {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        $identity = ("{0} {1} {2}" -f $cs.Manufacturer, $cs.Model, $bios.SerialNumber).ToLower()
        return [bool]($identity -match 'vmware|virtualbox|virtual machine|hyper-v|qemu|xen|parallels|bochs|innotek')
    }
    catch { return $false }
}

$isVm = Test-LabVirtualMachine
if (-not $isVm -and -not $Force) {
    throw 'VM guard: benign controls must also run in a snapshot VM (-Force only on disposable lab VM).'
}

$evidence = [ordered]@{
    control     = 'benign-service-audit'
    vm_detected = $isVm
    host        = $env:COMPUTERNAME
    log_path    = $LogPath
    marker_seen = $false
    cleanup     = ''
}

try {
    $directory = Split-Path -Parent $LogPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
        Name           = $filterName
        EventNamespace = 'root\cimv2'
        QueryLanguage  = 'WQL'
        Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Service'"
    }
    $consumer = Set-WmiInstance -Namespace root\subscription -Class LogFileEventConsumer -Arguments @{
        Name        = $consumerName
        LogFilePath = $LogPath
        Text        = 'Service changed: %TargetInstance.Name% -> %TargetInstance.State%'
    }
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
        Filter   = $filter
        Consumer = $consumer
    } | Out-Null

    if ($WaitForLog) {
        # Restart a harmless service to generate a real state change.
        $service = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
        if ($service) {
            Restart-Service -Name 'Spooler' -Force -ErrorAction SilentlyContinue
        }
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            if (Test-Path -LiteralPath $LogPath) {
                $evidence['marker_seen'] = (Get-Item -LiteralPath $LogPath).Length -gt 0
                if ($evidence['marker_seen']) { break }
            }
            Start-Sleep -Seconds 1
        }
    }
}
finally {
    if (-not $Keep) {
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
            Where-Object { "$($_.Filter)" -match $filterName -or "$($_.Consumer)" -match $consumerName } |
            Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'" -ErrorAction SilentlyContinue |
            Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class LogFileEventConsumer -Filter "Name='$consumerName'" -ErrorAction SilentlyContinue |
            Remove-WmiObject -ErrorAction SilentlyContinue
        $evidence['cleanup'] = 'removed'
    }
    else {
        $evidence['cleanup'] = 'kept (-Keep)'
    }

    if ($EvidencePath) {
        $dir = Split-Path -Parent $EvidencePath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $json = $evidence | ConvertTo-Json -Depth 4
        [System.IO.File]::WriteAllText($EvidencePath, $json, (New-Object System.Text.UTF8Encoding($false)))
    }
}

$evidence | ConvertTo-Json -Depth 4
