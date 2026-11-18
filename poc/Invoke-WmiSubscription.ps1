<#
.SYNOPSIS
    Benign T1546.003 PoC: create / inspect / remove permanent WMI event
    subscriptions that write an inert marker file.

.DESCRIPTION
    Lab-only. Every variant writes a text marker and nothing else. No network
    access, no credential access, no destructive action.

    Variants (the rubric requires >= 3 controlled variations):
      V1  baseline        __TimerEvent + CommandLineEventConsumer
      V2  filter/name     __InstanceCreationEvent (notepad) + masqueraded names
      V3  consumer        encoded PowerShell CommandLineEventConsumer
      V4  namespace/delay root\NT230Lab + 300 s timer + cmd copy
      V5  consumer        ActiveScriptEventConsumer (VBScript marker write)

    Actions:
      Create  create subscription, optionally wait for the marker, then clean up
              (unless -Keep is supplied)
      Remove  remove objects created by this script for the selected variant
      Status  list objects that match this lab's name prefix

.PARAMETER Force
    Bypass the virtual-machine guard. The course safety rules forbid running
    this PoC on a physical host, so use only in a disposable VM.

.PARAMETER WaitForMarker
    Wait until the marker file appears (or until -TimeoutSeconds).

.PARAMETER Keep
    Do not remove the subscription after creation (manual inspection only).

.EXAMPLE
    # Inside a snapshot VM, PowerShell as Administrator
    .\Invoke-WmiSubscription.ps1 -Variant V1 -WaitForMarker -EvidencePath ..\reports\poc-v1.json

.EXAMPLE
    .\Invoke-WmiSubscription.ps1 -Action Remove -Variant V4
#>
[CmdletBinding()]
param(
    [ValidateSet('V1', 'V2', 'V3', 'V4', 'V5')]
    [string]$Variant = 'V1',

    [ValidateSet('Create', 'Remove', 'Status')]
    [string]$Action = 'Create',

    [string]$MarkerPath,
    [int]$TriggerDelaySeconds = 0,
    [int]$TimeoutSeconds = 180,
    [switch]$WaitForMarker,
    [switch]$Keep,
    [switch]$Force,
    [switch]$DryRun,
    [string]$EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $MarkerPath) {
    $publicRoot = if ($env:PUBLIC) { $env:PUBLIC } else { 'C:\Users\Public' }
    $MarkerPath = Join-Path $publicRoot 'nt230_d12_marker.txt'
}

$script:Timeline = New-Object System.Collections.Generic.List[object]
$script:CreatedObjects = New-Object System.Collections.Generic.List[object]

function Add-Timeline {
    param([string]$Step, [string]$Detail = '')
    $script:Timeline.Add([ordered]@{
            time   = (Get-Date).ToUniversalTime().ToString('o')
            step   = $Step
            detail = $Detail
        })
}

function Test-LabVirtualMachine {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        $identity = ("{0} {1} {2}" -f $cs.Manufacturer, $cs.Model, $bios.SerialNumber).ToLower()
        return [bool]($identity -match 'vmware|virtualbox|virtual machine|hyper-v|qemu|xen|parallels|bochs|innotek')
    }
    catch {
        return $false
    }
}

function Get-VariantConfig {
    param([string]$Variant, [string]$MarkerPath, [int]$DelaySeconds)

    $common = [ordered]@{
        Namespace          = 'root\subscription'
        EventNamespace     = 'root\cimv2'
        FilterName         = "NT230_D12_${Variant}_Filter"
        ConsumerName       = "NT230_D12_${Variant}_Consumer"
        ConsumerClass      = 'CommandLineEventConsumer'
        ConsumerProperties = [ordered]@{}
        Query              = ''
        TimerId            = $null
        TimerIntervalMs    = 0
        TriggerProcess     = $null
        CreateNamespace    = $false
    }

    $cmdMarker = 'cmd.exe /c echo NT230-D12-MARKER > "{0}"' -f $MarkerPath

    switch ($Variant) {
        'V1' {
            $delay = if ($DelaySeconds -gt 0) { $DelaySeconds } else { 15 }
            # __IntervalTimerInstruction and __TimerEvent live in root\default.
            $common.EventNamespace = 'root\default'
            $common.Query = "SELECT * FROM __TimerEvent WHERE TimerID = 'NT230D12TimerV1'"
            $common.TimerId = 'NT230D12TimerV1'
            $common.TimerIntervalMs = $delay * 1000
            $common.ConsumerProperties['CommandLineTemplate'] = $cmdMarker
        }
        'V2' {
            $common.FilterName = 'NT230_D12_V2_Windows Update Monitor'
            $common.ConsumerName = 'NT230_D12_V2_Windows Update Consumer'
            $common.Query = "SELECT * FROM __InstanceCreationEvent WITHIN 3 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"
            $common.ConsumerProperties['CommandLineTemplate'] = $cmdMarker
            $common.TriggerProcess = 'notepad.exe'
        }
        'V3' {
            $markerLiteral = $MarkerPath.Replace("'", "''")
            $payloadScript = "Write-Output 'NT230-D12-MARKER' | Out-File -FilePath '$markerLiteral' -Encoding ascii"
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payloadScript))
            $common.Query = "SELECT * FROM __InstanceCreationEvent WITHIN 3 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"
            $common.ConsumerProperties['CommandLineTemplate'] =
                "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"
            $common.TriggerProcess = 'notepad.exe'
        }
        'V4' {
            $delay = if ($DelaySeconds -gt 0) { $DelaySeconds } else { 300 }
            # Timer events are delivered from root\default, even when the
            # filter/consumer/binding live in a custom namespace.
            $common.EventNamespace = 'root\default'
            $common.Namespace = 'root\NT230Lab'
            $common.CreateNamespace = $true
            $common.FilterName = 'NT230_D12_V4_Windows Defender Cache'
            $common.ConsumerName = 'NT230_D12_V4_DefenderCacheConsumer'
            $common.Query = "SELECT * FROM __TimerEvent WHERE TimerID = 'NT230D12TimerV4'"
            $common.TimerId = 'NT230D12TimerV4'
            $common.TimerIntervalMs = $delay * 1000
            $common.ConsumerProperties['CommandLineTemplate'] =
                'cmd.exe /c echo NT230-D12-MARKER > "{0}"' -f $MarkerPath
        }
        'V5' {
            $common.FilterName = 'NT230_D12_V5_InventorySync'
            $common.ConsumerName = 'NT230_D12_V5_InventorySyncAction'
            $common.ConsumerClass = 'ActiveScriptEventConsumer'
            $common.Query = "SELECT * FROM __InstanceCreationEvent WITHIN 3 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"
            $common.ConsumerProperties['ScriptingEngine'] = 'VBScript'
            $common.ConsumerProperties['ScriptText'] = @"
Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.CreateTextFile("$MarkerPath", True)
f.WriteLine "NT230-D12-MARKER"
f.Close
"@
            $common.TriggerProcess = 'notepad.exe'
        }
    }
    return $common
}

function New-LabNamespace {
    param([string]$Namespace)
    $name = $Namespace.Split('\')[-1]
    $existing = Get-CimInstance -Namespace root -ClassName __Namespace -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $name }
    if ($existing) { return $false }
    Set-WmiInstance -Namespace root -Class __Namespace -Arguments @{ Name = $name } | Out-Null
    Add-Timeline 'namespace-created' $Namespace
    return $true
}

function Remove-LabObjects {
    param([object]$Config)

    $removed = 0
    try {
        $bindings = Get-WmiObject -Namespace $Config.Namespace -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        foreach ($binding in $bindings) {
            if ("$($binding.Filter)" -match [regex]::Escape($Config.FilterName) -or
                "$($binding.Consumer)" -match [regex]::Escape($Config.ConsumerName)) {
                Remove-WmiObject -InputObject $binding -ErrorAction SilentlyContinue
                $removed++
            }
        }
    }
    catch { Write-Warning "binding cleanup: $($_.Exception.Message)" }

    try {
        $items = Get-WmiObject -Namespace $Config.Namespace -Class __EventFilter `
            -Filter "Name='$($Config.FilterName)'" -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            Remove-WmiObject -InputObject $item -ErrorAction SilentlyContinue
            $removed++
        }
    }
    catch { Write-Warning "filter cleanup: $($_.Exception.Message)" }

    try {
        $items = Get-WmiObject -Namespace $Config.Namespace -Class $Config.ConsumerClass `
            -Filter "Name='$($Config.ConsumerName)'" -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            Remove-WmiObject -InputObject $item -ErrorAction SilentlyContinue
            $removed++
        }
    }
    catch { Write-Warning "consumer cleanup: $($_.Exception.Message)" }

    if ($Config.TimerId) {
        try {
            $items = Get-WmiObject -Namespace root\default -Class __IntervalTimerInstruction `
                -Filter "TimerID='$($Config.TimerId)'" -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                Remove-WmiObject -InputObject $item -ErrorAction SilentlyContinue
                $removed++
            }
        }
        catch { Write-Warning "timer cleanup: $($_.Exception.Message)" }
    }

    if ($Config.CreateNamespace) {
        $name = $Config.Namespace.Split('\')[-1]
        try {
            $ns = Get-CimInstance -Namespace root -ClassName __Namespace -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $name }
            if ($ns) {
                Remove-CimInstance -InputObject $ns -ErrorAction SilentlyContinue
                Add-Timeline 'namespace-removed' $Config.Namespace
            }
        }
        catch { Write-Warning "namespace cleanup: $($_.Exception.Message)" }
    }

    Add-Timeline 'cleanup' "removed=$removed namespace=$($Config.Namespace)"
    return $removed
}

function New-LabSubscription {
    param([object]$Config)

    if ($Config.CreateNamespace) {
        New-LabNamespace -Namespace $Config.Namespace | Out-Null
    }

    if ($Config.TimerId) {
        Set-WmiInstance -Namespace root\default -Class __IntervalTimerInstruction -Arguments @{
            TimerID              = $Config.TimerId
            IntervalBetweenEvents = [uint32]$Config.TimerIntervalMs
            SkipIfPassed         = $false
        } | Out-Null
        Add-Timeline 'timer-created' "$($Config.TimerId) interval=$($Config.TimerIntervalMs)ms"
    }

    $filter = Set-WmiInstance -Namespace $Config.Namespace -Class __EventFilter -Arguments @{
        Name           = $Config.FilterName
        EventNamespace = $Config.EventNamespace
        QueryLanguage  = 'WQL'
        Query          = $Config.Query
    }
    $script:CreatedObjects.Add([ordered]@{ type = '__EventFilter'; name = $Config.FilterName; namespace = $Config.Namespace })

    $consumerArgs = @{
        Name = $Config.ConsumerName
    }
    foreach ($key in $Config.ConsumerProperties.Keys) {
        $consumerArgs[$key] = $Config.ConsumerProperties[$key]
    }
    $consumer = Set-WmiInstance -Namespace $Config.Namespace -Class $Config.ConsumerClass -Arguments $consumerArgs
    $script:CreatedObjects.Add([ordered]@{
            type      = $Config.ConsumerClass
            name      = $Config.ConsumerName
            namespace = $Config.Namespace
        })

    $binding = Set-WmiInstance -Namespace $Config.Namespace -Class __FilterToConsumerBinding -Arguments @{
        Filter   = $filter
        Consumer = $consumer
    }
    $script:CreatedObjects.Add([ordered]@{
            type      = '__FilterToConsumerBinding'
            name      = "$($Config.FilterName) -> $($Config.ConsumerName)"
            namespace = $Config.Namespace
        })

    Add-Timeline 'subscription-created' "$($Config.FilterName) -> $($Config.ConsumerClass):$($Config.ConsumerName)"
}

function Wait-Marker {
    param([string]$Path, [int]$Timeout, [string]$TriggerProcess)

    $launcher = $null
    if ($TriggerProcess) {
        $launcher = Start-Process -FilePath $TriggerProcess -PassThru
        Add-Timeline 'trigger-started' "$TriggerProcess pid=$($launcher.Id)"
    }

    $deadline = (Get-Date).AddSeconds($Timeout)
    $seen = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Path) { $seen = $true; break }
        Start-Sleep -Seconds 1
    }

    if ($launcher -and -not $launcher.HasExited) {
        Stop-Process -Id $launcher.Id -Force -ErrorAction SilentlyContinue
        Add-Timeline 'trigger-stopped' "$TriggerProcess pid=$($launcher.Id)"
    }

    Add-Timeline 'marker-check' "path=$Path seen=$seen"
    return $seen
}

# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

$config = Get-VariantConfig -Variant $Variant -MarkerPath $MarkerPath -DelaySeconds $TriggerDelaySeconds
$isVm = Test-LabVirtualMachine

if ($Action -eq 'Create' -and -not $isVm -and -not $Force -and -not $DryRun) {
    throw ("VM guard: this host does not look like a virtual machine. " +
        "The NT230 lab rules require a snapshot/rollback VM. " +
        "Use -Force only on a disposable lab VM.")
}

$evidence = [ordered]@{
    variant       = $Variant
    action        = $Action
    marker_path   = $MarkerPath
    vm_detected   = $isVm
    host          = $env:COMPUTERNAME
    started_at    = (Get-Date).ToUniversalTime().ToString('o')
    created       = @()
    marker_seen   = $false
    cleanup       = ''
    timeline      = @()
    verdict       = ''
}

try {
    switch ($Action) {
        'Status' {
            $objects = @()
            foreach ($class in @('__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer',
                    'LogFileEventConsumer', 'NTEventLogEventConsumer', '__FilterToConsumerBinding')) {
                $items = Get-WmiObject -Namespace $config.Namespace -Class $class -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    $display = if ($item.PSObject.Properties.Match('Name').Count -gt 0) {
                        "$($item.Name)"
                    }
                    else {
                        "$($item.Filter) -> $($item.Consumer)"
                    }
                    if ($display -like '*NT230_D12_*') { $objects += "$class :: $display" }
                }
            }
            $evidence['objects'] = $objects
            $objects | ForEach-Object { Write-Host $_ }
        }
        'Remove' {
            $count = Remove-LabObjects -Config $config
            $evidence['cleanup'] = "removed=$count"
            Write-Host "removed $count object group(s) for $Variant"
        }
        'Create' {
            if ($DryRun) {
                $evidence['dry_run'] = $true
                $evidence['config'] = $config
                Add-Timeline 'dry-run' 'no WMI object was created'
                break
            }
            New-LabSubscription -Config $config
            if ($WaitForMarker) {
                $evidence['marker_seen'] = Wait-Marker -Path $MarkerPath `
                    -Timeout $TimeoutSeconds -TriggerProcess $config.TriggerProcess
            }
            if (-not $Keep) {
                $count = Remove-LabObjects -Config $config
                $evidence['cleanup'] = "removed=$count"
            }
            else {
                $evidence['cleanup'] = 'kept (-Keep)'
            }
        }
    }

    $evidence['created'] = $script:CreatedObjects.ToArray()
    $evidence['timeline'] = $script:Timeline.ToArray()
    $evidence['finished_at'] = (Get-Date).ToUniversalTime().ToString('o')
    $evidence['verdict'] = if ($Action -eq 'Create' -and $WaitForMarker) {
        if ($evidence['marker_seen']) { 'marker-observed' } else { 'marker-not-observed' }
    }
    else { 'completed' }
}
catch {
    $evidence['error'] = $_.Exception.Message
    if ($Action -eq 'Create' -and -not $Keep) {
        Write-Warning "creation failed, rolling back: $($_.Exception.Message)"
        Remove-LabObjects -Config $config | Out-Null
    }
    throw
}
finally {
    if ($Action -eq 'Create' -and -not $Keep -and -not $DryRun -and $script:CreatedObjects.Count -eq 0) {
        Write-Warning 'subscription creation failed before any object was registered'
    }

    if ($EvidencePath) {
        $directory = Split-Path -Parent $EvidencePath
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        $json = $evidence | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText(
            $EvidencePath, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "evidence -> $EvidencePath"
    }
}

$evidence | ConvertTo-Json -Depth 4
