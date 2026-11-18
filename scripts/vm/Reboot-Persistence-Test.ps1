<#
.SYNOPSIS
    Two-phase reboot-persistence check for the D12 WMI subscription PoC.

.DESCRIPTION
    Lab-only. Phase Create installs the inert V1 subscription and reboots the
    guest; Phase Verify runs after boot, waits for the timer to create the
    marker again, collects repository/event evidence, then removes the objects.

    The script must run elevated (High Mandatory Level). It never touches
    objects outside the NT230_D12_ prefix.

.PARAMETER Phase
    Create or Verify.

.PARAMETER TimerSeconds
    Timer interval used by V1 (default 30 s, long enough to reboot before the
    first pre-reboot activation).

.PARAMETER MarkerWaitSeconds
    How long Verify waits for the post-reboot marker (default 90 s).

.PARAMETER Root
    Directory containing Invoke-WmiSubscription.ps1 and the collectors.
#>
[CmdletBinding()]
param(
    [ValidateSet('Create', 'Verify')]
    [string]$Phase = 'Create',
    [int]$TimerSeconds = 30,
    [int]$MarkerWaitSeconds = 90,
    [string]$Root = 'C:\NT230'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$marker = 'C:\Users\Public\nt230_d12_marker.txt'
$out = Join-Path $Root 'reboot-evidence'
New-Item -ItemType Directory -Path $out -Force | Out-Null
$log = Join-Path $out ("{0}.log" -f $Phase.ToLower())

function Write-Log {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date).ToUniversalTime().ToString('o'), $Message
    Add-Content -LiteralPath $log -Value $line -Encoding utf8
    Write-Host $line
}

function Get-LabObjects {
    $filters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'NT230_D12_*' })
    $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'NT230_D12_*' })
    $bindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Where-Object { "$($_.Filter)" -like '*NT230_D12_*' -or "$($_.Consumer)" -like '*NT230_D12_*' })
    return [pscustomobject]@{
        Filters   = $filters
        Consumers = $consumers
        Bindings  = $bindings
    }
}

try {
    Write-Log "phase=$Phase whoami=$(whoami) computer=$env:COMPUTERNAME"
    whoami /groups 2>&1 | Out-File (Join-Path $out 'whoami-groups.txt') -Encoding utf8
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Manufacturer, Model |
        Format-List | Out-File (Join-Path $out 'host.txt') -Encoding utf8
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime |
        Out-File (Join-Path $out ("lastboot-{0}.txt" -f $Phase.ToLower())) -Encoding utf8

    if ($Phase -eq 'Create') {
        try {
            & wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true 2>&1 |
                Out-File (Join-Path $out 'wevtutil.txt') -Encoding utf8
            Write-Log 'wmi-activity log enabled'
        } catch {
            Write-Log ('wevtutil failed: ' + $_.Exception.Message)
        }

        if (Test-Path -LiteralPath $marker) {
            Remove-Item -LiteralPath $marker -Force
            Write-Log 'pre-existing marker removed'
        }

        Write-Log ("creating V1 with -Keep -TriggerDelaySeconds {0}" -f $TimerSeconds)
        & (Join-Path $Root 'Invoke-WmiSubscription.ps1') -Variant V1 -Action Create `
            -Keep -TriggerDelaySeconds $TimerSeconds `
            -EvidencePath (Join-Path $out 'create-evidence.json') 2>&1 |
            Out-File (Join-Path $out 'create-transcript.txt') -Encoding utf8
        Start-Sleep -Seconds 2

        & (Join-Path $Root 'Invoke-WmiSubscription.ps1') -Variant V1 -Action Status 2>&1 |
            Out-File (Join-Path $out 'status-before-reboot.txt') -Encoding utf8

        # The marker may already exist if the timer fired; remove it so the
        # post-reboot marker can only have been created by the reloaded
        # subscription.
        if (Test-Path -LiteralPath $marker) {
            Remove-Item -LiteralPath $marker -Force
            Write-Log 'marker removed before reboot'
        } else {
            Write-Log 'no marker before reboot'
        }

        $objects = Get-LabObjects
        $objects.Filters | Select-Object Name, Query, EventNamespace |
            Out-File (Join-Path $out 'objects-before-reboot.txt') -Encoding utf8
        Write-Log ("objects before reboot: filters={0} consumers={1} bindings={2}" -f `
            $objects.Filters.Count, $objects.Consumers.Count, $objects.Bindings.Count)

        Set-Content -LiteralPath (Join-Path $out 'create-done.txt') -Value (Get-Date).ToUniversalTime().ToString('o') -Encoding ascii
        Write-Log 'requesting reboot'
        & shutdown.exe /r /t 5 /f | Out-Null
    }
    else {
        $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
        Write-Log ("last boot: {0}" -f $lastBoot.ToString('o'))

        $deadline = (Get-Date).AddSeconds($MarkerWaitSeconds)
        $seen = $false
        $elapsed = 0
        while ((Get-Date) -lt $deadline) {
            if (Test-Path -LiteralPath $marker) { $seen = $true; break }
            Start-Sleep -Seconds 5
            $elapsed += 5
        }
        Write-Log ("marker_exists={0} waited={1}s" -f $seen, $elapsed)

        $content = ''
        $markerCreated = $null
        if ($seen) {
            $content = [string](Get-Content -LiteralPath $marker -Raw)
            if ($content) { $content = $content.Trim() }
            $markerCreated = (Get-Item -LiteralPath $marker).CreationTimeUtc
            Get-Content -LiteralPath $marker -Raw |
                Out-File (Join-Path $out 'marker-after-reboot.txt') -Encoding utf8
            Write-Log ("marker content: {0}" -f $content)
            Write-Log ("marker created: {0}" -f $markerCreated.ToString('o'))
        }

        $objects = Get-LabObjects
        $objects.Filters | Select-Object Name, Query, EventNamespace |
            Out-File (Join-Path $out 'objects-after-reboot.txt') -Encoding utf8
        Write-Log ("objects after reboot: filters={0} consumers={1} bindings={2}" -f `
            $objects.Filters.Count, $objects.Consumers.Count, $objects.Bindings.Count)

        try {
            & (Join-Path $Root 'Collect-WmiSubscriptions.ps1') -OutputPath (Join-Path $out 'repository.json') `
                -Namespace root\subscription 2>&1 |
                Out-File (Join-Path $out 'collect-repository-transcript.txt') -Encoding utf8
            Write-Log 'repository collected'
        } catch {
            Write-Log ('repository collection failed: ' + $_.Exception.Message)
        }

        try {
            & (Join-Path $Root 'Collect-WmiActivityLog.ps1') -OutputPath (Join-Path $out 'wmi_activity.jsonl') `
                -MaxEvents 5000 -SinceDays 1 2>&1 |
                Out-File (Join-Path $out 'collect-events-transcript.txt') -Encoding utf8
            Write-Log 'events collected'
        } catch {
            Write-Log ('event collection failed: ' + $_.Exception.Message)
        }

        try {
            & (Join-Path $Root 'Invoke-WmiSubscription.ps1') -Variant V1 -Action Remove 2>&1 |
                Out-File (Join-Path $out 'cleanup.txt') -Encoding utf8
            Write-Log 'cleanup complete'
        } catch {
            Write-Log ('cleanup failed: ' + $_.Exception.Message)
        }

        $remaining = Get-LabObjects
        $markerCreatedText = if ($markerCreated) { $markerCreated.ToString('o') } else { $null }
        $verdict = if ($seen -and $objects.Filters.Count -ge 1 -and $objects.Bindings.Count -ge 1) { 'persisted' } else { 'failed' }
        $summary = [ordered]@{
            phase                 = 'Verify'
            completed_utc         = (Get-Date).ToUniversalTime().ToString('o')
            computer              = $env:COMPUTERNAME
            last_boot_utc         = $lastBoot.ToString('o')
            marker_exists         = $seen
            marker_content        = $content
            marker_created_utc    = $markerCreatedText
            wait_seconds          = $elapsed
            filters_after_reboot  = $objects.Filters.Count
            consumers_after_reboot = $objects.Consumers.Count
            bindings_after_reboot = $objects.Bindings.Count
            filters_remaining     = $remaining.Filters.Count
            consumers_remaining   = $remaining.Consumers.Count
            bindings_remaining    = $remaining.Bindings.Count
            verdict               = $verdict
        }
        $summary | ConvertTo-Json -Depth 4 |
            Out-File (Join-Path $out 'summary.json') -Encoding utf8
        Write-Log ("verdict: {0}" -f $summary.verdict)
    }
}
catch {
    Write-Log ('ERROR: ' + $_.Exception.Message)
    ($_ | Out-String) | Out-File (Join-Path $out ("{0}-error.txt" -f $Phase.ToLower())) -Encoding utf8
    throw
}
finally {
    Set-Content -LiteralPath (Join-Path $out ("{0}-done.txt" -f $Phase.ToLower())) `
        -Value (Get-Date).ToUniversalTime().ToString('o') -Encoding ascii
}
