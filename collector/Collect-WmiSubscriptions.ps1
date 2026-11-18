<#
.SYNOPSIS
    Read-only collector for permanent WMI event subscriptions (T1546.003).

.DESCRIPTION
    Enumerates __EventFilter, every __EventConsumer subclass and
    __FilterToConsumerBinding in one or more namespaces and writes a JSON
    snapshot consumed by detector/parser.py.

    This script NEVER creates, modifies or deletes WMI objects.

.PARAMETER OutputPath
    Destination JSON file. Default: data/live/repository.json relative to the
    repository root.

.PARAMETER Namespace
    Namespaces to scan. Default root\subscription. Add custom namespaces when
    hunting (for example root\NT230Lab).

.EXAMPLE
    .\Collect-WmiSubscriptions.ps1 -Namespace root\subscription,root\NT230Lab
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string[]]$Namespace = @('root\subscription')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-SidBytesToSid {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    try {
        $bytes = [byte[]]$Value
        if ($bytes.Length -lt 8) { return '' }
        $sid = New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)
        return $sid.Value
    }
    catch {
        return ''
    }
}

function Convert-SidToAccount {
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return '' }
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate(
            [System.Security.Principal.NTAccount]).Value
    }
    catch {
        return ''
    }
}

$root = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) {
    $OutputPath = Join-Path $root 'data/live/repository.json'
}

$systemProperties = @(
    'CimClass', 'CimInstanceProperties', 'CimSystemProperties', 'PSComputerName',
    '__PATH', '__CLASS', '__SUPERCLASS', '__DYNASTY', '__DERIVATION', '__GENUS',
    '__PROPERTY_COUNT', '__SERVER', '__NAMESPACE', '__RELPATH'
)

function Get-ObjectProperties {
    param([object]$Instance)
    $props = [ordered]@{}
    foreach ($property in $Instance.CimInstanceProperties) {
        if ($systemProperties -contains $property.Name) { continue }
        $value = $property.Value
        if ($null -eq $value) { continue }
        if ($value -is [System.Array] -and $property.Name -eq 'CreatorSID') {
            $value = Convert-SidBytesToSid $value
        }
        elseif ($value -is [System.Array]) {
            $value = ($value | ForEach-Object { "$_" }) -join ','
        }
        $props[$property.Name] = "$value"
    }
    return $props
}

$filters = New-Object System.Collections.Generic.List[object]
$consumers = New-Object System.Collections.Generic.List[object]
$bindings = New-Object System.Collections.Generic.List[object]

foreach ($ns in $Namespace) {
    Write-Verbose "Scanning $ns"

    try {
        $filterInstances = Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop
    }
    catch {
        Write-Warning "Cannot read __EventFilter in ${ns}: $($_.Exception.Message)"
        $filterInstances = @()
    }

    foreach ($item in $filterInstances) {
        $props = Get-ObjectProperties $item
        $creatorSid = Convert-SidBytesToSid $item.CreatorSID
        $filters.Add([ordered]@{
            name            = [string]$item.Name
            namespace       = $ns
            event_namespace = [string]$item.EventNamespace
            query           = [string]$item.Query
            query_language  = [string]$item.QueryLanguage
            creator_sid     = $creatorSid
            creator_user    = (Convert-SidToAccount $creatorSid)
            properties      = $props
        })
    }

    try {
        $consumerInstances = Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop
    }
    catch {
        Write-Warning "Cannot read __EventConsumer in ${ns}: $($_.Exception.Message)"
        $consumerInstances = @()
    }

    foreach ($item in $consumerInstances) {
        $class = $item.CimClass.CimClassName
        $props = Get-ObjectProperties $item
        $creatorSid = Convert-SidBytesToSid $item.CreatorSID
        $consumers.Add([ordered]@{
            name         = [string]$item.Name
            namespace    = $ns
            class        = $class
            properties   = $props
            creator_sid  = $creatorSid
            creator_user = (Convert-SidToAccount $creatorSid)
        })
    }

    try {
        $bindingInstances = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop
    }
    catch {
        Write-Warning "Cannot read __FilterToConsumerBinding in ${ns}: $($_.Exception.Message)"
        $bindingInstances = @()
    }

    foreach ($item in $bindingInstances) {
        $filterPath = [string]$item.Filter
        $consumerPath = [string]$item.Consumer
        # Accept both the WMI object path form
        #   \\HOST\root\subscription:__EventFilter.Name="X"
        # and the CIM reference string form
        #   __EventFilter (Name = "X")
        $filterMatch = [regex]::Match($filterPath, 'Name\s*=\s*"([^"]+)"', 'IgnoreCase')
        $consumerMatch = [regex]::Match($consumerPath, 'Name\s*=\s*"([^"]+)"', 'IgnoreCase')
        $consumerClass = [regex]::Match(
            $consumerPath, '(?<cls>[A-Za-z_]\w*)\s*(?:\.|\()\s*Name\s*=', 'IgnoreCase')
        $creatorSid = Convert-SidBytesToSid $item.CreatorSID
        $bindings.Add([ordered]@{
            filter_name         = if ($filterMatch.Success) { $filterMatch.Groups[1].Value } else { $filterPath }
            filter_namespace    = $ns
            consumer_name       = if ($consumerMatch.Success) { $consumerMatch.Groups[1].Value } else { $consumerPath }
            consumer_class      = if ($consumerClass.Success) { $consumerClass.Groups['cls'].Value } else { '' }
            consumer_namespace  = $ns
            creator_sid         = $creatorSid
            creator_user        = (Convert-SidToAccount $creatorSid)
        })
    }
}

$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

$snapshot = [ordered]@{
    schema_version = '1.0'
    collected_at   = (Get-Date).ToUniversalTime().ToString('o')
    collector      = 'Collect-WmiSubscriptions.ps1'
    host           = [ordered]@{
        hostname = $env:COMPUTERNAME
        os       = if ($os) { "$($os.Caption) $($os.Version)" } else { '' }
        model    = if ($computer) { "$($computer.Manufacturer) $($computer.Model)" } else { '' }
    }
    scope          = $Namespace
    filters        = $filters
    consumers      = $consumers
    bindings       = $bindings
}

$directory = Split-Path -Parent $OutputPath
if ($directory -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

$json = $snapshot | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ("collected filters={0} consumers={1} bindings={2} -> {3}" -f `
        $filters.Count, $consumers.Count, $bindings.Count, $OutputPath)
