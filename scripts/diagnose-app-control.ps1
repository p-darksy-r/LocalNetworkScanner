# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [string]$FilePath = (Join-Path $env:LOCALAPPDATA "Programs\LocalNetworkScanner\LocalNetworkScanner.exe"),

    [ValidateRange(1, 10080)]
    [int]$Minutes = 60,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-SafeEventMessage {
    param([Parameter(Mandatory = $true)]$EventRecord)

    try {
        return $EventRecord.Message
    }
    catch {
        return $null
    }
}

function Convert-EventData {
    param([Parameter(Mandatory = $true)]$EventRecord)

    $values = [ordered]@{}
    try {
        [xml]$xml = $EventRecord.ToXml()
        $index = 0
        foreach ($entry in @($xml.Event.EventData.Data)) {
            $name = [string]$entry.Name
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = "Value$index"
            }
            $values[$name] = [string]$entry.'#text'
            $index++
        }
    }
    catch {
        $values["ParseError"] = $_.Exception.Message
    }
    return $values
}

$targetPath = [IO.Path]::GetFullPath($FilePath)
$targetExists = Test-Path -LiteralPath $targetPath -PathType Leaf
$targetLeaf = Split-Path $targetPath -Leaf
$startedAfter = [DateTime]::Now.AddMinutes(-$Minutes)

$fileEvidence = [ordered]@{
    path = $targetPath
    exists = $targetExists
}
if ($targetExists) {
    $signature = Get-AuthenticodeSignature -LiteralPath $targetPath
    $fileEvidence["sha256"] = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fileEvidence["authenticodeStatus"] = [string]$signature.Status
    $fileEvidence["signerSubject"] = if ($null -ne $signature.SignerCertificate) {
        $signature.SignerCertificate.Subject
    }
    else {
        $null
    }
    $fileEvidence["signerThumbprint"] = if ($null -ne $signature.SignerCertificate) {
        $signature.SignerCertificate.Thumbprint
    }
    else {
        $null
    }
    $fileEvidence["hasMarkOfTheWeb"] =
        $null -ne (Get-Item -LiteralPath $targetPath -Stream "Zone.Identifier" -ErrorAction SilentlyContinue)
}

$policyEvidence = [ordered]@{
    available = $false
    policies = @()
    error = $null
}
$ciTool = Get-Command "CiTool.exe" -ErrorAction SilentlyContinue
if ($null -ne $ciTool) {
    $policyEvidence["available"] = $true
    try {
        $policyJson = & $ciTool.Source -lp -json 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "CiTool exited with code $LASTEXITCODE."
        }
        $parsedPolicies = ($policyJson -join [Environment]::NewLine) | ConvertFrom-Json
        $policyEvidence["policies"] = @($parsedPolicies.Policies | Select-Object `
            PolicyID, BasePolicyID, FriendlyName, Version, IsSignedPolicy, IsOnDisk, IsEnforced, IsAuthorized, Status)
    }
    catch {
        $policyEvidence["error"] = $_.Exception.Message
    }
}
else {
    $policyEvidence["error"] = "CiTool.exe is not available on this Windows version."
}

$eventEvidence = @()
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-CodeIntegrity/Operational"
        Id = 3076, 3077, 3089, 3099, 3114
        StartTime = $startedAfter
    } -ErrorAction Stop

    foreach ($event in $events) {
        try {
            $eventXml = $event.ToXml()
            $message = Get-SafeEventMessage $event
            $matchesTarget =
                [string]::IsNullOrWhiteSpace($targetLeaf) -or
                $eventXml.IndexOf($targetLeaf, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                ($null -ne $message -and $message.IndexOf($targetLeaf, [StringComparison]::OrdinalIgnoreCase) -ge 0)
            if ($matchesTarget) {
                $eventEvidence += [ordered]@{
                    id = $event.Id
                    timeCreated = $event.TimeCreated
                    level = $event.LevelDisplayName
                    message = $message
                    data = Convert-EventData $event
                }
            }
        }
        finally {
            $event.Dispose()
        }
    }
}
catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
    $eventLogError = "The CodeIntegrity Operational log is not available."
}
catch {
    if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") {
        $eventLogError = $null
    }
    else {
        $eventLogError = $_.Exception.Message
    }
}

$report = [ordered]@{
    schemaVersion = 1
    reportType = "LocalNetworkScanner.AppControlDiagnostic"
    generatedAt = [DateTimeOffset]::Now.ToString("o")
    readOnly = $true
    errorReference = [ordered]@{
        decimal = 4551
        hexadecimal = "0x11C7"
        symbol = "ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION"
    }
    system = [ordered]@{
        osVersion = [Environment]::OSVersion.VersionString
        processArchitecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    }
    file = $fileEvidence
    appControl = $policyEvidence
    codeIntegrity = [ordered]@{
        queriedAfter = $startedAfter.ToString("o")
        matchingEvents = $eventEvidence
        error = if (Get-Variable -Name eventLogError -ErrorAction SilentlyContinue) { $eventLogError } else { $null }
    }
}

$json = $report | ConvertTo-Json -Depth 10
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $fullOutputPath = [IO.Path]::GetFullPath($OutputPath)
    $outputDirectory = Split-Path $fullOutputPath -Parent
    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
    Set-Content -LiteralPath $fullOutputPath -Value $json -Encoding utf8
    Write-Host "Read-only App Control diagnostic written to: $fullOutputPath" -ForegroundColor Green
}
else {
    $json
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
