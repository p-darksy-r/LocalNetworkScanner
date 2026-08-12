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

function Test-ContainsOrdinalIgnoreCase {
    param(
        [AllowNull()]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return -not [string]::IsNullOrWhiteSpace($Text) -and
        $Text.IndexOf($Value, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function ConvertTo-NormalizedSha256 {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $normalized = ($Value -replace "[^0-9A-Fa-f]", "").ToLowerInvariant()
    if ($normalized.Length -eq 64) {
        return $normalized
    }
    return $null
}

function Test-RootRelativePathSuffix {
    param(
        [AllowNull()][string]$EventPath,
        [AllowNull()][string]$RootRelativeTarget
    )

    if ([string]::IsNullOrWhiteSpace($EventPath) -or
        [string]::IsNullOrWhiteSpace($RootRelativeTarget)) {
        return $false
    }

    $normalizedEventPath = $EventPath.Replace('/', '\').TrimEnd('\')
    $normalizedRelativeTarget = $RootRelativeTarget.Replace('/', '\').TrimStart('\')
    return $normalizedEventPath.EndsWith(
        "\$normalizedRelativeTarget",
        [StringComparison]::OrdinalIgnoreCase)
}

$targetPath = [IO.Path]::GetFullPath($FilePath)
$targetExists = Test-Path -LiteralPath $targetPath -PathType Leaf
$targetLeaf = Split-Path $targetPath -Leaf
$targetRoot = [IO.Path]::GetPathRoot($targetPath)
$targetRootRelativePath = if ([string]::IsNullOrWhiteSpace($targetRoot)) {
    $null
}
else {
    $targetPath.Substring($targetRoot.Length).TrimStart('\', '/')
}
$startedAfter = [DateTime]::Now.AddMinutes(-$Minutes)

$fileEvidence = [ordered]@{
    path = $targetPath
    exists = $targetExists
}
$signatureStatus = "FileMissing"
if ($targetExists) {
    $signature = Get-AuthenticodeSignature -LiteralPath $targetPath
    $signatureStatus = [string]$signature.Status
    $fileEvidence["sha256"] = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fileEvidence["authenticodeStatus"] = $signatureStatus
    $fileEvidence["authenticodeMessage"] = [string]$signature.StatusMessage
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
    $fileEvidence["timestampSubject"] = if ($null -ne $signature.TimeStamperCertificate) {
        $signature.TimeStamperCertificate.Subject
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
            $eventData = Convert-EventData $event
            $eventText = @($message, $eventXml) + @($eventData.Values)
            $matchesFullPath = @($eventText | Where-Object {
                Test-ContainsOrdinalIgnoreCase -Text ([string]$_) -Value $targetPath
            }).Count -gt 0
            $matchesFileName = @($eventText | Where-Object {
                Test-ContainsOrdinalIgnoreCase -Text ([string]$_) -Value $targetLeaf
            }).Count -gt 0
            $eventFilePath = [string]$eventData["File Name"]
            $matchesRootRelativePath = Test-RootRelativePathSuffix `
                -EventPath $eventFilePath `
                -RootRelativeTarget $targetRootRelativePath
            $matchesSha256 = $false
            if ($targetExists) {
                $targetSha256 = ConvertTo-NormalizedSha256 -Value ([string]$fileEvidence["sha256"])
                $eventFlatHashes = @($eventData.GetEnumerator() | Where-Object {
                    $_.Key -match "^(?i:SHA256 Flat Hash)$"
                } | ForEach-Object {
                    ConvertTo-NormalizedSha256 -Value ([string]$_.Value)
                } | Where-Object { $null -ne $_ })
                $matchesSha256 = $null -ne $targetSha256 -and
                    $eventFlatHashes -contains $targetSha256
            }

            if ($matchesSha256 -or $matchesFullPath -or $matchesFileName) {
                $eventEvidence += [ordered]@{
                    id = $event.Id
                    timeCreated = $event.TimeCreated
                    level = $event.LevelDisplayName
                    correlation = if ($matchesFullPath) {
                        "FullPath"
                    }
                    elseif ($matchesSha256 -and $matchesRootRelativePath) {
                        "Sha256AndPathSuffix"
                    }
                    elseif ($matchesSha256) {
                        "ContentHashOnly"
                    }
                    else {
                        "FileNameOnly"
                    }
                    message = $message
                    data = $eventData
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

$confirmedEnforcementEvents = @($eventEvidence | Where-Object {
    $_.id -eq 3077 -and $_.correlation -eq "FullPath"
})
$pathSuffixEnforcementEvents = @($eventEvidence | Where-Object {
    $_.id -eq 3077 -and $_.correlation -eq "Sha256AndPathSuffix"
})
$contentHashOnlyEnforcementEvents = @($eventEvidence | Where-Object {
    $_.id -eq 3077 -and $_.correlation -eq "ContentHashOnly"
})
$fileNameOnlyEnforcementEvents = @($eventEvidence | Where-Object {
    $_.id -eq 3077 -and $_.correlation -eq "FileNameOnly"
})
$confirmedAuditEvents = @($eventEvidence | Where-Object {
    $_.id -eq 3076 -and $_.correlation -eq "FullPath"
})
$pathSuffixAuditEvents = @($eventEvidence | Where-Object {
    $_.id -eq 3076 -and $_.correlation -eq "Sha256AndPathSuffix"
})
$contentHashOnlyAuditEvents = @($eventEvidence | Where-Object {
    $_.id -eq 3076 -and $_.correlation -eq "ContentHashOnly"
})
$fileNameOnlyAuditEvents = @($eventEvidence | Where-Object {
    $_.id -eq 3076 -and $_.correlation -eq "FileNameOnly"
})
$diagnosis = [ordered]@{
    code = "LNS-APP-006"
    result = "Inconclusive"
    confidence = "Low"
    policyBlockConfirmed = $false
    canApplicationFixAfterBlock = $false
    explanation = "No correlated App Control enforcement event was found for the selected file."
    recommendedActions = @(
        "Compare the file SHA-256 with the value published by the project.",
        "Do not disable Smart App Control, App Control for Business, AppLocker or Microsoft Defender.",
        "Review the CodeIntegrity evidence or send this report to the device administrator."
    )
}

if (-not $targetExists) {
    $diagnosis["code"] = "LNS-APP-002"
    $diagnosis["result"] = "TargetFileMissing"
    $diagnosis["confidence"] = "High"
    $diagnosis["explanation"] = "The selected file does not exist, so its signature and policy decision cannot be evaluated."
    $diagnosis["recommendedActions"] = @(
        "Pass -FilePath with the exact installer or application executable that Windows blocked.",
        "If setup completed, check %LOCALAPPDATA%\Programs\LocalNetworkScanner\LocalNetworkScanner.exe."
    )
}
elseif ($confirmedEnforcementEvents.Count -gt 0 -and $signatureStatus -eq "NotSigned") {
    $diagnosis["code"] = "LNS-APP-005"
    $diagnosis["result"] = "ConfirmedPolicyBlockUnsignedTarget"
    $diagnosis["confidence"] = "High"
    $diagnosis["policyBlockConfirmed"] = $true
    $diagnosis["explanation"] = "Windows recorded an App Control enforcement block and the selected file has no Authenticode publisher signature. Unknown unsigned code is commonly denied by Smart App Control and managed policies."
    $diagnosis["recommendedActions"] = @(
        "Use a release whose SIGNING-STATE.txt says Authenticode: Signed and whose signature validates locally.",
        "On a managed computer, ask the administrator to evaluate a publisher, catalog or hash rule.",
        "Do not treat a matching checksum as a substitute for publisher trust."
    )
}
elseif ($confirmedEnforcementEvents.Count -gt 0 -and $signatureStatus -eq "Valid") {
    $diagnosis["code"] = "LNS-APP-005"
    $diagnosis["result"] = "ConfirmedPolicyBlockSignedTarget"
    $diagnosis["confidence"] = "High"
    $diagnosis["policyBlockConfirmed"] = $true
    $diagnosis["explanation"] = "Windows recorded an App Control enforcement block even though Authenticode validates. The active policy may not trust this publisher or may contain an explicit deny rule."
    $diagnosis["recommendedActions"] = @(
        "Confirm that the signer subject and thumbprint match the publisher documented by the release.",
        "Ask the device administrator to inspect the correlated 3077 and 3089 events and the effective policy.",
        "Do not replace or weaken the organization policy without its administrator's approval."
    )
}
elseif ($confirmedEnforcementEvents.Count -gt 0) {
    $diagnosis["code"] = "LNS-APP-005"
    $diagnosis["result"] = "ConfirmedPolicyBlockInvalidOrUntrustedSignature"
    $diagnosis["confidence"] = "High"
    $diagnosis["policyBlockConfirmed"] = $true
    $diagnosis["explanation"] = "Windows recorded an App Control enforcement block and Authenticode is not valid for the selected file."
    $diagnosis["recommendedActions"] = @(
        "Download the file again only from the official release and compare its SHA-256.",
        "Use a timestamped release signed by a publicly trusted RSA Code Signing certificate.",
        "If the signature still fails, do not execute the file and report the evidence."
    )
}
elseif ($confirmedAuditEvents.Count -gt 0) {
    $diagnosis["result"] = "WouldBeBlockedInEnforcement"
    $diagnosis["confidence"] = "High"
    $diagnosis["explanation"] = "Windows recorded an App Control audit event: the selected file would be denied if the policy were enforced."
}
elseif ($pathSuffixEnforcementEvents.Count -gt 0) {
    $diagnosis["result"] = "LikelyMatchingPathAndContentEnforcementEvidence"
    $diagnosis["confidence"] = "Medium"
    $diagnosis["explanation"] = "Windows blocked byte-identical content at the same root-relative path, but the NT device volume could not be mapped to the selected drive. This is strong supporting evidence, not proof for the selected copy when path-specific rules are possible."
    $diagnosis["recommendedActions"] = @(
        "Reproduce the block and compare the structured NT File Name with the selected drive using an administrator-approved diagnostic.",
        "Ask the device administrator to confirm the volume mapping and effective App Control rule.",
        "Do not treat a matching suffix and content hash as proof for this particular copy."
    )
}
elseif ($pathSuffixAuditEvents.Count -gt 0) {
    $diagnosis["result"] = "LikelyMatchingPathAndContentAuditEvidence"
    $diagnosis["confidence"] = "Medium"
    $diagnosis["explanation"] = "Windows audited byte-identical content at the same root-relative path, but the NT device volume could not be mapped to the selected drive. The evidence is likely related, not conclusive for a path-specific policy."
}
elseif ($contentHashOnlyEnforcementEvents.Count -gt 0) {
    $diagnosis["result"] = "AmbiguousMatchingContentEnforcementEvidence"
    $diagnosis["confidence"] = "Medium"
    $diagnosis["explanation"] = "Windows blocked byte-identical content, but the event path does not identify the selected copy. A path-specific policy can treat two identical copies differently, so this does not confirm error 4551 for the selected path."
    $diagnosis["recommendedActions"] = @(
        "Reproduce the block and rerun this diagnostic with -FilePath set to the exact executable that Windows attempted to start.",
        "Compare the structured File Name field with the selected path before attributing the block.",
        "Do not treat a content-hash-only match as proof that this particular copy was denied."
    )
}
elseif ($contentHashOnlyAuditEvents.Count -gt 0) {
    $diagnosis["result"] = "AmbiguousMatchingContentAuditEvidence"
    $diagnosis["confidence"] = "Medium"
    $diagnosis["explanation"] = "Windows audited byte-identical content, but the event path does not identify the selected copy. This is useful content evidence, not confirmation for a path-specific policy."
}
elseif ($fileNameOnlyEnforcementEvents.Count -gt 0) {
    $diagnosis["result"] = "AmbiguousFileNameOnlyEnforcementEvidence"
    $diagnosis["confidence"] = "Low"
    $diagnosis["explanation"] = "Windows recorded an App Control enforcement event containing the same file name, but not the selected file's complete path. This is ambiguous evidence and does not confirm that error 4551 affected the selected file."
    $diagnosis["recommendedActions"] = @(
        "Reproduce the block and rerun this diagnostic with -FilePath set to the exact blocked executable.",
        "Inspect the matching event data and confirm the complete path before attributing the block.",
        "Do not treat a file-name-only match as proof of an App Control block for this target."
    )
}
elseif ($fileNameOnlyAuditEvents.Count -gt 0) {
    $diagnosis["result"] = "AmbiguousFileNameOnlyAuditEvidence"
    $diagnosis["confidence"] = "Low"
    $diagnosis["explanation"] = "Windows recorded an App Control audit event containing the same file name, but not the selected file's complete path. The selected file cannot be identified with confidence."
}
elseif ($signatureStatus -eq "NotSigned") {
    $diagnosis["result"] = "UnsignedWithoutCorrelatedEvent"
    $diagnosis["confidence"] = "Medium"
    $diagnosis["explanation"] = "The file is unsigned, but no matching enforcement event was found in the selected time window. This is a trust risk, not proof that error 4551 occurred."
}
elseif ($signatureStatus -eq "Valid") {
    $diagnosis["result"] = "ValidSignatureWithoutCorrelatedEvent"
    $diagnosis["confidence"] = "Medium"
    $diagnosis["explanation"] = "Authenticode validates, but no matching enforcement event was found. Increase -Minutes or ask the administrator for the relevant policy logs."
}
else {
    $diagnosis["result"] = "InvalidOrUntrustedSignatureWithoutCorrelatedEvent"
    $diagnosis["confidence"] = "Medium"
    $diagnosis["explanation"] = "Authenticode does not validate, but no matching enforcement event was found in the selected time window."
}

$report = [ordered]@{
    schemaVersion = 2
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
    diagnosis = $diagnosis
    appControl = $policyEvidence
    codeIntegrity = [ordered]@{
        queriedAfter = $startedAfter.ToString("o")
        matchingEvents = $eventEvidence
        error = if (Get-Variable -Name eventLogError -ErrorAction SilentlyContinue) { $eventLogError } else { $null }
    }
    officialDocumentation = @(
        "https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview",
        "https://learn.microsoft.com/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control"
    )
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
