# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^\d+\.\d+\.\d+$")]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Signed", "NotSigned")]
    [string]$SigningState,

    [Parameter(Mandatory = $true)]
    [ValidateSet("PublicRelease", "PrivateQa")]
    [string]$ReleaseMode,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CandidateArtifactName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^(sha256:)?[0-9a-fA-F]{64}$")]
    [string]$CandidateArtifactDigest,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Repository,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{40}$")]
    [string]$CommitSha,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceRef,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^\d+$")]
    [string]$WorkflowRunId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^\d+$")]
    [string]$WorkflowRunAttempt,

    [string]$ReleaseRoot,

    [string]$EvidenceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ReleaseRoot)) {
    $ReleaseRoot = Join-Path $repoRoot "artifacts\release"
}
if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $EvidenceRoot = Join-Path $repoRoot "artifacts\validation"
}
$releasePath = [IO.Path]::GetFullPath($ReleaseRoot)
$evidencePath = [IO.Path]::GetFullPath($EvidenceRoot)
$artifactsPath = [IO.Path]::GetFullPath((Join-Path $repoRoot "artifacts")).TrimEnd('\') + '\'
foreach ($path in @($releasePath, $evidencePath)) {
    if (-not ($path.TrimEnd('\') + '\').StartsWith(
            $artifactsPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "LNS-REL-008: release evidence paths must stay under the repository artifacts directory: $path"
    }
}
if ($releasePath.TrimEnd('\') -ieq $evidencePath.TrimEnd('\')) {
    throw "LNS-REL-008: candidate and evidence directories must be different."
}
if (-not (Test-Path -LiteralPath $releasePath -PathType Container)) {
    throw "LNS-REL-008: candidate release directory does not exist: $releasePath"
}

if (($ReleaseMode -eq "PublicRelease" -and $SigningState -ne "Signed") -or
    ($ReleaseMode -eq "PrivateQa" -and $SigningState -ne "NotSigned")) {
    throw "LNS-REL-005: illegal release trust combination: ReleaseMode=$ReleaseMode SigningState=$SigningState."
}

function Assert-ExactStateContract {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Actual,

        [Parameter(Mandatory = $true)]
        [string[]]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if ($Actual.Count -ne $Expected.Count) {
        throw "LNS-REL-007: $Description must contain exactly $($Expected.Count) ordered lines; received $($Actual.Count)."
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($Actual[$index] -cne $Expected[$index]) {
            throw "LNS-REL-007: $Description line $($index + 1) mismatch; actual='$($Actual[$index])' expected='$($Expected[$index])'."
        }
    }
}

$binaryNames = @(
    "LocalNetworkScanner-$Version-win-x64.zip",
    "LocalNetworkScanner-$Version-win-arm64.zip",
    "LocalNetworkScanner-$Version-win-x64-setup.exe",
    "LocalNetworkScanner-$Version-win-arm64-setup.exe"
)
$expectedNames = @(
    $binaryNames
    $binaryNames | ForEach-Object { "$_.sha256" }
    "SHA256SUMS.txt"
    "SIGNING-STATE.txt"
) | Sort-Object
$actualNames = @(
    Get-ChildItem -LiteralPath $releasePath -File |
        Select-Object -ExpandProperty Name |
        Sort-Object
)
$contractDifference = @(
    Compare-Object -ReferenceObject $expectedNames -DifferenceObject $actualNames
)
if ($contractDifference.Count -ne 0) {
    throw "LNS-REL-008: candidate does not match the exact 10-file contract: $($contractDifference | Out-String)"
}

$manifestPath = Join-Path $releasePath "SHA256SUMS.txt"
$manifestLines = @(Get-Content -LiteralPath $manifestPath)
if ($manifestLines.Count -ne $binaryNames.Count) {
    throw "LNS-REL-008: SHA256SUMS.txt must contain exactly $($binaryNames.Count) entries."
}
foreach ($binaryName in $binaryNames) {
    $binaryPath = Join-Path $releasePath $binaryName
    $expectedLine = "{0} *{1}" -f (
        Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256
    ).Hash.ToLowerInvariant(), $binaryName
    if ((Get-Content -LiteralPath "$binaryPath.sha256" -Raw).Trim() -cne $expectedLine -or
        $manifestLines -cnotcontains $expectedLine) {
        throw "LNS-REL-008: checksum mismatch for $binaryName."
    }
}

$expectedBackend = if ($ReleaseMode -eq "PublicRelease") {
    "Microsoft Artifact Signing OIDC"
}
else {
    "None"
}
$statePath = Join-Path $releasePath "SIGNING-STATE.txt"
$candidateState = @(Get-Content -LiteralPath $statePath)
$expectedCandidateState = @(
    "Version: $Version",
    "Authenticode: $SigningState",
    "Native x64: Pending",
    "Native ARM64: Pending",
    "Release mode: $ReleaseMode",
    "Signing backend: $expectedBackend",
    "Verification: Get-AuthenticodeSignature and signtool verify /pa /tw"
)
Assert-ExactStateContract `
    -Actual $candidateState `
    -Expected $expectedCandidateState `
    -Description "candidate SIGNING-STATE.txt"

$candidateFiles = @(
    foreach ($name in $expectedNames) {
        $file = Get-Item -LiteralPath (Join-Path $releasePath $name)
        [ordered]@{
            name = $file.Name
            size = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
)

$validatedState = @(
    "Version: $Version",
    "Authenticode: $SigningState",
    "Native x64: Validated",
    "Native ARM64: Validated",
    "Release mode: $ReleaseMode",
    "Signing backend: $expectedBackend",
    "Verification: Get-AuthenticodeSignature and signtool verify /pa /tw"
)

$evidenceParent = Split-Path -Parent $evidencePath
New-Item -ItemType Directory -Path $evidenceParent -Force | Out-Null
$stagingPath = Join-Path $evidenceParent (".validation-staging-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $stagingPath | Out-Null
try {
    $validatedStatePath = Join-Path $stagingPath "SIGNING-STATE.txt"
    Set-Content -LiteralPath $validatedStatePath -Value $validatedState -Encoding ascii

    $attestation = [ordered]@{
        schemaVersion = 1
        releaseVersion = $Version
        sourceRepository = $Repository
        sourceCommit = $CommitSha.ToLowerInvariant()
        sourceRef = $SourceRef
        workflowRunId = $WorkflowRunId
        workflowRunAttempt = $WorkflowRunAttempt
        candidateArtifact = $CandidateArtifactName
        candidateArtifactDigest = $CandidateArtifactDigest
        publicRelease = $ReleaseMode -eq "PublicRelease"
        authenticode = $SigningState
        releaseMode = $ReleaseMode
        nativeValidation = [ordered]@{
            x64 = [ordered]@{
                runtime = "win-x64"
                architecture = "X64"
                status = "Validated"
            }
            arm64 = [ordered]@{
                runtime = "win-arm64"
                architecture = "Arm64"
                status = "Validated"
            }
        }
        candidateFiles = $candidateFiles
        validatedSigningStateSha256 = (
            Get-FileHash -LiteralPath $validatedStatePath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        createdUtc = [DateTime]::UtcNow.ToString("o")
    }
    $attestationPath = Join-Path $stagingPath "VALIDATION-ATTESTATION.json"
    $attestation | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $attestationPath -Encoding utf8

    $stagedNames = @(
        Get-ChildItem -LiteralPath $stagingPath -File |
            Select-Object -ExpandProperty Name |
            Sort-Object
    )
    if (@(Compare-Object -ReferenceObject @("SIGNING-STATE.txt", "VALIDATION-ATTESTATION.json") -DifferenceObject $stagedNames).Count -ne 0) {
        throw "LNS-REL-008: staged validation evidence does not match the exact two-file contract."
    }

    if (Test-Path -LiteralPath $evidencePath) {
        if (@(Get-ChildItem -LiteralPath $evidencePath -Force).Count -ne 0) {
            throw "LNS-REL-008: refusing to overwrite an existing validation evidence directory: $evidencePath"
        }
        Remove-Item -LiteralPath $evidencePath -Force
    }
    Move-Item -LiteralPath $stagingPath -Destination $evidencePath
}
finally {
    if (Test-Path -LiteralPath $stagingPath) {
        Remove-Item -LiteralPath $stagingPath -Recurse -Force
    }
}

Write-Host "Created validation evidence for the immutable 10-file candidate."
Write-Host "Candidate artifact digest: $CandidateArtifactDigest"
Write-Host "Evidence directory: $evidencePath"

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
