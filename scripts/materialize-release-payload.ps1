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

    [switch]$AllowHistoricalWorkflowRun,

    [switch]$UseMaterializedValidatedState,

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
if (-not (Test-Path -LiteralPath $evidencePath -PathType Container)) {
    throw "LNS-REL-007: native validation evidence directory does not exist: $evidencePath"
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

$candidateStatePath = Join-Path $releasePath "SIGNING-STATE.txt"
$attestationPath = Join-Path $evidencePath "VALIDATION-ATTESTATION.json"
if (-not (Test-Path -LiteralPath $attestationPath -PathType Leaf)) {
    throw "LNS-REL-007: validation evidence file is missing: $attestationPath"
}
$evidenceStatePath = Join-Path $evidencePath "SIGNING-STATE.txt"
$validatedStatePath = if (Test-Path -LiteralPath $evidenceStatePath -PathType Leaf) {
    $evidenceStatePath
}
elseif ($UseMaterializedValidatedState) {
    $candidateStatePath
}
else {
    throw "LNS-REL-007: validation evidence file is missing: $evidenceStatePath"
}
try {
    $attestation = Get-Content -LiteralPath $attestationPath -Raw | ConvertFrom-Json
}
catch {
    throw "LNS-REL-007: validation attestation is invalid JSON: $($_.Exception.Message)"
}

$expectedPublicRelease = $ReleaseMode -eq "PublicRelease"
$metadataChecks = [ordered]@{
    schemaVersion = @([int]$attestation.schemaVersion, 1)
    releaseVersion = @([string]$attestation.releaseVersion, $Version)
    sourceRepository = @([string]$attestation.sourceRepository, $Repository)
    sourceCommit = @([string]$attestation.sourceCommit, $CommitSha.ToLowerInvariant())
    sourceRef = @([string]$attestation.sourceRef, $SourceRef)
    candidateArtifact = @([string]$attestation.candidateArtifact, $CandidateArtifactName)
    candidateArtifactDigest = @([string]$attestation.candidateArtifactDigest, $CandidateArtifactDigest)
    publicRelease = @([bool]$attestation.publicRelease, $expectedPublicRelease)
    authenticode = @([string]$attestation.authenticode, $SigningState)
    releaseMode = @([string]$attestation.releaseMode, $ReleaseMode)
}
if ($AllowHistoricalWorkflowRun) {
    if ([string]$attestation.workflowRunId -notmatch "^\d+$" -or
        [string]$attestation.workflowRunAttempt -notmatch "^\d+$") {
        throw "LNS-REL-007: historical validation attestation has an invalid workflow run identity."
    }
}
else {
    $metadataChecks["workflowRunId"] = @([string]$attestation.workflowRunId, $WorkflowRunId)
    $metadataChecks["workflowRunAttempt"] = @([string]$attestation.workflowRunAttempt, $WorkflowRunAttempt)
}
foreach ($entry in $metadataChecks.GetEnumerator()) {
    if ($entry.Value[0] -cne $entry.Value[1]) {
        throw "LNS-REL-007: validation attestation $($entry.Key) mismatch; actual='$($entry.Value[0])' expected='$($entry.Value[1])'."
    }
}

$nativeChecks = @(
    @($attestation.nativeValidation.x64.runtime, "win-x64"),
    @($attestation.nativeValidation.x64.architecture, "X64"),
    @($attestation.nativeValidation.x64.status, "Validated"),
    @($attestation.nativeValidation.arm64.runtime, "win-arm64"),
    @($attestation.nativeValidation.arm64.architecture, "Arm64"),
    @($attestation.nativeValidation.arm64.status, "Validated")
)
foreach ($nativeCheck in $nativeChecks) {
    if ([string]$nativeCheck[0] -cne [string]$nativeCheck[1]) {
        throw "LNS-REL-007: native validation attestation mismatch; actual='$($nativeCheck[0])' expected='$($nativeCheck[1])'."
    }
}

$expectedBackend = if ($ReleaseMode -eq "PublicRelease") {
    "Microsoft Artifact Signing OIDC"
}
else {
    "None"
}
$expectedCandidateState = @(
    "Version: $Version",
    "Authenticode: $SigningState",
    "Native x64: Pending",
    "Native ARM64: Pending",
    "Release mode: $ReleaseMode",
    "Signing backend: $expectedBackend",
    "Verification: Get-AuthenticodeSignature and signtool verify /pa /tw"
)
$expectedValidatedState = @(
    "Version: $Version",
    "Authenticode: $SigningState",
    "Native x64: Validated",
    "Native ARM64: Validated",
    "Release mode: $ReleaseMode",
    "Signing backend: $expectedBackend",
    "Verification: Get-AuthenticodeSignature and signtool verify /pa /tw"
)
$validatedStateHash = (
    Get-FileHash -LiteralPath $validatedStatePath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ([string]$attestation.validatedSigningStateSha256 -cne $validatedStateHash) {
    throw "LNS-REL-007: validated SIGNING-STATE.txt does not match its attested SHA-256."
}
$validatedState = @(Get-Content -LiteralPath $validatedStatePath)
Assert-ExactStateContract `
    -Actual $validatedState `
    -Expected $expectedValidatedState `
    -Description "validated SIGNING-STATE.txt"

$attestedFiles = @($attestation.candidateFiles)
if ($attestedFiles.Count -ne $expectedNames.Count) {
    throw "LNS-REL-008: validation attestation must describe exactly $($expectedNames.Count) candidate files."
}
$attestedNames = @($attestedFiles | ForEach-Object { [string]$_.name } | Sort-Object)
$attestedDifference = @(
    Compare-Object -ReferenceObject $expectedNames -DifferenceObject $attestedNames
)
if ($attestedDifference.Count -ne 0) {
    throw "LNS-REL-008: attested candidate names do not match the exact contract: $($attestedDifference | Out-String)"
}
$alreadyMaterialized = $false
foreach ($name in $expectedNames) {
    $records = @($attestedFiles | Where-Object { [string]$_.name -ceq $name })
    if ($records.Count -ne 1) {
        throw "LNS-REL-008: validation attestation must contain exactly one record for $name."
    }
    $file = Get-Item -LiteralPath (Join-Path $releasePath $name)
    $actualHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $matchesCandidate = [string]$records[0].sha256 -ceq $actualHash -and
        [long]$records[0].size -eq $file.Length
    if ($name -ceq "SIGNING-STATE.txt" -and -not $matchesCandidate -and
        $actualHash -ceq $validatedStateHash) {
        $alreadyMaterialized = $true
        continue
    }
    if (-not $matchesCandidate) {
        throw "LNS-REL-008: candidate file differs from native validation evidence: $name."
    }
}

$manifestLines = @(Get-Content -LiteralPath (Join-Path $releasePath "SHA256SUMS.txt"))
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

$candidateState = @(Get-Content -LiteralPath $candidateStatePath)
if ($alreadyMaterialized) {
    Assert-ExactStateContract `
        -Actual $candidateState `
        -Expected $expectedValidatedState `
        -Description "materialized SIGNING-STATE.txt"
}
else {
    Assert-ExactStateContract `
        -Actual $candidateState `
        -Expected $expectedCandidateState `
        -Description "candidate SIGNING-STATE.txt"

    $temporaryStatePath = Join-Path $releasePath (".SIGNING-STATE-" + [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        Copy-Item -LiteralPath $validatedStatePath -Destination $temporaryStatePath
        Move-Item -LiteralPath $temporaryStatePath -Destination $candidateStatePath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryStatePath) {
            Remove-Item -LiteralPath $temporaryStatePath -Force
        }
    }
}
$finalNames = @(
    Get-ChildItem -LiteralPath $releasePath -File |
        Select-Object -ExpandProperty Name |
        Sort-Object
)
$finalDifference = @(
    Compare-Object -ReferenceObject $expectedNames -DifferenceObject $finalNames
)
if ($finalDifference.Count -ne 0) {
    throw "LNS-REL-008: materialized payload no longer matches the exact 10-file contract."
}

Write-Host "Materialized the validated 10-file payload from one immutable candidate and its validation evidence."

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
