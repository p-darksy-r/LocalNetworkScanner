# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Create", "DownloadCandidate", "StageEvidence", "DownloadEvidence", "StageSbom", "DownloadFinal", "Publish", "Cleanup")]
    [string]$Operation,

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
    [string]$Repository,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^\d+$")]
    [string]$RepositoryId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{40}$")]
    [string]$CommitSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^v\d+\.\d+\.\d+$")]
    [string]$ReleaseTag,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^\d+$")]
    [string]$WorkflowRunId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^\d+$")]
    [string]$WorkflowRunAttempt,

    [ValidatePattern("^\d*$")]
    [string]$ReleaseId,

    [ValidatePattern("^(|sha256:[0-9a-fA-F]{64})$")]
    [string]$CandidateDigest,

    [ValidatePattern("^(|sha256:[0-9a-fA-F]{64})$")]
    [string]$FinalPayloadDigest,

    [ValidatePattern("^(|sha256:[0-9a-fA-F]{64})$")]
    [string]$FinalReleaseDigest,

    [string]$ReleaseRoot,

    [string]$EvidenceRoot,

    [string]$SbomPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (($ReleaseMode -eq "PublicRelease" -and $SigningState -ne "Signed") -or
    ($ReleaseMode -eq "PrivateQa" -and $SigningState -ne "NotSigned")) {
    throw "LNS-REL-005: illegal release trust combination: ReleaseMode=$ReleaseMode SigningState=$SigningState."
}
if ($ReleaseTag -cne "v$Version") {
    throw "LNS-REL-009: release tag '$ReleaseTag' does not match version 'v$Version'."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactsRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "artifacts"))
if ([string]::IsNullOrWhiteSpace($ReleaseRoot)) {
    $ReleaseRoot = Join-Path $artifactsRoot "release"
}
if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $EvidenceRoot = Join-Path $artifactsRoot "validation"
}
if ([string]::IsNullOrWhiteSpace($SbomPath)) {
    $SbomPath = Join-Path $artifactsRoot "sbom\LocalNetworkScanner-$Version-sbom.spdx.json"
}
$releasePath = [IO.Path]::GetFullPath($ReleaseRoot)
$evidencePath = [IO.Path]::GetFullPath($EvidenceRoot)
$sbomFilePath = [IO.Path]::GetFullPath($SbomPath)
$artifactsPrefix = $artifactsRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
foreach ($path in @($releasePath, $evidencePath, $sbomFilePath)) {
    if (-not $path.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "LNS-REL-008: release transport paths must stay below the repository artifacts directory: $path"
    }
}

$token = [Environment]::GetEnvironmentVariable("GH_TOKEN")
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "LNS-REL-008: GH_TOKEN is required for the private draft release transport."
}
$githubApiUrl = [Environment]::GetEnvironmentVariable("GITHUB_API_URL")
if ([string]::IsNullOrWhiteSpace($githubApiUrl)) {
    $githubApiUrl = "https://api.github.com"
}
$apiRoot = "$($githubApiUrl.TrimEnd('/'))/repos/$Repository"
$apiHeaders = @{
    Accept = "application/vnd.github+json"
    Authorization = "Bearer $token"
    "X-GitHub-Api-Version" = "2022-11-28"
}
$downloadHeaders = @{
    Accept = "application/octet-stream"
    Authorization = "Bearer $token"
    "X-GitHub-Api-Version" = "2022-11-28"
}
$normalizedCommit = $CommitSha.ToLowerInvariant()
$normalizedCandidateDigest = $CandidateDigest.ToLowerInvariant()
$normalizedFinalPayloadDigest = $FinalPayloadDigest.ToLowerInvariant()
$normalizedFinalReleaseDigest = $FinalReleaseDigest.ToLowerInvariant()
$transportTitle = "[transport] Local Network Scanner $Version"
$sbomAssetName = "LocalNetworkScanner-$Version-sbom.spdx.json"
$attestationAssetName = "VALIDATION-ATTESTATION.json"

$binaryNames = @(
    "LocalNetworkScanner-$Version-win-x64.zip",
    "LocalNetworkScanner-$Version-win-arm64.zip",
    "LocalNetworkScanner-$Version-win-x64-setup.exe",
    "LocalNetworkScanner-$Version-win-arm64-setup.exe"
)
$candidateNames = @(
    $binaryNames
    $binaryNames | ForEach-Object { "$_.sha256" }
    "SHA256SUMS.txt"
    "SIGNING-STATE.txt"
) | Sort-Object
$evidenceNames = @($candidateNames + $attestationAssetName) | Sort-Object
$finalNames = @($evidenceNames + $sbomAssetName) | Sort-Object

function Invoke-GitHubJson {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Get", "Post", "Patch", "Delete")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [hashtable]$Body,

        [switch]$AllowNotFound
    )

    $request = @{
        Method = $Method
        Uri = if ([string]::IsNullOrEmpty($Path)) { $apiRoot } else { "$apiRoot/$Path" }
        Headers = $apiHeaders
    }
    if ($null -ne $Body) {
        $request.ContentType = "application/json"
        $request.Body = $Body | ConvertTo-Json -Depth 8 -Compress
    }
    try {
        Invoke-RestMethod @request
    }
    catch {
        $statusCode = 0
        if ($null -ne $_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($AllowNotFound -and $statusCode -eq 404) {
            return $null
        }
        throw "LNS-REL-008: GitHub API $Method '$Path' failed with HTTP ${statusCode}: $($_.Exception.Message)"
    }
}

function Get-Sha256Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-CanonicalDigest {
    param([Parameter(Mandatory = $true)][object[]]$Records)

    $lines = @($Records | Sort-Object name | ForEach-Object {
        $hash = ([string]$_.sha256).ToLowerInvariant().Replace("sha256:", "")
        if ($hash -notmatch "^[0-9a-f]{64}$" -or [long]$_.size -lt 0) {
            throw "LNS-REL-008: invalid file record in the canonical candidate digest."
        }
        "$hash $([long]$_.size) $([string]$_.name)"
    })
    $canonical = ($lines -join "`n") + "`n"
    "sha256:$(Get-Sha256Bytes -Bytes ([Text.Encoding]::UTF8.GetBytes($canonical)))"
}

function Get-LocalRecords {
    param(
        [Parameter(Mandatory = $true)][string[]]$Names,
        [Parameter(Mandatory = $true)][hashtable]$Paths
    )

    @(
        foreach ($name in $Names) {
            if (-not $Paths.ContainsKey($name)) {
                throw "LNS-REL-008: no local path was assigned to required asset '$name'."
            }
            $file = Get-Item -LiteralPath $Paths[$name] -ErrorAction Stop
            if (-not $file.PSIsContainer -and $file.Length -ge 0) {
                [pscustomobject]@{
                    name = $name
                    size = [long]$file.Length
                    sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                    path = $file.FullName
                }
            }
            else {
                throw "LNS-REL-008: release asset is not a regular file: $($file.FullName)"
            }
        }
    )
}

function Get-LocalPathMap {
    param([Parameter(Mandatory = $true)][ValidateSet("Candidate", "Evidence", "Final")][string]$Phase)

    $map = @{}
    foreach ($name in $candidateNames) {
        $map[$name] = Join-Path $releasePath $name
    }
    if ($Phase -in @("Evidence", "Final")) {
        $map[$attestationAssetName] = Join-Path $evidencePath $attestationAssetName
    }
    if ($Phase -eq "Final") {
        $map[$sbomAssetName] = $sbomFilePath
    }
    $map
}

function Get-ExpectedNames {
    param([Parameter(Mandatory = $true)][ValidateSet("Candidate", "Evidence", "Final")][string]$Phase)

    switch ($Phase) {
        "Candidate" { return $candidateNames }
        "Evidence" { return $evidenceNames }
        "Final" { return $finalNames }
    }
}

function Assert-ExactNames {
    param(
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][object[]]$Assets,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $actual = @($Assets | ForEach-Object { [string]$_.name } | Sort-Object)
    $difference = @(Compare-Object -ReferenceObject $Expected -DifferenceObject $actual)
    if ($Assets.Count -ne $Expected.Count -or $difference.Count -ne 0) {
        throw "LNS-REL-008: $Description does not match the exact $($Expected.Count)-asset contract: $($difference | Out-String)"
    }
    foreach ($name in $Expected) {
        if (@($Assets | Where-Object { [string]$_.name -ceq $name }).Count -ne 1) {
            throw "LNS-REL-008: $Description must contain exactly one asset named '$name'."
        }
    }
}

function Get-RemoteRecords {
    param([Parameter(Mandatory = $true)][object[]]$Assets)

    @(
        foreach ($asset in $Assets) {
            $digest = ([string]$asset.digest).ToLowerInvariant()
            if ([string]$asset.state -cne "uploaded" -or
                $digest -notmatch "^sha256:[0-9a-f]{64}$") {
                throw "LNS-REL-008: remote asset '$($asset.name)' is not fully uploaded with a SHA-256 digest."
            }
            [pscustomobject]@{
                name = [string]$asset.name
                size = [long]$asset.size
                sha256 = $digest.Replace("sha256:", "")
                id = [long]$asset.id
            }
        }
    )
}

function Assert-RecordsEqual {
    param(
        [Parameter(Mandatory = $true)][object[]]$LocalRecords,
        [Parameter(Mandatory = $true)][object[]]$RemoteRecords,
        [Parameter(Mandatory = $true)][string]$Description
    )

    foreach ($local in $LocalRecords) {
        $matches = @($RemoteRecords | Where-Object { [string]$_.name -ceq [string]$local.name })
        if ($matches.Count -ne 1 -or
            [long]$matches[0].size -ne [long]$local.size -or
            ([string]$matches[0].sha256).Replace("sha256:", "") -cne ([string]$local.sha256).Replace("sha256:", "")) {
            throw "LNS-REL-008: $Description digest or size mismatch for '$($local.name)'."
        }
    }
}

function Get-LiveTagTargetCommit {
    $escapedTag = [Uri]::EscapeDataString($ReleaseTag)
    $reference = Invoke-GitHubJson -Method Get -Path "git/ref/tags/$escapedTag"
    if ([string]$reference.ref -cne "refs/tags/$ReleaseTag") {
        throw "LNS-REL-009: GitHub returned an unexpected ref for $ReleaseTag."
    }
    $initialType = ([string]$reference.object.type).ToLowerInvariant()
    $initialSha = ([string]$reference.object.sha).ToLowerInvariant()
    $object = $reference.object
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $resolved = $null
    for ($depth = 0; $depth -lt 8; $depth++) {
        $type = ([string]$object.type).ToLowerInvariant()
        $sha = ([string]$object.sha).ToLowerInvariant()
        if ($sha -notmatch "^[0-9a-f]{40}$") {
            throw "LNS-REL-009: tag $ReleaseTag resolved to an invalid Git object SHA."
        }
        if ($type -eq "commit") {
            $resolved = $sha
            break
        }
        if ($type -ne "tag" -or -not $visited.Add($sha)) {
            throw "LNS-REL-009: tag $ReleaseTag does not resolve safely to one commit."
        }
        $tagObject = Invoke-GitHubJson -Method Get -Path "git/tags/$sha"
        if ([string]$tagObject.sha -cne $sha) {
            throw "LNS-REL-009: annotated tag object SHA changed while resolving $ReleaseTag."
        }
        $object = $tagObject.object
    }
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw "LNS-REL-009: tag $ReleaseTag exceeds the safe dereference depth."
    }
    $confirmed = Invoke-GitHubJson -Method Get -Path "git/ref/tags/$escapedTag"
    if ([string]$confirmed.ref -cne "refs/tags/$ReleaseTag" -or
        ([string]$confirmed.object.type).ToLowerInvariant() -cne $initialType -or
        ([string]$confirmed.object.sha).ToLowerInvariant() -cne $initialSha) {
        throw "LNS-REL-009: tag $ReleaseTag changed while its target was being resolved."
    }
    $resolved
}

function Assert-LiveTag {
    $target = Get-LiveTagTargetCommit
    if ($target -cne $normalizedCommit) {
        throw "LNS-REL-009: live tag $ReleaseTag targets $target instead of workflow commit $normalizedCommit."
    }
}

function Assert-PrivateBoundary {
    if ($ReleaseMode -ne "PrivateQa") {
        return
    }
    $repositoryState = Invoke-GitHubJson -Method Get -Path ""
    if (-not [bool]$repositoryState.private -or [string]$repositoryState.visibility -cne "private") {
        throw "LNS-REL-005: live repository visibility is not private; refusing to transport or publish NotSigned assets."
    }
}

function Get-OwnershipNonce {
    param([Parameter(Mandatory = $true)][string]$Digest)

    $inputText = "$RepositoryId|$WorkflowRunId|$WorkflowRunAttempt|$normalizedCommit|$ReleaseTag|$Digest"
    (Get-Sha256Bytes -Bytes ([Text.Encoding]::UTF8.GetBytes($inputText))).Substring(0, 32)
}

function Get-OwnershipMarker {
    param([Parameter(Mandatory = $true)][string]$Digest)

    $nonce = Get-OwnershipNonce -Digest $Digest
    "<!-- lns-release-transport schema=2 repository_id=$RepositoryId run_id=$WorkflowRunId run_attempt=$WorkflowRunAttempt commit=$normalizedCommit tag=$ReleaseTag candidate=$Digest nonce=$nonce -->"
}

function Get-OwnershipMetadata {
    param([Parameter(Mandatory = $true)][object]$Release)

    $pattern = "<!-- lns-release-transport schema=2 repository_id=(?<repository>\d+) run_id=(?<run>\d+) run_attempt=(?<attempt>\d+) commit=(?<commit>[0-9a-f]{40}) tag=(?<tag>v\d+\.\d+\.\d+) candidate=(?<digest>sha256:[0-9a-f]{64}) nonce=(?<nonce>[0-9a-f]{32}) -->"
    $match = [regex]::Match([string]$Release.body, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) {
        return $null
    }
    [pscustomobject]@{
        repositoryId = $match.Groups["repository"].Value
        runId = $match.Groups["run"].Value
        runAttempt = $match.Groups["attempt"].Value
        commit = $match.Groups["commit"].Value
        tag = $match.Groups["tag"].Value
        digest = $match.Groups["digest"].Value
        nonce = $match.Groups["nonce"].Value
    }
}

function Assert-OwnedDraft {
    param(
        [Parameter(Mandatory = $true)][object]$Release,
        [switch]$AllowPreviousRun
    )

    if (-not [bool]$Release.draft -or
        [string]$Release.tag_name -cne $ReleaseTag -or
        [string]$Release.name -cne $transportTitle) {
        throw "LNS-REL-008: release $($Release.id) is not the expected private transport draft."
    }
    $metadata = Get-OwnershipMetadata -Release $Release
    if ($null -eq $metadata -or
        $metadata.repositoryId -cne $RepositoryId -or
        $metadata.commit -cne $normalizedCommit -or
        $metadata.tag -cne $ReleaseTag) {
        throw "LNS-REL-008: transport draft $($Release.id) does not have safe repository/tag/commit ownership."
    }
    $expectedNonceInput = "$RepositoryId|$($metadata.runId)|$($metadata.runAttempt)|$normalizedCommit|$ReleaseTag|$($metadata.digest)"
    $expectedNonce = (Get-Sha256Bytes -Bytes ([Text.Encoding]::UTF8.GetBytes($expectedNonceInput))).Substring(0, 32)
    if ($metadata.nonce -cne $expectedNonce) {
        throw "LNS-REL-008: transport draft $($Release.id) has an invalid ownership nonce."
    }
    if ($AllowPreviousRun) {
        if ($metadata.runId -cne $WorkflowRunId -or
            [int]$metadata.runAttempt -gt [int]$WorkflowRunAttempt) {
            throw "LNS-REL-008: transport draft $($Release.id) is not owned by this workflow run or a recoverable earlier attempt."
        }
    }
    elseif ($metadata.runId -cne $WorkflowRunId -or
        $metadata.runAttempt -cne $WorkflowRunAttempt) {
        throw "LNS-REL-008: transport draft $($Release.id) is not owned by this workflow run attempt."
    }
    $metadata
}

function Get-ReleaseById {
    param([switch]$AllowNotFound)

    if ([string]::IsNullOrWhiteSpace($ReleaseId)) {
        throw "LNS-REL-008: ReleaseId is required for operation '$Operation'."
    }
    Invoke-GitHubJson -Method Get -Path "releases/$ReleaseId" -AllowNotFound:$AllowNotFound
}

function Find-ReleaseByTag {
    $matches = [Collections.Generic.List[object]]::new()
    for ($page = 1; $page -le 20; $page++) {
        $batch = @(Invoke-GitHubJson -Method Get -Path "releases?per_page=100&page=$page")
        foreach ($release in $batch) {
            if ([string]$release.tag_name -ceq $ReleaseTag) {
                $matches.Add($release)
            }
        }
        if ($batch.Count -lt 100) {
            break
        }
    }
    if ($matches.Count -gt 1) {
        throw "LNS-REL-008: multiple releases were found for tag $ReleaseTag."
    }
    if ($matches.Count -eq 1) {
        return $matches[0]
    }
    $null
}

function Wait-ForReleaseAssets {
    param(
        [Parameter(Mandatory = $true)][long]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedNames
    )

    $lastError = ""
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        $release = Invoke-GitHubJson -Method Get -Path "releases/$Id"
        try {
            Assert-ExactNames -Expected $ExpectedNames -Assets @($release.assets) -Description "remote draft"
            $null = Get-RemoteRecords -Assets @($release.assets)
            return $release
        }
        catch {
            $lastError = $_.Exception.Message
            if ($attempt -lt 10) {
                Start-Sleep -Seconds 2
            }
        }
    }
    throw "LNS-REL-008: remote draft asset verification did not converge: $lastError"
}

function Wait-ForLatestRelease {
    param(
        [Parameter(Mandatory = $true)][long]$Id,
        [Parameter(Mandatory = $true)][string]$Tag
    )

    $lastError = "Latest still points to another release."
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        try {
            $latest = Invoke-GitHubJson -Method Get -Path "releases/latest"
            if ([long]$latest.id -eq $Id -and [string]$latest.tag_name -ceq $Tag) {
                return $latest
            }
            $lastError = "Latest returned id '$($latest.id)' and tag '$($latest.tag_name)'."
        }
        catch {
            $lastError = $_.Exception.Message
        }

        if ($attempt -lt 10) {
            Start-Sleep -Seconds 2
        }
    }

    throw "LNS-REL-008: the signed production release was not selected as Latest after bounded retries: $lastError"
}

function Remove-Asset {
    param([Parameter(Mandatory = $true)][long]$AssetId)

    Invoke-GitHubJson -Method Delete -Path "releases/assets/$AssetId" | Out-Null
}

function Upload-Asset {
    param(
        [Parameter(Mandatory = $true)][object]$Release,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $uploadRoot = ([string]$Release.upload_url) -replace "\{.*$", ""
    if ([string]::IsNullOrWhiteSpace($uploadRoot)) {
        throw "LNS-REL-008: draft release did not expose an upload URL."
    }
    $uri = "$uploadRoot`?name=$([Uri]::EscapeDataString($Name))"
    try {
        $response = Invoke-WebRequest `
            -Method Post `
            -Uri $uri `
            -Headers $apiHeaders `
            -ContentType "application/octet-stream" `
            -InFile $Path
        if ([int]$response.StatusCode -notin @(200, 201)) {
            throw "unexpected HTTP status $($response.StatusCode)"
        }
    }
    catch {
        throw "LNS-REL-008: upload failed for draft asset '$Name': $($_.Exception.Message)"
    }
}

function Add-OrVerifyAsset {
    param(
        [Parameter(Mandatory = $true)][object]$Release,
        [Parameter(Mandatory = $true)][object]$LocalRecord
    )

    $matches = @($Release.assets | Where-Object { [string]$_.name -ceq [string]$LocalRecord.name })
    if ($matches.Count -gt 1) {
        throw "LNS-REL-008: draft contains duplicate asset '$($LocalRecord.name)'."
    }
    if ($matches.Count -eq 1) {
        $remote = $matches[0]
        $remoteHash = ([string]$remote.digest).ToLowerInvariant().Replace("sha256:", "")
        if ([string]$remote.state -ceq "uploaded" -and
            [long]$remote.size -eq [long]$LocalRecord.size -and
            $remoteHash -ceq [string]$LocalRecord.sha256) {
            return
        }
        if ([string]$remote.state -ceq "starter") {
            Remove-Asset -AssetId ([long]$remote.id)
        }
        else {
            throw "LNS-REL-008: refusing to replace divergent draft asset '$($LocalRecord.name)'."
        }
    }
    Upload-Asset -Release $Release -Name $LocalRecord.name -Path $LocalRecord.path
}

function Download-Asset {
    param(
        [Parameter(Mandatory = $true)][object]$Asset,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporary = "$Destination.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        $response = Invoke-WebRequest `
            -Uri "$apiRoot/releases/assets/$($Asset.id)" `
            -Headers $downloadHeaders `
            -OutFile $temporary `
            -PassThru
        if ([int]$response.StatusCode -notin @(200, 302)) {
            throw "unexpected HTTP status $($response.StatusCode)"
        }
        $file = Get-Item -LiteralPath $temporary
        $hash = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
        $expectedHash = ([string]$Asset.digest).ToLowerInvariant().Replace("sha256:", "")
        if ($file.Length -ne [long]$Asset.size -or $hash -cne $expectedHash) {
            throw "downloaded bytes do not match the API size/SHA-256"
        }
        Move-Item -LiteralPath $temporary -Destination $Destination -Force
    }
    catch {
        throw "LNS-REL-008: authenticated download failed for '$($Asset.name)': $($_.Exception.Message)"
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Get-FinalReleaseMetadata {
    $isPublic = $ReleaseMode -eq "PublicRelease"
    if ($isPublic) {
        $title = "Local Network Scanner $Version"
        $lead = "Windows desktop release $Version."
        $bodyLines = @(
            $lead,
            "",
            "- Exact x64 and ARM64 ZIPs/installers passed native install, UI/CLI smoke and uninstall validation.",
            "- Executables and diagnostic scripts use timestamped Microsoft Artifact Signing.",
            "- The 12-asset contract includes checksums, validation attestation and SPDX 2.2 SBOM.",
            "",
            "If Windows reports code 4551, see docs/APP_CONTROL.md; do not disable Application Control."
        )
    }
    else {
        $title = "Local Network Scanner $Version - Private QA (NotSigned)"
        $lead = "Private QA prerelease $Version (NotSigned)."
        $bodyLines = @(
            $lead,
            "",
            "**Do not distribute as a production release.** These assets have no public Authenticode identity and may be blocked with code 4551.",
            "",
            "- Exact x64 and ARM64 ZIPs/installers passed native install, UI/CLI smoke and uninstall validation.",
            "- SIGNING-STATE.txt records PrivateQa, NotSigned and both native validations.",
            "- The 12-asset contract includes checksums, validation attestation and SPDX 2.2 SBOM.",
            "- This prerelease was published only after live confirmation that the repository remained private."
        )
    }
    [pscustomobject]@{
        title = $title
        lead = $lead
        bodyLines = $bodyLines
        prerelease = -not $isPublic
        makeLatest = if ($isPublic) { "true" } else { "false" }
    }
}

if ($Operation -ne "Cleanup") {
    Assert-LiveTag
    Assert-PrivateBoundary
}

switch ($Operation) {
    "Create" {
        $localMap = Get-LocalPathMap -Phase Candidate
        $localRecords = Get-LocalRecords -Names $candidateNames -Paths $localMap
        $computedDigest = Get-CanonicalDigest -Records $localRecords
        if (-not [string]::IsNullOrWhiteSpace($CandidateDigest) -and
            $normalizedCandidateDigest -cne $computedDigest) {
            throw "LNS-REL-008: supplied candidate digest does not match the exact local 10-file contract."
        }
        $normalizedCandidateDigest = $computedDigest
        $ownedDraftId = $null
        try {
        $existing = Find-ReleaseByTag
        if ($null -ne $existing -and -not [bool]$existing.draft) {
            $metadata = Get-FinalReleaseMetadata
            $finalMarkerPrefix = "<!-- lns-final-release schema=2 repository_id=$RepositoryId commit=$normalizedCommit tag=$ReleaseTag mode=$ReleaseMode "
            if ([string]$existing.name -cne $metadata.title -or
                [bool]$existing.prerelease -ne [bool]$metadata.prerelease -or
                ([string]$existing.body).IndexOf($finalMarkerPrefix, [StringComparison]::Ordinal) -lt 0) {
                throw "LNS-REL-008: an unowned or mismatched published release already exists for $ReleaseTag."
            }
            Assert-ExactNames -Expected $finalNames -Assets @($existing.assets) -Description "published release"
            $remoteRecords = Get-RemoteRecords -Assets @($existing.assets)
            $finalMarkerMatch = [regex]::Match(
                [string]$existing.body,
                "<!-- lns-final-release schema=2 repository_id=$RepositoryId commit=$normalizedCommit tag=$ReleaseTag mode=$ReleaseMode candidate=(?<candidate>sha256:[0-9a-f]{64}) payload=(?<payload>sha256:[0-9a-f]{64}) release=(?<release>sha256:[0-9a-f]{64}) attestation=(?<attestation>sha256:[0-9a-f]{64}) sbom=(?<sbom>sha256:[0-9a-f]{64}) -->",
                [Text.RegularExpressions.RegexOptions]::CultureInvariant)
            if (-not $finalMarkerMatch.Success) {
                throw "LNS-REL-008: published release ownership marker is incomplete or contradictory."
            }
            $publishedPayloadRecords = @($remoteRecords | Where-Object { $_.name -in $candidateNames })
            $attestationRemote = @($remoteRecords | Where-Object { $_.name -ceq $attestationAssetName })[0]
            $sbomRemote = @($remoteRecords | Where-Object { $_.name -ceq $sbomAssetName })[0]
            if ((Get-CanonicalDigest -Records $publishedPayloadRecords) -cne $finalMarkerMatch.Groups["payload"].Value -or
                (Get-CanonicalDigest -Records $remoteRecords) -cne $finalMarkerMatch.Groups["release"].Value -or
                "sha256:$($attestationRemote.sha256)" -cne $finalMarkerMatch.Groups["attestation"].Value -or
                "sha256:$($sbomRemote.sha256)" -cne $finalMarkerMatch.Groups["sbom"].Value) {
                throw "LNS-REL-008: published release assets do not match their final ownership marker digests."
            }
            $normalizedCandidateDigest = $finalMarkerMatch.Groups["candidate"].Value
            "release_id=$($existing.id)" >> $env:GITHUB_OUTPUT
            "candidate_digest=$normalizedCandidateDigest" >> $env:GITHUB_OUTPUT
            "already_published=true" >> $env:GITHUB_OUTPUT
            Write-Host "Using the already-published exact release as an idempotent read-only validation source."
            break
        }

        if ($null -ne $existing) {
            $null = Assert-OwnedDraft -Release $existing -AllowPreviousRun
            $existingRemoteRecords = @()
            try {
                Assert-ExactNames -Expected $candidateNames -Assets @($existing.assets) -Description "existing transport draft"
                $existingRemoteRecords = Get-RemoteRecords -Assets @($existing.assets)
            }
            catch {
                $existingRemoteRecords = @()
            }
            $existingDigest = if ($existingRemoteRecords.Count -eq $candidateNames.Count) {
                Get-CanonicalDigest -Records $existingRemoteRecords
            }
            else {
                ""
            }
            if ($existingDigest -cne $computedDigest) {
                $deleteCandidate = Invoke-GitHubJson -Method Get -Path "releases/$($existing.id)"
                $null = Assert-OwnedDraft -Release $deleteCandidate -AllowPreviousRun
                Invoke-GitHubJson -Method Delete -Path "releases/$($deleteCandidate.id)" | Out-Null
                $existing = $null
            }
        }

        $marker = Get-OwnershipMarker -Digest $computedDigest
        $body = @(
            "Internal validation transport. Never publish before both native architecture gates pass.",
            "",
            $marker
        ) -join [Environment]::NewLine
        if ($null -eq $existing) {
            $existing = Invoke-GitHubJson -Method Post -Path "releases" -Body @{
                tag_name = $ReleaseTag
                target_commitish = $normalizedCommit
                name = $transportTitle
                body = $body
                draft = $true
                prerelease = $true
            }
            if ([long]$existing.id -le 0) {
                throw "LNS-REL-008: GitHub did not return a valid transport draft ID."
            }
            $ownedDraftId = [long]$existing.id
        }
        else {
            $existing = Invoke-GitHubJson -Method Patch -Path "releases/$($existing.id)" -Body @{
                name = $transportTitle
                body = $body
                draft = $true
                prerelease = $true
            }
        }
        $null = Assert-OwnedDraft -Release $existing
        $ownedDraftId = [long]$existing.id
        foreach ($record in $localRecords) {
            $existing = Invoke-GitHubJson -Method Get -Path "releases/$($existing.id)"
            Add-OrVerifyAsset -Release $existing -LocalRecord $record
        }
        $verified = Wait-ForReleaseAssets -Id ([long]$existing.id) -ExpectedNames $candidateNames
        $remoteRecords = Get-RemoteRecords -Assets @($verified.assets)
        Assert-RecordsEqual -LocalRecords $localRecords -RemoteRecords $remoteRecords -Description "transport draft"
        if ((Get-CanonicalDigest -Records $remoteRecords) -cne $computedDigest) {
            throw "LNS-REL-008: remote transport draft canonical digest mismatch."
        }
        Assert-LiveTag
        Assert-PrivateBoundary
        "release_id=$($verified.id)" >> $env:GITHUB_OUTPUT
        "candidate_digest=$computedDigest" >> $env:GITHUB_OUTPUT
        "already_published=false" >> $env:GITHUB_OUTPUT
        Write-Host "Created or resumed private draft transport $($verified.id) with the exact 10-file candidate."
        }
        catch {
            $originalFailure = $_
            if ($null -ne $ownedDraftId) {
                try {
                    $cleanupCandidate = Invoke-GitHubJson -Method Get -Path "releases/$ownedDraftId" -AllowNotFound
                    if ($null -ne $cleanupCandidate) {
                        $cleanupOwner = Assert-OwnedDraft -Release $cleanupCandidate
                        if ($cleanupOwner.digest -cne $computedDigest) {
                            throw "owned draft digest changed before failure cleanup"
                        }
                        Invoke-GitHubJson -Method Delete -Path "releases/$ownedDraftId" | Out-Null
                        Write-Host "Removed owned draft $ownedDraftId after candidate transport failure."
                    }
                }
                catch {
                    Write-Host "::warning title=LNS-REL-008::Owned draft cleanup could not complete safely: $($_.Exception.Message)"
                }
            }
            throw $originalFailure
        }
    }

    { $_ -in @("DownloadCandidate", "DownloadEvidence", "DownloadFinal") } {
        $phase = switch ($Operation) {
            "DownloadCandidate" { "Candidate" }
            "DownloadEvidence" { "Evidence" }
            "DownloadFinal" { "Final" }
        }
        $release = Get-ReleaseById
        if ([string]$release.tag_name -cne $ReleaseTag) {
            throw "LNS-REL-008: release ID $ReleaseId does not belong to tag $ReleaseTag."
        }
        if ([bool]$release.draft) {
            $owner = Assert-OwnedDraft -Release $release
            if ($owner.digest -cne $normalizedCandidateDigest) {
                throw "LNS-REL-008: transport ownership candidate digest mismatch."
            }
        }
        elseif ($phase -ne "Candidate" -and $phase -ne "Final") {
            throw "LNS-REL-008: a published release cannot be used as an intermediate evidence draft."
        }
        $expected = if (-not [bool]$release.draft -and $phase -eq "Candidate") {
            $finalNames
        }
        else {
            Get-ExpectedNames -Phase $phase
        }
        Assert-ExactNames -Expected $expected -Assets @($release.assets) -Description "download source"
        $remoteRecords = Get-RemoteRecords -Assets @($release.assets)
        $selectedNames = if (-not [bool]$release.draft -and $phase -eq "Candidate") {
            $candidateNames
        }
        else {
            Get-ExpectedNames -Phase $phase
        }
        $selectedRecords = @($remoteRecords | Where-Object { $_.name -in $selectedNames })
        if ($phase -eq "Candidate") {
            if ([bool]$release.draft -and
                (Get-CanonicalDigest -Records $selectedRecords) -cne $normalizedCandidateDigest) {
                throw "LNS-REL-008: download source candidate digest mismatch."
            }
            if (-not [bool]$release.draft -and
                ([string]$release.body).IndexOf("candidate=$normalizedCandidateDigest", [StringComparison]::Ordinal) -lt 0) {
                throw "LNS-REL-008: published validation source does not attest the selected initial candidate digest."
            }
        }
        $pathMap = Get-LocalPathMap -Phase $phase
        foreach ($name in $selectedNames) {
            $asset = @($release.assets | Where-Object { [string]$_.name -ceq $name })[0]
            Download-Asset -Asset $asset -Destination $pathMap[$name]
        }
        $localRecords = Get-LocalRecords -Names $selectedNames -Paths $pathMap
        Assert-RecordsEqual -LocalRecords $localRecords -RemoteRecords $selectedRecords -Description "authenticated draft download"
        Assert-LiveTag
        Assert-PrivateBoundary
        Write-Host "Downloaded and verified $($selectedNames.Count) assets from release $ReleaseId ($phase phase)."
    }

    "StageEvidence" {
        $release = Get-ReleaseById
        $owner = Assert-OwnedDraft -Release $release
        if ($owner.digest -cne $normalizedCandidateDigest) {
            throw "LNS-REL-008: transport ownership candidate digest mismatch before evidence staging."
        }
        $candidateMap = Get-LocalPathMap -Phase Candidate
        $candidateRecords = Get-LocalRecords -Names $candidateNames -Paths $candidateMap
        $evidenceMap = Get-LocalPathMap -Phase Evidence
        $validatedStateMap = @{
            "SIGNING-STATE.txt" = Join-Path $evidencePath "SIGNING-STATE.txt"
        }
        $validatedState = Get-LocalRecords -Names @("SIGNING-STATE.txt") -Paths $validatedStateMap
        $attestationRecord = Get-LocalRecords -Names @($attestationAssetName) -Paths $evidenceMap
        try {
            $attestation = Get-Content -LiteralPath $attestationRecord[0].path -Raw | ConvertFrom-Json
        }
        catch {
            throw "LNS-REL-007: validation attestation is not valid JSON: $($_.Exception.Message)"
        }
        $attestedCandidateRecords = @($attestation.candidateFiles | ForEach-Object {
            [pscustomobject]@{
                name = [string]$_.name
                size = [long]$_.size
                sha256 = [string]$_.sha256
            }
        })
        Assert-ExactNames -Expected $candidateNames -Assets $attestedCandidateRecords -Description "attested candidate"
        if ((Get-CanonicalDigest -Records $attestedCandidateRecords) -cne $normalizedCandidateDigest -or
            [string]$attestation.candidateArtifactDigest -cne $normalizedCandidateDigest) {
            throw "LNS-REL-007: native attestation does not preserve the canonical initial candidate digest."
        }
        Assert-RecordsEqual `
            -LocalRecords @($candidateRecords | Where-Object { $_.name -cne "SIGNING-STATE.txt" }) `
            -RemoteRecords $attestedCandidateRecords `
            -Description "materialized local payload"
        $remoteNames = @($release.assets | ForEach-Object { [string]$_.name })
        $unexpected = @($remoteNames | Where-Object { $_ -notin $evidenceNames })
        if ($unexpected.Count -ne 0) {
            throw "LNS-REL-008: transport draft has unexpected assets before evidence staging: $($unexpected -join ', ')."
        }
        $stateAsset = @($release.assets | Where-Object { [string]$_.name -ceq "SIGNING-STATE.txt" })
        if ($stateAsset.Count -gt 1) {
            throw "LNS-REL-008: transport draft has duplicate SIGNING-STATE.txt assets."
        }
        if ($stateAsset.Count -eq 0) {
            Add-OrVerifyAsset -Release $release -LocalRecord $validatedState[0]
        }
        else {
            $remoteStateHash = ([string]$stateAsset[0].digest).ToLowerInvariant().Replace("sha256:", "")
            $pendingState = @($attestedCandidateRecords | Where-Object { $_.name -ceq "SIGNING-STATE.txt" })[0]
            if ($remoteStateHash -cne [string]$validatedState[0].sha256) {
                if ([string]$stateAsset[0].state -ceq "starter") {
                    $deleteRelease = Invoke-GitHubJson -Method Get -Path "releases/$ReleaseId"
                    $null = Assert-OwnedDraft -Release $deleteRelease
                    $deleteMatch = @($deleteRelease.assets | Where-Object {
                        [long]$_.id -eq [long]$stateAsset[0].id -and [string]$_.name -ceq "SIGNING-STATE.txt"
                    })
                    if ($deleteMatch.Count -ne 1) {
                        throw "LNS-REL-008: SIGNING-STATE.txt changed before controlled starter cleanup."
                    }
                    Remove-Asset -AssetId ([long]$deleteMatch[0].id)
                }
                elseif ($remoteStateHash -ceq [string]$pendingState.sha256) {
                    $deleteRelease = Invoke-GitHubJson -Method Get -Path "releases/$ReleaseId"
                    $null = Assert-OwnedDraft -Release $deleteRelease
                    $deleteMatch = @($deleteRelease.assets | Where-Object {
                        [long]$_.id -eq [long]$stateAsset[0].id -and
                        [string]$_.name -ceq "SIGNING-STATE.txt" -and
                        ([string]$_.digest).ToLowerInvariant().Replace("sha256:", "") -ceq [string]$pendingState.sha256
                    })
                    if ($deleteMatch.Count -ne 1) {
                        throw "LNS-REL-008: pending SIGNING-STATE.txt changed before controlled replacement."
                    }
                    Remove-Asset -AssetId ([long]$deleteMatch[0].id)
                }
                else {
                    throw "LNS-REL-008: refusing to replace a divergent SIGNING-STATE.txt in the transport draft."
                }
                $release = Invoke-GitHubJson -Method Get -Path "releases/$ReleaseId"
                Add-OrVerifyAsset -Release $release -LocalRecord $validatedState[0]
            }
        }
        $release = Invoke-GitHubJson -Method Get -Path "releases/$ReleaseId"
        Add-OrVerifyAsset -Release $release -LocalRecord $attestationRecord[0]
        $verified = Wait-ForReleaseAssets -Id ([long]$ReleaseId) -ExpectedNames $evidenceNames
        $remoteRecords = Get-RemoteRecords -Assets @($verified.assets)
        $expectedRecords = @(
            $attestedCandidateRecords | Where-Object { $_.name -cne "SIGNING-STATE.txt" }
            $validatedState
            $attestationRecord
        )
        Assert-RecordsEqual -LocalRecords $expectedRecords -RemoteRecords $remoteRecords -Description "evidence-staged draft"
        Assert-LiveTag
        Assert-PrivateBoundary
        Write-Host "Staged validated SIGNING-STATE.txt and attestation; draft remains unpublished."
    }

    "StageSbom" {
        $release = Get-ReleaseById
        $localMap = Get-LocalPathMap -Phase Final
        $localRecords = Get-LocalRecords -Names $finalNames -Paths $localMap
        if ([bool]$release.draft) {
            $owner = Assert-OwnedDraft -Release $release
            if ($owner.digest -cne $normalizedCandidateDigest) {
                throw "LNS-REL-008: transport ownership candidate digest mismatch before SBOM staging."
            }
            Assert-ExactNames -Expected $evidenceNames -Assets @($release.assets) -Description "evidence-staged draft"
            $existingRecords = Get-RemoteRecords -Assets @($release.assets)
            Assert-RecordsEqual `
                -LocalRecords @($localRecords | Where-Object { $_.name -in $evidenceNames }) `
                -RemoteRecords $existingRecords `
                -Description "evidence-staged draft"
            $sbomRecord = @($localRecords | Where-Object { $_.name -ceq $sbomAssetName })[0]
            Add-OrVerifyAsset -Release $release -LocalRecord $sbomRecord
            $verified = Wait-ForReleaseAssets -Id ([long]$ReleaseId) -ExpectedNames $finalNames
            $remoteRecords = Get-RemoteRecords -Assets @($verified.assets)
            Assert-RecordsEqual -LocalRecords $localRecords -RemoteRecords $remoteRecords -Description "final draft"
        }
        else {
            Assert-ExactNames -Expected $finalNames -Assets @($release.assets) -Description "published release"
            Assert-RecordsEqual -LocalRecords $localRecords -RemoteRecords (Get-RemoteRecords -Assets @($release.assets)) -Description "published release"
            if (([string]$release.body).IndexOf("candidate=$normalizedCandidateDigest", [StringComparison]::Ordinal) -lt 0) {
                throw "LNS-REL-008: published release does not retain the initial candidate digest."
            }
        }
        $finalPayloadDigest = Get-CanonicalDigest -Records @($localRecords | Where-Object { $_.name -in $candidateNames })
        $finalReleaseDigest = Get-CanonicalDigest -Records $localRecords
        Assert-LiveTag
        Assert-PrivateBoundary
        "final_payload_digest=$finalPayloadDigest" >> $env:GITHUB_OUTPUT
        "final_release_digest=$finalReleaseDigest" >> $env:GITHUB_OUTPUT
        Write-Host "Verified the exact 12-asset final contract; an unpublished draft was staged when required."
    }

    "Publish" {
        $release = Get-ReleaseById
        if ([string]$release.tag_name -cne $ReleaseTag) {
            throw "LNS-REL-008: release ID $ReleaseId does not belong to tag $ReleaseTag."
        }
        $localMap = Get-LocalPathMap -Phase Final
        $localRecords = Get-LocalRecords -Names $finalNames -Paths $localMap
        $computedFinalPayloadDigest = Get-CanonicalDigest -Records @($localRecords | Where-Object { $_.name -in $candidateNames })
        $computedFinalReleaseDigest = Get-CanonicalDigest -Records $localRecords
        if (-not [string]::IsNullOrWhiteSpace($normalizedFinalPayloadDigest) -and
            $normalizedFinalPayloadDigest -cne $computedFinalPayloadDigest) {
            throw "LNS-REL-008: final 10-file payload digest changed before publication."
        }
        if (-not [string]::IsNullOrWhiteSpace($normalizedFinalReleaseDigest) -and
            $normalizedFinalReleaseDigest -cne $computedFinalReleaseDigest) {
            throw "LNS-REL-008: final 12-asset release digest changed before publication."
        }
        Assert-ExactNames -Expected $finalNames -Assets @($release.assets) -Description "publication source"
        Assert-RecordsEqual -LocalRecords $localRecords -RemoteRecords (Get-RemoteRecords -Assets @($release.assets)) -Description "publication source"
        $metadata = Get-FinalReleaseMetadata
        $attestationHash = @($localRecords | Where-Object { $_.name -ceq $attestationAssetName })[0].sha256
        $sbomHash = @($localRecords | Where-Object { $_.name -ceq $sbomAssetName })[0].sha256
        $finalMarker = "<!-- lns-final-release schema=2 repository_id=$RepositoryId commit=$normalizedCommit tag=$ReleaseTag mode=$ReleaseMode candidate=$normalizedCandidateDigest payload=$computedFinalPayloadDigest release=$computedFinalReleaseDigest attestation=sha256:$attestationHash sbom=sha256:$sbomHash -->"
        $body = ($metadata.bodyLines + @("", $finalMarker)) -join [Environment]::NewLine
        if ([bool]$release.draft) {
            $owner = Assert-OwnedDraft -Release $release
            if ($owner.digest -cne $normalizedCandidateDigest) {
                throw "LNS-REL-008: transport ownership candidate digest mismatch before publication."
            }
            Assert-LiveTag
            Assert-PrivateBoundary
            $publicationCandidate = Invoke-GitHubJson -Method Get -Path "releases/$ReleaseId"
            $publicationOwner = Assert-OwnedDraft -Release $publicationCandidate
            if ($publicationOwner.digest -cne $normalizedCandidateDigest) {
                throw "LNS-REL-008: draft ownership changed immediately before publication."
            }
            Assert-ExactNames -Expected $finalNames -Assets @($publicationCandidate.assets) -Description "pre-publication draft"
            Assert-RecordsEqual -LocalRecords $localRecords -RemoteRecords (Get-RemoteRecords -Assets @($publicationCandidate.assets)) -Description "pre-publication draft"
            Assert-LiveTag
            Assert-PrivateBoundary
            $release = Invoke-GitHubJson -Method Patch -Path "releases/$ReleaseId" -Body @{
                name = $metadata.title
                body = $body
                draft = $false
                prerelease = [bool]$metadata.prerelease
                make_latest = $metadata.makeLatest
            }
        }
        $release = Invoke-GitHubJson -Method Get -Path "releases/$ReleaseId"
        if ([bool]$release.draft -or
            [string]$release.name -cne $metadata.title -or
            [bool]$release.prerelease -ne [bool]$metadata.prerelease -or
            ([string]$release.body).IndexOf($finalMarker, [StringComparison]::Ordinal) -lt 0) {
            throw "LNS-REL-008: published release metadata does not match the verified final contract."
        }
        Assert-ExactNames -Expected $finalNames -Assets @($release.assets) -Description "published release"
        Assert-RecordsEqual -LocalRecords $localRecords -RemoteRecords (Get-RemoteRecords -Assets @($release.assets)) -Description "published release"
        $escapedReleaseTag = [Uri]::EscapeDataString($ReleaseTag)
        $releaseByTag = Invoke-GitHubJson -Method Get -Path "releases/tags/$escapedReleaseTag"
        if ([long]$releaseByTag.id -ne [long]$ReleaseId) {
            throw "LNS-REL-008: published tag lookup does not resolve to the release verified by ID."
        }
        Assert-ExactNames -Expected $finalNames -Assets @($releaseByTag.assets) -Description "published tag lookup"
        Assert-RecordsEqual -LocalRecords $localRecords -RemoteRecords (Get-RemoteRecords -Assets @($releaseByTag.assets)) -Description "published tag lookup"
        if ($ReleaseMode -eq "PublicRelease") {
            $latestRelease = Wait-ForLatestRelease -Id ([long]$ReleaseId) -Tag $ReleaseTag
            Assert-ExactNames -Expected $finalNames -Assets @($latestRelease.assets) -Description "Latest release lookup"
            Assert-RecordsEqual -LocalRecords $localRecords -RemoteRecords (Get-RemoteRecords -Assets @($latestRelease.assets)) -Description "Latest release lookup"
        }
        Assert-LiveTag
        Assert-PrivateBoundary
        "release_url=$($release.html_url)" >> $env:GITHUB_OUTPUT
        Write-Host "Published and reverified the exact 12-asset release: $($release.html_url)"
    }

    "Cleanup" {
        $release = Get-ReleaseById -AllowNotFound
        if ($null -eq $release) {
            Write-Host "Transport draft is already absent."
            break
        }
        if (-not [bool]$release.draft) {
            if ([string]$release.tag_name -cne $ReleaseTag) {
                throw "LNS-REL-008: refusing cleanup because published release $ReleaseId belongs to another tag."
            }
            Write-Host "Release $ReleaseId is already published; cleanup is intentionally a no-op."
            break
        }
        $owner = Assert-OwnedDraft -Release $release
        if ($owner.digest -cne $normalizedCandidateDigest) {
            throw "LNS-REL-008: refusing to delete draft $ReleaseId with a different candidate digest."
        }
        Invoke-GitHubJson -Method Delete -Path "releases/$ReleaseId" | Out-Null
        if ($null -ne (Invoke-GitHubJson -Method Get -Path "releases/$ReleaseId" -AllowNotFound)) {
            throw "LNS-REL-008: owned transport draft $ReleaseId still exists after cleanup."
        }
        Write-Host "Deleted owned unpublished transport draft $ReleaseId."
    }
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
