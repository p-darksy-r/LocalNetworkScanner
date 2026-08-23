# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactsRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "artifacts"))
$testRoot = Join-Path $artifactsRoot (".release-evidence-tests-" + [Guid]::NewGuid().ToString("N"))
$newEvidenceScript = Join-Path $PSScriptRoot "new-release-validation-evidence.ps1"
$materializeScript = Join-Path $PSScriptRoot "materialize-release-payload.ps1"
$version = "1.2.3"
$passed = 0

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw "Synthetic release evidence assertion failed: $Message"
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,

        [Parameter(Mandatory = $true)]
        [string]$MessagePattern
    )

    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notmatch $MessagePattern) {
            throw "Expected failure matching '$MessagePattern'; received '$($_.Exception.Message)'."
        }
        return
    }
    throw "Expected failure matching '$MessagePattern', but the action succeeded."
}

function New-CandidateFixture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string[]]$StateLines
    )

    $fixtureRoot = Join-Path $testRoot $Name
    $releaseRoot = Join-Path $fixtureRoot "release"
    $evidenceRoot = Join-Path $fixtureRoot "evidence"
    New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null

    $binaryNames = @(
        "LocalNetworkScanner-$version-win-x64.zip",
        "LocalNetworkScanner-$version-win-arm64.zip",
        "LocalNetworkScanner-$version-win-x64-setup.exe",
        "LocalNetworkScanner-$version-win-arm64-setup.exe"
    )
    $manifestLines = @(
        foreach ($binaryName in $binaryNames) {
            $binaryPath = Join-Path $releaseRoot $binaryName
            [IO.File]::WriteAllBytes(
                $binaryPath,
                [Text.Encoding]::UTF8.GetBytes("synthetic fixture: $binaryName"))
            $hash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $checksumLine = "$hash *$binaryName"
            Set-Content -LiteralPath "$binaryPath.sha256" -Value $checksumLine -Encoding ascii
            $checksumLine
        }
    )
    Set-Content `
        -LiteralPath (Join-Path $releaseRoot "SHA256SUMS.txt") `
        -Value $manifestLines `
        -Encoding ascii

    if ($null -eq $StateLines) {
        $StateLines = @(
            "Version: $version",
            "Authenticode: NotSigned",
            "Native x64: Pending",
            "Native ARM64: Pending",
            "Release mode: PrivateQa",
            "Signing backend: None",
            "Verification: Get-AuthenticodeSignature and signtool verify /pa /tw"
        )
    }
    Set-Content `
        -LiteralPath (Join-Path $releaseRoot "SIGNING-STATE.txt") `
        -Value $StateLines `
        -Encoding ascii

    [pscustomobject]@{
        ReleaseRoot = $releaseRoot
        EvidenceRoot = $evidenceRoot
    }
}

function New-InvocationParameters {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Fixture,

        [string]$SigningState = "NotSigned",

        [string]$ReleaseMode = "PrivateQa"
    )

    @{
        Version = $version
        SigningState = $SigningState
        ReleaseMode = $ReleaseMode
        CandidateArtifactName = "LocalNetworkScanner-$version-windows-candidate"
        CandidateArtifactDigest = "sha256:$('a' * 64)"
        Repository = "example/LocalNetworkScanner"
        CommitSha = "$('b' * 40)"
        SourceRef = "refs/heads/main"
        WorkflowRunId = "123"
        WorkflowRunAttempt = "1"
        ReleaseRoot = $Fixture.ReleaseRoot
        EvidenceRoot = $Fixture.EvidenceRoot
    }
}

try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null

    $happyFixture = New-CandidateFixture -Name "happy"
    $happyParameters = New-InvocationParameters -Fixture $happyFixture
    & $newEvidenceScript @happyParameters *> $null
    & $materializeScript @happyParameters *> $null
    & $materializeScript @happyParameters *> $null
    $materializedState = @(Get-Content -LiteralPath (Join-Path $happyFixture.ReleaseRoot "SIGNING-STATE.txt"))
    Assert-True `
        -Condition ($materializedState.Count -eq 7 -and
            $materializedState[2] -ceq "Native x64: Validated" -and
            $materializedState[3] -ceq "Native ARM64: Validated") `
        -Message "materialization must be repeatable and preserve the exact validated state"
    $passed++

    $publicState = @(
        "Version: $version",
        "Authenticode: Signed",
        "Native x64: Pending",
        "Native ARM64: Pending",
        "Release mode: PublicRelease",
        "Signing backend: Microsoft Artifact Signing OIDC",
        "Verification: Get-AuthenticodeSignature and signtool verify /pa /tw"
    )
    $publicFixture = New-CandidateFixture -Name "public-signed" -StateLines $publicState
    $publicParameters = New-InvocationParameters `
        -Fixture $publicFixture `
        -SigningState "Signed" `
        -ReleaseMode "PublicRelease"
    & $newEvidenceScript @publicParameters *> $null
    & $materializeScript @publicParameters *> $null
    Assert-True `
        -Condition (@(Get-Content -LiteralPath (Join-Path $publicFixture.ReleaseRoot "SIGNING-STATE.txt")) -ccontains "Native ARM64: Validated") `
        -Message "the canonical PublicRelease/Signed trust combination must materialize"
    $passed++

    $historicalFixture = New-CandidateFixture -Name "historical-published-rerun"
    $historicalParameters = New-InvocationParameters -Fixture $historicalFixture
    & $newEvidenceScript @historicalParameters *> $null
    $historicalRerunParameters = @{} + $historicalParameters
    $historicalRerunParameters.WorkflowRunId = "456"
    $historicalRerunParameters.WorkflowRunAttempt = "2"
    $historicalRerunParameters.AllowHistoricalWorkflowRun = $true
    & $materializeScript @historicalRerunParameters *> $null
    Assert-True `
        -Condition (@(Get-Content -LiteralPath (Join-Path $historicalFixture.ReleaseRoot "SIGNING-STATE.txt")) -ccontains "Native x64: Validated") `
        -Message "an already-published attestation may retain its original verified run identity during an idempotent rerun"
    $passed++

    $tamperFixture = New-CandidateFixture -Name "tamper"
    $tamperParameters = New-InvocationParameters -Fixture $tamperFixture
    & $newEvidenceScript @tamperParameters *> $null
    Add-Content `
        -LiteralPath (Join-Path $tamperFixture.ReleaseRoot "LocalNetworkScanner-$version-win-x64.zip") `
        -Value "tampered"
    Assert-Throws `
        -Action { & $materializeScript @tamperParameters *> $null } `
        -MessagePattern "candidate file differs from native validation evidence"
    $passed++

    $contradictoryState = @(
        "Version: $version",
        "Authenticode: NotSigned",
        "Authenticode: Signed",
        "Native x64: Pending",
        "Native ARM64: Pending",
        "Release mode: PrivateQa",
        "Signing backend: None",
        "Verification: Get-AuthenticodeSignature and signtool verify /pa /tw"
    )
    $contradictoryFixture = New-CandidateFixture `
        -Name "contradictory-state" `
        -StateLines $contradictoryState
    $contradictoryParameters = New-InvocationParameters -Fixture $contradictoryFixture
    Assert-Throws `
        -Action { & $newEvidenceScript @contradictoryParameters *> $null } `
        -MessagePattern "must contain exactly 7 ordered lines"
    $passed++

    $illegalFixture = New-CandidateFixture -Name "illegal-combination"
    $illegalParameters = New-InvocationParameters `
        -Fixture $illegalFixture `
        -SigningState "Signed" `
        -ReleaseMode "PrivateQa"
    Assert-Throws `
        -Action { & $newEvidenceScript @illegalParameters *> $null } `
        -MessagePattern "illegal release trust combination"
    $passed++

    $atomicFixture = New-CandidateFixture -Name "atomic-no-overwrite"
    $atomicParameters = New-InvocationParameters -Fixture $atomicFixture
    New-Item -ItemType Directory -Path $atomicFixture.EvidenceRoot | Out-Null
    $sentinelPath = Join-Path $atomicFixture.EvidenceRoot "sentinel.txt"
    Set-Content -LiteralPath $sentinelPath -Value "preserve" -Encoding ascii
    Assert-Throws `
        -Action { & $newEvidenceScript @atomicParameters *> $null } `
        -MessagePattern "refusing to overwrite"
    Assert-True `
        -Condition ((Get-Content -LiteralPath $sentinelPath -Raw).Trim() -ceq "preserve") `
        -Message "an existing evidence directory must remain untouched"
    Assert-True `
        -Condition (@(Get-ChildItem -LiteralPath (Split-Path -Parent $atomicFixture.EvidenceRoot) -Directory -Filter ".validation-staging-*").Count -eq 0) `
        -Message "failed evidence publication must clean its staging directory"
    $passed++

    $releaseWorkflow = Get-Content -LiteralPath (Join-Path $repoRoot ".github\workflows\release.yml") -Raw
    $validatorJobs = [regex]::Matches(
        $releaseWorkflow,
        '(?ms)^  validate-(?:x64|arm64):\r?\n(?<body>.*?)(?=^  [a-zA-Z0-9_-]+:)')
    Assert-True `
        -Condition ($validatorJobs.Count -eq 2) `
        -Message "the release workflow must contain exactly the x64 and ARM64 validator jobs"
    foreach ($validatorJob in $validatorJobs) {
        $body = $validatorJob.Groups["body"].Value
        $operations = @([regex]::Matches($body, '-Operation\s+(?<operation>[A-Za-z]+)'))
        Assert-True `
            -Condition ($body -match '(?m)^    permissions:\r?\n(?:      #.*\r?\n)*      contents: write\r?$') `
            -Message "private draft validators require documented contents: write push access"
        Assert-True `
            -Condition ($body -match '(?m)^          persist-credentials: false\r?$') `
            -Message "validator checkouts must never persist the write-capable token"
        Assert-True `
            -Condition ($operations.Count -eq 1 -and $operations[0].Groups["operation"].Value -ceq "DownloadCandidate") `
            -Message "validators with draft push access may invoke only DownloadCandidate"
    }
    $passed++

    $publishJob = [regex]::Match(
        $releaseWorkflow,
        '(?ms)^  publish:\r?\n(?<body>.*?)(?=^  [a-zA-Z0-9_-]+:)')
    Assert-True `
        -Condition $publishJob.Success `
        -Message "the release workflow must contain the publish job"
    $publishCondition = [regex]::Match(
        $publishJob.Groups["body"].Value,
        '(?ms)^    if: >-\r?\n(?<condition>.*?)(?=^    needs:)')
    Assert-True `
        -Condition ($publishCondition.Success -and
            $publishCondition.Groups["condition"].Value -match '!cancelled\(\)' -and
            $publishCondition.Groups["condition"].Value -match "needs\.preflight\.result == 'success'" -and
            $publishCondition.Groups["condition"].Value -match "needs\.package\.result == 'success'" -and
            $publishCondition.Groups["condition"].Value -match "needs\.validation-gate\.result == 'success'") `
        -Message "publish must override implicit success and require every direct release gate"

    $cleanupJob = [regex]::Match(
        $releaseWorkflow,
        '(?ms)^  cleanup-transport:\r?\n(?<body>.*?)(?=^  [a-zA-Z0-9_-]+:)')
    Assert-True `
        -Condition ($cleanupJob.Success -and
            $cleanupJob.Groups["body"].Value -match "needs\.publish\.result != 'success'") `
        -Message "draft cleanup must run only when publication did not succeed"

    $resultJob = [regex]::Match(
        $releaseWorkflow,
        '(?ms)^  release-result:\r?\n(?<body>.*?)(?=^# Copyright|\z)')
    Assert-True `
        -Condition ($resultJob.Success -and
            $resultJob.Groups["body"].Value -match '(?m)^    if: \$\{\{ !cancelled\(\) && needs\.preflight\.result == ''success'' && needs\.preflight\.outputs\.run_candidate == ''true'' \}\}\r?$' -and
            $resultJob.Groups["body"].Value -match '(?m)^    needs: \[.*publish, cleanup-transport\]\r?$' -and
            $resultJob.Groups["body"].Value -match '(?m)^          PUBLISH_RESULT: \$\{\{ needs\.publish\.result \}\}\r?$' -and
            $resultJob.Groups["body"].Value -match 'publish = \$env:PUBLISH_RESULT' -and
            $resultJob.Groups["body"].Value -match 'Where-Object \{ \$_\.Value -ne ''success'' \}' -and
            $resultJob.Groups["body"].Value -match 'releases/tags/\$escapedTag' -and
            $resultJob.Groups["body"].Value -match '\$assets\.Count -ne 12' -and
            $resultJob.Groups["body"].Value -match 'Get-CanonicalRemoteDigest -Records \$records') `
        -Message "a terminal status gate must reject incomplete publication and independently verify the release API"
    $passed++

    Write-Host "$passed/9 synthetic release evidence tests passed." -ForegroundColor Green
}
finally {
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    $artifactsPrefix = $artifactsRoot.TrimEnd('\') + '\'
    if (-not ($resolvedTestRoot.TrimEnd('\') + '\').StartsWith(
            $artifactsPrefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing unsafe synthetic test cleanup target: $resolvedTestRoot"
    }
    if (Test-Path -LiteralPath $resolvedTestRoot) {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
