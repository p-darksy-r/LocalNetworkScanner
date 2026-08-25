# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$updateScript = Join-Path $PSScriptRoot "update-local-app.ps1"
$appReadme = Join-Path $repoRoot "app\README.md"
$launcher = Join-Path $repoRoot "app\Abrir Local Network Scanner.cmd"
$ciWorkflow = Join-Path $repoRoot ".github\workflows\ci.yml"
$releaseWorkflow = Join-Path $repoRoot ".github\workflows\release.yml"
$testRoot = Join-Path $repoRoot ("artifacts\.app-entry-tests-" + [Guid]::NewGuid().ToString("N"))
$passed = 0
$total = 0

function Assert-Contract {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:total++
    if (-not $Condition) {
        throw "App entrypoint contract failed: $Message"
    }
    $script:passed++
}

function Test-GitIgnored {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    & git -C $repoRoot check-ignore --quiet -- $RelativePath
    $exitCode = $LASTEXITCODE
    if ($exitCode -notin @(0, 1)) {
        throw "git check-ignore failed for '$RelativePath' with code $exitCode."
    }
    return $exitCode -eq 0
}

function Write-TestPePayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [byte]$Marker
    )

    $payload = [byte[]]::new(128)
    $payload[0] = 0x4D
    $payload[1] = 0x5A
    [BitConverter]::GetBytes([int]64).CopyTo($payload, 0x3C)
    $payload[64] = 0x50
    $payload[65] = 0x45
    [BitConverter]::GetBytes([uint16]0x8664).CopyTo($payload, 68)
    $payload[80] = $Marker
    [IO.File]::WriteAllBytes($Path, $payload)
}

foreach ($requiredFile in @($updateScript, $appReadme, $launcher, $ciWorkflow, $releaseWorkflow)) {
    Assert-Contract `
        -Condition (Test-Path -LiteralPath $requiredFile -PathType Leaf) `
        -Message "required file is missing: $requiredFile"
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is required to validate the root app ignore contract."
}

$launcherText = Get-Content -LiteralPath $launcher -Raw
$updateScriptText = Get-Content -LiteralPath $updateScript -Raw
Assert-Contract `
    -Condition $launcherText.Contains('%~dp0..\scripts\update-local-app.ps1') `
    -Message "launcher must resolve the updater relative to its own directory"
Assert-Contract `
    -Condition ($launcherText -notmatch '(?im)[A-Z]:\\') `
    -Message "launcher must not contain an absolute drive path"
Assert-Contract `
    -Condition ($launcherText.Contains('-Quick') -and $launcherText.Contains('-Launch')) `
    -Message "launcher must request quick materialization and application launch"
Assert-Contract `
    -Condition ($launcherText.Contains('pwsh.exe') -and $launcherText.Contains('powershell.exe')) `
    -Message "launcher must prefer PowerShell 7 and retain the built-in Windows fallback"
Assert-Contract `
    -Condition ($launcherText.Contains('%ProgramFiles%\PowerShell\7\pwsh.exe') -and
        $launcherText.Contains('%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe') -and
        -not $launcherText.Contains('where pwsh.exe')) `
    -Message "launcher must resolve trusted fixed PowerShell locations instead of PATH"

$ciWorkflowText = Get-Content -LiteralPath $ciWorkflow -Raw
$releaseWorkflowText = Get-Content -LiteralPath $releaseWorkflow -Raw
Assert-Contract `
    -Condition (-not $updateScriptText.Contains('publish-windows.ps1') -and
        -not $updateScriptText.Contains('artifacts\release') -and
        $updateScriptText.Contains('local-app')) `
    -Message "root app materialization must remain isolated from release packaging"
Assert-Contract `
    -Condition (-not $releaseWorkflowText.Contains('update-local-app.ps1')) `
    -Message "release packaging must not consume the generated root app entrypoint"
Assert-Contract `
    -Condition (@([regex]::Matches(
        $ciWorkflowText,
        '\.\\scripts\\update-local-app\.ps1 -Force -SkipChecks')).Count -eq 2) `
    -Message "CI must materialize and smoke the exact root app entrypoint on x64 and ARM64"
Assert-Contract `
    -Condition (@([regex]::Matches(
        $ciWorkflowText,
        'git status --porcelain --untracked-files=all')).Count -eq 2) `
    -Message "both native app materializations must prove that generated outputs remain ignored"
Assert-Contract `
    -Condition $updateScriptText.Contains('& $checkScript -Configuration Release -VerifyFormat | Out-Host') `
    -Message "the full quality gate must not pollute the published executable return value"
Assert-Contract `
    -Condition ($updateScriptText.Contains('$postPublishFingerprint = Get-AppSourceFingerprint') -and
        $updateScriptText.Contains('$postPublishFingerprint -cne $sourceFingerprint')) `
    -Message "source inputs must be revalidated after publishing to prevent a stale install"

foreach ($ignoredPath in @(
    "app/LocalNetworkScanner.exe",
    "app/LocalNetworkScanner.lnk",
    "app/APP-BUILD.json",
    "app/.update-fixture.tmp",
    "app/.update.lock"
)) {
    Assert-Contract `
        -Condition (Test-GitIgnored -RelativePath $ignoredPath) `
        -Message "generated output must be ignored: $ignoredPath"
}
foreach ($trackedSourcePath in @(
    "app/README.md",
    "app/Abrir Local Network Scanner.cmd",
    "scripts/update-local-app.ps1"
)) {
    Assert-Contract `
        -Condition (-not (Test-GitIgnored -RelativePath $trackedSourcePath)) `
        -Message "source entrypoint must not be ignored: $trackedSourcePath"
}

$trackedAppFiles = @(& git -C $repoRoot ls-files -- "app/*.exe" "app/*.lnk" "app/APP-BUILD.json")
if ($LASTEXITCODE -ne 0) {
    throw "git ls-files failed while checking generated app outputs."
}
Assert-Contract `
    -Condition ($trackedAppFiles.Count -eq 0) `
    -Message "generated app binaries, shortcuts or manifests must never be tracked"

. $updateScript

try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    $sourceOne = Join-Path $testRoot "source-one.exe"
    $sourceTwo = Join-Path $testRoot "source-two.exe"
    $destination = Join-Path $testRoot "app"
    Write-TestPePayload -Path $sourceOne -Marker 1
    Write-TestPePayload -Path $sourceTwo -Marker 2

    $null = Install-LocalAppPayload `
        -PublishedExecutable $sourceOne `
        -DestinationRoot $destination `
        -Version "1.4.1" `
        -RuntimeIdentifier "win-x64" `
        -SourceFingerprint ("a" * 64) `
        -Commit ("b" * 40) `
        -WorkingTreeDirty $false `
        -AuthenticodeStatus "NotSigned" `
        -SignerSubject $null

    $installedExecutable = Join-Path $destination "LocalNetworkScanner.exe"
    $installedManifestPath = Join-Path $destination "APP-BUILD.json"
    $installedManifest = Read-AppBuildManifest -ManifestPath $installedManifestPath
    $sourceOneHash = (Get-FileHash -LiteralPath $sourceOne -Algorithm SHA256).Hash
    $installedHash = (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash
    Assert-Contract `
        -Condition ($sourceOneHash -ceq $installedHash) `
        -Message "materialized executable must match the published source byte-for-byte"
    Assert-Contract `
        -Condition (Test-LocalAppCurrent `
            -Executable $installedExecutable `
            -Manifest $installedManifest `
            -Version "1.4.1" `
            -RuntimeIdentifier "win-x64" `
            -SourceFingerprint ("a" * 64)) `
        -Message "fresh payload and manifest must satisfy the current-build contract"
    Assert-Contract `
        -Condition (-not (Test-LocalAppCurrent `
            -Executable $installedExecutable `
            -Manifest $installedManifest `
            -Version "1.4.1" `
            -RuntimeIdentifier "win-arm64" `
            -SourceFingerprint ("a" * 64))) `
        -Message "a payload for another architecture must be rejected"
    $forgedArmManifest = [pscustomobject]@{
        schemaVersion = 1
        version = "1.4.1"
        runtimeIdentifier = "win-arm64"
        sourceFingerprint = ("a" * 64)
        sha256 = $installedHash.ToLowerInvariant()
    }
    Assert-Contract `
        -Condition (-not (Test-LocalAppCurrent `
            -Executable $installedExecutable `
            -Manifest $forgedArmManifest `
            -Version "1.4.1" `
            -RuntimeIdentifier "win-arm64" `
            -SourceFingerprint ("a" * 64))) `
        -Message "manifest metadata must not override the executable's actual PE architecture"
    $malformedManifest = [pscustomobject]@{
        schemaVersion = "not-an-integer"
        version = "1.4.1"
        runtimeIdentifier = "win-x64"
        sourceFingerprint = ("a" * 64)
        sha256 = $null
    }
    Assert-Contract `
        -Condition (-not (Test-LocalAppCurrent `
            -Executable $installedExecutable `
            -Manifest $malformedManifest `
            -Version "1.4.1" `
            -RuntimeIdentifier "win-x64" `
            -SourceFingerprint ("a" * 64))) `
        -Message "a JSON-valid but wrongly typed manifest must trigger a rebuild instead of throwing"

    $hashBeforeBlockedUpdate = (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash
    $manifestHashBeforeBlockedUpdate = (Get-FileHash -LiteralPath $installedManifestPath -Algorithm SHA256).Hash
    $lock = [IO.File]::Open(
        $installedExecutable,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    $blockedUpdateFailed = $false
    try {
        try {
            $null = Install-LocalAppPayload `
                -PublishedExecutable $sourceTwo `
                -DestinationRoot $destination `
                -Version "1.4.1" `
                -RuntimeIdentifier "win-x64" `
                -SourceFingerprint ("c" * 64) `
                -Commit ("d" * 40) `
                -WorkingTreeDirty $true `
                -AuthenticodeStatus "NotSigned" `
                -SignerSubject $null
        }
        catch {
            $blockedUpdateFailed = $true
        }
    }
    finally {
        $lock.Dispose()
    }

    Assert-Contract `
        -Condition $blockedUpdateFailed `
        -Message "a locked destination must fail instead of deleting the previous executable"
    Assert-Contract `
        -Condition ((Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash -ceq $hashBeforeBlockedUpdate) `
        -Message "a failed replacement must preserve the previous executable"
    Assert-Contract `
        -Condition ((Get-FileHash -LiteralPath $installedManifestPath -Algorithm SHA256).Hash -ceq
            $manifestHashBeforeBlockedUpdate) `
        -Message "a failed replacement must roll back the previous manifest"
    $manifestAfterBlockedUpdate = Read-AppBuildManifest -ManifestPath $installedManifestPath
    Assert-Contract `
        -Condition (-not (Test-LocalAppCurrent `
            -Executable $installedExecutable `
            -Manifest $manifestAfterBlockedUpdate `
            -Version "1.4.1" `
            -RuntimeIdentifier "win-x64" `
            -SourceFingerprint ("c" * 64))) `
        -Message "a partial metadata update must remain detectably stale and recoverable"
    Assert-Contract `
        -Condition (@(Get-ChildItem -LiteralPath $destination -File -Filter ".update-*.tmp").Count -eq 0) `
        -Message "temporary files must be cleaned after a failed replacement"

    $null = Install-LocalAppPayload `
        -PublishedExecutable $sourceTwo `
        -DestinationRoot $destination `
        -Version "1.4.1" `
        -RuntimeIdentifier "win-x64" `
        -SourceFingerprint ("c" * 64) `
        -Commit ("d" * 40) `
        -WorkingTreeDirty $true `
        -AuthenticodeStatus "NotSigned" `
        -SignerSubject $null
    Assert-Contract `
        -Condition ((Get-FileHash -LiteralPath $sourceTwo -Algorithm SHA256).Hash -ceq
            (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash) `
        -Message "a later successful update must replace the executable"

    $hashBeforeManifestLock = (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash
    $manifestHashBeforeManifestLock = (Get-FileHash -LiteralPath $installedManifestPath -Algorithm SHA256).Hash
    $manifestLock = [IO.File]::Open(
        $installedManifestPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    $manifestLockedUpdateFailed = $false
    try {
        try {
            $null = Install-LocalAppPayload `
                -PublishedExecutable $sourceOne `
                -DestinationRoot $destination `
                -Version "1.4.1" `
                -RuntimeIdentifier "win-x64" `
                -SourceFingerprint ("e" * 64) `
                -Commit ("f" * 40) `
                -WorkingTreeDirty $true `
                -AuthenticodeStatus "NotSigned" `
                -SignerSubject $null
        }
        catch {
            $manifestLockedUpdateFailed = $true
        }
    }
    finally {
        $manifestLock.Dispose()
    }
    Assert-Contract `
        -Condition $manifestLockedUpdateFailed `
        -Message "a locked manifest must reject the transaction before replacing the executable"
    Assert-Contract `
        -Condition ((Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash -ceq
            $hashBeforeManifestLock) `
        -Message "a manifest replacement failure must preserve the previous executable"
    Assert-Contract `
        -Condition ((Get-FileHash -LiteralPath $installedManifestPath -Algorithm SHA256).Hash -ceq
            $manifestHashBeforeManifestLock) `
        -Message "a manifest replacement failure must preserve the previous manifest"
    Assert-Contract `
        -Condition (@(Get-ChildItem -LiteralPath $destination -File -Filter ".update-*.tmp").Count -eq 0) `
        -Message "a pre-commit failure must remove all transaction scratch files"

    $hashBeforeRollbackFailure = (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash
    $manifestHashBeforeRollbackFailure = (Get-FileHash -LiteralPath $installedManifestPath -Algorithm SHA256).Hash
    $executableLock = [IO.File]::Open(
        $installedExecutable,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    $rollbackFailureMessage = $null
    try {
        try {
            $null = Install-LocalAppPayload `
                -PublishedExecutable $sourceOne `
                -DestinationRoot $destination `
                -Version "1.4.1" `
                -RuntimeIdentifier "win-x64" `
                -SourceFingerprint ("1" * 64) `
                -Commit ("2" * 40) `
                -WorkingTreeDirty $true `
                -AuthenticodeStatus "NotSigned" `
                -SignerSubject $null `
                -RollbackAction {
                    param($Destination, $Backup, $Existed)
                    throw "falha de rollback controlada"
                }
        }
        catch {
            $rollbackFailureMessage = $_.Exception.Message
        }
    }
    finally {
        $executableLock.Dispose()
    }

    $preservedManifestBackups = @(
        Get-ChildItem -LiteralPath $destination -File -Filter ".update-backup-*.json.tmp"
    )
    Assert-Contract `
        -Condition (-not [string]::IsNullOrWhiteSpace($rollbackFailureMessage)) `
        -Message "an incomplete rollback must fail explicitly"
    Assert-Contract `
        -Condition ($preservedManifestBackups.Count -eq 1) `
        -Message "an incomplete rollback must preserve the available manifest backup"
    Assert-Contract `
        -Condition ($preservedManifestBackups.Count -eq 1 -and
            $rollbackFailureMessage.Contains($preservedManifestBackups[0].FullName)) `
        -Message "an incomplete rollback error must report the preserved recovery path"
    Assert-Contract `
        -Condition ((Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash -ceq
            $hashBeforeRollbackFailure) `
        -Message "an incomplete manifest rollback must still leave the locked executable untouched"
    Assert-Contract `
        -Condition (@(Get-ChildItem -LiteralPath $destination -File -Filter ".update-*.tmp" |
            Where-Object { $_.Name -notlike ".update-backup-*" }).Count -eq 0) `
        -Message "an incomplete rollback must clean scratch files while retaining recovery backups"

    if ($preservedManifestBackups.Count -eq 1) {
        Assert-Contract `
            -Condition ((Get-FileHash -LiteralPath $preservedManifestBackups[0].FullName -Algorithm SHA256).Hash -ceq
                $manifestHashBeforeRollbackFailure) `
            -Message "the preserved recovery backup must contain the previous manifest"
        Restore-LocalAppTarget `
            -Destination $installedManifestPath `
            -Backup $preservedManifestBackups[0].FullName `
            -Existed $true
    }
    Assert-Contract `
        -Condition ((Get-FileHash -LiteralPath $installedManifestPath -Algorithm SHA256).Hash -ceq
            $manifestHashBeforeRollbackFailure) `
        -Message "the preserved backup must support successful manual recovery"
    Assert-Contract `
        -Condition (@(Get-ChildItem -LiteralPath $destination -File -Filter ".update-backup-*.tmp").Count -eq 0) `
        -Message "manual recovery must consume the preserved backup"

    $lockPath = Join-Path $testRoot ".update.lock"
    $firstLock = Enter-LocalAppUpdateLock -LockPath $lockPath -TimeoutMilliseconds 0
    $secondLockRejected = $false
    try {
        try {
            $secondLock = Enter-LocalAppUpdateLock -LockPath $lockPath -TimeoutMilliseconds 0
            $secondLock.Dispose()
        }
        catch {
            $secondLockRejected = $true
        }
    }
    finally {
        $firstLock.Dispose()
        Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
    }
    Assert-Contract `
        -Condition $secondLockRejected `
        -Message "a second concurrent app update must be rejected by the cross-process lock"
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host "$passed/$total synthetic app entrypoint contract tests passed."

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
