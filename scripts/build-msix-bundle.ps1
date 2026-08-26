# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [ValidateSet("PrivateTest", "Store")]
    [string]$Mode = "PrivateTest",

    [string]$IdentityName,

    [string]$Publisher,

    [string]$PublisherDisplayName,

    [string]$SigningCertificateThumbprint,

    [string]$PublicCertificatePath = (Join-Path (Split-Path -Parent $PSScriptRoot) "crt\LocalNetworkScanner-PrivateTest.crt"),

    [ValidateRange(0, 65535)]
    [int]$PackageRevision = 0,

    [string]$MakeAppxPath,

    [string]$SignToolPath,

    [switch]$SkipChecks,

    [switch]$SkipWpfSmoke,

    [switch]$DisableReadyToRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactsRoot = Join-Path $repoRoot "artifacts"
$buildScript = Join-Path $PSScriptRoot "build-msix.ps1"
$validatorScript = Join-Path $PSScriptRoot "validate-msix-package.ps1"
$checkScript = Join-Path $PSScriptRoot "check.ps1"

function Invoke-NativeTool {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    Write-Host ("> " + (Split-Path $FilePath -Leaf) + " " + ($Arguments -join " ")) -ForegroundColor DarkGray
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-MSX-004: $(Split-Path $FilePath -Leaf) exited with code $LASTEXITCODE."
    }
}

function Resolve-WindowsSdkTool {
    param(
        [Parameter(Mandatory)][string]$ToolName,
        [string]$RequestedPath
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $resolved = [IO.Path]::GetFullPath($RequestedPath)
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "LNS-MSX-004: $ToolName was not found at the requested path: $resolved"
        }
        return $resolved
    }

    $command = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    $candidates = @()
    if (Test-Path -LiteralPath $kitsRoot -PathType Container) {
        $candidates = @(
            Get-ChildItem -LiteralPath $kitsRoot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
                Sort-Object { [version]$_.Name } -Descending |
                ForEach-Object { Join-Path $_.FullName "x64\$ToolName" } |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
        )
    }
    if ($candidates.Count -eq 0) {
        throw "LNS-MSX-004: $ToolName was not found. Install the Windows SDK MSIX packaging tools."
    }
    return $candidates[0]
}

function Assert-InsideArtifacts {
    param([Parameter(Mandatory)][string]$Path)

    $base = [IO.Path]::GetFullPath($artifactsRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        throw "LNS-MSX-004: refusing to modify a path outside artifacts: $full"
    }
    return $full
}

if (-not (Test-Path -LiteralPath $buildScript -PathType Leaf) -or
    -not (Test-Path -LiteralPath $validatorScript -PathType Leaf)) {
    throw "LNS-MSX-004: required MSIX build/validation scripts are missing."
}
if ($Mode -eq "Store") {
    foreach ($field in @{
        IdentityName = $IdentityName
        Publisher = $Publisher
        PublisherDisplayName = $PublisherDisplayName
    }.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string]$field.Value)) {
            throw "LNS-MSX-001: -$($field.Key) is required for a Store bundle."
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        throw "LNS-MSX-001: Store bundles remain unsigned until Microsoft Store certification."
    }
    if (-not [string]::IsNullOrWhiteSpace($SignToolPath)) {
        throw "LNS-MSX-001: Store bundles do not accept a signing tool."
    }
    if ($PackageRevision -ne 0) {
        throw "LNS-MSX-001: Store bundles must use revision 0."
    }
}
elseif (-not [string]::IsNullOrWhiteSpace($IdentityName) -or
    -not [string]::IsNullOrWhiteSpace($Publisher) -or
    -not [string]::IsNullOrWhiteSpace($PublisherDisplayName)) {
    throw "LNS-MSX-001: PrivateTest uses a fixed isolated identity; do not pass Store identity parameters."
}

$resolvedMakeAppx = Resolve-WindowsSdkTool "makeappx.exe" $MakeAppxPath
$resolvedSignTool = if ($Mode -eq "PrivateTest") {
    Resolve-WindowsSdkTool "signtool.exe" $SignToolPath
}
else {
    $null
}

Push-Location $repoRoot
try {
    if (-not $SkipChecks) {
        & $checkScript -Configuration Release
        if ($LASTEXITCODE -ne 0) {
            throw "LNS-MSX-004: the validation script failed with code $LASTEXITCODE."
        }
    }

    foreach ($runtimeIdentifier in @("win-x64", "win-arm64")) {
        $buildParameters = @{
            Mode = $Mode
            RuntimeIdentifier = $runtimeIdentifier
            PackageRevision = $PackageRevision
            MakeAppxPath = $resolvedMakeAppx
            SkipChecks = $true
            SkipWpfSmoke = $SkipWpfSmoke.IsPresent
            DisableReadyToRun = $DisableReadyToRun.IsPresent
        }
        if ($Mode -eq "PrivateTest") {
            if (-not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
                $buildParameters.SigningCertificateThumbprint = $SigningCertificateThumbprint
            }
            $buildParameters.PublicCertificatePath = $PublicCertificatePath
            $buildParameters.SignToolPath = $resolvedSignTool
        }
        else {
            $buildParameters.IdentityName = $IdentityName
            $buildParameters.Publisher = $Publisher
            $buildParameters.PublisherDisplayName = $PublisherDisplayName
        }

        & $buildScript @buildParameters
        if ($LASTEXITCODE -ne 0) {
            throw "LNS-MSX-004: MSIX package build failed for $runtimeIdentifier with code $LASTEXITCODE."
        }
    }

    $modeDirectoryName = if ($Mode -eq "PrivateTest") { "private-test" } else { "store" }
    $states = @()
    foreach ($runtimeIdentifier in @("win-x64", "win-arm64")) {
        $statePath = Join-Path $artifactsRoot "msix\$modeDirectoryName\$runtimeIdentifier\MSIX-BUILD-STATE.json"
        if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
            throw "LNS-MSX-004: package state was not produced for $runtimeIdentifier."
        }
        $states += Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    }
    if (@($states.packageVersion | Sort-Object -Unique).Count -ne 1 -or
        @($states.identityName | Sort-Object -Unique).Count -ne 1 -or
        @($states.publisher | Sort-Object -Unique).Count -ne 1) {
        throw "LNS-MSX-005: x64 and ARM64 package state does not share an exact identity and version."
    }

    $bundleWork = Join-Path $artifactsRoot "msix\work\$modeDirectoryName\bundle"
    $bundleInput = Join-Path $bundleWork "input"
    $bundleOutput = Join-Path $artifactsRoot "msix\$modeDirectoryName\bundle"
    foreach ($directory in @($bundleWork, $bundleOutput)) {
        $safeDirectory = Assert-InsideArtifacts $directory
        if (Test-Path -LiteralPath $safeDirectory) {
            Remove-Item -LiteralPath $safeDirectory -Recurse -Force
        }
        New-Item -ItemType Directory -Path $safeDirectory -Force | Out-Null
    }
    New-Item -ItemType Directory -Path $bundleInput -Force | Out-Null

    foreach ($index in 0..1) {
        $runtimeIdentifier = @("win-x64", "win-arm64")[$index]
        $packagePath = Join-Path $artifactsRoot "msix\$modeDirectoryName\$runtimeIdentifier\$($states[$index].packageFile)"
        $actualHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $states[$index].sha256) {
            throw "LNS-MSX-005: $runtimeIdentifier package changed after validation."
        }
        Copy-Item -LiteralPath $packagePath -Destination $bundleInput
    }

    $packageVersion = [string]$states[0].packageVersion
    $bundleSuffix = if ($Mode -eq "PrivateTest") { "PrivateTest" } else { "Store-Unsigned" }
    $bundleFileName = "LocalNetworkScanner-$packageVersion-$bundleSuffix.msixbundle"
    $bundlePath = Join-Path $bundleOutput $bundleFileName
    Invoke-NativeTool $resolvedMakeAppx @(
        "bundle", "/v", "/o", "/bv", $packageVersion,
        "/d", $bundleInput,
        "/p", $bundlePath
    )

    $expectedSigner = $null
    if ($Mode -eq "PrivateTest") {
        $expectedSigner = [string]$states[0].signerThumbprint
        if ([string]::IsNullOrWhiteSpace($expectedSigner) -or
            $expectedSigner -ne [string]$states[1].signerThumbprint) {
            throw "LNS-MSX-005: PrivateTest packages were not signed by the same certificate."
        }
        Invoke-NativeTool $resolvedSignTool @(
            "sign", "/v", "/fd", "SHA256", "/s", "My",
            "/sha1", $expectedSigner,
            $bundlePath
        )
    }

    $validationParameters = @{
        Path = $bundlePath
        ExpectedMode = $Mode
        MakeAppxPath = $resolvedMakeAppx
    }
    if ($null -ne $expectedSigner) {
        $validationParameters.ExpectedSignerThumbprint = $expectedSigner
    }
    else {
        $validationParameters.ExpectedIdentityName = $IdentityName
        $validationParameters.ExpectedPublisher = $Publisher
        $validationParameters.ExpectedPublisherDisplayName = $PublisherDisplayName
    }
    & $validatorScript @validationParameters
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-MSX-005: MSIX bundle validation failed with code $LASTEXITCODE."
    }

    $bundleHash = Get-FileHash -LiteralPath $bundlePath -Algorithm SHA256
    Set-Content -LiteralPath "$bundlePath.sha256" -Encoding ascii -Value ("{0} *{1}" -f $bundleHash.Hash.ToLowerInvariant(), $bundleFileName)
    [ordered]@{
        schemaVersion = 1
        productVersion = [string]$states[0].productVersion
        packageVersion = $packageVersion
        mode = $Mode
        signingState = if ($Mode -eq "PrivateTest") { "PrivateTestSelfSigned" } else { "UnsignedForMicrosoftStore" }
        architectures = @("x64", "arm64")
        identityName = [string]$states[0].identityName
        publisher = [string]$states[0].publisher
        publisherDisplayName = [string]$states[0].publisherDisplayName
        bundleFile = $bundleFileName
        sha256 = $bundleHash.Hash.ToLowerInvariant()
        signerThumbprint = $expectedSigner
        sourceCommit = [string](& git rev-parse HEAD 2>$null)
        createdUtc = [DateTime]::UtcNow.ToString("o")
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $bundleOutput "MSIX-BUNDLE-STATE.json") -Encoding utf8

    Write-Host "MSIX x64+ARM64 bundle created and validated." -ForegroundColor Green
    Write-Host "Mode:       $Mode"
    Write-Host "Bundle:     $bundlePath"
    Write-Host "SHA-256:    $($bundleHash.Hash.ToLowerInvariant())"
    if ($Mode -eq "Store") {
        Write-Warning "The bundle is intentionally unsigned for Partner Center and is not a sideload installer."
    }
}
finally {
    Pop-Location
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
