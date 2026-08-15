# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [string]$ReleaseRoot,

    [string]$OutputRoot,

    [string]$ComponentRoot,

    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$ToolVersion = '4.1.5'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactsRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'artifacts'))
$releasePath = if ([string]::IsNullOrWhiteSpace($ReleaseRoot)) {
    Join-Path $artifactsRoot 'release'
}
else {
    $ReleaseRoot
}
$outputPath = if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    Join-Path $artifactsRoot 'sbom'
}
else {
    $OutputRoot
}
$componentPath = if ([string]::IsNullOrWhiteSpace($ComponentRoot)) {
    Join-Path $artifactsRoot 'sbom-components'
}
else {
    $ComponentRoot
}

$releasePath = [IO.Path]::GetFullPath($releasePath)
$outputPath = [IO.Path]::GetFullPath($outputPath)
$componentPath = [IO.Path]::GetFullPath($componentPath)
$artifactsPrefix = $artifactsRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
if (-not $releasePath.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not $outputPath.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not $componentPath.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $releasePath.Equals($outputPath, [StringComparison]::OrdinalIgnoreCase) -or
    $releasePath.Equals($componentPath, [StringComparison]::OrdinalIgnoreCase) -or
    $outputPath.Equals($componentPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'LNS-REL-010: SBOM input, output and component evidence must be distinct paths below the repository artifacts directory.'
}
if (-not (Test-Path -LiteralPath $releasePath -PathType Container)) {
    throw "LNS-REL-010: release payload was not found at '$releasePath'."
}
if (-not (Get-ChildItem -LiteralPath $releasePath -File | Select-Object -First 1)) {
    throw "LNS-REL-010: release payload is empty at '$releasePath'."
}

if (Test-Path -LiteralPath $outputPath) {
    Remove-Item -LiteralPath $outputPath -Recurse -Force
}
$null = New-Item -Path $outputPath -ItemType Directory -Force
if (Test-Path -LiteralPath $componentPath) {
    Remove-Item -LiteralPath $componentPath -Recurse -Force
}
$null = New-Item -Path $componentPath -ItemType Directory -Force

$solutionPath = Join-Path $repoRoot 'LocalNetworkScanner.slnx'
$runtimeIdentifiers = @('win-x64', 'win-arm64')
$projects = @(Get-ChildItem -LiteralPath $repoRoot -Filter '*.csproj' -File -Recurse |
        Where-Object { -not $_.FullName.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase) })
if ($projects.Count -eq 0) {
    throw 'LNS-REL-010: no project metadata was found for SBOM component discovery.'
}

foreach ($runtimeIdentifier in $runtimeIdentifiers) {
    dotnet restore $solutionPath --runtime $runtimeIdentifier --no-cache
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-REL-010: dependency metadata restore failed for '$runtimeIdentifier'."
    }

    foreach ($project in $projects) {
        $assetsPath = Join-Path $project.DirectoryName 'obj\project.assets.json'
        if (-not (Test-Path -LiteralPath $assetsPath -PathType Leaf)) {
            throw "LNS-REL-010: dependency metadata is missing for '$($project.Name)' and '$runtimeIdentifier'."
        }

        $relativeProjectDirectory = $project.DirectoryName.Substring(
            $repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar).Length
        ).TrimStart([IO.Path]::DirectorySeparatorChar)
        $evidenceDirectory = Join-Path $componentPath "$runtimeIdentifier\$relativeProjectDirectory\obj"
        $null = New-Item -Path $evidenceDirectory -ItemType Directory -Force
        Copy-Item -LiteralPath $assetsPath -Destination (Join-Path $evidenceDirectory 'project.assets.json')
    }
}

$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$toolRoot = [IO.Path]::GetFullPath((
        Join-Path $tempRoot "local-network-scanner-sbom-tool-$ToolVersion"
    ))
$tempPrefix = $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
if (-not $toolRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'LNS-REL-010: refusing to create the SBOM tool cache outside the temporary directory.'
}
if (Test-Path -LiteralPath $toolRoot) {
    Remove-Item -LiteralPath $toolRoot -Recurse -Force
}
$null = New-Item -Path $toolRoot -ItemType Directory -Force

dotnet tool install Microsoft.Sbom.DotNetTool `
    --tool-path $toolRoot `
    --version $ToolVersion `
    --no-cache
if ($LASTEXITCODE -ne 0) {
    throw "LNS-REL-010: Microsoft SBOM Tool $ToolVersion could not be installed."
}

$toolPath = Join-Path $toolRoot 'sbom-tool.exe'
if (-not (Test-Path -LiteralPath $toolPath -PathType Leaf)) {
    throw "LNS-REL-010: Microsoft SBOM Tool executable was not found at '$toolPath'."
}

& $toolPath generate `
    -b $releasePath `
    -bc $componentPath `
    -m $outputPath `
    -pn LocalNetworkScanner `
    -pv $Version `
    -ps p-darksy-r `
    -nsb 'https://github.com/p-darksy-r/LocalNetworkScanner' `
    -mi 'SPDX:2.2'
if ($LASTEXITCODE -ne 0) {
    throw 'LNS-REL-010: SPDX 2.2 SBOM generation failed.'
}

$manifestRoot = Join-Path $outputPath '_manifest'
$manifestPath = Join-Path $manifestRoot 'spdx_2.2\manifest.spdx.json'
$validationPath = Join-Path $outputPath 'validation-result.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "LNS-REL-010: generated SBOM was not found at '$manifestPath'."
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$detectedPackageNames = @($manifest.packages | ForEach-Object { $_.name })
$expectedRuntimePackages = @(
    'Microsoft.NETCore.App.Runtime.win-x64',
    'Microsoft.WindowsDesktop.App.Runtime.win-x64',
    'Microsoft.NETCore.App.Runtime.win-arm64',
    'Microsoft.WindowsDesktop.App.Runtime.win-arm64'
)
$missingRuntimePackages = @($expectedRuntimePackages |
        Where-Object { $detectedPackageNames -notcontains $_ })
if ($missingRuntimePackages.Count -gt 0) {
    throw "LNS-REL-010: SBOM runtime coverage is incomplete: $($missingRuntimePackages -join ', ')."
}

& $toolPath validate `
    -b $releasePath `
    -m $manifestRoot `
    -o $validationPath `
    -mi 'SPDX:2.2'
if ($LASTEXITCODE -ne 0 -or
    -not (Test-Path -LiteralPath $validationPath -PathType Leaf)) {
    throw 'LNS-REL-010: SPDX 2.2 SBOM validation failed.'
}

$coveragePath = Join-Path $outputPath 'runtime-coverage.json'
[ordered]@{
    schemaVersion = 1
    version = $Version
    runtimeIdentifiers = $runtimeIdentifiers
    expectedPackages = $expectedRuntimePackages
    detectedPackages = @($detectedPackageNames | Sort-Object -Unique)
    status = 'Validated'
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $coveragePath -Encoding utf8

Write-Host "Validated SPDX 2.2 SBOM with win-x64 and win-arm64 coverage: $manifestPath"

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
