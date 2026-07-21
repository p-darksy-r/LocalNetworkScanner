[CmdletBinding()]
param(
    [Alias("Rid")]
    [ValidateSet("win-x64", "win-arm64")]
    [string]$RuntimeIdentifier = "win-x64",

    [switch]$SkipPublish,

    [switch]$SkipChecks,

    [string]$IsccPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$propsPath = Join-Path $repoRoot "Directory.Build.props"
$publishScript = Join-Path $PSScriptRoot "publish-windows.ps1"
$installerScript = Join-Path $repoRoot "installer\LocalNetworkScanner.iss"
$setupIcon = Join-Path $repoRoot "LocalNetworkScanner.Wpf\Assets\App.ico"
$artifactsRoot = Join-Path $repoRoot "artifacts"
$releaseRoot = Join-Path $artifactsRoot "release"

function Resolve-Iscc {
    param([string]$RequestedPath)

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidates += $RequestedPath
    }

    $command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        $candidates += $command.Source
    }

    $candidates += @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )

    $resolved = $candidates |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
        Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw "Inno Setup 6 was not found. Install it from https://jrsoftware.org/isdl.php or pass -IsccPath. Portable ZIP publishing does not require Inno Setup."
    }

    return [IO.Path]::GetFullPath($resolved)
}

if (-not (Test-Path -LiteralPath $installerScript -PathType Leaf)) {
    throw "Installer definition not found: $installerScript"
}
if (-not (Test-Path -LiteralPath $propsPath -PathType Leaf)) {
    throw "Build metadata not found: $propsPath"
}
if (-not (Test-Path -LiteralPath $setupIcon -PathType Leaf)) {
    throw "Installer icon not found: $setupIcon"
}

[xml]$props = Get-Content -LiteralPath $propsPath -Raw
$version = [string]$props.Project.PropertyGroup.Version
if ($version -notmatch "^\d+\.\d+\.\d+$") {
    throw "The installer requires a stable three-part Version; found '$version'."
}

Push-Location $repoRoot
try {
    if (-not $SkipPublish) {
        $publishArguments = @("-RuntimeIdentifier", $RuntimeIdentifier, "-SkipWpfSmoke")
        if ($SkipChecks) {
            $publishArguments += "-SkipChecks"
        }
        & $publishScript @publishArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Portable package publishing failed with code $LASTEXITCODE."
        }
    }

    $stagingRoot = Join-Path $artifactsRoot ("staging\LocalNetworkScanner-$version-$RuntimeIdentifier")
    $requiredFiles = @(
        "LocalNetworkScanner.exe",
        "LocalNetworkScanner.Cli.exe",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "SECURITY.md",
        "docs\TECHNICAL_LIMITS.md",
        "docs\RELEASE_CHECKLIST.md",
        "docs\INSTALLATION.md"
    )
    foreach ($relativePath in $requiredFiles) {
        $candidate = Join-Path $stagingRoot $relativePath
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "The staged release is incomplete: $candidate. Run publish-windows.ps1 first or remove -SkipPublish."
        }
    }

    New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
    $iscc = Resolve-Iscc $IsccPath
    $outputBaseName = "LocalNetworkScanner-$version-$RuntimeIdentifier-setup"
    $installerPath = Join-Path $releaseRoot ($outputBaseName + ".exe")
    $checksumPath = $installerPath + ".sha256"

    Remove-Item -LiteralPath $installerPath, $checksumPath -Force -ErrorAction SilentlyContinue

    $compilerArguments = @(
        "/DSourceRoot=$stagingRoot",
        "/DOutputDirectory=$releaseRoot",
        "/DAppVersion=$version",
        "/DRuntimeIdentifier=$RuntimeIdentifier",
        "/DOutputBaseFilename=$outputBaseName",
        "/DSetupIconFile=$setupIcon",
        $installerScript
    )
    Write-Host ("> ISCC.exe " + ($compilerArguments -join " ")) -ForegroundColor DarkGray
    & $iscc @compilerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup exited with code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
        throw "Inno Setup did not create the expected installer: $installerPath"
    }

    $hash = Get-FileHash -LiteralPath $installerPath -Algorithm SHA256
    $checksumLine = "{0} *{1}" -f $hash.Hash.ToLowerInvariant(), (Split-Path $installerPath -Leaf)
    Set-Content -LiteralPath $checksumPath -Value $checksumLine -Encoding ascii

    $signature = Get-AuthenticodeSignature -LiteralPath $installerPath
    if ($signature.Status -ne "Valid") {
        Write-Warning "Installer is not release-signed: $installerPath ($($signature.Status))"
    }

    Write-Host "Windows installer created successfully." -ForegroundColor Green
    Write-Host "Installer: $installerPath"
    Write-Host "SHA-256:  $($hash.Hash.ToLowerInvariant())"
}
finally {
    Pop-Location
}
