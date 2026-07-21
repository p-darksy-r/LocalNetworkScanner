[CmdletBinding()]
param(
    [Alias("Rid")]
    [ValidateSet("win-x64", "win-arm64")]
    [string]$RuntimeIdentifier = "win-x64",

    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [switch]$SkipChecks,

    [switch]$SkipWpfSmoke,

    [switch]$DisableReadyToRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$checkScript = Join-Path $PSScriptRoot "check.ps1"
$cliProject = Join-Path $repoRoot "LocalNetworkScanner.Cli\LocalNetworkScanner.Cli.csproj"
$wpfProject = Join-Path $repoRoot "LocalNetworkScanner.Wpf\LocalNetworkScanner.Wpf.csproj"
$artifactsRoot = Join-Path $repoRoot "artifacts"
$publishRoot = Join-Path $artifactsRoot ("publish\" + $RuntimeIdentifier)
$wpfPublish = Join-Path $publishRoot "wpf"
$cliPublish = Join-Path $publishRoot "cli"
$releaseRoot = Join-Path $artifactsRoot "release"

function Invoke-DotNet {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host ("> dotnet " + ($Arguments -join " ")) -ForegroundColor DarkGray
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet exited with code $LASTEXITCODE."
    }
}

function Assert-InsideArtifacts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $base = [IO.Path]::GetFullPath($artifactsRoot)
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $base + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside the artifacts directory: $full"
    }
    return $full
}

function Reset-ArtifactDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $safePath = Assert-InsideArtifacts $Path
    if (Test-Path -LiteralPath $safePath) {
        Remove-Item -LiteralPath $safePath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $safePath -Force | Out-Null
}

function Invoke-WpfSmokeTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable
    )

    Write-Host "> Published WPF smoke test (window lifecycle)" -ForegroundColor DarkGray
    $process = Start-Process -FilePath $Executable -PassThru
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 250
            $process.Refresh()
        }
        while (-not $process.HasExited -and
               $process.MainWindowHandle -eq 0 -and
               [DateTime]::UtcNow -lt $deadline)

        if ($process.HasExited) {
            throw "The published UI exited before creating a window (exit code $($process.ExitCode))."
        }
        if ($process.MainWindowHandle -eq 0 -or
            $process.MainWindowTitle -ne "Local Network Scanner" -or
            -not $process.Responding) {
            throw "The published UI did not create a responsive main window within 20 seconds."
        }
        if (-not $process.CloseMainWindow()) {
            throw "The published UI did not accept a normal window-close request."
        }
        if (-not $process.WaitForExit(8000)) {
            throw "The published UI did not close normally within 8 seconds."
        }
        if ($process.ExitCode -ne 0) {
            throw "The published UI smoke test exited with code $($process.ExitCode)."
        }
    }
    finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        $process.Dispose()
    }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "The .NET SDK is required and dotnet was not found on PATH."
}
if (-not (Get-Command Compress-Archive -ErrorAction SilentlyContinue)) {
    throw "Compress-Archive is required and was not found."
}
if (-not (Test-Path -LiteralPath $wpfProject)) {
    throw "The WPF project is required for a release package: $wpfProject"
}
if (-not (Test-Path -LiteralPath $cliProject)) {
    throw "The CLI project is required for a release package: $cliProject"
}

Push-Location $repoRoot
try {
    if (-not $SkipChecks) {
        & $checkScript -Configuration $Configuration
        if ($LASTEXITCODE -ne 0) {
            throw "The validation script failed with code $LASTEXITCODE."
        }
    }

    $versionOutput = & dotnet msbuild $cliProject -nologo -getProperty:Version
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read the effective Version property."
    }
    $version = [string]($versionOutput | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Last 1)
    $version = $version.Trim()
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "The effective Version property is empty."
    }

    $readyToRun = "true"
    if ($DisableReadyToRun) {
        $readyToRun = "false"
    }

    Reset-ArtifactDirectory $publishRoot
    New-Item -ItemType Directory -Path $wpfPublish, $cliPublish, $releaseRoot -Force | Out-Null

    foreach ($project in @($wpfProject, $cliProject)) {
        Invoke-DotNet @(
            "restore",
            $project,
            "--runtime", $RuntimeIdentifier,
            "-p:PublishReadyToRun=$readyToRun"
        )
    }

    $commonPublishArguments = @(
        "--configuration", $Configuration,
        "--runtime", $RuntimeIdentifier,
        "--self-contained", "true",
        "--no-restore",
        "--nologo",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "-p:EnableCompressionInSingleFile=true",
        "-p:PublishTrimmed=false",
        "-p:PublishReadyToRun=$readyToRun",
        "-p:DebugType=None",
        "-p:DebugSymbols=false"
    )

    Invoke-DotNet (@("publish", $wpfProject, "--output", $wpfPublish) + $commonPublishArguments)
    Invoke-DotNet (@("publish", $cliProject, "--output", $cliPublish) + $commonPublishArguments)

    $wpfExe = Join-Path $wpfPublish "LocalNetworkScanner.exe"
    $cliExe = Join-Path $cliPublish "LocalNetworkScanner.Cli.exe"
    foreach ($executable in @($wpfExe, $cliExe)) {
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
            throw "Expected executable was not published: $executable"
        }
    }

    $hostArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $canRunPublishedCli =
        ($RuntimeIdentifier -eq "win-x64" -and $hostArchitecture -in @("X64", "Arm64")) -or
        ($RuntimeIdentifier -eq "win-arm64" -and $hostArchitecture -eq "Arm64")

    if ($canRunPublishedCli) {
        Write-Host "> Published CLI smoke test (--help)" -ForegroundColor DarkGray
        & $cliExe --help | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Published CLI smoke test failed with code $LASTEXITCODE."
        }

        if (-not $SkipWpfSmoke) {
            Invoke-WpfSmokeTest $wpfExe
        }
    }
    else {
        Write-Warning "The $RuntimeIdentifier executable cannot run on the $hostArchitecture build host. Run the published CLI smoke test on a native target before release."
    }

    $packageName = "LocalNetworkScanner-$version-$RuntimeIdentifier"
    $stagingRoot = Join-Path $artifactsRoot ("staging\" + $packageName)
    Reset-ArtifactDirectory $stagingRoot

    Copy-Item -LiteralPath $wpfExe -Destination (Join-Path $stagingRoot "LocalNetworkScanner.exe")
    Copy-Item -LiteralPath $cliExe -Destination (Join-Path $stagingRoot "LocalNetworkScanner.Cli.exe")

    foreach ($file in @("README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md")) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $file) -Destination $stagingRoot
    }

    $stagingDocs = Join-Path $stagingRoot "docs"
    New-Item -ItemType Directory -Path $stagingDocs -Force | Out-Null
    foreach ($document in @("TECHNICAL_LIMITS.md", "RELEASE_CHECKLIST.md", "INSTALLATION.md")) {
        Copy-Item -LiteralPath (Join-Path $repoRoot ("docs\" + $document)) -Destination $stagingDocs
    }

    $archivePath = Join-Path $releaseRoot ($packageName + ".zip")
    $checksumPath = $archivePath + ".sha256"
    Assert-InsideArtifacts $archivePath | Out-Null
    Assert-InsideArtifacts $checksumPath | Out-Null
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    if (Test-Path -LiteralPath $checksumPath) {
        Remove-Item -LiteralPath $checksumPath -Force
    }

    Compress-Archive -LiteralPath $stagingRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $hash = Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
    $checksumLine = "{0} *{1}" -f $hash.Hash.ToLowerInvariant(), (Split-Path $archivePath -Leaf)
    Set-Content -LiteralPath $checksumPath -Value $checksumLine -Encoding ascii

    foreach ($executable in @($wpfExe, $cliExe)) {
        $signature = Get-AuthenticodeSignature -LiteralPath $executable
        if ($signature.Status -ne "Valid") {
            Write-Warning "Executable is not release-signed: $executable ($($signature.Status))"
        }
    }

    Write-Host "Windows package created successfully." -ForegroundColor Green
    Write-Host "Archive:  $archivePath"
    Write-Host "SHA-256:  $($hash.Hash.ToLowerInvariant())"
    Write-Host "Checksum: $checksumPath"
}
finally {
    Pop-Location
}
