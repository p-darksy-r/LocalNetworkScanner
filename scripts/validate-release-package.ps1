# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^\d+\.\d+\.\d+$")]
    [string]$Version,

    [ValidateSet("win-x64", "win-arm64")]
    [string]$RuntimeIdentifier = "win-arm64",

    [string]$ReleaseRoot,

    [switch]$RequireSigned
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ReleaseRoot)) {
    $ReleaseRoot = Join-Path $repoRoot "artifacts\release"
}
$releasePath = [IO.Path]::GetFullPath($ReleaseRoot)
if (-not (Test-Path -LiteralPath $releasePath -PathType Container)) {
    throw "LNS-REL-008: release directory does not exist: $releasePath"
}

$expectedArchitecture = if ($RuntimeIdentifier -eq "win-arm64") { "Arm64" } else { "X64" }
$hostArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($hostArchitecture -ne $expectedArchitecture) {
    throw "LNS-REL-007: expected a native $expectedArchitecture host for $RuntimeIdentifier; received $hostArchitecture."
}

function Assert-Checksum {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string[]]$ManifestLines
    )

    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        throw "LNS-REL-008: expected release binary is missing: $BinaryPath"
    }
    $name = Split-Path $BinaryPath -Leaf
    $expectedLine = "{0} *{1}" -f (
        Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256
    ).Hash.ToLowerInvariant(), $name
    $individualPath = "$BinaryPath.sha256"
    if (-not (Test-Path -LiteralPath $individualPath -PathType Leaf)) {
        throw "LNS-REL-008: individual checksum is missing: $individualPath"
    }
    $individualLine = (Get-Content -LiteralPath $individualPath -Raw).Trim()
    if ($individualLine -cne $expectedLine -or $ManifestLines -cnotcontains $expectedLine) {
        throw "LNS-REL-008: checksum validation failed for $name."
    }
}

function Assert-Signature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ExpectedThumbprint
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $actualThumbprint = if ($null -ne $signature.SignerCertificate) {
        $signature.SignerCertificate.Thumbprint
    }
    else {
        $null
    }
    if ($signature.Status -ne "Valid" -or
        [string]::IsNullOrWhiteSpace($actualThumbprint) -or
        $null -eq $signature.TimeStamperCertificate -or
        (-not [string]::IsNullOrWhiteSpace($ExpectedThumbprint) -and $actualThumbprint -ne $ExpectedThumbprint)) {
        throw "LNS-REL-005: signature validation failed for '$Path': status=$($signature.Status), signer=$actualThumbprint, timestamp=$($null -ne $signature.TimeStamperCertificate)."
    }
    return $actualThumbprint
}

function Invoke-WpfSmokeTest {
    param([Parameter(Mandatory = $true)][string]$Executable)

    Write-Host "> Exact-package WPF smoke test: $Executable" -ForegroundColor DarkGray
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
            throw "LNS-REL-007: packaged UI exited before creating a window (exit code $($process.ExitCode))."
        }
        if ($process.MainWindowHandle -eq 0 -or
            $process.MainWindowTitle -ne "Local Network Scanner" -or
            -not $process.Responding) {
            throw "LNS-REL-007: packaged UI did not create a responsive main window within 20 seconds."
        }
        if (-not $process.CloseMainWindow() -or -not $process.WaitForExit(8000)) {
            throw "LNS-REL-007: packaged UI did not close normally."
        }
        if ($process.ExitCode -ne 0) {
            throw "LNS-REL-007: packaged UI smoke test exited with code $($process.ExitCode)."
        }
    }
    finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        $process.Dispose()
    }
}

function Invoke-CliSmokeTest {
    param([Parameter(Mandatory = $true)][string]$Executable)

    Write-Host "> Exact-package CLI smoke test: $Executable --help" -ForegroundColor DarkGray
    & $Executable --help | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-REL-007: packaged CLI smoke test exited with code $LASTEXITCODE."
    }
}

$packageName = "LocalNetworkScanner-$Version-$RuntimeIdentifier"
$archivePath = Join-Path $releasePath "$packageName.zip"
$installerPath = Join-Path $releasePath "$packageName-setup.exe"
$manifestPath = Join-Path $releasePath "SHA256SUMS.txt"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "LNS-REL-008: combined checksum manifest is missing: $manifestPath"
}
$manifestLines = @(Get-Content -LiteralPath $manifestPath)
Assert-Checksum $archivePath $manifestLines
Assert-Checksum $installerPath $manifestLines

$runnerTempPath = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    [IO.Path]::GetTempPath()
}
else {
    $env:RUNNER_TEMP
}
$validationRoot = Join-Path $runnerTempPath "LocalNetworkScanner-$Version-$RuntimeIdentifier-validation"
$runnerTemp = [IO.Path]::GetFullPath($runnerTempPath).TrimEnd('\') + '\'
$fullValidationRoot = [IO.Path]::GetFullPath($validationRoot)
if (-not $fullValidationRoot.StartsWith($runnerTemp, [StringComparison]::OrdinalIgnoreCase)) {
    throw "LNS-REL-008: refusing to use a validation path outside RUNNER_TEMP: $fullValidationRoot"
}

if (Test-Path -LiteralPath $fullValidationRoot) {
    Remove-Item -LiteralPath $fullValidationRoot -Recurse -Force
}
$extractRoot = Join-Path $fullValidationRoot "portable"
$installRoot = Join-Path $fullValidationRoot "installed"
New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null

$portableUi = Join-Path (Join-Path $extractRoot $packageName) "LocalNetworkScanner.exe"
$portableCli = Join-Path (Join-Path $extractRoot $packageName) "LocalNetworkScanner.Cli.exe"
$portableDiagnostic = Join-Path (Join-Path $extractRoot $packageName) "tools\diagnose-app-control.ps1"
$installedUi = Join-Path $installRoot "LocalNetworkScanner.exe"
$installedCli = Join-Path $installRoot "LocalNetworkScanner.Cli.exe"
$installedDiagnostic = Join-Path $installRoot "tools\diagnose-app-control.ps1"
$signerThumbprint = $null
$installerInvoked = $false
$validationError = $null
$uninstallError = $null
$uninstallConfirmed = $false

try {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot
    $archiveEntries = @(Get-ChildItem -LiteralPath $extractRoot -Force)
    if ($archiveEntries.Count -ne 1 -or
        -not $archiveEntries[0].PSIsContainer -or
        $archiveEntries[0].Name -cne $packageName) {
        throw "LNS-REL-008: portable archive must contain exactly the '$packageName' root directory."
    }

    $packageRoot = $archiveEntries[0].FullName
    $expectedSignablePaths = @(
        "LocalNetworkScanner.Cli.exe",
        "LocalNetworkScanner.exe",
        "tools/diagnose-app-control.ps1"
    ) | Sort-Object
    $signableExtensions = @(
        ".appx", ".cat", ".dll", ".exe", ".msi", ".msix", ".ocx",
        ".ps1", ".psd1", ".psm1", ".sys"
    )
    $actualSignablePaths = @(
        Get-ChildItem -LiteralPath $packageRoot -Recurse -File |
            Where-Object { $_.Extension.ToLowerInvariant() -in $signableExtensions } |
            ForEach-Object {
                [IO.Path]::GetRelativePath($packageRoot, $_.FullName).Replace("\", "/")
            } |
            Sort-Object
    )
    $contractDifference = @(
        Compare-Object -ReferenceObject $expectedSignablePaths -DifferenceObject $actualSignablePaths
    )
    if ($contractDifference.Count -ne 0) {
        throw "LNS-REL-008: portable signable-file contract differs from the three exact paths: $($contractDifference | Out-String)"
    }
    foreach ($expectedFile in @($portableUi, $portableCli, $portableDiagnostic)) {
        if (-not (Test-Path -LiteralPath $expectedFile -PathType Leaf)) {
            throw "LNS-REL-008: exact portable payload path is missing: $expectedFile"
        }
    }

    $portableHashes = @{}
    foreach ($portableFile in @($portableUi, $portableCli, $portableDiagnostic)) {
        $portableHashes[$portableFile] = (Get-FileHash -LiteralPath $portableFile -Algorithm SHA256).Hash
    }

    if ($RequireSigned) {
        $signerThumbprint = Assert-Signature $portableUi
        foreach ($signedFile in @($portableCli, $portableDiagnostic, $installerPath)) {
            [void](Assert-Signature $signedFile $signerThumbprint)
        }
    }

    Invoke-CliSmokeTest $portableCli
    Invoke-WpfSmokeTest $portableUi
    foreach ($portableFile in @($portableUi, $portableCli, $portableDiagnostic)) {
        if ((Get-FileHash -LiteralPath $portableFile -Algorithm SHA256).Hash -cne
            $portableHashes[$portableFile]) {
            throw "LNS-REL-008: portable smoke testing changed the validated payload: $portableFile"
        }
    }

    $installerInvoked = $true
    $install = $null
    try {
        $install = Start-Process -FilePath $installerPath -ArgumentList @(
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/SP-",
            "/CURRENTUSER",
            "/DIR=`"$installRoot`""
        ) -Wait -PassThru
        if ($install.ExitCode -ne 0) {
            throw "LNS-REL-007: exact installer exited with code $($install.ExitCode)."
        }
    }
    finally {
        if ($null -ne $install) {
            $install.Dispose()
        }
    }

    $payloadPairs = @(
        [pscustomobject]@{ Portable = $portableUi; Installed = $installedUi },
        [pscustomobject]@{ Portable = $portableCli; Installed = $installedCli },
        [pscustomobject]@{ Portable = $portableDiagnostic; Installed = $installedDiagnostic }
    )
    foreach ($pair in $payloadPairs) {
        if (-not (Test-Path -LiteralPath $pair.Installed -PathType Leaf) -or
            $portableHashes[$pair.Portable] -cne
            (Get-FileHash -LiteralPath $pair.Installed -Algorithm SHA256).Hash) {
            throw "LNS-REL-008: installed payload hash does not match the exact portable file: $($pair.Installed)"
        }
    }

    $uninstaller = @(Get-ChildItem -LiteralPath $installRoot -File -Filter "unins*.exe")
    if ($uninstaller.Count -ne 1) {
        throw "LNS-REL-008: exact installer did not create one expected uninstaller."
    }
    if ($RequireSigned) {
        foreach ($signedFile in @($installedUi, $installedCli, $installedDiagnostic, $uninstaller[0].FullName)) {
            [void](Assert-Signature $signedFile $signerThumbprint)
        }
    }

    Invoke-CliSmokeTest $installedCli
    Invoke-WpfSmokeTest $installedUi
}
catch {
    $validationError = $_
}
finally {
    if ($installerInvoked) {
        try {
            $uninstaller = @(
                Get-ChildItem -LiteralPath $installRoot -File -Filter "unins*.exe" -ErrorAction SilentlyContinue
            )
            if ($uninstaller.Count -ne 1) {
                throw "LNS-REL-007: cleanup requires exactly one uninstaller after invoking the installer; found $($uninstaller.Count)."
            }
            if ($RequireSigned -and -not [string]::IsNullOrWhiteSpace($signerThumbprint)) {
                [void](Assert-Signature $uninstaller[0].FullName $signerThumbprint)
            }

            $uninstall = $null
            try {
                $uninstall = Start-Process -FilePath $uninstaller[0].FullName -ArgumentList @(
                    "/VERYSILENT",
                    "/SUPPRESSMSGBOXES",
                    "/NORESTART"
                ) -Wait -PassThru
                if ($uninstall.ExitCode -ne 0) {
                    throw "LNS-REL-007: exact uninstaller exited with code $($uninstall.ExitCode)."
                }
            }
            finally {
                if ($null -ne $uninstall) {
                    $uninstall.Dispose()
                }
            }

            $removalDeadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                $remainingPayload = @(
                    @($installedUi, $installedCli, $installedDiagnostic) |
                        Where-Object { Test-Path -LiteralPath $_ }
                )
                $installDirectoryStillExists = Test-Path -LiteralPath $installRoot
                if ($remainingPayload.Count -eq 0 -and -not $installDirectoryStillExists) {
                    $uninstallConfirmed = $true
                    break
                }
                Start-Sleep -Milliseconds 250
            }
            while ([DateTime]::UtcNow -lt $removalDeadline)

            if (-not $uninstallConfirmed) {
                throw "LNS-REL-007: uninstaller returned success but payload or install directory remained after 30 seconds: $($remainingPayload -join ', ')."
            }
        }
        catch {
            $uninstallError = $_
        }
    }

    if ((-not $installerInvoked -or $uninstallConfirmed) -and
        (Test-Path -LiteralPath $fullValidationRoot)) {
        Remove-Item -LiteralPath $fullValidationRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($null -ne $validationError -and $null -ne $uninstallError) {
    throw "LNS-REL-007: package validation failed and mandatory uninstall also failed. Validation: $($validationError.Exception.Message) Uninstall: $($uninstallError.Exception.Message) Evidence retained at '$fullValidationRoot'."
}
if ($null -ne $uninstallError) {
    throw $uninstallError
}
if ($null -ne $validationError) {
    throw $validationError
}

Write-Host "Exact $RuntimeIdentifier release archive, installer, UI, CLI, diagnostic and confirmed uninstall validated natively." -ForegroundColor Green

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
