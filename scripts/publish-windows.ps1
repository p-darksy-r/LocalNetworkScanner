# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [Alias("Rid")]
    [ValidateSet("win-x64", "win-arm64")]
    [string]$RuntimeIdentifier = "win-x64",

    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [switch]$SkipChecks,

    [switch]$SkipWpfSmoke,

    [switch]$DisableReadyToRun,

    [string]$SigningCertificateThumbprint,

    [string]$SignToolPath,

    [string]$ExternalSignerScript,

    [ValidateSet("CurrentUser", "LocalMachine")]
    [string]$SigningCertificateStore = "CurrentUser",

    [string]$TimestampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$checkScript = Join-Path $PSScriptRoot "check.ps1"
$cliProject = Join-Path $repoRoot "LocalNetworkScanner.Cli\LocalNetworkScanner.Cli.csproj"
$wpfProject = Join-Path $repoRoot "LocalNetworkScanner.Wpf\LocalNetworkScanner.Wpf.csproj"
$appControlDiagnosticScript = Join-Path $PSScriptRoot "diagnose-app-control.ps1"
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
    try {
        $process = Start-Process -FilePath $Executable -PassThru
    }
    catch {
        throw (New-NativeLaunchDiagnostic $Executable $_.Exception)
    }
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

function Get-NativeErrorCode {
    param(
        [Parameter(Mandatory = $true)]
        [Exception]$Exception
    )

    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [ComponentModel.Win32Exception]) {
            return $current.NativeErrorCode
        }
        $current = $current.InnerException
    }

    return $null
}

function New-NativeLaunchDiagnostic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [Exception]$Exception
    )

    $nativeErrorCode = Get-NativeErrorCode $Exception
    if ($nativeErrorCode -eq 4551) {
        return "LNS-REL-007: Windows App Control blocked '$Target' before it could start (CreateProcess 4551 / ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION). Use a release signed by a trusted Authenticode publisher or ask the device administrator to authorize it; do not disable the policy."
    }

    $codeSuffix = if ($null -eq $nativeErrorCode) {
        ""
    }
    else {
        " (native error $nativeErrorCode)"
    }
    return "LNS-REL-007: unable to start '$Target'$codeSuffix."
}

function Resolve-SignTool {
    param([string]$RequestedPath)

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidates += $RequestedPath
    }

    $command = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        $candidates += $command.Source
    }

    $windowsKitsBin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    if (Test-Path -LiteralPath $windowsKitsBin -PathType Container) {
        $candidates += Get-ChildItem -LiteralPath $windowsKitsBin -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" }
    }

    $resolved = $candidates |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
        Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw "LNS-REL-003: Authenticode signing was requested, but signtool.exe was not found. Install the Windows SDK or pass -SignToolPath."
    }

    return [IO.Path]::GetFullPath($resolved)
}

function Resolve-SigningCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter(Mandatory = $true)]
        [string]$Store
    )

    $normalized = [Regex]::Replace($Thumbprint, "\s", "").ToUpperInvariant()
    if ($normalized -notmatch "^[0-9A-F]{40}$") {
        throw "LNS-REL-003: SigningCertificateThumbprint must be a 40-character SHA-1 certificate thumbprint. SHA-1 is used only to select the certificate; file signatures use SHA-256."
    }

    $certificatePath = "Cert:\$Store\My\$normalized"
    $certificate = Get-Item -LiteralPath $certificatePath -ErrorAction SilentlyContinue
    if ($null -eq $certificate) {
        throw "LNS-REL-003: Authenticode signing was requested, but certificate '$normalized' was not found in $Store\My."
    }
    if (-not $certificate.HasPrivateKey) {
        throw "LNS-REL-003: the signing certificate '$normalized' does not expose a private key."
    }
    if ([DateTime]::Now -lt $certificate.NotBefore -or [DateTime]::Now -gt $certificate.NotAfter) {
        throw "LNS-REL-004: the signing certificate '$normalized' is not currently valid ($($certificate.NotBefore.ToString('u')) to $($certificate.NotAfter.ToString('u')))."
    }
    if ($certificate.Subject -eq $certificate.Issuer) {
        throw "LNS-REL-004: the signing certificate '$normalized' is self-signed. A certificate chained to a trusted public CA is required for release signing."
    }

    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    if ($null -eq $rsa) {
        throw "LNS-REL-004: the signing certificate '$normalized' is not an RSA certificate."
    }
    $rsa.Dispose()

    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $ekuExtension = $certificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
        Select-Object -First 1
    $hasCodeSigningEku =
        $null -ne $ekuExtension -and
        @($ekuExtension.EnhancedKeyUsages | Where-Object { $_.Value -eq $codeSigningOid }).Count -gt 0
    if (-not $hasCodeSigningEku) {
        throw "LNS-REL-004: the certificate '$normalized' is not authorized for Code Signing (EKU $codeSigningOid)."
    }

    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(30)
        if (-not $chain.Build($certificate)) {
            $chainErrors = ($chain.ChainStatus | ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }) -join "; "
            throw "LNS-REL-004: the signing certificate '$normalized' does not build to a trusted CA or failed revocation checking: $chainErrors"
        }
    }
    finally {
        $chain.Dispose()
    }

    return $certificate
}

function Assert-TimestampServer {
    param([Parameter(Mandatory = $true)][string]$Uri)

    $parsed = $null
    if (-not [Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -notin @("http", "https") -or
        -not [string]::IsNullOrWhiteSpace($parsed.UserInfo)) {
        throw "LNS-REL-003: TimestampServer must be an absolute HTTP or HTTPS URL without embedded credentials."
    }
}

function Invoke-AuthenticodeSign {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ToolPath,

        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter(Mandatory = $true)]
        [string]$CertificateStore,

        [Parameter(Mandatory = $true)]
        [string]$TimestampUri
    )

    Write-Host "> Authenticode sign $(Split-Path $FilePath -Leaf)" -ForegroundColor DarkGray
    $signArguments = @("sign", "/s", "My")
    if ($CertificateStore -eq "LocalMachine") {
        $signArguments += "/sm"
    }
    $signArguments += @(
        "/sha1", $Thumbprint,
        "/fd", "SHA256",
        "/tr", $TimestampUri,
        "/td", "SHA256",
        "/v",
        $FilePath
    )
    & $ToolPath @signArguments
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-REL-005: signtool sign failed for '$FilePath' with code $LASTEXITCODE."
    }

    & $ToolPath verify /pa /tw /v $FilePath
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-REL-005: signtool verify failed for '$FilePath' with code $LASTEXITCODE."
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $FilePath
    $actualThumbprint = if ($null -ne $signature.SignerCertificate) {
        $signature.SignerCertificate.Thumbprint
    }
    else {
        "<none>"
    }
    if ($signature.Status -ne "Valid" -or $actualThumbprint -ne $Thumbprint) {
        throw "LNS-REL-005: Authenticode verification failed for '$FilePath': status=$($signature.Status), signer=$actualThumbprint."
    }
}

function Assert-ValidSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string]$ExpectedThumbprint
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $FilePath
    $actualThumbprint = if ($null -ne $signature.SignerCertificate) {
        $signature.SignerCertificate.Thumbprint
    }
    else {
        $null
    }
    if ($signature.Status -ne "Valid" -or
        [string]::IsNullOrWhiteSpace($actualThumbprint) -or
        $null -eq $signature.TimeStamperCertificate -or
        (-not [string]::IsNullOrWhiteSpace($ExpectedThumbprint) -and
         $actualThumbprint -ne $ExpectedThumbprint)) {
        throw "LNS-REL-005: Authenticode verification failed for '$FilePath': status=$($signature.Status), signer=$actualThumbprint, timestamp=$($null -ne $signature.TimeStamperCertificate)."
    }
    return $actualThumbprint
}

function Invoke-ExternalAuthenticodeSign {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [string]$ExpectedThumbprint
    )

    & $ScriptPath -FilePath $FilePath
    if (-not $?) {
        throw "LNS-REL-005: external signing command failed for '$FilePath'."
    }
    return Assert-ValidSignature $FilePath $ExpectedThumbprint
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
if (-not (Test-Path -LiteralPath $appControlDiagnosticScript -PathType Leaf)) {
    throw "The App Control diagnostic tool is required for a release package: $appControlDiagnosticScript"
}

$certificateSigningEnabled = -not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)
$externalSigningEnabled = -not [string]::IsNullOrWhiteSpace($ExternalSignerScript)
if ($certificateSigningEnabled -and $externalSigningEnabled) {
    throw "LNS-REL-003: choose either a certificate-store signer or -ExternalSignerScript, not both."
}
$signingEnabled = $certificateSigningEnabled -or $externalSigningEnabled
if (-not $certificateSigningEnabled -and -not [string]::IsNullOrWhiteSpace($SignToolPath)) {
    throw "LNS-REL-003: -SignToolPath was provided without -SigningCertificateThumbprint. Signing configuration is incomplete."
}

$normalizedSigningThumbprint = $null
$resolvedSignTool = $null
$resolvedExternalSigner = $null
$signingCertificate = $null
if ($certificateSigningEnabled) {
    Assert-TimestampServer $TimestampServer
    $signingCertificate = Resolve-SigningCertificate $SigningCertificateThumbprint $SigningCertificateStore
    $normalizedSigningThumbprint = $signingCertificate.Thumbprint.ToUpperInvariant()
    $resolvedSignTool = Resolve-SignTool $SignToolPath
    Write-Host "Authenticode signing enabled: $($signingCertificate.Subject)" -ForegroundColor Cyan
}
elseif ($externalSigningEnabled) {
    $resolvedExternalSigner = [IO.Path]::GetFullPath($ExternalSignerScript)
    if (-not (Test-Path -LiteralPath $resolvedExternalSigner -PathType Leaf)) {
        throw "LNS-REL-003: external signer script was not found: $resolvedExternalSigner"
    }
    Write-Host "External Authenticode signing enabled: $resolvedExternalSigner" -ForegroundColor Cyan
}
else {
    Write-Host "Authenticode signing state: NotSigned (no certificate thumbprint supplied)." -ForegroundColor Yellow
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

    $expectedSignerThumbprint = $normalizedSigningThumbprint
    if ($signingEnabled) {
        foreach ($executable in @($wpfExe, $cliExe)) {
            if ($externalSigningEnabled) {
                $expectedSignerThumbprint = Invoke-ExternalAuthenticodeSign `
                    $executable `
                    $resolvedExternalSigner `
                    $expectedSignerThumbprint
            }
            else {
                Invoke-AuthenticodeSign `
                    $executable `
                    $resolvedSignTool `
                    $normalizedSigningThumbprint `
                    $SigningCertificateStore `
                    $TimestampServer
                [void](Assert-ValidSignature $executable $expectedSignerThumbprint)
            }
        }
    }

    $hostArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $canRunPublishedCli =
        ($RuntimeIdentifier -eq "win-x64" -and $hostArchitecture -in @("X64", "Arm64")) -or
        ($RuntimeIdentifier -eq "win-arm64" -and $hostArchitecture -eq "Arm64")

    if ($canRunPublishedCli) {
        Write-Host "> Published CLI smoke test (--help)" -ForegroundColor DarkGray
        try {
            & $cliExe --help | Out-Host
        }
        catch {
            throw (New-NativeLaunchDiagnostic $cliExe $_.Exception)
        }
        if ($LASTEXITCODE -ne 0) {
            throw "LNS-REL-007: published CLI smoke test failed with exit code $LASTEXITCODE."
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

    foreach ($file in @("README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md")) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $file) -Destination $stagingRoot
    }

    $stagingDocs = Join-Path $stagingRoot "docs"
    New-Item -ItemType Directory -Path $stagingDocs -Force | Out-Null
    $documentationFiles = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot "docs") -File -Filter "*.md")
    if ($documentationFiles.Count -eq 0) {
        throw "No Markdown documentation files were found for the release package."
    }
    foreach ($document in $documentationFiles) {
        Copy-Item -LiteralPath $document.FullName -Destination $stagingDocs
    }

    $stagingTools = Join-Path $stagingRoot "tools"
    New-Item -ItemType Directory -Path $stagingTools -Force | Out-Null
    $stagedDiagnosticScript = Join-Path $stagingTools "diagnose-app-control.ps1"
    Copy-Item -LiteralPath $appControlDiagnosticScript -Destination $stagedDiagnosticScript
    if ($externalSigningEnabled) {
        $expectedSignerThumbprint = Invoke-ExternalAuthenticodeSign `
            $stagedDiagnosticScript `
            $resolvedExternalSigner `
            $expectedSignerThumbprint
    }
    elseif ($certificateSigningEnabled) {
        $scriptSignature = Set-AuthenticodeSignature `
            -LiteralPath $stagedDiagnosticScript `
            -Certificate $signingCertificate `
            -HashAlgorithm SHA256 `
            -TimestampServer $TimestampServer
        if ($scriptSignature.Status -ne "Valid") {
            throw "LNS-REL-005: Authenticode signing failed for '$stagedDiagnosticScript': status=$($scriptSignature.Status)."
        }
        [void](Assert-ValidSignature $stagedDiagnosticScript $expectedSignerThumbprint)
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

    if (-not $signingEnabled) {
        foreach ($file in @($wpfExe, $cliExe, $stagedDiagnosticScript)) {
            $signature = Get-AuthenticodeSignature -LiteralPath $file
            if ($signature.Status -ne "Valid") {
                Write-Warning "Release file is NotSigned: $file ($($signature.Status))"
            }
        }
    }

    Write-Host "Windows package created successfully." -ForegroundColor Green
    Write-Host "Authenticode: $(if ($signingEnabled) { 'Signed' } else { 'NotSigned' })"
    Write-Host "Archive:  $archivePath"
    Write-Host "SHA-256:  $($hash.Hash.ToLowerInvariant())"
    Write-Host "Checksum: $checksumPath"
}
finally {
    Pop-Location
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
