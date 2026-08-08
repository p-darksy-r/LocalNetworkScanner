# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [Alias("Rid")]
    [ValidateSet("win-x64", "win-arm64")]
    [string]$RuntimeIdentifier = "win-x64",

    [switch]$SkipPublish,

    [switch]$SkipChecks,

    [string]$IsccPath,

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

function Assert-TimestampServer {
    param([Parameter(Mandatory = $true)][string]$Uri)

    $parsed = $null
    if (-not [Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -notin @("http", "https") -or
        -not [string]::IsNullOrWhiteSpace($parsed.UserInfo)) {
        throw "LNS-REL-003: TimestampServer must be an absolute HTTP or HTTPS URL without embedded credentials."
    }
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

    $certificate = Get-Item -LiteralPath "Cert:\$Store\My\$normalized" -ErrorAction SilentlyContinue
    if ($null -eq $certificate -or -not $certificate.HasPrivateKey) {
        throw "LNS-REL-003: Authenticode signing was requested, but a certificate with a private key was not found at $Store\My\$normalized."
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
            $chainErrors = ($chain.ChainStatus |
                ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }) -join "; "
            throw "LNS-REL-004: the signing certificate '$normalized' does not build to a trusted CA or failed revocation checking: $chainErrors"
        }
    }
    finally {
        $chain.Dispose()
    }

    return $certificate
}

function Assert-ExpectedSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedThumbprint,

        [Parameter(Mandatory = $true)]
        [string]$ToolPath
    )

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
    if ($signature.Status -ne "Valid" -or
        $actualThumbprint -ne $ExpectedThumbprint -or
        $null -eq $signature.TimeStamperCertificate) {
        throw "LNS-REL-005: Authenticode verification failed for '$FilePath': status=$($signature.Status), signer=$actualThumbprint, timestamp=$($null -ne $signature.TimeStamperCertificate)."
    }
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

$certificateSigningEnabled = -not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)
$externalSigningEnabled = -not [string]::IsNullOrWhiteSpace($ExternalSignerScript)
if ($certificateSigningEnabled -and $externalSigningEnabled) {
    throw "LNS-REL-003: choose either a certificate-store signer or -ExternalSignerScript, not both."
}
$signingEnabled = $certificateSigningEnabled -or $externalSigningEnabled
if (-not $signingEnabled -and -not [string]::IsNullOrWhiteSpace($SignToolPath)) {
    throw "LNS-REL-003: -SignToolPath was provided without -SigningCertificateThumbprint. Signing configuration is incomplete."
}

$normalizedSigningThumbprint = $null
$resolvedSignTool = $null
$resolvedExternalSigner = $null
$signingHost = $null
if ($certificateSigningEnabled) {
    Assert-TimestampServer $TimestampServer
    $certificate = Resolve-SigningCertificate $SigningCertificateThumbprint $SigningCertificateStore
    $normalizedSigningThumbprint = $certificate.Thumbprint.ToUpperInvariant()
    $resolvedSignTool = Resolve-SignTool $SignToolPath
}
elseif ($externalSigningEnabled) {
    $resolvedExternalSigner = [IO.Path]::GetFullPath($ExternalSignerScript)
    if (-not (Test-Path -LiteralPath $resolvedExternalSigner -PathType Leaf)) {
        throw "LNS-REL-003: external signer script was not found: $resolvedExternalSigner"
    }
    $resolvedSignTool = Resolve-SignTool $SignToolPath
    $signingHost = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($signingHost) -or
        -not (Test-Path -LiteralPath $signingHost -PathType Leaf)) {
        throw "LNS-REL-003: unable to resolve the current PowerShell host for the external signer."
    }
}

Push-Location $repoRoot
try {
    if (-not $SkipPublish) {
        $publishParameters = @{
            RuntimeIdentifier = $RuntimeIdentifier
            SkipWpfSmoke = $true
        }
        if ($SkipChecks) {
            $publishParameters.SkipChecks = $true
        }
        if ($certificateSigningEnabled) {
            $publishParameters.SigningCertificateThumbprint = $normalizedSigningThumbprint
            $publishParameters.SignToolPath = $resolvedSignTool
            $publishParameters.SigningCertificateStore = $SigningCertificateStore
            $publishParameters.TimestampServer = $TimestampServer
        }
        elseif ($externalSigningEnabled) {
            $publishParameters.ExternalSignerScript = $resolvedExternalSigner
        }
        & $publishScript @publishParameters
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
        "THIRD_PARTY_NOTICES.md",
        "docs\TECHNICAL_LIMITS.md",
        "docs\RELEASE_CHECKLIST.md",
        "docs\INSTALLATION.md",
        "docs\APP_CONTROL.md",
        "docs\VENDOR_DATABASE.md",
        "tools\diagnose-app-control.ps1"
    )
    foreach ($relativePath in $requiredFiles) {
        $candidate = Join-Path $stagingRoot $relativePath
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "The staged release is incomplete: $candidate. Run publish-windows.ps1 first or remove -SkipPublish."
        }
    }

    if ($signingEnabled) {
        $signedPayload = @(
            (Join-Path $stagingRoot "LocalNetworkScanner.exe"),
            (Join-Path $stagingRoot "LocalNetworkScanner.Cli.exe"),
            (Join-Path $stagingRoot "tools\diagnose-app-control.ps1")
        )
        if ($externalSigningEnabled) {
            $firstSignature = Get-AuthenticodeSignature -LiteralPath $signedPayload[0]
            if ($null -eq $firstSignature.SignerCertificate) {
                throw "LNS-REL-005: externally signed payload has no signer certificate: $($signedPayload[0])"
            }
            $normalizedSigningThumbprint = $firstSignature.SignerCertificate.Thumbprint
        }
        foreach ($signedFile in $signedPayload) {
            Assert-ExpectedSignature $signedFile $normalizedSigningThumbprint $resolvedSignTool
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
        "/DSetupIconFile=$setupIcon"
    )
    if ($certificateSigningEnabled) {
        $signToolName = "LocalNetworkScannerAuthenticode"
        $escapedSignTool = $resolvedSignTool.Replace('$', '$$')
        $escapedTimestampServer = $TimestampServer.Replace('$', '$$')
        $storeArguments = if ($SigningCertificateStore -eq "LocalMachine") {
            " /s My /sm"
        }
        else {
            " /s My"
        }
        $signCommand = '$q' + $escapedSignTool + '$q sign' + $storeArguments + ' /sha1 ' +
            $normalizedSigningThumbprint + ' /fd SHA256 /tr $q' +
            $escapedTimestampServer + '$q /td SHA256 /v $f'
        $compilerArguments += @(
            "/DSignToolName=$signToolName",
            "/S$signToolName=$signCommand"
        )
    }
    elseif ($externalSigningEnabled) {
        $signToolName = "LocalNetworkScannerArtifactSigning"
        $escapedHost = $signingHost.Replace('$', '$$')
        $escapedScript = $resolvedExternalSigner.Replace('$', '$$')
        $signCommand = '$q' + $escapedHost + '$q -NoLogo -NoProfile -NonInteractive ' +
            '-ExecutionPolicy Bypass -File $q' + $escapedScript + '$q -FilePath $f'
        $compilerArguments += @(
            "/DSignToolName=$signToolName",
            "/S$signToolName=$signCommand"
        )
    }
    $compilerArguments += $installerScript

    Write-Host ("> ISCC.exe " + ($compilerArguments -join " ")) -ForegroundColor DarkGray
    & $iscc @compilerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup exited with code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
        throw "Inno Setup did not create the expected installer: $installerPath"
    }

    if ($signingEnabled) {
        Assert-ExpectedSignature $installerPath $normalizedSigningThumbprint $resolvedSignTool
    }

    $hash = Get-FileHash -LiteralPath $installerPath -Algorithm SHA256
    $checksumLine = "{0} *{1}" -f $hash.Hash.ToLowerInvariant(), (Split-Path $installerPath -Leaf)
    Set-Content -LiteralPath $checksumPath -Value $checksumLine -Encoding ascii

    if (-not $signingEnabled) {
        $signature = Get-AuthenticodeSignature -LiteralPath $installerPath
        if ($signature.Status -ne "Valid") {
            Write-Warning "Installer is NotSigned: $installerPath ($($signature.Status))"
        }
    }

    Write-Host "Windows installer created successfully." -ForegroundColor Green
    Write-Host "Authenticode: $(if ($signingEnabled) { 'Signed (application, CLI, installer and uninstaller)' } else { 'NotSigned' })"
    Write-Host "Installer: $installerPath"
    Write-Host "SHA-256:  $($hash.Hash.ToLowerInvariant())"
}
finally {
    Pop-Location
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
