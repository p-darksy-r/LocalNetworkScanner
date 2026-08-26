# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repoRoot "packaging\msix\AppxManifest.template.xml"
$assetDirectory = Join-Path $repoRoot "packaging\msix\Assets"
$certificatePath = Join-Path $repoRoot "crt\LocalNetworkScanner-PrivateTest.crt"
$privatePublisher = "CN=p-darksy-r Local Network Scanner Private Test"
$codeSigningEku = "1.3.6.1.5.5.7.3.3"
$requiredScripts = @(
    "new-private-test-certificate.ps1",
    "install-private-test-certificate.ps1",
    "generate-msix-assets.ps1",
    "build-msix.ps1",
    "build-msix-bundle.ps1",
    "validate-msix-package.ps1",
    "test-msix-contract.ps1"
)

foreach ($relativePath in @(
    "packaging\msix\AppxManifest.template.xml",
    "packaging\msix\README.md",
    "crt\README.md",
    "crt\LocalNetworkScanner-PrivateTest.crt",
    "docs\MSIX.md"
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $relativePath) -PathType Leaf)) {
        throw "MSIX contract input is missing: $relativePath"
    }
}
foreach ($scriptName in $requiredScripts) {
    $scriptPath = Join-Path $PSScriptRoot $scriptName
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "MSIX script is missing: $scriptName"
    }
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw "MSIX script contains parser errors: $scriptName"
    }
}

[xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw
$namespaces = [Xml.XmlNamespaceManager]::new($manifest.NameTable)
$namespaces.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
$namespaces.AddNamespace("uap", "http://schemas.microsoft.com/appx/manifest/uap/windows10")
$namespaces.AddNamespace("uap10", "http://schemas.microsoft.com/appx/manifest/uap/windows10/10")
$namespaces.AddNamespace("rescap", "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities")

$identity = $manifest.SelectSingleNode("/f:Package/f:Identity", $namespaces)
$application = $manifest.SelectSingleNode("/f:Package/f:Applications/f:Application", $namespaces)
$targetFamily = $manifest.SelectSingleNode("/f:Package/f:Dependencies/f:TargetDeviceFamily", $namespaces)
$visualElements = $manifest.SelectSingleNode("/f:Package/f:Applications/f:Application/uap:VisualElements", $namespaces)
if ($null -in @($identity, $application, $targetFamily, $visualElements)) {
    throw "MSIX manifest template is missing a required node."
}

$expectedTokens = [ordered]@{
    Name = "__IDENTITY_NAME__"
    Publisher = "__PUBLISHER__"
    Version = "__VERSION__"
    ProcessorArchitecture = "__ARCHITECTURE__"
}
foreach ($entry in $expectedTokens.GetEnumerator()) {
    if ($identity.GetAttribute($entry.Key) -cne $entry.Value) {
        throw "MSIX manifest token '$($entry.Value)' is missing from Identity/$($entry.Key)."
    }
}
if ($manifest.Package.Properties.DisplayName -cne "__DISPLAY_NAME__" -or
    $manifest.Package.Properties.PublisherDisplayName -cne "__PUBLISHER_DISPLAY_NAME__" -or
    $visualElements.GetAttribute("DisplayName") -cne "__DISPLAY_NAME__") {
    throw "MSIX display-name tokens are incomplete."
}
if ($targetFamily.Name -ne "Windows.Desktop" -or
    $targetFamily.MinVersion -ne "10.0.19041.0" -or
    $targetFamily.MaxVersionTested -ne "10.0.26100.0") {
    throw "MSIX target-family contract changed unexpectedly."
}
if ($application.Id -ne "LocalNetworkScanner" -or
    $application.Executable -ne "LocalNetworkScanner.exe" -or
    $application.GetAttribute("RuntimeBehavior", "http://schemas.microsoft.com/appx/manifest/uap/windows10/10") -ne "packagedClassicApp" -or
    $application.GetAttribute("TrustLevel", "http://schemas.microsoft.com/appx/manifest/uap/windows10/10") -ne "mediumIL") {
    throw "MSIX desktop application contract changed unexpectedly."
}
$capabilities = @($manifest.SelectNodes("/f:Package/f:Capabilities/*", $namespaces))
if ($capabilities.Count -ne 1 -or
    $capabilities[0].NamespaceURI -ne "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" -or
    $capabilities[0].GetAttribute("Name") -ne "runFullTrust") {
    throw "MSIX must declare exactly rescap:runFullTrust and no extra capabilities."
}
$languages = @($manifest.SelectNodes("/f:Package/f:Resources/f:Resource", $namespaces) | ForEach-Object { $_.Language })
if (($languages | Sort-Object) -join "," -ne "pt-PT") {
    throw "MSIX language contract must contain exactly pt-PT until a complete additional UI localization exists."
}

Add-Type -AssemblyName System.Drawing
$expectedAssets = [ordered]@{
    "StoreLogo.png" = @(50, 50)
    "Square44x44Logo.png" = @(44, 44)
    "Square150x150Logo.png" = @(150, 150)
    "Wide310x150Logo.png" = @(310, 150)
    "Square310x310Logo.png" = @(310, 310)
}
foreach ($entry in $expectedAssets.GetEnumerator()) {
    $assetPath = Join-Path $assetDirectory $entry.Key
    if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) {
        throw "MSIX asset is missing: $($entry.Key)"
    }
    $image = [Drawing.Image]::FromFile($assetPath)
    try {
        if ($image.Width -ne $entry.Value[0] -or $image.Height -ne $entry.Value[1]) {
            throw "MSIX asset '$($entry.Key)' has dimensions $($image.Width)x$($image.Height), expected $($entry.Value[0])x$($entry.Value[1])."
        }
    }
    finally {
        $image.Dispose()
    }
}

$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
try {
    if ($certificate.HasPrivateKey) {
        throw "The versioned PrivateTest CRT must never contain a private key."
    }
    if ($certificate.Subject -cne $privatePublisher -or $certificate.Issuer -cne $privatePublisher) {
        throw "The versioned PrivateTest CRT subject/issuer is not the isolated publisher."
    }
    if ($certificate.NotBefore -gt [DateTime]::Now -or $certificate.NotAfter -lt [DateTime]::Now.AddDays(30)) {
        throw "The versioned PrivateTest CRT is not usable for at least another 30 days."
    }
    if ($certificate.SignatureAlgorithm.Value -ne "1.2.840.113549.1.1.11") {
        throw "The versioned PrivateTest CRT must use SHA-256/RSA."
    }
    $basicConstraints = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" })
    if ($basicConstraints.Count -ne 1 -or
        -not ($basicConstraints[0] -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) -or
        $basicConstraints[0].CertificateAuthority) {
        throw "The PrivateTest CRT must explicitly be CA=false."
    }
    $keyUsage = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" })
    if ($keyUsage.Count -ne 1 -or
        $keyUsage[0].KeyUsages -ne [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) {
        throw "The PrivateTest CRT must allow DigitalSignature only."
    }
    $eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" })
    $ekuOids = @(
        if ($eku.Count -eq 1) {
            $eku[0].EnhancedKeyUsages | ForEach-Object { $_.Value }
        }
    )
    if ($ekuOids.Count -ne 1 -or $ekuOids[0] -cne $codeSigningEku) {
        throw "The PrivateTest CRT must contain only the Code Signing EKU."
    }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    try {
        if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
            throw "The PrivateTest CRT must use RSA with at least 3072 bits."
        }
    }
    finally {
        if ($null -ne $rsa) { $rsa.Dispose() }
    }
}
finally {
    $certificate.Dispose()
}

$forbiddenExtensions = @(".pfx", ".p12", ".key", ".pem", ".pvk", ".snk")
$trackedPaths = @(& git -C $repoRoot ls-files)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to enumerate tracked files for the MSIX private-key guard."
}
$trackedForbidden = @($trackedPaths | Where-Object { [IO.Path]::GetExtension($_).ToLowerInvariant() -in $forbiddenExtensions })
if ($trackedForbidden.Count -gt 0) {
    throw "Tracked private key/container material is forbidden: $($trackedForbidden -join ', ')."
}
$forbiddenFiles = @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot "crt") -Recurse -File |
        Where-Object { $_.Extension.ToLowerInvariant() -in $forbiddenExtensions }
)
if ($forbiddenFiles.Count -gt 0) {
    throw "Private key/container material exists under crt: $($forbiddenFiles.Name -join ', ')."
}
$textFiles = @(
    Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Include *.ps1, *.md, *.xml, *.yml, *.yaml, *.json |
        Where-Object { $_.FullName -notmatch '[\\/](\.git|artifacts|bin|obj)[\\/]' }
)
foreach ($textFile in $textFiles) {
    $content = Get-Content -LiteralPath $textFile.FullName -Raw
    if ($content -match '-----BEGIN (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----') {
        throw "Private key PEM marker found in repository text: $($textFile.FullName)"
    }
}

$buildScriptContent = Get-Content -LiteralPath (Join-Path $PSScriptRoot "build-msix.ps1") -Raw
$bundleScriptContent = Get-Content -LiteralPath (Join-Path $PSScriptRoot "build-msix-bundle.ps1") -Raw
$validatorScriptContent = Get-Content -LiteralPath (Join-Path $PSScriptRoot "validate-msix-package.ps1") -Raw
$installerScriptContent = Get-Content -LiteralPath (Join-Path $PSScriptRoot "install-private-test-certificate.ps1") -Raw
foreach ($content in @($buildScriptContent, $bundleScriptContent)) {
    if ($content -notmatch 'ValidateSet\("PrivateTest", "Store"\)' -or
        $content -notmatch 'UnsignedForMicrosoftStore' -or
        $content -match '(?i)git\s+(tag|push)|gh\s+release|artifacts[\\/]release') {
        throw "MSIX build scripts no longer preserve the isolated PrivateTest/Store contract."
    }
}
if ($buildScriptContent -notmatch 'Store mode must remain unsigned' -or
    $buildScriptContent -notmatch 'Subject and manifest Publisher do not match exactly') {
    throw "MSIX build script is missing signing/identity fail-closed guards."
}
foreach ($content in @($buildScriptContent, $bundleScriptContent, $validatorScriptContent)) {
    if ($content -notmatch 'ExpectedIdentityName' -or
        $content -notmatch 'ExpectedPublisherDisplayName') {
        throw "MSIX Store identity values are not propagated through every build/validation layer."
    }
}
if ($validatorScriptContent -notmatch 'Product identity does not exactly match' -or
    $validatorScriptContent -notmatch 'unexpected payload outside the closed single-file contract' -or
    $validatorScriptContent -notmatch 'additional activation points are not permitted' -or
    $validatorScriptContent -notmatch 'versionedPrivateSignerThumbprint') {
    throw "MSIX validator is missing closed payload, activation, Store identity, or signer-pinning guards."
}
if ($installerScriptContent -match '\bImport-Certificate\b' -or
    $installerScriptContent -notmatch '\bX509Store\b' -or
    $installerScriptContent -notmatch '\$store\.Add\(\$certificate\)') {
    throw "PrivateTest trust installation must import the already validated certificate object without reopening the source path."
}

Write-Host "MSIX contract tests passed (manifest, assets, public CRT, scripts, and secret guards)." -ForegroundColor Green

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
