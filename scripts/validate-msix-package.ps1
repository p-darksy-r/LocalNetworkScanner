# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [ValidateSet("Auto", "PrivateTest", "Store")]
    [string]$ExpectedMode = "Auto",

    [string]$ExpectedSignerThumbprint,

    [string]$ExpectedIdentityName,

    [string]$ExpectedPublisher,

    [string]$ExpectedPublisherDisplayName,

    [string]$MakeAppxPath,

    [switch]$RequireTrustedSignature
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$privateIdentityName = "p-darksy-r.LocalNetworkScanner.PrivateTest"
$privatePublisher = "CN=p-darksy-r Local Network Scanner Private Test"
$codeSigningEku = "1.3.6.1.5.5.7.3.3"
$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactsRoot = Join-Path $repoRoot "artifacts"
$versionedPrivateCertificatePath = Join-Path $repoRoot "crt\LocalNetworkScanner-PrivateTest.crt"

$storeExpectationValues = @($ExpectedIdentityName, $ExpectedPublisher, $ExpectedPublisherDisplayName)
$providedStoreExpectationCount = @($storeExpectationValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
if ($providedStoreExpectationCount -notin @(0, 3)) {
    throw "LNS-MSX-001: Store identity validation requires IdentityName, Publisher, and PublisherDisplayName together."
}
if ($ExpectedMode -eq "Store" -and $providedStoreExpectationCount -ne 3) {
    throw "LNS-MSX-001: ExpectedMode Store requires the three exact Product identity values copied from Partner Center."
}
if ($ExpectedMode -eq "PrivateTest" -and $providedStoreExpectationCount -ne 0) {
    throw "LNS-MSX-001: Store identity expectations cannot be used with ExpectedMode PrivateTest."
}
if ($ExpectedMode -eq "Store" -and -not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint)) {
    throw "LNS-MSX-001: a Store candidate must be unsigned; do not supply a signer thumbprint."
}

$versionedPrivateSignerThumbprint = $null

function Get-VersionedPrivateSignerThumbprint {
    if ($null -ne $script:versionedPrivateSignerThumbprint) {
        return $script:versionedPrivateSignerThumbprint
    }
    if (-not (Test-Path -LiteralPath $versionedPrivateCertificatePath -PathType Leaf)) {
        throw "LNS-MSX-002: the versioned PrivateTest public certificate is missing."
    }

    $versionedPrivateCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($versionedPrivateCertificatePath)
    try {
        if ($versionedPrivateCertificate.HasPrivateKey -or
            $versionedPrivateCertificate.Subject -cne $privatePublisher -or
            $versionedPrivateCertificate.Issuer -cne $privatePublisher) {
            throw "LNS-MSX-002: the versioned PrivateTest certificate is not the approved public-only identity."
        }
        $script:versionedPrivateSignerThumbprint = $versionedPrivateCertificate.Thumbprint.ToUpperInvariant()
        return $script:versionedPrivateSignerThumbprint
    }
    finally {
        $versionedPrivateCertificate.Dispose()
    }
}

function Invoke-NativeTool {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    Write-Host ("> " + (Split-Path $FilePath -Leaf) + " " + ($Arguments -join " ")) -ForegroundColor DarkGray
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-MSX-005: $(Split-Path $FilePath -Leaf) exited with code $LASTEXITCODE."
    }
}

function Resolve-WindowsSdkTool {
    param([string]$RequestedPath)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $resolved = [IO.Path]::GetFullPath($RequestedPath)
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "LNS-MSX-004: makeappx.exe was not found at the requested path: $resolved"
        }
        return $resolved
    }

    $command = Get-Command "makeappx.exe" -ErrorAction SilentlyContinue
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
                ForEach-Object { Join-Path $_.FullName "x64\makeappx.exe" } |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
        )
    }
    if ($candidates.Count -eq 0) {
        throw "LNS-MSX-004: makeappx.exe was not found. Install the Windows SDK MSIX packaging tools."
    }
    return $candidates[0]
}

function New-ValidationDirectory {
    $root = [IO.Path]::GetFullPath((Join-Path $artifactsRoot "msix\validation"))
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $directory = Join-Path $root ([Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    return $directory
}

function Get-PeMachine {
    param([Parameter(Mandatory)][string]$ExecutablePath)

    $stream = [IO.File]::OpenRead($ExecutablePath)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) {
                throw "LNS-MSX-005: executable does not contain an MZ header."
            }
            $stream.Position = 0x3C
            $peOffset = $reader.ReadInt32()
            if ($peOffset -lt 0x40 -or $peOffset -gt ($stream.Length - 6)) {
                throw "LNS-MSX-005: executable has an invalid PE offset."
            }
            $stream.Position = $peOffset
            if ($reader.ReadUInt32() -ne 0x00004550) {
                throw "LNS-MSX-005: executable does not contain a PE signature."
            }
            return $reader.ReadUInt16()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-AppxBlockMap {
    param([Parameter(Mandatory)][string]$UnpackedDirectory)

    $blockMapPath = Join-Path $UnpackedDirectory "AppxBlockMap.xml"
    if (-not (Test-Path -LiteralPath $blockMapPath -PathType Leaf)) {
        throw "LNS-MSX-005: AppxBlockMap.xml is missing."
    }
    [xml]$blockMap = Get-Content -LiteralPath $blockMapPath -Raw
    $namespaces = [Xml.XmlNamespaceManager]::new($blockMap.NameTable)
    $namespaces.AddNamespace("b", "http://schemas.microsoft.com/appx/2010/blockmap")
    $namespaces.AddNamespace("b4", "http://schemas.microsoft.com/appx/2021/blockmap")
    if ($blockMap.BlockMap.HashMethod -ne "http://www.w3.org/2001/04/xmlenc#sha256") {
        throw "LNS-MSX-005: the package block map must use SHA-256."
    }

    $root = [IO.Path]::GetFullPath($UnpackedDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $listedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $fileNodes = @($blockMap.SelectNodes("/b:BlockMap/b:File", $namespaces))
        if ($fileNodes.Count -eq 0) {
            throw "LNS-MSX-005: the package block map contains no files."
        }
        foreach ($fileNode in $fileNodes) {
            $relativePath = [string]$fileNode.Name
            if ([string]::IsNullOrWhiteSpace($relativePath) -or
                [IO.Path]::IsPathRooted($relativePath) -or
                $relativePath -match '(^|[\\/])\.\.([\\/]|$)') {
                throw "LNS-MSX-005: unsafe path in package block map: '$relativePath'."
            }
            $filePath = [IO.Path]::GetFullPath((Join-Path $UnpackedDirectory $relativePath))
            if (-not $filePath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
                throw "LNS-MSX-005: block-map payload is missing or outside the package: '$relativePath'."
            }
            [void]$listedPaths.Add($filePath)
            $fileInfo = Get-Item -LiteralPath $filePath
            if ([uint64]$fileInfo.Length -ne [uint64]$fileNode.Size) {
                throw "LNS-MSX-005: block-map size mismatch for '$relativePath'."
            }

            $stream = [IO.File]::OpenRead($filePath)
            try {
                $blocks = @($fileNode.SelectNodes("b:Block", $namespaces))
                $buffer = [byte[]]::new(65536)
                foreach ($block in $blocks) {
                    $remaining = $stream.Length - $stream.Position
                    $requested = [int][Math]::Min(65536, $remaining)
                    $read = 0
                    while ($read -lt $requested) {
                        $count = $stream.Read($buffer, $read, $requested - $read)
                        if ($count -eq 0) { break }
                        $read += $count
                    }
                    if ($read -ne $requested) {
                        throw "LNS-MSX-005: unexpected end of file while hashing '$relativePath'."
                    }
                    $actualBlockHash = [Convert]::ToBase64String($sha256.ComputeHash($buffer, 0, $read))
                    if ($actualBlockHash -cne [string]$block.Hash) {
                        throw "LNS-MSX-005: SHA-256 block-map mismatch for '$relativePath'."
                    }
                }
                if ($stream.Position -ne $stream.Length) {
                    throw "LNS-MSX-005: block map does not cover the complete file '$relativePath'."
                }
            }
            finally {
                $stream.Dispose()
            }

            $wholeFileHash = $fileNode.SelectSingleNode("b4:FileHash", $namespaces)
            if ($null -ne $wholeFileHash) {
                $hashStream = [IO.File]::OpenRead($filePath)
                try {
                    $actualFileHash = [Convert]::ToBase64String($sha256.ComputeHash($hashStream))
                    if ($actualFileHash -cne [string]$wholeFileHash.Hash) {
                        throw "LNS-MSX-005: whole-file SHA-256 mismatch for '$relativePath'."
                    }
                }
                finally {
                    $hashStream.Dispose()
                }
            }
        }
    }
    finally {
        $sha256.Dispose()
    }

    $isBundleLayout = Test-Path -LiteralPath (Join-Path $UnpackedDirectory "AppxMetadata\AppxBundleManifest.xml") -PathType Leaf
    $unlistedPayloads = @(
        Get-ChildItem -LiteralPath $UnpackedDirectory -Recurse -File |
            Where-Object {
                $relative = $_.FullName.Substring($root.Length)
                $_.FullName -notin $listedPaths -and
                $relative -notin @("AppxBlockMap.xml", "AppxSignature.p7x", "[Content_Types].xml") -and
                $relative -notlike "AppxMetadata\*" -and
                -not ($isBundleLayout -and $_.DirectoryName -eq $UnpackedDirectory -and $_.Extension -in @(".msix", ".appx"))
            }
    )
    if ($unlistedPayloads.Count -gt 0) {
        throw "LNS-MSX-005: package contains payload not covered by AppxBlockMap.xml: $($unlistedPayloads.Name -join ', ')."
    }
}

function Test-CodeSigningEku {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            $oids = @($extension.EnhancedKeyUsages | ForEach-Object { $_.Value })
            return $oids.Count -eq 1 -and $oids[0] -ceq $codeSigningEku
        }
    }
    return $false
}

function Assert-PackageSignature {
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$Mode,
        [string]$SignerThumbprint
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $PackagePath
    if ($Mode -eq "Store") {
        if ($signature.Status -ne "NotSigned") {
            throw "LNS-MSX-005: a Store candidate must be unsigned before Microsoft Store processing; status=$($signature.Status)."
        }
        return
    }

    if ($signature.Status -in @("NotSigned", "HashMismatch")) {
        throw "LNS-MSX-005: the PrivateTest package has no intact embedded signature; status=$($signature.Status)."
    }
    if ($RequireTrustedSignature -and $signature.Status -ne "Valid") {
        throw "LNS-MSX-005: the package signature is not trusted on this computer; status=$($signature.Status). Import the public CRT into LocalMachine\TrustedPeople on an authorized test computer."
    }
    if ($null -eq $signature.SignerCertificate) {
        throw "LNS-MSX-005: the PrivateTest package signature does not expose a signer certificate."
    }

    $signer = $signature.SignerCertificate
    if ($signer.Subject -cne $privatePublisher -or $signer.Issuer -cne $signer.Subject) {
        throw "LNS-MSX-005: the PrivateTest package was not signed by the isolated self-signed test publisher."
    }
    if ($signer.NotBefore -gt [DateTime]::Now -or $signer.NotAfter -lt [DateTime]::Now.AddDays(30) -or
        $signer.SignatureAlgorithm.Value -ne "1.2.840.113549.1.1.11") {
        throw "LNS-MSX-005: the signer must be currently valid for at least 30 days and use SHA-256/RSA."
    }
    if (-not (Test-CodeSigningEku $signer)) {
        throw "LNS-MSX-005: the signer certificate does not contain the Code Signing EKU."
    }
    $basicConstraints = @($signer.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" })
    if ($basicConstraints.Count -ne 1 -or
        -not ($basicConstraints[0] -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) -or
        $basicConstraints[0].CertificateAuthority) {
        throw "LNS-MSX-005: the signer certificate must explicitly have CA=false."
    }
    $keyUsage = @($signer.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" })
    if ($keyUsage.Count -ne 1 -or
        $keyUsage[0].KeyUsages -ne [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) {
        throw "LNS-MSX-005: the signer certificate key usage must be exactly DigitalSignature."
    }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($signer)
    try {
        if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
            throw "LNS-MSX-005: the signer certificate must use RSA with at least 3072 bits."
        }
    }
    finally {
        if ($null -ne $rsa) { $rsa.Dispose() }
    }

    if (-not [string]::IsNullOrWhiteSpace($SignerThumbprint)) {
        $expected = $SignerThumbprint.Replace(" ", "").ToUpperInvariant()
        if ($signer.Thumbprint.ToUpperInvariant() -ne $expected) {
            throw "LNS-MSX-005: signer thumbprint mismatch."
        }
    }

    if ($signature.Status -ne "Valid") {
        Write-Warning "The PrivateTest signature is intact but not trusted on this computer (status=$($signature.Status)). Trust the public CRT only on authorized test computers."
    }
}

function Assert-PackageLayout {
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$UnpackedDirectory,
        [Parameter(Mandatory)][string]$Mode,
        [string]$SignerThumbprint,
        [string]$StoreIdentityName,
        [string]$StorePublisher,
        [string]$StorePublisherDisplayName
    )

    Assert-AppxBlockMap $UnpackedDirectory

    $manifestPath = Join-Path $UnpackedDirectory "AppxManifest.xml"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "LNS-MSX-005: AppxManifest.xml is missing from the package."
    }
    [xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw
    $namespaces = [Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $namespaces.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
    $namespaces.AddNamespace("uap", "http://schemas.microsoft.com/appx/manifest/uap/windows10")
    $namespaces.AddNamespace("uap10", "http://schemas.microsoft.com/appx/manifest/uap/windows10/10")
    $namespaces.AddNamespace("rescap", "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities")

    $identity = $manifest.SelectSingleNode("/f:Package/f:Identity", $namespaces)
    $applications = @($manifest.SelectNodes("/f:Package/f:Applications/f:Application", $namespaces))
    $application = if ($applications.Count -eq 1) { $applications[0] } else { $null }
    $targetFamily = $manifest.SelectSingleNode("/f:Package/f:Dependencies/f:TargetDeviceFamily", $namespaces)
    $publisherDisplayNameNode = $manifest.SelectSingleNode("/f:Package/f:Properties/f:PublisherDisplayName", $namespaces)
    if ($null -in @($identity, $application, $targetFamily, $publisherDisplayNameNode)) {
        throw "LNS-MSX-005: the package manifest must contain one identity, one application, target-family metadata, and PublisherDisplayName."
    }
    $extensions = @($manifest.SelectNodes("//*[local-name()='Extension' or local-name()='Extensions']"))
    if ($extensions.Count -ne 0) {
        throw "LNS-MSX-005: package/application extensions and additional activation points are not permitted."
    }

    $actualMode = if ($identity.Name -ceq $privateIdentityName -and $identity.Publisher -ceq $privatePublisher) {
        "PrivateTest"
    }
    else {
        "Store"
    }
    if ($Mode -ne "Auto" -and $actualMode -ne $Mode) {
        throw "LNS-MSX-005: package identity is '$actualMode', expected '$Mode'."
    }
    if ($actualMode -eq "PrivateTest" -and ($identity.Name -cne $privateIdentityName -or $identity.Publisher -cne $privatePublisher)) {
        throw "LNS-MSX-005: the PrivateTest identity is not exact."
    }
    if ($actualMode -eq "Store" -and ($identity.Name -eq $privateIdentityName -or $identity.Publisher -eq $privatePublisher)) {
        throw "LNS-MSX-005: private and Store identities are partially mixed."
    }
    if ($actualMode -eq "PrivateTest" -and $providedStoreExpectationCount -ne 0) {
        throw "LNS-MSX-005: Store identity expectations were supplied for a PrivateTest package."
    }
    if ($actualMode -eq "Store" -and $providedStoreExpectationCount -eq 3 -and
        ($identity.Name -cne $StoreIdentityName -or
            $identity.Publisher -cne $StorePublisher -or
            $publisherDisplayNameNode.InnerText -cne $StorePublisherDisplayName)) {
        throw "LNS-MSX-005: Store Product identity does not exactly match the expected Partner Center values."
    }

    if ($identity.Version -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw "LNS-MSX-005: MSIX version must use four numeric components."
    }
    if ($identity.ProcessorArchitecture -notin @("x64", "arm64")) {
        throw "LNS-MSX-005: unsupported package architecture '$($identity.ProcessorArchitecture)'."
    }
    if ($targetFamily.Name -ne "Windows.Desktop" -or [version]$targetFamily.MinVersion -lt [version]"10.0.19041.0") {
        throw "LNS-MSX-005: package must target Windows.Desktop 10.0.19041.0 or newer."
    }

    $runtimeBehavior = $application.GetAttribute("RuntimeBehavior", "http://schemas.microsoft.com/appx/manifest/uap/windows10/10")
    $trustLevel = $application.GetAttribute("TrustLevel", "http://schemas.microsoft.com/appx/manifest/uap/windows10/10")
    if ($application.Id -ne "LocalNetworkScanner" -or
        $application.Executable -ne "LocalNetworkScanner.exe" -or
        $runtimeBehavior -ne "packagedClassicApp" -or
        $trustLevel -ne "mediumIL") {
        throw "LNS-MSX-005: packaged desktop application metadata is not the approved full-trust WPF contract."
    }

    $capabilities = @($manifest.SelectNodes("/f:Package/f:Capabilities/*", $namespaces))
    if ($capabilities.Count -ne 1 -or
        $capabilities[0].NamespaceURI -ne "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" -or
        $capabilities[0].LocalName -ne "Capability" -or
        $capabilities[0].GetAttribute("Name") -ne "runFullTrust") {
        throw "LNS-MSX-005: the package must declare exactly one capability: rescap:runFullTrust."
    }

    $requiredRelativeFiles = @(
        "LocalNetworkScanner.exe",
        "Assets\StoreLogo.png",
        "Assets\Square44x44Logo.png",
        "Assets\Square150x150Logo.png",
        "Assets\Wide310x150Logo.png",
        "Assets\Square310x310Logo.png",
        "LICENSE",
        "PRIVACY.md",
        "THIRD_PARTY_NOTICES.md"
    )
    foreach ($relativeFile in $requiredRelativeFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $UnpackedDirectory $relativeFile) -PathType Leaf)) {
            throw "LNS-MSX-005: required package file is missing: $relativeFile"
        }
    }

    $allowedRelativeFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($relativeFile in $requiredRelativeFiles + @("AppxManifest.xml", "AppxBlockMap.xml", "[Content_Types].xml")) {
        [void]$allowedRelativeFiles.Add($relativeFile)
    }
    if ($actualMode -eq "PrivateTest") {
        [void]$allowedRelativeFiles.Add("AppxSignature.p7x")
        [void]$allowedRelativeFiles.Add("AppxMetadata\CodeIntegrity.cat")
    }
    $unpackedRoot = [IO.Path]::GetFullPath($UnpackedDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $unexpectedFiles = @(
        Get-ChildItem -LiteralPath $UnpackedDirectory -Recurse -File |
            Where-Object {
                $relativePath = $_.FullName.Substring($unpackedRoot.Length)
                -not $allowedRelativeFiles.Contains($relativePath)
            }
    )
    if ($unexpectedFiles.Count -ne 0) {
        throw "LNS-MSX-005: package contains unexpected payload outside the closed single-file contract: $($unexpectedFiles.Name -join ', ')."
    }

    $forbidden = @(
        Get-ChildItem -LiteralPath $UnpackedDirectory -Recurse -File |
            Where-Object {
                $_.Extension.ToLowerInvariant() -in @(".pfx", ".p12", ".key", ".pem", ".pvk", ".snk") -or
                $_.Name -match '(?i)(password|secret|private.?key)'
            }
    )
    if ($forbidden.Count -gt 0) {
        throw "LNS-MSX-005: package contains forbidden secret/private-key material: $($forbidden.Name -join ', ')."
    }

    $executable = Join-Path $UnpackedDirectory "LocalNetworkScanner.exe"
    $machine = Get-PeMachine $executable
    $expectedMachine = if ($identity.ProcessorArchitecture -eq "x64") { 0x8664 } else { 0xAA64 }
    if ($machine -ne $expectedMachine) {
        throw ("LNS-MSX-005: PE machine 0x{0:X4} does not match manifest architecture '{1}'." -f $machine, $identity.ProcessorArchitecture)
    }

    $fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($executable)
    $productVersion = ([string]$fileVersion.ProductVersion -split '[+-]')[0]
    $manifestProductVersion = ($identity.Version -split '\.')[0..2] -join "."
    if ($productVersion -ne $manifestProductVersion) {
        throw "LNS-MSX-005: executable product version '$productVersion' does not match package version '$($identity.Version)'."
    }

    $effectiveSignerThumbprint = if ($actualMode -eq "PrivateTest" -and [string]::IsNullOrWhiteSpace($SignerThumbprint)) {
        Get-VersionedPrivateSignerThumbprint
    }
    else {
        $SignerThumbprint
    }
    Assert-PackageSignature $PackagePath $actualMode $effectiveSignerThumbprint

    return [pscustomobject]@{
        Mode = $actualMode
        IdentityName = [string]$identity.Name
        Publisher = [string]$identity.Publisher
        PublisherDisplayName = [string]$publisherDisplayNameNode.InnerText
        Version = [string]$identity.Version
        Architecture = [string]$identity.ProcessorArchitecture
        PackagePath = $PackagePath
    }
}

$resolvedPath = [IO.Path]::GetFullPath($Path)
if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
    throw "LNS-MSX-005: MSIX package was not found: $resolvedPath"
}
$extension = [IO.Path]::GetExtension($resolvedPath).ToLowerInvariant()
if ($extension -notin @(".msix", ".appx", ".msixbundle", ".appxbundle")) {
    throw "LNS-MSX-005: unsupported package extension '$extension'."
}
$resolvedMakeAppx = Resolve-WindowsSdkTool $MakeAppxPath
$validationDirectory = New-ValidationDirectory

try {
    if ($extension -in @(".msix", ".appx")) {
        Invoke-NativeTool $resolvedMakeAppx @("unpack", "/v", "/o", "/p", $resolvedPath, "/d", $validationDirectory)
        $result = Assert-PackageLayout `
            -PackagePath $resolvedPath `
            -UnpackedDirectory $validationDirectory `
            -Mode $ExpectedMode `
            -SignerThumbprint $ExpectedSignerThumbprint `
            -StoreIdentityName $ExpectedIdentityName `
            -StorePublisher $ExpectedPublisher `
            -StorePublisherDisplayName $ExpectedPublisherDisplayName
        Write-Host "MSIX validation passed: $($result.IdentityName) $($result.Version) $($result.Architecture) [$($result.Mode)]" -ForegroundColor Green
        return
    }

    Invoke-NativeTool $resolvedMakeAppx @("unbundle", "/v", "/o", "/p", $resolvedPath, "/d", $validationDirectory)
    Assert-AppxBlockMap $validationDirectory
    $innerPackages = @(Get-ChildItem -LiteralPath $validationDirectory -Recurse -File | Where-Object { $_.Extension -in @(".msix", ".appx") })
    if ($innerPackages.Count -ne 2) {
        throw "LNS-MSX-005: an x64+ARM64 bundle must contain exactly two application packages; found $($innerPackages.Count)."
    }

    $results = @()
    foreach ($innerPackage in $innerPackages) {
        $innerDirectory = Join-Path $validationDirectory ("unpacked-" + [IO.Path]::GetFileNameWithoutExtension($innerPackage.Name))
        Invoke-NativeTool $resolvedMakeAppx @("unpack", "/v", "/o", "/p", $innerPackage.FullName, "/d", $innerDirectory)
        $results += Assert-PackageLayout `
            -PackagePath $innerPackage.FullName `
            -UnpackedDirectory $innerDirectory `
            -Mode $ExpectedMode `
            -SignerThumbprint $ExpectedSignerThumbprint `
            -StoreIdentityName $ExpectedIdentityName `
            -StorePublisher $ExpectedPublisher `
            -StorePublisherDisplayName $ExpectedPublisherDisplayName
    }
    if (@($results.Architecture | Sort-Object -Unique) -join "," -ne "arm64,x64") {
        throw "LNS-MSX-005: bundle does not contain exactly x64 and ARM64 packages."
    }
    if (@($results.IdentityName | Sort-Object -Unique).Count -ne 1 -or
        @($results.Publisher | Sort-Object -Unique).Count -ne 1 -or
        @($results.PublisherDisplayName | Sort-Object -Unique).Count -ne 1 -or
        @($results.Version | Sort-Object -Unique).Count -ne 1) {
        throw "LNS-MSX-005: bundle packages do not share one identity, publisher, publisher display name, and version."
    }
    $effectiveBundleSignerThumbprint = if ($results[0].Mode -eq "PrivateTest" -and [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint)) {
        Get-VersionedPrivateSignerThumbprint
    }
    else {
        $ExpectedSignerThumbprint
    }
    Assert-PackageSignature $resolvedPath $results[0].Mode $effectiveBundleSignerThumbprint
    Write-Host "MSIX bundle validation passed: $($results[0].IdentityName) $($results[0].Version) [x64, arm64] [$($results[0].Mode)]" -ForegroundColor Green
}
finally {
    $fullArtifacts = [IO.Path]::GetFullPath($artifactsRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $fullValidation = [IO.Path]::GetFullPath($validationDirectory)
    if ($fullValidation.StartsWith($fullArtifacts, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $fullValidation)) {
        Remove-Item -LiteralPath $fullValidation -Recurse -Force
    }
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
