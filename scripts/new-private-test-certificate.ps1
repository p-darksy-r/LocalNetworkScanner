# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Subject = 'CN=p-darksy-r Local Network Scanner Private Test',

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'crt\LocalNetworkScanner-PrivateTest.crt'),

    [ValidateRange(30, 3650)]
    [int]$ValidityDays = 730,

    [ValidateRange(1, 365)]
    [int]$MinimumRemainingDays = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$personalStore = 'Cert:\CurrentUser\My'
$codeSigningOid = '1.3.6.1.5.5.7.3.3'
$sha256WithRsaOid = '1.2.840.113549.1.1.11'
$minimumKeySize = 3072

function Test-PrivateTestCertificate {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [datetime]$MinimumExpiry
    )

    if ($Certificate.Subject -cne $Subject -or
        $Certificate.Issuer -cne $Subject -or
        -not $Certificate.HasPrivateKey -or
        $Certificate.NotBefore -gt [datetime]::Now -or
        $Certificate.NotAfter -lt $MinimumExpiry -or
        $Certificate.SignatureAlgorithm.Value -ne $sha256WithRsaOid) {
        return $false
    }

    $basicConstraints = @($Certificate.Extensions | Where-Object {
            $_.Oid.Value -eq '2.5.29.19'
        } | Select-Object -First 1)
    if ($basicConstraints.Count -ne 1 -or
        -not ($basicConstraints[0] -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) -or
        $basicConstraints[0].CertificateAuthority) {
        return $false
    }

    $keyUsage = @($Certificate.Extensions | Where-Object {
            $_.Oid.Value -eq '2.5.29.15'
        } | Select-Object -First 1)
    if ($keyUsage.Count -ne 1 -or
        -not ($keyUsage[0] -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) -or
        $keyUsage[0].KeyUsages -ne [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) {
        return $false
    }

    $enhancedKeyUsage = @($Certificate.Extensions | Where-Object {
            $_.Oid.Value -eq '2.5.29.37'
        } | Select-Object -First 1)
    $ekuOids = @(
        if ($enhancedKeyUsage.Count -eq 1 -and
            $enhancedKeyUsage[0] -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            $enhancedKeyUsage[0].EnhancedKeyUsages | ForEach-Object { $_.Value }
        }
    )
    if ($ekuOids.Count -ne 1 -or $ekuOids[0] -cne $codeSigningOid) {
        return $false
    }

    $publicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    if ($null -eq $publicKey) {
        return $false
    }

    try {
        if ($publicKey.KeySize -lt $minimumKeySize) {
            return $false
        }
    }
    finally {
        $publicKey.Dispose()
    }

    $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -eq $privateKey -or -not ($privateKey -is [System.Security.Cryptography.RSACng])) {
        if ($null -ne $privateKey) {
            $privateKey.Dispose()
        }
        return $false
    }

    try {
        return $privateKey.Key.ExportPolicy -eq [System.Security.Cryptography.CngExportPolicies]::None
    }
    catch {
        return $false
    }
    finally {
        $privateKey.Dispose()
    }
}

$minimumExpiry = [datetime]::Now.AddDays($MinimumRemainingDays)
$certificate = @(Get-ChildItem -Path $personalStore | Where-Object {
        Test-PrivateTestCertificate -Certificate $_ -MinimumExpiry $minimumExpiry
    } | Sort-Object NotAfter -Descending | Select-Object -First 1)
$created = $false

if ($certificate.Count -eq 0) {
    $enhancedKeyUsages = [System.Security.Cryptography.OidCollection]::new()
    [void]$enhancedKeyUsages.Add([System.Security.Cryptography.Oid]::new($codeSigningOid, 'Code Signing'))
    $extensions = @(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true),
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($enhancedKeyUsages, $true)
    )

    $certificate = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $Subject `
        -FriendlyName 'Local Network Scanner Private Test' `
        -CertStoreLocation $personalStore `
        -Provider 'Microsoft Software Key Storage Provider' `
        -KeyAlgorithm RSA `
        -KeyLength $minimumKeySize `
        -KeyUsage DigitalSignature `
        -KeyUsageProperty Sign `
        -KeyExportPolicy NonExportable `
        -HashAlgorithm SHA256 `
        -NotBefore ([datetime]::Now.AddMinutes(-5)) `
        -NotAfter ([datetime]::Now.AddDays($ValidityDays)) `
        -Extension $extensions
    $created = $true

    if (-not (Test-PrivateTestCertificate -Certificate $certificate -MinimumExpiry $minimumExpiry)) {
        Remove-Item -LiteralPath (Join-Path $personalStore $certificate.Thumbprint) -Force -ErrorAction SilentlyContinue
        throw 'LNS-MSX-002: the generated certificate did not satisfy the required private-test certificate policy.'
    }
}
else {
    $certificate = $certificate[0]
}

$resolvedOutputPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
Export-Certificate -Cert $certificate -FilePath $resolvedOutputPath -Type CERT -Force | Out-Null

$publicCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedOutputPath)
try {
    if ($publicCertificate.HasPrivateKey -or
        $publicCertificate.Thumbprint -cne $certificate.Thumbprint -or
        -not [System.Linq.Enumerable]::SequenceEqual[byte]($publicCertificate.RawData, $certificate.RawData)) {
        throw 'LNS-MSX-002: the exported .crt failed public-certificate validation.'
    }
}
finally {
    $publicCertificate.Dispose()
}

[pscustomobject]@{
    Created               = $created
    Subject               = $certificate.Subject
    Thumbprint            = $certificate.Thumbprint
    NotAfter              = $certificate.NotAfter
    PrivateKeyStore       = $personalStore
    PrivateKeyExportable  = $false
    PublicCertificatePath = $resolvedOutputPath
    TrustedAutomatically  = $false
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
