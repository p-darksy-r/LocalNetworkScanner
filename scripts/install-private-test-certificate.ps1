# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Install', 'Remove')]
    [string]$Action = 'Install',

    [ValidateNotNullOrEmpty()]
    [string]$CertificatePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'crt\LocalNetworkScanner-PrivateTest.crt'),

    [ValidateNotNullOrEmpty()]
    [string]$ExpectedSubject = 'CN=p-darksy-r Local Network Scanner Private Test',

    [string]$ExpectedThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$trustedPeopleStore = 'Cert:\LocalMachine\TrustedPeople'
$codeSigningOid = '1.3.6.1.5.5.7.3.3'
$sha256WithRsaOid = '1.2.840.113549.1.1.11'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'LNS-MSX-002: run this script from an elevated PowerShell session. Only LocalMachine\TrustedPeople is modified.'
        }
    }
    finally {
        $identity.Dispose()
    }
}

function Assert-PublicPrivateTestCertificate {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [switch]$RequireCurrentValidity
    )

    if ($Certificate.HasPrivateKey) {
        throw 'LNS-MSX-002: the certificate file contains a private key and is not accepted.'
    }
    if ($Certificate.Subject -cne $ExpectedSubject -or $Certificate.Issuer -cne $ExpectedSubject) {
        throw "LNS-MSX-002: certificate subject/issuer mismatch. Expected exactly '$ExpectedSubject'."
    }
    if ($Certificate.SignatureAlgorithm.Value -ne $sha256WithRsaOid) {
        throw 'LNS-MSX-002: the certificate must use an RSA SHA-256 signature.'
    }
    if ($RequireCurrentValidity -and
        ($Certificate.NotBefore -gt [datetime]::Now -or $Certificate.NotAfter -le [datetime]::Now)) {
        throw 'LNS-MSX-002: the certificate is not currently valid.'
    }

    $basicConstraints = @($Certificate.Extensions | Where-Object {
            $_.Oid.Value -eq '2.5.29.19'
        } | Select-Object -First 1)
    if ($basicConstraints.Count -ne 1 -or
        -not ($basicConstraints[0] -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) -or
        $basicConstraints[0].CertificateAuthority) {
        throw 'LNS-MSX-002: the certificate must contain a CA=false basic constraint.'
    }

    $keyUsage = @($Certificate.Extensions | Where-Object {
            $_.Oid.Value -eq '2.5.29.15'
        } | Select-Object -First 1)
    if ($keyUsage.Count -ne 1 -or
        -not ($keyUsage[0] -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) -or
        $keyUsage[0].KeyUsages -ne [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) {
        throw 'LNS-MSX-002: the certificate key usage must be exactly DigitalSignature.'
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
        throw 'LNS-MSX-002: the certificate EKU must contain exactly Code Signing.'
    }

    $publicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    if ($null -eq $publicKey) {
        throw 'LNS-MSX-002: the certificate does not contain an RSA public key.'
    }
    try {
        if ($publicKey.KeySize -lt 3072) {
            throw 'LNS-MSX-002: the certificate RSA public key must be at least 3072 bits.'
        }
    }
    finally {
        $publicKey.Dispose()
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedThumbprint)) {
        $normalizedExpectedThumbprint = $ExpectedThumbprint.Replace(' ', '').ToUpperInvariant()
        if ($normalizedExpectedThumbprint -notmatch '^[0-9A-F]{40}$') {
            throw 'LNS-MSX-002: ExpectedThumbprint must contain exactly 40 hexadecimal SHA-1 thumbprint characters.'
        }
        if ($Certificate.Thumbprint -cne $normalizedExpectedThumbprint) {
            throw "LNS-MSX-002: certificate thumbprint mismatch. Expected '$normalizedExpectedThumbprint'."
        }
    }
}

Assert-Administrator
if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
    throw "LNS-MSX-002: the public certificate file was not found: $CertificatePath"
}
$resolvedCertificatePath = (Resolve-Path -LiteralPath $CertificatePath -ErrorAction Stop).Path
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedCertificatePath)
try {
    Assert-PublicPrivateTestCertificate -Certificate $certificate -RequireCurrentValidity:($Action -eq 'Install')
    $targetPath = Join-Path $trustedPeopleStore $certificate.Thumbprint
    $installedCertificate = Get-Item -LiteralPath $targetPath -ErrorAction SilentlyContinue

    if ($Action -eq 'Install') {
        if ($null -ne $installedCertificate) {
            if ($installedCertificate.Subject -cne $ExpectedSubject -or
                -not [System.Linq.Enumerable]::SequenceEqual[byte]($installedCertificate.RawData, $certificate.RawData)) {
                throw "LNS-MSX-002: TrustedPeople already contains a different certificate at thumbprint '$($certificate.Thumbprint)'."
            }
            Write-Host "Certificate is already installed in LocalMachine\TrustedPeople: $($certificate.Thumbprint)" -ForegroundColor Green
            return
        }

        if ($PSCmdlet.ShouldProcess("LocalMachine\TrustedPeople\$($certificate.Thumbprint)", 'Install private-test public certificate')) {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
                [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($certificate)
            }
            finally {
                $store.Dispose()
            }
            $installedCertificate = Get-Item -LiteralPath $targetPath -ErrorAction Stop
            if ($installedCertificate.Subject -cne $ExpectedSubject -or
                -not [System.Linq.Enumerable]::SequenceEqual[byte]($installedCertificate.RawData, $certificate.RawData)) {
                throw 'LNS-MSX-002: certificate installation verification failed.'
            }
            Write-Host "Certificate installed only in LocalMachine\TrustedPeople: $($certificate.Thumbprint)" -ForegroundColor Green
        }
        return
    }

    if ($null -eq $installedCertificate) {
        Write-Host "Certificate is not installed in LocalMachine\TrustedPeople: $($certificate.Thumbprint)" -ForegroundColor Yellow
        return
    }
    if ($installedCertificate.Subject -cne $ExpectedSubject -or
        -not [System.Linq.Enumerable]::SequenceEqual[byte]($installedCertificate.RawData, $certificate.RawData)) {
        throw 'LNS-MSX-002: refusing removal because the installed certificate is not an exact match for the supplied public certificate.'
    }

    if ($PSCmdlet.ShouldProcess("LocalMachine\TrustedPeople\$($certificate.Thumbprint)", 'Remove exact private-test public certificate')) {
        Remove-Item -LiteralPath $targetPath -Force -Confirm:$false
        if (Test-Path -LiteralPath $targetPath) {
            throw 'LNS-MSX-002: certificate removal verification failed.'
        }
        Write-Host "Exact certificate removed from LocalMachine\TrustedPeople: $($certificate.Thumbprint)" -ForegroundColor Green
    }
}
finally {
    $certificate.Dispose()
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
