# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$fullPath = [IO.Path]::GetFullPath($FilePath)
if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
    throw "LNS-REL-003: the file requested for Artifact Signing does not exist: $fullPath"
}

$supportedExtensions = @(".dll", ".exe", ".ps1")
$extension = [IO.Path]::GetExtension($fullPath).ToLowerInvariant()
if ($extension -notin $supportedExtensions) {
    throw "LNS-REL-003: Artifact Signing is restricted to these release file types: $($supportedExtensions -join ', ')."
}

$endpoint = $env:ARTIFACT_SIGNING_ENDPOINT
$accountName = $env:ARTIFACT_SIGNING_ACCOUNT
$profileName = $env:ARTIFACT_SIGNING_PROFILE
$timestampServer = $env:ARTIFACT_SIGNING_TIMESTAMP_SERVER
if ([string]::IsNullOrWhiteSpace($timestampServer)) {
    $timestampServer = "http://timestamp.acs.microsoft.com"
}

$missing = @()
foreach ($setting in @{
        ARTIFACT_SIGNING_ENDPOINT = $endpoint
        ARTIFACT_SIGNING_ACCOUNT = $accountName
        ARTIFACT_SIGNING_PROFILE = $profileName
    }.GetEnumerator()) {
    if ([string]::IsNullOrWhiteSpace([string]$setting.Value)) {
        $missing += $setting.Key
    }
}
if ($missing.Count -gt 0) {
    throw "LNS-REL-002: Artifact Signing configuration is incomplete: $($missing -join ', ')."
}

$parsedEndpoint = $null
if (-not [Uri]::TryCreate($endpoint, [UriKind]::Absolute, [ref]$parsedEndpoint) -or
    $parsedEndpoint.Scheme -ne "https" -or
    -not $parsedEndpoint.DnsSafeHost.EndsWith(".codesigning.azure.net", [StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::IsNullOrWhiteSpace($parsedEndpoint.UserInfo)) {
    throw "LNS-REL-003: ARTIFACT_SIGNING_ENDPOINT must be an HTTPS *.codesigning.azure.net endpoint without credentials."
}

$parsedTimestamp = $null
if (-not [Uri]::TryCreate($timestampServer, [UriKind]::Absolute, [ref]$parsedTimestamp) -or
    $parsedTimestamp.Scheme -notin @("http", "https") -or
    -not [string]::IsNullOrWhiteSpace($parsedTimestamp.UserInfo)) {
    throw "LNS-REL-003: ARTIFACT_SIGNING_TIMESTAMP_SERVER must be an absolute HTTP or HTTPS URL without credentials."
}

$requiredModuleVersion = [Version]"0.1.8"
$module = Get-Module -ListAvailable -Name "ArtifactSigning" |
    Where-Object { $_.Version -eq $requiredModuleVersion } |
    Select-Object -First 1
if ($null -eq $module) {
    throw "LNS-REL-003: ArtifactSigning PowerShell module $requiredModuleVersion is not installed."
}
Import-Module -Name $module.Path -Force

Write-Host "> Artifact Signing $(Split-Path $fullPath -Leaf)" -ForegroundColor DarkGray
try {
    $signingParameters = @{
        Endpoint = $parsedEndpoint.AbsoluteUri
        CodeSigningAccountName = $accountName
        CertificateProfileName = $profileName
        Files = $fullPath
        FileDigest = "SHA256"
        TimestampRfc3161 = $parsedTimestamp.AbsoluteUri
        TimestampDigest = "SHA256"
        ExcludeEnvironmentCredential = $true
        ExcludeWorkloadIdentityCredential = $true
        ExcludeManagedIdentityCredential = $true
        ExcludeSharedTokenCacheCredential = $true
        ExcludeVisualStudioCredential = $true
        ExcludeVisualStudioCodeCredential = $true
        ExcludeAzureCliCredential = $false
        ExcludeAzurePowerShellCredential = $true
        ExcludeAzureDeveloperCliCredential = $true
        ExcludeInteractiveBrowserCredential = $true
    }
    $null = Invoke-ArtifactSigning @signingParameters
}
catch {
    throw "LNS-REL-005: Artifact Signing failed for '$fullPath': $($_.Exception.Message)"
}

$signature = Get-AuthenticodeSignature -LiteralPath $fullPath
if ($signature.Status -ne "Valid" -or
    $null -eq $signature.SignerCertificate -or
    $null -eq $signature.TimeStamperCertificate) {
    throw "LNS-REL-005: Artifact Signing verification failed for '$fullPath': status=$($signature.Status), timestamp=$($null -ne $signature.TimeStamperCertificate)."
}

Write-Host "Artifact Signing verified: $($signature.SignerCertificate.Subject)" -ForegroundColor Green

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
