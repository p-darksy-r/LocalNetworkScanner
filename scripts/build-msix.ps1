# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [ValidateSet("PrivateTest", "Store")]
    [string]$Mode = "PrivateTest",

    [ValidateSet("win-x64", "win-arm64")]
    [string]$RuntimeIdentifier = "win-x64",

    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [string]$IdentityName,

    [string]$Publisher,

    [string]$PublisherDisplayName,

    [string]$SigningCertificateThumbprint,

    [string]$PublicCertificatePath = (Join-Path (Split-Path -Parent $PSScriptRoot) "crt\LocalNetworkScanner-PrivateTest.crt"),

    [ValidateRange(0, 65535)]
    [int]$PackageRevision = 0,

    [string]$MakeAppxPath,

    [string]$SignToolPath,

    [switch]$SkipChecks,

    [switch]$SkipWpfSmoke,

    [switch]$DisableReadyToRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$privateIdentityName = "p-darksy-r.LocalNetworkScanner.PrivateTest"
$privatePublisher = "CN=p-darksy-r Local Network Scanner Private Test"
$privatePublisherDisplayName = "p-darksy-r (Private Test)"
$privateDisplayName = "Local Network Scanner (Private Test)"
$codeSigningEku = "1.3.6.1.5.5.7.3.3"
$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactsRoot = Join-Path $repoRoot "artifacts"
$wpfProject = Join-Path $repoRoot "LocalNetworkScanner.Wpf\LocalNetworkScanner.Wpf.csproj"
$propsPath = Join-Path $repoRoot "Directory.Build.props"
$manifestTemplatePath = Join-Path $repoRoot "packaging\msix\AppxManifest.template.xml"
$assetSource = Join-Path $repoRoot "packaging\msix\Assets"
$checkScript = Join-Path $PSScriptRoot "check.ps1"
$validatorScript = Join-Path $PSScriptRoot "validate-msix-package.ps1"

function Invoke-NativeTool {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    Write-Host ("> " + (Split-Path $FilePath -Leaf) + " " + ($Arguments -join " ")) -ForegroundColor DarkGray
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-MSX-004: $(Split-Path $FilePath -Leaf) exited with code $LASTEXITCODE."
    }
}

function Invoke-DotNet {
    param([Parameter(Mandatory)][string[]]$Arguments)

    Write-Host ("> dotnet " + ($Arguments -join " ")) -ForegroundColor DarkGray
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-MSX-004: dotnet exited with code $LASTEXITCODE."
    }
}

function Assert-InsideArtifacts {
    param([Parameter(Mandatory)][string]$Path)

    $base = [IO.Path]::GetFullPath($artifactsRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        throw "LNS-MSX-004: refusing to modify a path outside artifacts: $full"
    }

    return $full
}

function Reset-ArtifactDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $safePath = Assert-InsideArtifacts $Path
    if (Test-Path -LiteralPath $safePath) {
        Remove-Item -LiteralPath $safePath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $safePath -Force | Out-Null
}

function Resolve-WindowsSdkTool {
    param(
        [Parameter(Mandatory)][string]$ToolName,
        [string]$RequestedPath
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $resolved = [IO.Path]::GetFullPath($RequestedPath)
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "LNS-MSX-004: $ToolName was not found at the requested path: $resolved"
        }
        return $resolved
    }

    $command = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path -LiteralPath $kitsRoot -PathType Container) {
        $candidates = @(
            Get-ChildItem -LiteralPath $kitsRoot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
                Sort-Object { [version]$_.Name } -Descending |
                ForEach-Object { Join-Path $_.FullName "x64\$ToolName" } |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
        )
        if ($candidates.Count -gt 0) {
            return $candidates[0]
        }
    }

    throw "LNS-MSX-004: $ToolName was not found. Install the Windows SDK MSIX packaging tools."
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

function Resolve-PrivateTestCertificate {
    param([string]$RequestedThumbprint)

    $now = Get-Date
    $normalized = if ([string]::IsNullOrWhiteSpace($RequestedThumbprint)) {
        $null
    }
    else {
        $RequestedThumbprint.Replace(" ", "").ToUpperInvariant()
    }

    $candidates = @(
        Get-ChildItem -Path Cert:\CurrentUser\My |
            Where-Object {
                ($null -eq $normalized -or $_.Thumbprint.ToUpperInvariant() -eq $normalized) -and
                $_.Subject -ceq $privatePublisher -and
                $_.Issuer -ceq $_.Subject -and
                $_.HasPrivateKey -and
                $_.NotBefore -le $now -and
                $_.NotAfter -gt $now.AddDays(30) -and
                $_.SignatureAlgorithm.Value -eq "1.2.840.113549.1.1.11" -and
                (Test-CodeSigningEku $_)
            } |
            Sort-Object NotAfter -Descending
    )

    if ($candidates.Count -eq 0) {
        $hint = if ($null -eq $normalized) {
            "Run .\scripts\new-private-test-certificate.ps1 first."
        }
        else {
            "The requested thumbprint was not a valid matching private-test certificate."
        }
        throw "LNS-MSX-002: no usable private-test signing certificate was found in CurrentUser\My. $hint"
    }

    $certificate = $candidates[0]
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    try {
        if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
            throw "LNS-MSX-002: the private-test certificate must use RSA with at least 3072 bits."
        }
    }
    finally {
        if ($null -ne $rsa) { $rsa.Dispose() }
    }

    $basicConstraints = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" })
    if ($basicConstraints.Count -ne 1 -or
        -not ($basicConstraints[0] -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) -or
        $basicConstraints[0].CertificateAuthority) {
        throw "LNS-MSX-002: the private-test certificate must explicitly have CA=false."
    }
    $keyUsage = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" })
    if ($keyUsage.Count -ne 1 -or
        $keyUsage[0].KeyUsages -ne [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) {
        throw "LNS-MSX-002: the private-test certificate key usage must be exactly DigitalSignature."
    }
    $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    if ($null -eq $privateKey -or -not ($privateKey -is [Security.Cryptography.RSACng])) {
        if ($null -ne $privateKey) { $privateKey.Dispose() }
        throw "LNS-MSX-002: the private-test key must be a non-exportable Windows CNG RSA key."
    }
    try {
        if ($privateKey.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None) {
            throw "LNS-MSX-002: the private-test key must be non-exportable."
        }
    }
    finally {
        $privateKey.Dispose()
    }

    return $certificate
}

function Invoke-WpfSmokeTest {
    param([Parameter(Mandatory)][string]$Executable)

    Write-Host "> Published WPF smoke test (window lifecycle)" -ForegroundColor DarkGray
    $process = Start-Process -FilePath $Executable -PassThru
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 250
            $process.Refresh()
        }
        while (-not $process.HasExited -and $process.MainWindowHandle -eq 0 -and [DateTime]::UtcNow -lt $deadline)

        if ($process.HasExited -or $process.MainWindowHandle -eq 0 -or -not $process.Responding) {
            throw "LNS-MSX-006: the published UI did not create a responsive window within 20 seconds."
        }
        if (-not $process.CloseMainWindow() -or -not $process.WaitForExit(8000) -or $process.ExitCode -ne 0) {
            throw "LNS-MSX-006: the published UI did not close normally after the MSIX pre-package smoke test."
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
    throw "LNS-MSX-004: the .NET SDK is required and dotnet was not found on PATH."
}
foreach ($required in @($wpfProject, $propsPath, $manifestTemplatePath, $assetSource, $validatorScript)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "LNS-MSX-004: required MSIX input was not found: $required"
    }
}

$architecture = if ($RuntimeIdentifier -eq "win-x64") { "x64" } else { "arm64" }
$displayName = "Local Network Scanner"
$certificate = $null
if ($Mode -eq "PrivateTest") {
    foreach ($value in @($IdentityName, $Publisher, $PublisherDisplayName)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            throw "LNS-MSX-001: PrivateTest uses a fixed isolated identity; do not pass Store identity parameters."
        }
    }
    $IdentityName = $privateIdentityName
    $Publisher = $privatePublisher
    $PublisherDisplayName = $privatePublisherDisplayName
    $displayName = $privateDisplayName
    $certificate = Resolve-PrivateTestCertificate $SigningCertificateThumbprint
    $resolvedPublicCertificatePath = [IO.Path]::GetFullPath($PublicCertificatePath)
    if (-not (Test-Path -LiteralPath $resolvedPublicCertificatePath -PathType Leaf)) {
        throw "LNS-MSX-002: the matching public PrivateTest CRT was not found: $resolvedPublicCertificatePath"
    }
    $publicCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedPublicCertificatePath)
    try {
        if ($publicCertificate.HasPrivateKey -or
            $publicCertificate.Thumbprint -cne $certificate.Thumbprint -or
            -not [Linq.Enumerable]::SequenceEqual[byte]($publicCertificate.RawData, $certificate.RawData)) {
            throw "LNS-MSX-002: the selected private key does not match the supplied public PrivateTest CRT."
        }
    }
    finally {
        $publicCertificate.Dispose()
    }
}
else {
    if (-not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        throw "LNS-MSX-001: Store mode must remain unsigned for Microsoft Store processing; do not pass a test certificate."
    }
    if (-not [string]::IsNullOrWhiteSpace($SignToolPath)) {
        throw "LNS-MSX-001: Store mode does not accept a signing tool; Microsoft signs only after certification."
    }
    if ($PackageRevision -ne 0) {
        throw "LNS-MSX-001: Store packages must use revision 0."
    }
    foreach ($field in @{
        IdentityName = $IdentityName
        Publisher = $Publisher
        PublisherDisplayName = $PublisherDisplayName
    }.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string]$field.Value)) {
            throw "LNS-MSX-001: -$($field.Key) must be copied exactly from Partner Center in Store mode."
        }
    }
    if ($IdentityName -eq $privateIdentityName -or $Publisher -eq $privatePublisher) {
        throw "LNS-MSX-001: the isolated PrivateTest identity cannot be used for a Store package."
    }
}

$resolvedMakeAppx = Resolve-WindowsSdkTool "makeappx.exe" $MakeAppxPath
$resolvedSignTool = if ($Mode -eq "PrivateTest") {
    Resolve-WindowsSdkTool "signtool.exe" $SignToolPath
}
else {
    $null
}

[xml]$props = Get-Content -LiteralPath $propsPath -Raw
$versionText = [string]($props.Project.PropertyGroup.Version | Select-Object -First 1)
if ($versionText -notmatch '^(\d+)\.(\d+)\.(\d+)(?:\.\d+)?$') {
    throw "LNS-MSX-003: Directory.Build.props Version is not a supported MSIX version: '$versionText'."
}
$packageVersion = "{0}.{1}.{2}.{3}" -f $Matches[1], $Matches[2], $Matches[3], $PackageRevision
foreach ($component in @($Matches[1], $Matches[2], $Matches[3], $PackageRevision)) {
    if ([int]$component -gt 65535) {
        throw "LNS-MSX-003: every MSIX version component must be between 0 and 65535."
    }
}

$modeDirectoryName = if ($Mode -eq "PrivateTest") { "private-test" } else { "store" }
$modeSuffix = if ($Mode -eq "PrivateTest") { "PrivateTest" } else { "Store-Unsigned" }
$workRoot = Join-Path $artifactsRoot "msix\work\$modeDirectoryName\$RuntimeIdentifier"
$publishDirectory = Join-Path $workRoot "publish"
$layoutDirectory = Join-Path $workRoot "layout"
$outputDirectory = Join-Path $artifactsRoot "msix\$modeDirectoryName\$RuntimeIdentifier"
$packageFileName = "LocalNetworkScanner-$packageVersion-$modeSuffix-$architecture.msix"
$packagePath = Join-Path $outputDirectory $packageFileName

Push-Location $repoRoot
try {
    if (-not $SkipChecks) {
        & $checkScript -Configuration $Configuration
        if ($LASTEXITCODE -ne 0) {
            throw "LNS-MSX-004: the validation script failed with code $LASTEXITCODE."
        }
    }

    Reset-ArtifactDirectory $workRoot
    Reset-ArtifactDirectory $outputDirectory
    New-Item -ItemType Directory -Path $publishDirectory, $layoutDirectory -Force | Out-Null

    $readyToRun = if ($DisableReadyToRun) { "false" } else { "true" }
    Invoke-DotNet @(
        "restore", $wpfProject,
        "--runtime", $RuntimeIdentifier,
        "-p:PublishReadyToRun=$readyToRun"
    )
    Invoke-DotNet @(
        "publish", $wpfProject,
        "--configuration", $Configuration,
        "--runtime", $RuntimeIdentifier,
        "--self-contained", "true",
        "--output", $publishDirectory,
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

    $publishedExecutable = Join-Path $publishDirectory "LocalNetworkScanner.exe"
    if (-not (Test-Path -LiteralPath $publishedExecutable -PathType Leaf)) {
        throw "LNS-MSX-004: the expected WPF executable was not published: $publishedExecutable"
    }

    $hostArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $canRun = ($architecture -eq "x64" -and $hostArchitecture -in @("X64", "Arm64")) -or
        ($architecture -eq "arm64" -and $hostArchitecture -eq "Arm64")
    if (-not $SkipWpfSmoke -and $canRun) {
        Invoke-WpfSmokeTest $publishedExecutable
    }

    Copy-Item -LiteralPath $publishedExecutable -Destination (Join-Path $layoutDirectory "LocalNetworkScanner.exe")
    Copy-Item -LiteralPath $assetSource -Destination (Join-Path $layoutDirectory "Assets") -Recurse
    foreach ($legalFile in @("LICENSE", "PRIVACY.md", "THIRD_PARTY_NOTICES.md")) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $legalFile) -Destination $layoutDirectory
    }

    [xml]$manifest = Get-Content -LiteralPath $manifestTemplatePath -Raw
    $namespaceManager = [Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $namespaceManager.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
    $namespaceManager.AddNamespace("uap", "http://schemas.microsoft.com/appx/manifest/uap/windows10")
    $namespaceManager.AddNamespace("uap10", "http://schemas.microsoft.com/appx/manifest/uap/windows10/10")
    $identityNode = $manifest.SelectSingleNode("/f:Package/f:Identity", $namespaceManager)
    $propertiesNode = $manifest.SelectSingleNode("/f:Package/f:Properties", $namespaceManager)
    $applicationNode = $manifest.SelectSingleNode("/f:Package/f:Applications/f:Application", $namespaceManager)
    $visualNode = $manifest.SelectSingleNode("/f:Package/f:Applications/f:Application/uap:VisualElements", $namespaceManager)
    if ($null -in @($identityNode, $propertiesNode, $applicationNode, $visualNode)) {
        throw "LNS-MSX-003: the MSIX manifest template is missing required nodes."
    }

    $identityNode.SetAttribute("Name", $IdentityName)
    $identityNode.SetAttribute("Publisher", $Publisher)
    $identityNode.SetAttribute("Version", $packageVersion)
    $identityNode.SetAttribute("ProcessorArchitecture", $architecture)
    $propertiesNode.SelectSingleNode("f:DisplayName", $namespaceManager).InnerText = $displayName
    $propertiesNode.SelectSingleNode("f:PublisherDisplayName", $namespaceManager).InnerText = $PublisherDisplayName
    $visualNode.SetAttribute("DisplayName", $displayName)
    $manifestPath = Join-Path $layoutDirectory "AppxManifest.xml"
    $manifest.Save($manifestPath)

    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    Invoke-NativeTool $resolvedMakeAppx @(
        "pack", "/v", "/o", "/h", "SHA256",
        "/d", $layoutDirectory,
        "/p", $packagePath
    )

    if ($Mode -eq "PrivateTest") {
        if ($certificate.Subject -cne $Publisher) {
            throw "LNS-MSX-002: certificate Subject and manifest Publisher do not match exactly."
        }
        Invoke-NativeTool $resolvedSignTool @(
            "sign", "/v", "/fd", "SHA256", "/s", "My",
            "/sha1", $certificate.Thumbprint,
            $packagePath
        )
    }

    $validationParameters = @{
        Path = $packagePath
        ExpectedMode = $Mode
        MakeAppxPath = $resolvedMakeAppx
    }
    if ($Mode -eq "PrivateTest") {
        $validationParameters.ExpectedSignerThumbprint = $certificate.Thumbprint
    }
    else {
        $validationParameters.ExpectedIdentityName = $IdentityName
        $validationParameters.ExpectedPublisher = $Publisher
        $validationParameters.ExpectedPublisherDisplayName = $PublisherDisplayName
    }
    & $validatorScript @validationParameters
    if ($LASTEXITCODE -ne 0) {
        throw "LNS-MSX-005: MSIX package validation failed with code $LASTEXITCODE."
    }

    $hash = Get-FileHash -LiteralPath $packagePath -Algorithm SHA256
    $checksumPath = "$packagePath.sha256"
    Set-Content -LiteralPath $checksumPath -Encoding ascii -Value ("{0} *{1}" -f $hash.Hash.ToLowerInvariant(), $packageFileName)
    $statePath = Join-Path $outputDirectory "MSIX-BUILD-STATE.json"
    [ordered]@{
        schemaVersion = 1
        productVersion = $versionText
        packageVersion = $packageVersion
        mode = $Mode
        signingState = if ($Mode -eq "PrivateTest") { "PrivateTestSelfSigned" } else { "UnsignedForMicrosoftStore" }
        runtimeIdentifier = $RuntimeIdentifier
        processorArchitecture = $architecture
        identityName = $IdentityName
        publisher = $Publisher
        publisherDisplayName = $PublisherDisplayName
        packageFile = $packageFileName
        sha256 = $hash.Hash.ToLowerInvariant()
        signerThumbprint = if ($null -ne $certificate) { $certificate.Thumbprint } else { $null }
        sourceCommit = [string](& git rev-parse HEAD 2>$null)
        createdUtc = [DateTime]::UtcNow.ToString("o")
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding utf8

    Write-Host "MSIX package created and validated." -ForegroundColor Green
    Write-Host "Mode:       $Mode"
    Write-Host "Identity:   $IdentityName"
    Write-Host "Version:    $packageVersion"
    Write-Host "Package:    $packagePath"
    Write-Host "SHA-256:    $($hash.Hash.ToLowerInvariant())"
    if ($Mode -eq "Store") {
        Write-Warning "This Store candidate is intentionally unsigned and cannot be installed locally. Microsoft signs it only after Store certification."
    }
}
finally {
    Pop-Location
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
