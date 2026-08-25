# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [switch]$Force,

    [switch]$Launch,

    [switch]$Quick,

    [switch]$SkipChecks,

    [switch]$SkipWpfSmoke
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$appRoot = Join-Path $repoRoot "app"
$appExecutable = Join-Path $appRoot "LocalNetworkScanner.exe"
$appManifest = Join-Path $appRoot "APP-BUILD.json"
$appUpdateLock = Join-Path $appRoot ".update.lock"
$checkScript = Join-Path $PSScriptRoot "check.ps1"
$wpfProject = Join-Path $repoRoot "LocalNetworkScanner.Wpf\LocalNetworkScanner.Wpf.csproj"
$artifactsRoot = Join-Path $repoRoot "artifacts"
$localPublishRoot = Join-Path $artifactsRoot "local-app"

function Get-NativeRuntimeIdentifier {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows)) {
        throw "A pasta app só pode ser materializada num computador Windows."
    }

    switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        ([Runtime.InteropServices.Architecture]::X64) { return "win-x64" }
        ([Runtime.InteropServices.Architecture]::Arm64) { return "win-arm64" }
        default {
            throw "Arquitetura Windows não suportada para a pasta app: $([Runtime.InteropServices.RuntimeInformation]::OSArchitecture)."
        }
    }
}

function Get-EffectiveAppVersion {
    $buildProperties = Join-Path $repoRoot "Directory.Build.props"
    [xml]$document = Get-Content -LiteralPath $buildProperties -Raw
    $versionNodes = @(Select-Xml -Xml $document -XPath "/Project/PropertyGroup/Version")
    if ($versionNodes.Count -ne 1) {
        throw "Directory.Build.props deve declarar exatamente uma propriedade Version."
    }

    $version = ([string]$versionNodes[0].Node.InnerText).Trim()
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "A versão efetiva da aplicação está vazia."
    }

    return $version
}

function Get-AppSourceFingerprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $inputs = [Collections.Generic.List[IO.FileInfo]]::new()
    foreach ($relativeRoot in @("LocalNetworkScanner.Core", "LocalNetworkScanner.Wpf")) {
        $sourceRoot = Join-Path $RepositoryRoot $relativeRoot
        foreach ($file in (Get-ChildItem -LiteralPath $sourceRoot -File -Recurse)) {
            if ($file.FullName -notmatch "[\\/](bin|obj)[\\/]") {
                $inputs.Add($file)
            }
        }
    }

    $rootBuildFiles = @(
        Get-ChildItem -LiteralPath $RepositoryRoot -File |
            Where-Object { $_.Name -like "Directory.Build.*" }
    )
    foreach ($file in $rootBuildFiles) {
        $inputs.Add($file)
    }
    foreach ($relativeFile in @("global.json", "scripts\update-local-app.ps1")) {
        $candidate = Join-Path $RepositoryRoot $relativeFile
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $inputs.Add((Get-Item -LiteralPath $candidate))
        }
    }

    $repositoryPrefix = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $lines = foreach ($file in ($inputs | Sort-Object FullName -Unique)) {
        if (-not $file.FullName.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "O input da aplicação está fora da raiz do repositório: $($file.FullName)"
        }
        $relativePath = $file.FullName.Substring($repositoryPrefix.Length).Replace('\', '/')
        $fileHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$relativePath`0$fileHash"
    }

    $payload = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($payload)
    }
    finally {
        $algorithm.Dispose()
    }

    return ([BitConverter]::ToString($digest)).Replace("-", "").ToLowerInvariant()
}

function Get-PeRuntimeIdentifier {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable
    )

    $stream = [IO.File]::Open($Executable, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw "O executável publicado não contém um cabeçalho PE válido: $Executable"
        }

        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or $peOffset -gt ($stream.Length - 6)) {
            throw "O executável publicado contém um offset PE inválido: $Executable"
        }

        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "O executável publicado não contém uma assinatura PE válida: $Executable"
        }

        switch ($reader.ReadUInt16()) {
            0x8664 { return "win-x64" }
            0xAA64 { return "win-arm64" }
            default { throw "A arquitetura PE do executável publicado não é suportada." }
        }
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Get-CurrentGitCommit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        return $null
    }

    $commit = & git -C $RepositoryRoot rev-parse HEAD 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    return ([string]$commit).Trim()
}

function Get-CurrentGitDirtyState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        return $null
    }

    $status = @(& git -C $RepositoryRoot status --porcelain --untracked-files=normal 2>$null)
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    return $status.Count -gt 0
}

function Read-AppBuildManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Test-LocalAppCurrent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [string]$RuntimeIdentifier,

        [Parameter(Mandatory = $true)]
        [string]$SourceFingerprint
    )

    if ($null -eq $Manifest -or -not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        return $false
    }

    $requiredProperties = @(
        "schemaVersion",
        "version",
        "runtimeIdentifier",
        "sourceFingerprint",
        "sha256"
    )
    foreach ($property in $requiredProperties) {
        if ($Manifest.PSObject.Properties.Name -notcontains $property) {
            return $false
        }
    }

    try {
        $schemaVersion = [Convert]::ToInt32($Manifest.schemaVersion, [Globalization.CultureInfo]::InvariantCulture)
        $manifestVersion = [string]$Manifest.version
        $manifestRuntime = [string]$Manifest.runtimeIdentifier
        $manifestFingerprint = [string]$Manifest.sourceFingerprint
        $manifestHash = [string]$Manifest.sha256
    }
    catch {
        return $false
    }

    if ($schemaVersion -ne 1 -or
        $manifestVersion -cne $Version -or
        $manifestRuntime -cne $RuntimeIdentifier -or
        $manifestFingerprint -cne $SourceFingerprint -or
        $manifestHash -notmatch '^[0-9a-fA-F]{64}$') {
        return $false
    }

    try {
        $actualRuntime = Get-PeRuntimeIdentifier -Executable $Executable
        if ($actualRuntime -cne $RuntimeIdentifier) {
            return $false
        }
        $actualHash = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant()
        return $actualHash -ceq $manifestHash.ToLowerInvariant()
    }
    catch {
        return $false
    }
}

function Enter-LocalAppUpdateLock {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LockPath,

        [ValidateRange(0, 120000)]
        [int]$TimeoutMilliseconds = 5000
    )

    $resolvedLockPath = [IO.Path]::GetFullPath($LockPath)
    New-Item -ItemType Directory -Path (Split-Path -Parent $resolvedLockPath) -Force | Out-Null
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)

    do {
        try {
            return [IO.File]::Open(
                $resolvedLockPath,
                [IO.FileMode]::OpenOrCreate,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None)
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw "Já existe outra atualização da pasta app em curso. Aguarde que termine e tente novamente."
            }
            Start-Sleep -Milliseconds 200
        }
    }
    while ($true)
}

function Invoke-DotNet {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host ("> dotnet " + ($Arguments -join " ")) -ForegroundColor DarkGray
    & dotnet @Arguments | Out-Host
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "dotnet terminou com o código $exitCode."
    }
}

function Reset-LocalPublishDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $artifactsPrefix = [IO.Path]::GetFullPath($artifactsRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "A publicação local recusou alterar um caminho fora de artifacts: $fullPath"
    }

    if (Test-Path -LiteralPath $fullPath) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    return $fullPath
}

function Invoke-LocalAppSmokeTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable
    )

    Write-Host "> Smoke da UI materializada (ciclo da janela)" -ForegroundColor DarkGray
    try {
        $process = Start-Process -FilePath $Executable -PassThru
    }
    catch {
        $current = $_.Exception
        while ($null -ne $current) {
            if ($current -is [ComponentModel.Win32Exception] -and $current.NativeErrorCode -eq 4551) {
                throw "LNS-REL-007: o Windows Application Control bloqueou o smoke da aplicação (CreateProcess 4551)."
            }
            $current = $current.InnerException
        }
        throw "Não foi possível iniciar o smoke da aplicação: $($_.Exception.Message)"
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
            throw "A aplicação terminou antes de criar a janela (código $($process.ExitCode))."
        }
        if ($process.MainWindowHandle -eq 0 -or
            $process.MainWindowTitle -ne "Local Network Scanner" -or
            -not $process.Responding) {
            throw "A aplicação não criou uma janela principal responsiva dentro de 20 segundos."
        }
        if (-not $process.CloseMainWindow() -or -not $process.WaitForExit(8000)) {
            throw "A aplicação não concluiu um fecho normal durante o smoke."
        }
        if ($process.ExitCode -ne 0) {
            throw "A aplicação terminou o smoke com o código $($process.ExitCode)."
        }
    }
    finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        $process.Dispose()
    }
}

function Publish-LocalAppExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuntimeIdentifier,

        [switch]$RunChecks,

        [switch]$RunSmoke
    )

    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "O .NET SDK definido em global.json é necessário para reconstruir a pasta app."
    }

    if ($RunChecks) {
        & $checkScript -Configuration Release -VerifyFormat | Out-Host
        $checkExitCode = $LASTEXITCODE
        if ($checkExitCode -ne 0) {
            throw "O gate local falhou com o código $checkExitCode."
        }
    }

    $output = Reset-LocalPublishDirectory (Join-Path $localPublishRoot $RuntimeIdentifier)
    Invoke-DotNet @(
        "restore",
        $wpfProject,
        "--runtime", $RuntimeIdentifier,
        "-p:PublishReadyToRun=true"
    )
    Invoke-DotNet @(
        "publish",
        $wpfProject,
        "--output", $output,
        "--configuration", "Release",
        "--runtime", $RuntimeIdentifier,
        "--self-contained", "true",
        "--no-restore",
        "--nologo",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "-p:EnableCompressionInSingleFile=true",
        "-p:PublishTrimmed=false",
        "-p:PublishReadyToRun=true",
        "-p:DebugType=None",
        "-p:DebugSymbols=false"
    )

    $executable = Join-Path $output "LocalNetworkScanner.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "A publicação local terminou sem criar o executável esperado: $executable"
    }
    if ($RunSmoke) {
        Invoke-LocalAppSmokeTest -Executable $executable
    }

    return $executable
}

function Restore-LocalAppTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [string]$Backup,

        [Parameter(Mandatory = $true)]
        [bool]$Existed
    )

    if (-not $Existed) {
        if (Test-Path -LiteralPath $Destination) {
            Remove-Item -LiteralPath $Destination -Force
        }
        return
    }

    if (-not (Test-Path -LiteralPath $Backup -PathType Leaf)) {
        throw "O backup transacional não foi encontrado: $Backup"
    }

    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        $discard = Join-Path (Split-Path -Parent $Destination) `
            (".update-discard-" + [Guid]::NewGuid().ToString("N") + ".tmp")
        try {
            [IO.File]::Replace($Backup, $Destination, $discard, $false)
        }
        finally {
            if (Test-Path -LiteralPath $discard) {
                Remove-Item -LiteralPath $discard -Force -ErrorAction SilentlyContinue
            }
        }
    }
    else {
        [IO.File]::Move($Backup, $Destination)
    }
}

function Install-LocalAppPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PublishedExecutable,

        [Parameter(Mandatory = $true)]
        [string]$DestinationRoot,

        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [string]$RuntimeIdentifier,

        [Parameter(Mandatory = $true)]
        [string]$SourceFingerprint,

        [AllowNull()]
        [string]$Commit,

        [AllowNull()]
        [Nullable[bool]]$WorkingTreeDirty,

        [Parameter(Mandatory = $true)]
        [string]$AuthenticodeStatus,

        [AllowNull()]
        [string]$SignerSubject,

        [AllowNull()]
        [scriptblock]$RollbackAction
    )

    $source = [IO.Path]::GetFullPath($PublishedExecutable)
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "O executável publicado não foi encontrado: $source"
    }

    $destination = [IO.Path]::GetFullPath($DestinationRoot)
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $targetExecutable = Join-Path $destination "LocalNetworkScanner.exe"
    $targetManifest = Join-Path $destination "APP-BUILD.json"
    $temporaryExecutable = Join-Path $destination (".update-" + [Guid]::NewGuid().ToString("N") + ".exe.tmp")
    $temporaryManifest = Join-Path $destination (".update-" + [Guid]::NewGuid().ToString("N") + ".json.tmp")
    $executableBackup = Join-Path $destination (".update-backup-" + [Guid]::NewGuid().ToString("N") + ".exe.tmp")
    $manifestBackup = Join-Path $destination (".update-backup-" + [Guid]::NewGuid().ToString("N") + ".json.tmp")
    $executableExisted = Test-Path -LiteralPath $targetExecutable -PathType Leaf
    $manifestExisted = Test-Path -LiteralPath $targetManifest -PathType Leaf
    $executableChanged = $false
    $manifestChanged = $false
    $preserveBackups = $false

    if ($null -eq $RollbackAction) {
        $RollbackAction = {
            param($Destination, $Backup, $Existed)

            Restore-LocalAppTarget `
                -Destination $Destination `
                -Backup $Backup `
                -Existed $Existed
        }
    }

    try {
        Copy-Item -LiteralPath $source -Destination $temporaryExecutable
        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        $temporaryHash = (Get-FileHash -LiteralPath $temporaryExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($temporaryHash -cne $sourceHash) {
            throw "A cópia temporária da aplicação não corresponde ao executável publicado."
        }

        $manifest = [ordered]@{
            schemaVersion = 1
            product = "Local Network Scanner"
            executable = "LocalNetworkScanner.exe"
            version = $Version
            runtimeIdentifier = $RuntimeIdentifier
            sourceFingerprint = $SourceFingerprint
            commit = $Commit
            workingTreeDirty = $WorkingTreeDirty
            generatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
            sizeBytes = (Get-Item -LiteralPath $temporaryExecutable).Length
            sha256 = $temporaryHash
            authenticodeStatus = $AuthenticodeStatus
            signerSubject = $SignerSubject
            copyright = "Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License."
        }
        $json = ($manifest | ConvertTo-Json -Depth 4) + [Environment]::NewLine
        [IO.File]::WriteAllText($temporaryManifest, $json, [Text.UTF8Encoding]::new($false))

        try {
            if ($manifestExisted) {
                [IO.File]::Replace($temporaryManifest, $targetManifest, $manifestBackup, $false)
            }
            else {
                [IO.File]::Move($temporaryManifest, $targetManifest)
            }
            $manifestChanged = $true

            if ($executableExisted) {
                [IO.File]::Replace($temporaryExecutable, $targetExecutable, $executableBackup, $false)
            }
            else {
                [IO.File]::Move($temporaryExecutable, $targetExecutable)
            }
            $executableChanged = $true

            $installedManifest = Read-AppBuildManifest -ManifestPath $targetManifest
            if (-not (Test-LocalAppCurrent `
                -Executable $targetExecutable `
                -Manifest $installedManifest `
                -Version $Version `
                -RuntimeIdentifier $RuntimeIdentifier `
                -SourceFingerprint $SourceFingerprint)) {
                throw "A validação final do executável e manifesto materializados falhou."
            }
        }
        catch {
            $updateFailure = $_.Exception.Message
            $rollbackFailures = [Collections.Generic.List[string]]::new()

            if ($executableChanged) {
                try {
                    & $RollbackAction $targetExecutable $executableBackup $executableExisted
                }
                catch {
                    $rollbackFailures.Add("executável: $($_.Exception.Message)")
                }
            }
            if ($manifestChanged) {
                try {
                    & $RollbackAction $targetManifest $manifestBackup $manifestExisted
                }
                catch {
                    $rollbackFailures.Add("manifesto: $($_.Exception.Message)")
                }
            }

            if ($rollbackFailures.Count -gt 0) {
                $preserveBackups = $true
                $recoveryPaths = @(
                    @($executableBackup, $manifestBackup) |
                        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
                )
                $recoveryHint = if ($recoveryPaths.Count -gt 0) {
                    " Backups preservados para recuperação manual: $($recoveryPaths -join ', ')."
                }
                else {
                    " Não foi possível preservar um backup recuperável."
                }
                throw "A atualização falhou e o rollback não ficou completo ($($rollbackFailures -join '; ')).$recoveryHint Falha inicial: $updateFailure"
            }
            throw "Não foi possível atualizar a pasta app. Feche LocalNetworkScanner.exe e tente novamente; a cópia anterior foi restaurada. $updateFailure"
        }

        return Get-Item -LiteralPath $targetExecutable
    }
    finally {
        foreach ($temporaryFile in @(
            $temporaryExecutable,
            $temporaryManifest
        )) {
            if (Test-Path -LiteralPath $temporaryFile) {
                Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
            }
        }
        if (-not $preserveBackups) {
            foreach ($backupFile in @($executableBackup, $manifestBackup)) {
                if (Test-Path -LiteralPath $backupFile) {
                    Remove-Item -LiteralPath $backupFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Start-LocalApp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable
    )

    try {
        Start-Process -FilePath $Executable | Out-Null
    }
    catch {
        $current = $_.Exception
        $nativeErrorCode = $null
        while ($null -ne $current) {
            if ($current -is [ComponentModel.Win32Exception]) {
                $nativeErrorCode = $current.NativeErrorCode
                break
            }
            $current = $current.InnerException
        }

        if ($nativeErrorCode -eq 4551) {
            throw "LNS-REL-007: o Windows Application Control bloqueou a aplicação (CreateProcess 4551). A pasta app não ignora políticas; use uma build assinada/autorizada ou contacte o administrador."
        }

        throw
    }
}

function Invoke-LocalAppUpdate {
    $updateLock = Enter-LocalAppUpdateLock -LockPath $appUpdateLock
    try {
        $runtimeIdentifier = Get-NativeRuntimeIdentifier
        $version = Get-EffectiveAppVersion
        $sourceFingerprint = Get-AppSourceFingerprint -RepositoryRoot $repoRoot
        $manifest = Read-AppBuildManifest -ManifestPath $appManifest
        $isCurrent = Test-LocalAppCurrent `
            -Executable $appExecutable `
            -Manifest $manifest `
            -Version $version `
            -RuntimeIdentifier $runtimeIdentifier `
            -SourceFingerprint $sourceFingerprint

        if ($Force -or -not $isCurrent) {
            Write-Host "A preparar Local Network Scanner $version para $runtimeIdentifier..." -ForegroundColor Cyan
            $runChecks = -not $Quick -and -not $SkipChecks
            $runSmoke = -not $Quick -and -not $SkipWpfSmoke
            if ($Quick) {
                Write-Warning "Modo Quick: gate e smoke prévios foram omitidos; compilação, versão, PE e SHA-256 continuam obrigatórios."
            }

            $publishedExecutable = Publish-LocalAppExecutable `
                -RuntimeIdentifier $runtimeIdentifier `
                -RunChecks:$runChecks `
                -RunSmoke:$runSmoke
            $postPublishFingerprint = Get-AppSourceFingerprint -RepositoryRoot $repoRoot
            if ($postPublishFingerprint -cne $sourceFingerprint) {
                throw "Os inputs da aplicação mudaram durante a publicação. A cópia anterior foi preservada; repita a atualização."
            }
            $publishedRuntime = Get-PeRuntimeIdentifier -Executable $publishedExecutable
            if ($publishedRuntime -cne $runtimeIdentifier) {
                throw "A publicação criou $publishedRuntime, mas a pasta app exige $runtimeIdentifier."
            }

            $productVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($publishedExecutable).ProductVersion
            $normalizedProductVersion = ([string]$productVersion -split '\+', 2)[0]
            if ($normalizedProductVersion -cne $version) {
                throw "A publicação criou a versão '$productVersion', mas o projeto exige '$version'."
            }

            $signature = Get-AuthenticodeSignature -LiteralPath $publishedExecutable
            $signerSubject = if ($null -eq $signature.SignerCertificate) {
                $null
            }
            else {
                $signature.SignerCertificate.Subject
            }

            $null = Install-LocalAppPayload `
                -PublishedExecutable $publishedExecutable `
                -DestinationRoot $appRoot `
                -Version $version `
                -RuntimeIdentifier $runtimeIdentifier `
                -SourceFingerprint $sourceFingerprint `
                -Commit (Get-CurrentGitCommit -RepositoryRoot $repoRoot) `
                -WorkingTreeDirty (Get-CurrentGitDirtyState -RepositoryRoot $repoRoot) `
                -AuthenticodeStatus ([string]$signature.Status) `
                -SignerSubject $signerSubject

            Write-Host "Aplicação atualizada: $appExecutable" -ForegroundColor Green
        }
        else {
            Write-Host "A pasta app já contém Local Network Scanner $version para $runtimeIdentifier." -ForegroundColor Green
        }

        if ($Launch) {
            Start-LocalApp -Executable $appExecutable
        }
    }
    finally {
        $updateLock.Dispose()
        Remove-Item -LiteralPath $appUpdateLock -Force -ErrorAction SilentlyContinue
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-LocalAppUpdate
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
