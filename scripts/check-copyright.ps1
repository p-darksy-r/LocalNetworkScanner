# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repositoryRootPrefix = $repositoryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$copyrightText = 'Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.'
$footerText = $copyrightText
$excludedDirectoryNames = @('.git', '.vs', 'artifacts', 'bin', 'obj', 'packages', 'TestResults')
$excludedFileNames = @('LICENSE')

function Get-RepositoryRelativePath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $fullName = [IO.Path]::GetFullPath($LiteralPath)
    if (-not $fullName.StartsWith($repositoryRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path outside repository root is not allowed: $fullName"
    }

    return $fullName.Substring($repositoryRootPrefix.Length)
}

function Get-CommentStyle {
    param([Parameter(Mandatory)][IO.FileInfo]$File)

    if ($File.Name -eq 'global.json') {
        return @{ Prefix = '//'; Suffix = '' }
    }

    switch ($File.Extension.ToLowerInvariant()) {
        '.cs'         { return @{ Prefix = '//'; Suffix = '' } }
        '.csproj'     { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.props'      { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.targets'    { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.xaml'       { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.xml'        { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.slnx'       { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.manifest'   { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.resx'       { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.config'     { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.md'         { return @{ Prefix = '<!--'; Suffix = '-->' } }
        '.yml'        { return @{ Prefix = '#'; Suffix = '' } }
        '.yaml'       { return @{ Prefix = '#'; Suffix = '' } }
        '.ps1'        { return @{ Prefix = '#'; Suffix = '' } }
        '.psm1'       { return @{ Prefix = '#'; Suffix = '' } }
        '.psd1'       { return @{ Prefix = '#'; Suffix = '' } }
        '.py'         { return @{ Prefix = '#'; Suffix = '' } }
        '.sh'         { return @{ Prefix = '#'; Suffix = '' } }
        '.toml'       { return @{ Prefix = '#'; Suffix = '' } }
        '.cmd'        { return @{ Prefix = '@REM'; Suffix = '' } }
        '.bat'        { return @{ Prefix = '@REM'; Suffix = '' } }
        '.iss'        { return @{ Prefix = ';'; Suffix = ''; FooterPrefix = '//'; FooterSuffix = '' } }
        default {
            if ($File.Name -in @('.gitignore', '.gitattributes', '.editorconfig', 'CODEOWNERS')) {
                return @{ Prefix = '#'; Suffix = '' }
            }

            return $null
        }
    }
}

function Format-Comment {
    param(
        [Parameter(Mandatory)][hashtable]$Style,
        [Parameter(Mandatory)][string]$Text,
        [switch]$Footer
    )

    $prefix = if ($Footer -and $Style.ContainsKey('FooterPrefix')) {
        $Style.FooterPrefix
    }
    else {
        $Style.Prefix
    }
    $suffix = if ($Footer -and $Style.ContainsKey('FooterSuffix')) {
        $Style.FooterSuffix
    }
    else {
        $Style.Suffix
    }

    if ([string]::IsNullOrEmpty($suffix)) {
        return "$prefix $Text"
    }

    return "$prefix $Text $suffix"
}

function Get-TargetFiles {
    $requestedPaths = if ($Path -and $Path.Count -gt 0) { $Path } else { @($repositoryRoot) }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($requestedPath in $requestedPaths) {
        $resolved = Resolve-Path -LiteralPath $requestedPath -ErrorAction Stop
        $item = Get-Item -LiteralPath $resolved.Path -Force
        $files = if ($item.PSIsContainer) {
            @(Get-ChildItem -LiteralPath $item.FullName -File -Recurse -Force)
        }
        else {
            @($item)
        }

        foreach ($file in $files) {
            $relativePath = Get-RepositoryRelativePath $file.FullName
            $segments = $relativePath -split '[\\/]'
            if ($file.Name -notin $excludedFileNames -and
                @($segments | Where-Object { $_ -in $excludedDirectoryNames }).Count -eq 0 -and
                $null -ne (Get-CommentStyle $file) -and
                $seen.Add($file.FullName)) {
                $file
            }
        }
    }
}

$failures = [Collections.Generic.List[string]]::new()
$checkedCount = 0

foreach ($file in (Get-TargetFiles | Sort-Object FullName)) {
    $relativePath = Get-RepositoryRelativePath $file.FullName
    $style = Get-CommentStyle $file
    $checkedCount++
    $header = Format-Comment $style $copyrightText
    $footer = Format-Comment $style $footerText -Footer
    $content = [IO.File]::ReadAllText($file.FullName)
    $lines = @($content -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) {
        $failures.Add("$relativePath`: file is empty")
        continue
    }

    $headerIndex = if ($lines[0] -match '^\s*<\?xml\s' -or $lines[0] -match '^#!') { 1 } else { 0 }
    $hasHeader = $lines.Count -gt $headerIndex -and $lines[$headerIndex].Trim() -ceq $header
    $hasFooter = $lines[$lines.Count - 1].Trim() -ceq $footer

    if (-not $hasHeader -or -not $hasFooter) {
        $missing = @()
        if (-not $hasHeader) { $missing += 'header' }
        if (-not $hasFooter) { $missing += 'footer' }
        $failures.Add("$relativePath`: missing $($missing -join ' and ')")
    }
}

if ($failures.Count -gt 0) {
    Write-Error ("Copyright validation failed for {0} file(s):`n - {1}`nRun .\scripts\apply-copyright.ps1 and review the changes." -f $failures.Count, ($failures -join "`n - "))
}

Write-Host "Copyright validation passed for $checkedCount commentable text file(s)."

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
