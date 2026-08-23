# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0)]
    [string[]]$Path,

    [switch]$PassThru
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
        # The .NET SDK deliberately accepts comments in global.json.
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
        '.iss'        { return @{ Prefix = ';'; Suffix = ''; FooterPrefix = '//'; FooterSuffix = '' } }
        default {
            if ($File.Name -in @('.gitignore', '.gitattributes', '.editorconfig', 'CODEOWNERS')) {
                return @{ Prefix = '#'; Suffix = '' }
            }

            return $null
        }
    }
}

function Test-IsExcluded {
    param([Parameter(Mandatory)][IO.FileInfo]$File)

    if ($File.Name -in $excludedFileNames) {
        return $true
    }

    $relativePath = Get-RepositoryRelativePath $File.FullName
    foreach ($segment in ($relativePath -split '[\\/]')) {
        if ($segment -in $excludedDirectoryNames) {
            return $true
        }
    }

    return $false
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
            $fullName = [IO.Path]::GetFullPath($file.FullName)
            [void](Get-RepositoryRelativePath $fullName)

            if (-not (Test-IsExcluded $file) -and
                $null -ne (Get-CommentStyle $file) -and
                $seen.Add($fullName)) {
                $file
            }
        }
    }
}

function Read-SourceFile {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $bytes = [IO.File]::ReadAllBytes($LiteralPath)
    $encoding = if ($bytes.Length -ge 3 -and
        $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        [Text.UTF8Encoding]::new($true)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        [Text.UnicodeEncoding]::new($false, $true)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        [Text.UnicodeEncoding]::new($true, $true)
    }
    else {
        [Text.UTF8Encoding]::new($false)
    }

    $content = if ($bytes.Length -eq 0) { '' } else { $encoding.GetString($bytes) }
    if ($content.Length -gt 0 -and $content[0] -eq [char]0xFEFF) {
        $content = $content.Substring(1)
    }

    return @{
        Content = $content
        Encoding = $encoding
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

$changedFiles = [Collections.Generic.List[string]]::new()

foreach ($file in (Get-TargetFiles | Sort-Object FullName)) {
    $style = Get-CommentStyle $file
    $header = Format-Comment $style $copyrightText
    $footer = Format-Comment $style $footerText -Footer
    $source = Read-SourceFile $file.FullName
    $newline = if ($source.Content.Contains("`r`n")) { "`r`n" } else { "`n" }
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($line in ($source.Content -split '\r?\n')) {
        $trimmedLine = $line.Trim()
        $isLegacyMarker =
            $trimmedLine -match '^(?://|#|;|<!--)\s*(?:End of file\s*[-:]\s*)?Copyright \(c\) 2026 p-darksy-r\b.*?(?:\s*-->)?$' -or
            $trimmedLine -match '^// End of file:\s*.+$'
        if ($trimmedLine -notin @($header, $footer) -and -not $isLegacyMarker) {
            $lines.Add($line)
        }
    }

    while ($lines.Count -gt 0 -and [string]::IsNullOrWhiteSpace($lines[0])) {
        $lines.RemoveAt(0)
    }
    while ($lines.Count -gt 0 -and [string]::IsNullOrWhiteSpace($lines[$lines.Count - 1])) {
        $lines.RemoveAt($lines.Count - 1)
    }

    $headerIndex = 0
    if ($lines.Count -gt 0 -and
        ($lines[0] -match '^\s*<\?xml\s' -or $lines[0] -match '^#!')) {
        $headerIndex = 1
    }

    $lines.Insert($headerIndex, $header)
    if ($lines.Count -gt ($headerIndex + 1) -and
        -not [string]::IsNullOrWhiteSpace($lines[$headerIndex + 1])) {
        $lines.Insert($headerIndex + 1, '')
    }

    if ($lines.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($lines[$lines.Count - 1])) {
        $lines.Add('')
    }
    $lines.Add($footer)

    $updated = [string]::Join($newline, $lines) + $newline
    if ($updated -ceq $source.Content) {
        continue
    }

    $relativePath = Get-RepositoryRelativePath $file.FullName
    if ($PSCmdlet.ShouldProcess($relativePath, 'Apply copyright header and footer')) {
        [IO.File]::WriteAllText($file.FullName, $updated, $source.Encoding)
        $changedFiles.Add($relativePath)
    }
}

Write-Host "Copyright markers applied to $($changedFiles.Count) file(s)."
if ($PassThru) {
    $changedFiles
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
