# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param(
    [string]$OutputPath,

    [string]$SourceDirectory,

    [ValidatePattern("^\d{4}-\d{2}-\d{2}$")]
    [string]$SnapshotDate = [DateTime]::UtcNow.ToString("yyyy-MM-dd")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repoRoot "LocalNetworkScanner.Core\Data\ieee-mac-vendors.tsv.gz"
}
else {
    $OutputPath = [IO.Path]::GetFullPath($OutputPath)
}

$sources = @(
    [pscustomobject]@{
        Registry = "MA-L"
        FileName = "oui.csv"
        Url = "https://standards-oui.ieee.org/oui/oui.csv"
        PrefixLength = 6
        MinimumRows = 30000
        MaximumRows = 100000
    },
    [pscustomobject]@{
        Registry = "MA-M"
        FileName = "mam.csv"
        Url = "https://standards-oui.ieee.org/oui28/mam.csv"
        PrefixLength = 7
        MinimumRows = 4000
        MaximumRows = 30000
    },
    [pscustomobject]@{
        Registry = "MA-S"
        FileName = "oui36.csv"
        Url = "https://standards-oui.ieee.org/oui36/oui36.csv"
        PrefixLength = 9
        MinimumRows = 4000
        MaximumRows = 30000
    },
    [pscustomobject]@{
        Registry = "IAB"
        FileName = "iab.csv"
        Url = "https://standards-oui.ieee.org/iab/iab.csv"
        PrefixLength = 9
        MinimumRows = 3000
        MaximumRows = 20000
    }
)

function Assert-InsideRepository {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $repoRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The bundled database must be written inside the repository: $full"
    }

    return $full
}

function Normalize-Assignment {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][int]$ExpectedLength
    )

    $invalidCharacters = [Regex]::Replace($Value, "[0-9A-Fa-f:\-.\s]", "")
    if ($invalidCharacters.Length -gt 0) {
        return $null
    }

    $normalized = [Regex]::Replace($Value, "[:\-.\s]", "").ToUpperInvariant()
    if ($normalized.Length -ne $ExpectedLength) {
        return $null
    }

    return $normalized
}

$OutputPath = Assert-InsideRepository $OutputPath
$outputDirectory = Split-Path $OutputPath -Parent
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("LocalNetworkScanner-ieee-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null

try {
    [xml]$props = Get-Content -LiteralPath (Join-Path $repoRoot "Directory.Build.props") -Raw
    $version = [string]$props.Project.PropertyGroup.Version
    $userAgent = "LocalNetworkScanner/$version"
    $entries = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $uniquePrefixes = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $counts = [ordered]@{}
    $hashes = [ordered]@{}

    foreach ($source in $sources) {
        $sourcePath = if ([string]::IsNullOrWhiteSpace($SourceDirectory)) {
            $downloadPath = Join-Path $temporaryRoot $source.FileName
            Write-Host "Downloading $($source.Registry) from $($source.Url)" -ForegroundColor Cyan
            Invoke-WebRequest `
                -Uri $source.Url `
                -OutFile $downloadPath `
                -UseBasicParsing `
                -Headers @{ "User-Agent" = $userAgent }
            $downloadPath
        }
        else {
            Join-Path ([IO.Path]::GetFullPath($SourceDirectory)) $source.FileName
        }

        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "IEEE source file not found: $sourcePath"
        }

        $sourceFile = Get-Item -LiteralPath $sourcePath
        if ($sourceFile.Length -le 0 -or $sourceFile.Length -gt 20MB) {
            throw "$($source.Registry) has an unexpected size of $($sourceFile.Length) bytes."
        }

        $firstLine = (Get-Content -LiteralPath $sourcePath -Encoding UTF8 -TotalCount 1).TrimStart(
            [char]0xFEFF)
        if ($firstLine -ne "Registry,Assignment,Organization Name,Organization Address") {
            throw "$($source.Registry) has an unexpected CSV header."
        }

        $records = @(Import-Csv -LiteralPath $sourcePath -Encoding UTF8)
        if ($records.Count -lt $source.MinimumRows -or $records.Count -gt $source.MaximumRows) {
            throw "$($source.Registry) contains $($records.Count) rows; expected between $($source.MinimumRows) and $($source.MaximumRows)."
        }

        $accepted = 0
        foreach ($record in $records) {
            if ([string]$record.Registry -ne $source.Registry) {
                throw "Unexpected registry '$($record.Registry)' in $($source.FileName)."
            }

            $assignment = Normalize-Assignment ([string]$record.Assignment) $source.PrefixLength
            $organization = [Regex]::Replace(
                ([string]$record.'Organization Name').Trim(),
                "\s+",
                " ")
            if ([string]::IsNullOrWhiteSpace($assignment)) {
                throw "$($source.Registry) contains an invalid assignment '$($record.Assignment)'."
            }
            if ([string]::IsNullOrWhiteSpace($organization) -or
                $organization.Length -gt 2048) {
                throw "$($source.Registry) contains an invalid organization name."
            }

            $line = "$($source.Registry)`t$assignment`t$organization"
            if (-not $entries.Add($line)) {
                throw "Duplicate IEEE record '$line'."
            }
            [void]$uniquePrefixes.Add($assignment)
            $accepted++
        }

        if ($accepted -lt $source.MinimumRows) {
            throw "$($source.Registry) contains only $accepted valid assignments."
        }

        $counts[$source.Registry] = $accepted
        $hashes[$source.Registry] =
            (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $temporaryOutput = "$OutputPath.tmp-$([Guid]::NewGuid().ToString('N'))"
    try {
        $file = [IO.File]::Create($temporaryOutput)
        try {
            $gzip = [IO.Compression.GZipStream]::new(
                $file,
                [IO.Compression.CompressionLevel]::Optimal,
                $false)
            try {
                $writer = [IO.StreamWriter]::new(
                    $gzip,
                    [Text.UTF8Encoding]::new($false),
                    64 * 1024,
                    $false)
                try {
                    $writer.WriteLine("# IEEE Registration Authority public assignment data.")
                    $writer.WriteLine("# format=LocalNetworkScanner.IEEE-MAC-Vendors/v1")
                    $writer.WriteLine("# snapshotDate=$SnapshotDate")
                    $writer.WriteLine("# entries=$($entries.Count)")
                    $writer.WriteLine("# uniquePrefixes=$($uniquePrefixes.Count)")
                    $writer.WriteLine("# sourceCopyright=IEEE. All rights reserved.")
                    $writer.WriteLine("# notice=Bundled for offline lookup; no IEEE endorsement implied.")
                    foreach ($source in $sources) {
                        $writer.WriteLine("# source.$($source.Registry)=$($source.Url)")
                        $writer.WriteLine("# count.$($source.Registry)=$($counts[$source.Registry])")
                        $writer.WriteLine("# sha256.$($source.Registry)=$($hashes[$source.Registry])")
                    }

                    [string[]]$lines = @($entries)
                    [Array]::Sort($lines, [StringComparer]::Ordinal)
                    foreach ($line in $lines) {
                        $writer.WriteLine($line)
                    }
                    $writer.WriteLine("# End of IEEE Registration Authority public assignment data.")
                }
                finally {
                    $writer.Dispose()
                }
            }
            finally {
                $gzip.Dispose()
            }
        }
        finally {
            $file.Dispose()
        }

        Move-Item -LiteralPath $temporaryOutput -Destination $OutputPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryOutput -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryOutput -Force
        }
    }

    $compressed = Get-Item -LiteralPath $OutputPath
    Write-Host "Bundled IEEE vendor database updated." -ForegroundColor Green
    Write-Host "Entries:    $($entries.Count)"
    Write-Host "Prefixes:   $($uniquePrefixes.Count)"
    Write-Host "Compressed: $($compressed.Length) bytes"
    Write-Host "Output:     $OutputPath"
    foreach ($source in $sources) {
        Write-Host "$($source.Registry): $($counts[$source.Registry]) rows; SHA-256 $($hashes[$source.Registry])"
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot -PathType Container) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
