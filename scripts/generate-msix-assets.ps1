# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $repoRoot "LocalNetworkScanner.Wpf\Assets\AppIcon.png"
$outputDirectory = Join-Path $repoRoot "packaging\msix\Assets"

if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "LNS-MSX-004: source icon not found: $sourcePath"
}

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$assetSpecifications = @(
    [pscustomobject]@{ Name = "StoreLogo.png"; Width = 50; Height = 50; IconSize = 40 },
    [pscustomobject]@{ Name = "Square44x44Logo.png"; Width = 44; Height = 44; IconSize = 36 },
    [pscustomobject]@{ Name = "Square150x150Logo.png"; Width = 150; Height = 150; IconSize = 120 },
    [pscustomobject]@{ Name = "Wide310x150Logo.png"; Width = 310; Height = 150; IconSize = 120 },
    [pscustomobject]@{ Name = "Square310x310Logo.png"; Width = 310; Height = 310; IconSize = 248 }
)

$sourceImage = [System.Drawing.Image]::FromFile($sourcePath)
try {
    if ($sourceImage.Width -ne $sourceImage.Height) {
        throw "LNS-MSX-004: the source icon must be square; found $($sourceImage.Width)x$($sourceImage.Height)."
    }

    foreach ($asset in $assetSpecifications) {
        $bitmap = [System.Drawing.Bitmap]::new(
            $asset.Width,
            $asset.Height,
            [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            $bitmap.SetResolution(96, 96)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.Clear([System.Drawing.Color]::Transparent)
                $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceOver
                $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
                $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality

                $left = [int](($asset.Width - $asset.IconSize) / 2)
                $top = [int](($asset.Height - $asset.IconSize) / 2)
                $destination = [System.Drawing.Rectangle]::new(
                    $left,
                    $top,
                    $asset.IconSize,
                    $asset.IconSize)
                $graphics.DrawImage(
                    $sourceImage,
                    $destination,
                    0,
                    0,
                    $sourceImage.Width,
                    $sourceImage.Height,
                    [System.Drawing.GraphicsUnit]::Pixel)
            }
            finally {
                $graphics.Dispose()
            }

            $outputPath = Join-Path $outputDirectory $asset.Name
            $bitmap.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
            Write-Host "Generated MSIX asset: $outputPath"
        }
        finally {
            $bitmap.Dispose()
        }
    }
}
finally {
    $sourceImage.Dispose()
}

# Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
