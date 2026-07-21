[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

$repoRoot = Split-Path -Parent $PSScriptRoot
$assetDirectory = Join-Path $repoRoot "LocalNetworkScanner.Wpf\Assets"
$iconPath = Join-Path $assetDirectory "App.ico"
$previewPath = Join-Path $assetDirectory "AppIcon.png"
New-Item -ItemType Directory -Path $assetDirectory -Force | Out-Null

function New-RoundedRectanglePath {
    param(
        [System.Drawing.RectangleF]$Rectangle,
        [float]$Radius
    )

    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $diameter = $Radius * 2
    $arc = [System.Drawing.RectangleF]::new($Rectangle.X, $Rectangle.Y, $diameter, $diameter)
    $path.AddArc($arc, 180, 90)
    $arc.X = $Rectangle.Right - $diameter
    $path.AddArc($arc, 270, 90)
    $arc.Y = $Rectangle.Bottom - $diameter
    $path.AddArc($arc, 0, 90)
    $arc.X = $Rectangle.Left
    $path.AddArc($arc, 90, 90)
    $path.CloseFigure()
    return $path
}

function New-IconPngBytes {
    param([int]$Size)

    $bitmap = [System.Drawing.Bitmap]::new($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
            $graphics.Clear([System.Drawing.Color]::Transparent)

            $padding = [Math]::Max(1.0, $Size * 0.035)
            $bounds = [System.Drawing.RectangleF]::new(
                [float]$padding,
                [float]$padding,
                [float]($Size - (2 * $padding)),
                [float]($Size - (2 * $padding)))
            $corner = [Math]::Max(2.0, $Size * 0.19)
            $backgroundPath = New-RoundedRectanglePath -Rectangle $bounds -Radius ([float]$corner)
            try {
                $background = [System.Drawing.Drawing2D.LinearGradientBrush]::new(
                    $bounds,
                    [System.Drawing.Color]::FromArgb(255, 7, 28, 55),
                    [System.Drawing.Color]::FromArgb(255, 22, 105, 224),
                    42.0)
                try {
                    $graphics.FillPath($background, $backgroundPath)
                }
                finally {
                    $background.Dispose()
                }
            }
            finally {
                $backgroundPath.Dispose()
            }

            $center = [System.Drawing.PointF]::new([float]($Size * 0.5), [float]($Size * 0.5))
            $radarRadius = [float]($Size * 0.335)
            $lineWidth = [Math]::Max(1.15, $Size * 0.018)
            $gridPen = [System.Drawing.Pen]::new(
                [System.Drawing.Color]::FromArgb(122, 135, 224, 255),
                [float]$lineWidth)
            try {
                foreach ($ratio in @(0.34, 0.67, 1.0)) {
                    $radius = $radarRadius * $ratio
                    $graphics.DrawEllipse(
                        $gridPen,
                        $center.X - $radius,
                        $center.Y - $radius,
                        2 * $radius,
                        2 * $radius)
                }
                $graphics.DrawLine($gridPen, $center.X - $radarRadius, $center.Y, $center.X + $radarRadius, $center.Y)
                $graphics.DrawLine($gridPen, $center.X, $center.Y - $radarRadius, $center.X, $center.Y + $radarRadius)
            }
            finally {
                $gridPen.Dispose()
            }

            $sweepPen = [System.Drawing.Pen]::new(
                [System.Drawing.Color]::FromArgb(235, 105, 245, 255),
                [float][Math]::Max(1.5, $Size * 0.027))
            try {
                $sweepPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
                $sweepPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
                $angle = -38 * [Math]::PI / 180
                $end = [System.Drawing.PointF]::new(
                    [float]($center.X + ([Math]::Cos($angle) * $radarRadius)),
                    [float]($center.Y + ([Math]::Sin($angle) * $radarRadius)))
                $graphics.DrawLine($sweepPen, $center, $end)
            }
            finally {
                $sweepPen.Dispose()
            }

            $nodeBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
            $glowBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(95, 78, 238, 255))
            try {
                $nodes = @(
                    [pscustomobject]@{ X = $Size * 0.31; Y = $Size * 0.35; Radius = 0.037 },
                    [pscustomobject]@{ X = $Size * 0.67; Y = $Size * 0.38; Radius = 0.044 },
                    [pscustomobject]@{ X = $Size * 0.61; Y = $Size * 0.68; Radius = 0.034 },
                    [pscustomobject]@{ X = $Size * 0.39; Y = $Size * 0.62; Radius = 0.029 }
                )
                foreach ($node in $nodes) {
                    $radius = [Math]::Max(1.2, $Size * $node.Radius)
                    $graphics.FillEllipse(
                        $glowBrush,
                        [float]($node.X - ($radius * 1.8)),
                        [float]($node.Y - ($radius * 1.8)),
                        [float]($radius * 3.6),
                        [float]($radius * 3.6))
                    $graphics.FillEllipse(
                        $nodeBrush,
                        [float]($node.X - $radius),
                        [float]($node.Y - $radius),
                        [float]($radius * 2),
                        [float]($radius * 2))
                }
            }
            finally {
                $nodeBrush.Dispose()
                $glowBrush.Dispose()
            }
        }
        finally {
            $graphics.Dispose()
        }

        $stream = [System.IO.MemoryStream]::new()
        try {
            $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
            Write-Output -NoEnumerate ($stream.ToArray())
            return
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $bitmap.Dispose()
    }
}

$sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
$images = @($sizes | ForEach-Object { New-IconPngBytes -Size $_ })
$headerLength = 6 + (16 * $images.Count)
$offset = $headerLength

$file = [System.IO.File]::Create($iconPath)
try {
    $writer = [System.IO.BinaryWriter]::new($file)
    try {
        $writer.Write([uint16]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]$images.Count)
        for ($index = 0; $index -lt $images.Count; $index++) {
            $size = $sizes[$index]
            $writer.Write([byte]($(if ($size -eq 256) { 0 } else { $size })))
            $writer.Write([byte]($(if ($size -eq 256) { 0 } else { $size })))
            $writer.Write([byte]0)
            $writer.Write([byte]0)
            $writer.Write([uint16]1)
            $writer.Write([uint16]32)
            $writer.Write([uint32]$images[$index].Length)
            $writer.Write([uint32]$offset)
            $offset += $images[$index].Length
        }
        foreach ($image in $images) {
            $writer.Write($image)
        }
    }
    finally {
        $writer.Dispose()
    }
}
finally {
    $file.Dispose()
}

[System.IO.File]::WriteAllBytes($previewPath, (New-IconPngBytes -Size 512))
Write-Host "Icon generated: $iconPath" -ForegroundColor Green
