// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Windows;
using System.Windows.Controls;

namespace LocalNetworkScanner.Wpf.Controls;

/// <summary>
/// Measures star rows against the visible height. If the Auto rows and row minima
/// need more room, the enclosing vertical ScrollViewer can scroll the whole grid.
/// </summary>
public sealed class ScrollViewportGrid : Grid
{
    public static readonly DependencyProperty ViewportHeightProperty = DependencyProperty.Register(
        nameof(ViewportHeight), typeof(double), typeof(ScrollViewportGrid),
        new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public double ViewportHeight
    {
        get => (double)GetValue(ViewportHeightProperty);
        set => SetValue(ViewportHeightProperty, value);
    }

    protected override Size MeasureOverride(Size constraint) =>
        base.MeasureOverride(new Size(constraint.Width, Math.Min(constraint.Height, ViewportHeight)));
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
