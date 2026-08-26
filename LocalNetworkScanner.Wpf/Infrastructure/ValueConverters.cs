// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using LocalNetworkScanner.Wpf.Services;

namespace LocalNetworkScanner.Wpf.Infrastructure;

public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is null ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class InverseBooleanConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is bool boolean && !boolean;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is bool boolean && !boolean;
}

public sealed class RiskToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string key = (value as string) switch
        {
            "Alto" or "High" => "RiskHighBrush",
            "Médio" or "Medium" => "RiskMediumBrush",
            _ => "RiskLowBrush"
        };

        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class RiskToForegroundConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string key = (value as string) switch
        {
            "Alto" or "High" => "RiskHighForegroundBrush",
            "Médio" or "Medium" => "RiskMediumForegroundBrush",
            _ => "RiskLowForegroundBrush"
        };

        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Black;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Formats a bound value while keeping the surrounding UI text localizable.
/// Parameter syntax is <c>prefix|suffix|format</c>; the last two parts are optional.
/// </summary>
public sealed class LocalizedFormatConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        culture = LocalizationService.CurrentCulture;
        string[] parts = (parameter?.ToString() ?? "").Split('|', 3);
        string prefix = parts.Length > 0 ? LocalizationService.Translate(parts[0]) : string.Empty;
        string suffix = parts.Length > 1 ? LocalizationService.Translate(parts[1]) : string.Empty;
        string format = parts.Length > 2 && !string.IsNullOrWhiteSpace(parts[2]) ? parts[2] : string.Empty;
        string rendered = string.IsNullOrEmpty(format)
            ? value is IFormattable formattable
                ? formattable.ToString(null, culture) ?? string.Empty
                : value?.ToString() ?? string.Empty
            : value is IFormattable formatted
                ? formatted.ToString(format, culture) ?? string.Empty
                : value?.ToString() ?? string.Empty;
        return prefix + LocalizationService.Translate(rendered) + suffix;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
