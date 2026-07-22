// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Wpf.Services;

namespace LocalNetworkScanner.Wpf;

public partial class App : Application
{
    private readonly Dictionary<string, object> _defaultPalette = [];

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        SystemParameters.StaticPropertyChanged += OnSystemParametersChanged;
        CaptureDefaultPalette();
        ApplyAccessibilityPalette();

        MainWindow window = new();
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        DispatcherUnhandledException -= OnDispatcherUnhandledException;
        SystemParameters.StaticPropertyChanged -= OnSystemParametersChanged;
        base.OnExit(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        new UserDialogService().ShowDiagnostic(
            "Local Network Scanner",
            DiagnosticMapper.FromException(e.Exception, "interface gráfica"));
        e.Handled = true;
    }

    private void OnSystemParametersChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.IsNullOrEmpty(e.PropertyName) || e.PropertyName == nameof(SystemParameters.HighContrast))
            ApplyAccessibilityPalette();
    }

    private void CaptureDefaultPalette()
    {
        foreach (string key in PaletteKeys)
        {
            if (Resources[key] is object resource)
                _defaultPalette[key] = resource;
        }
    }

    private void ApplyAccessibilityPalette()
    {
        if (!SystemParameters.HighContrast)
        {
            foreach ((string key, object value) in _defaultPalette)
                Resources[key] = value;
            return;
        }

        Resources["WindowBackgroundBrush"] = SystemColors.WindowBrush;
        Resources["SurfaceBrush"] = SystemColors.WindowBrush;
        Resources["SurfaceMutedBrush"] = SystemColors.ControlBrush;
        Resources["BorderBrush"] = SystemColors.ControlTextBrush;
        Resources["TextPrimaryBrush"] = SystemColors.WindowTextBrush;
        Resources["TextSecondaryBrush"] = SystemColors.WindowTextBrush;
        Resources["AccentBrush"] = SystemColors.HighlightBrush;
        Resources["AccentDarkBrush"] = SystemColors.HighlightBrush;
        Resources["SelectionBrush"] = SystemColors.HighlightBrush;
        Resources["SelectionForegroundBrush"] = SystemColors.HighlightTextBrush;
        Resources["SuccessBrush"] = SystemColors.WindowTextBrush;
        Resources["WarningBrush"] = SystemColors.WindowTextBrush;
        Resources["DangerBrush"] = SystemColors.WindowTextBrush;
        Resources["RiskHighBrush"] = SystemColors.ControlBrush;
        Resources["RiskMediumBrush"] = SystemColors.ControlBrush;
        Resources["RiskLowBrush"] = SystemColors.ControlBrush;
        Resources["RiskHighForegroundBrush"] = SystemColors.ControlTextBrush;
        Resources["RiskMediumForegroundBrush"] = SystemColors.ControlTextBrush;
        Resources["RiskLowForegroundBrush"] = SystemColors.ControlTextBrush;
    }

    private static IReadOnlyList<string> PaletteKeys { get; } =
    [
        "WindowBackgroundBrush",
        "SurfaceBrush",
        "SurfaceMutedBrush",
        "BorderBrush",
        "TextPrimaryBrush",
        "TextSecondaryBrush",
        "AccentBrush",
        "AccentDarkBrush",
        "SelectionBrush",
        "SelectionForegroundBrush",
        "SuccessBrush",
        "WarningBrush",
        "DangerBrush",
        "RiskHighBrush",
        "RiskMediumBrush",
        "RiskLowBrush",
        "RiskHighForegroundBrush",
        "RiskMediumForegroundBrush",
        "RiskLowForegroundBrush"
    ];
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
