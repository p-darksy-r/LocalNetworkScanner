// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Wpf.Services;

namespace LocalNetworkScanner.Wpf;

public partial class App : Application
{
    private readonly Dictionary<string, object> _defaultPalette = [];
    private readonly LocalDiagnosticLogService _diagnosticLog = new();
    private int _fatalDialogShown;

    public AppThemeMode CurrentTheme { get; private set; } = AppThemeMode.Light;

    public event EventHandler? ThemeChanged;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // WPF can deliver a queued startup callback after a host has already
        // supplied its own main window (the test harness does this deliberately).
        // Never create a second window or overwrite its selected language/theme.
        if (MainWindow is not null)
            return;

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        SystemParameters.StaticPropertyChanged += OnSystemParametersChanged;
        CaptureDefaultPalette();
        UiSettings startupSettings = new UiSettingsService().Load();
        LocalizationService.SetLanguage(startupSettings.Language, notify: false);
        AppThemeMode startupTheme = startupSettings.Theme;
        ApplyTheme(startupTheme, notify: false);

        MainWindow window = new();
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        DispatcherUnhandledException -= OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException -= OnDomainUnhandledException;
        TaskScheduler.UnobservedTaskException -= OnUnobservedTaskException;
        SystemParameters.StaticPropertyChanged -= OnSystemParametersChanged;
        base.OnExit(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        if (Interlocked.Exchange(ref _fatalDialogShown, 1) != 0)
        {
            try
            {
                (MainWindow as LocalNetworkScanner.Wpf.MainWindow)?.PrepareForFatalShutdown();
            }
            finally
            {
                Shutdown(1);
            }
            return;
        }

        ScanDiagnostic diagnostic = DiagnosticMapper.FromException(e.Exception, "interface gráfica");
        _diagnosticLog.TryWriteUnhandled(
            DiagnosticLogSource.WpfDispatcher,
            e.Exception,
            diagnostic,
            processTerminating: true);

        try
        {
            (MainWindow as LocalNetworkScanner.Wpf.MainWindow)?.PrepareForFatalShutdown();
            new UserDialogService().ShowDiagnostic("Local Network Scanner", diagnostic);
        }
        catch (Exception dialogException) when (
            dialogException is InvalidOperationException or Win32Exception)
        {
            ScanDiagnostic dialogDiagnostic = DiagnosticMapper.FromException(
                dialogException,
                "diálogo de falha fatal");
            _diagnosticLog.TryWriteUnhandled(
                DiagnosticLogSource.WpfDispatcher,
                dialogException,
                dialogDiagnostic,
                processTerminating: true);
        }
        finally
        {
            // O estado do Dispatcher pode estar corrompido. Continuar depois de uma
            // exceção não tratada arriscaria resultados ou definições inconsistentes.
            Shutdown(1);
        }
    }

    private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is not Exception exception)
            return;

        ScanDiagnostic diagnostic = DiagnosticMapper.FromException(exception, "processo da aplicação");
        _diagnosticLog.TryWriteUnhandled(
            DiagnosticLogSource.AppDomain,
            exception,
            diagnostic,
            e.IsTerminating);
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        ScanDiagnostic diagnostic = DiagnosticMapper.FromException(e.Exception, "tarefa assíncrona");
        _diagnosticLog.TryWriteUnhandled(
            DiagnosticLogSource.TaskScheduler,
            e.Exception,
            diagnostic,
            processTerminating: false);
        e.SetObserved();
    }

    private void OnSystemParametersChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.IsNullOrEmpty(e.PropertyName) || e.PropertyName == nameof(SystemParameters.HighContrast))
            ApplyAccessibilityPalette();
    }

    public void ApplyTheme(AppThemeMode theme, bool notify = true)
    {
        if (_defaultPalette.Count == 0)
            CaptureDefaultPalette();

        CurrentTheme = Enum.IsDefined(theme) ? theme : AppThemeMode.Light;
        ApplyAccessibilityPalette();
        if (notify)
            ThemeChanged?.Invoke(this, EventArgs.Empty);
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
        if (!SystemParameters.HighContrast && CurrentTheme == AppThemeMode.Dark)
        {
            ApplyDarkPalette();
            return;
        }

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
        Resources["AccentForegroundBrush"] = SystemColors.HighlightTextBrush;
        Resources["SelectionBrush"] = SystemColors.HighlightBrush;
        Resources["SelectionForegroundBrush"] = SystemColors.HighlightTextBrush;
        Resources["SuccessBrush"] = SystemColors.WindowTextBrush;
        Resources["WarningBrush"] = SystemColors.WindowTextBrush;
        Resources["DangerBrush"] = SystemColors.WindowTextBrush;
        Resources["DangerForegroundBrush"] = SystemColors.WindowBrush;
        Resources["RiskHighBrush"] = SystemColors.ControlBrush;
        Resources["RiskMediumBrush"] = SystemColors.ControlBrush;
        Resources["RiskLowBrush"] = SystemColors.ControlBrush;
        Resources["RiskHighForegroundBrush"] = SystemColors.ControlTextBrush;
        Resources["RiskMediumForegroundBrush"] = SystemColors.ControlTextBrush;
        Resources["RiskLowForegroundBrush"] = SystemColors.ControlTextBrush;
        Resources["ToolTipBackgroundBrush"] = SystemColors.InfoBrush;
        Resources["ToolTipForegroundBrush"] = SystemColors.InfoTextBrush;
    }

    private void ApplyDarkPalette()
    {
        SetPaletteBrush("WindowBackgroundBrush", 0x11, 0x16, 0x1D);
        SetPaletteBrush("SurfaceBrush", 0x1A, 0x21, 0x2B);
        SetPaletteBrush("SurfaceMutedBrush", 0x22, 0x2C, 0x38);
        SetPaletteBrush("BorderBrush", 0x5D, 0x70, 0x87);
        SetPaletteBrush("TextPrimaryBrush", 0xF4, 0xF7, 0xFB);
        SetPaletteBrush("TextSecondaryBrush", 0xAA, 0xB7, 0xC8);
        SetPaletteBrush("AccentBrush", 0x66, 0xA8, 0xFF);
        SetPaletteBrush("AccentDarkBrush", 0x9C, 0xC5, 0xFF);
        SetPaletteBrush("AccentForegroundBrush", 0x08, 0x11, 0x1E);
        SetPaletteBrush("SuccessBrush", 0x63, 0xD7, 0xA0);
        SetPaletteBrush("WarningBrush", 0xFF, 0xC6, 0x6B);
        SetPaletteBrush("DangerBrush", 0xFF, 0x93, 0x88);
        SetPaletteBrush("DangerForegroundBrush", 0x2B, 0x0C, 0x09);
        SetPaletteBrush("SelectionBrush", 0x29, 0x4A, 0x72);
        SetPaletteBrush("SelectionForegroundBrush", 0xF4, 0xF8, 0xFF);
        SetPaletteBrush("RiskHighBrush", 0x57, 0x2A, 0x2E);
        SetPaletteBrush("RiskHighForegroundBrush", 0xFF, 0xB8, 0xB1);
        SetPaletteBrush("RiskMediumBrush", 0x57, 0x42, 0x1F);
        SetPaletteBrush("RiskMediumForegroundBrush", 0xFF, 0xD5, 0x8A);
        SetPaletteBrush("RiskLowBrush", 0x21, 0x4C, 0x39);
        SetPaletteBrush("RiskLowForegroundBrush", 0xA9, 0xF3, 0xC9);
        SetPaletteBrush("ToolTipBackgroundBrush", 0x2A, 0x34, 0x42);
        SetPaletteBrush("ToolTipForegroundBrush", 0xF4, 0xF7, 0xFB);
    }

    private void SetPaletteBrush(string key, byte red, byte green, byte blue)
    {
        SolidColorBrush brush = new(Color.FromRgb(red, green, blue));
        brush.Freeze();
        Resources[key] = brush;
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
        "AccentForegroundBrush",
        "SelectionBrush",
        "SelectionForegroundBrush",
        "SuccessBrush",
        "WarningBrush",
        "DangerBrush",
        "DangerForegroundBrush",
        "RiskHighBrush",
        "RiskMediumBrush",
        "RiskLowBrush",
        "RiskHighForegroundBrush",
        "RiskMediumForegroundBrush",
        "RiskLowForegroundBrush"
        ,
        "ToolTipBackgroundBrush",
        "ToolTipForegroundBrush"
    ];
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
