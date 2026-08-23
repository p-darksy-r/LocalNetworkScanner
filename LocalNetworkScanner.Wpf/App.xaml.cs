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

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
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
    ];
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
