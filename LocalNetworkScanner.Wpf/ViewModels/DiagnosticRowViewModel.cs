// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.ComponentModel;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Wpf.Services;

namespace LocalNetworkScanner.Wpf.ViewModels;

public sealed class DiagnosticRowViewModel : INotifyPropertyChanged
{
    public DiagnosticRowViewModel(ScanDiagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        Diagnostic = diagnostic;
    }

    public ScanDiagnostic Diagnostic { get; }

    public string Code => Diagnostic.Code;

    public DiagnosticSeverity Severity => Diagnostic.Severity;

    public string SeverityLabel => Diagnostic.Severity switch
    {
        DiagnosticSeverity.Information => L("Informação"),
        DiagnosticSeverity.Warning => L("Aviso"),
        DiagnosticSeverity.Error => L("Erro"),
        DiagnosticSeverity.Critical => L("Erro crítico"),
        _ => L("Desconhecido")
    };

    public string CategoryLabel => Diagnostic.Category switch
    {
        DiagnosticCategory.User => L("Utilizador"),
        DiagnosticCategory.Network => L("Rede"),
        DiagnosticCategory.Device => L("Dispositivo/dados"),
        DiagnosticCategory.Application => L("Aplicação"),
        _ => L("Desconhecida")
    };

    public string Message => DiagnosticLocalizationService.GetText(Diagnostic).Message;

    public string RecommendedAction => DiagnosticLocalizationService.GetText(Diagnostic).RecommendedAction;

    public string? Target => Diagnostic.Target;

    public bool HasTarget => !string.IsNullOrWhiteSpace(Target);

    public event PropertyChangedEventHandler? PropertyChanged;

    public void RefreshLocalized()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SeverityLabel)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CategoryLabel)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Message)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(RecommendedAction)));
    }

    private static string L(string value) => LocalizationService.Translate(value);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
