// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Wpf.ViewModels;

public sealed class DiagnosticRowViewModel
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
        DiagnosticSeverity.Information => "Informação",
        DiagnosticSeverity.Warning => "Aviso",
        DiagnosticSeverity.Error => "Erro",
        DiagnosticSeverity.Critical => "Erro crítico",
        _ => "Desconhecido"
    };

    public string CategoryLabel => Diagnostic.Category switch
    {
        DiagnosticCategory.User => "Utilizador",
        DiagnosticCategory.Network => "Rede",
        DiagnosticCategory.Device => "Dispositivo/dados",
        DiagnosticCategory.Application => "Aplicação",
        _ => "Desconhecida"
    };

    public string Message => Diagnostic.Message;

    public string RecommendedAction => Diagnostic.RecommendedAction;

    public string? Target => Diagnostic.Target;

    public bool HasTarget => !string.IsNullOrWhiteSpace(Target);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
