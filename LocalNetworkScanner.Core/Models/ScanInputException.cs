// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

/// <summary>Falha de entrada que mantém compatibilidade com consumidores de ArgumentException.</summary>
public sealed class ScanInputException : ArgumentException, IHasScanDiagnostic
{
    public ScanInputException(ScanDiagnostic diagnostic, string? parameterName = null)
        : base(diagnostic?.Message, parameterName)
    {
        Diagnostic = diagnostic ?? throw new ArgumentNullException(nameof(diagnostic));
    }

    public ScanDiagnostic Diagnostic { get; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
