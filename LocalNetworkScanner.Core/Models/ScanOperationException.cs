// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

/// <summary>Falha operacional que mantém compatibilidade com InvalidOperationException.</summary>
public sealed class ScanOperationException : InvalidOperationException, IHasScanDiagnostic
{
    public ScanOperationException(ScanDiagnostic diagnostic, Exception? innerException = null)
        : base(diagnostic?.Message, innerException)
    {
        Diagnostic = diagnostic ?? throw new ArgumentNullException(nameof(diagnostic));
    }

    public ScanDiagnostic Diagnostic { get; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
