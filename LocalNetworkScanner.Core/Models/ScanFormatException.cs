// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

/// <summary>Falha de formato que mantém compatibilidade com consumidores de FormatException.</summary>
public sealed class ScanFormatException : FormatException, IHasScanDiagnostic
{
    public ScanFormatException(ScanDiagnostic diagnostic, Exception? innerException = null)
        : base(diagnostic?.Message, innerException)
    {
        Diagnostic = diagnostic ?? throw new ArgumentNullException(nameof(diagnostic));
    }

    public ScanDiagnostic Diagnostic { get; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
