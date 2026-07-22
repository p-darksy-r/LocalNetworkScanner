// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

/// <summary>
/// Falha de limite numérico que preserva compatibilidade com ArgumentOutOfRangeException.
/// </summary>
public sealed class ScanRangeException : ArgumentOutOfRangeException, IHasScanDiagnostic
{
    public ScanRangeException(
        ScanDiagnostic diagnostic,
        string? parameterName = null,
        object? actualValue = null)
        : base(parameterName, actualValue, diagnostic?.Message)
    {
        Diagnostic = diagnostic ?? throw new ArgumentNullException(nameof(diagnostic));
    }

    public ScanDiagnostic Diagnostic { get; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
