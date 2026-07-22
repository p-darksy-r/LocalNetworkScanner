// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

/// <summary>Expõe um diagnóstico estruturado sem obrigar todas as falhas à mesma hierarquia.</summary>
public interface IHasScanDiagnostic
{
    ScanDiagnostic Diagnostic { get; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
