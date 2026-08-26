// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

/// <summary>
/// Resultado de uma consulta opcional a um switch, access point ou controlador.
/// Uma snapshot vazia é válida e significa que não houve telemetria aplicável.
/// </summary>
public sealed class InfrastructureSnapshot
{
    public required InfrastructureProviderKind Provider { get; init; }

    public required string ProviderName { get; init; }

    public required DateTimeOffset CollectedAt { get; init; }

    public bool IsAvailable { get; init; }

    public IReadOnlyList<InfrastructureObservation> Observations { get; init; } = [];

    public IReadOnlyList<ScanDiagnostic> Diagnostics { get; init; } = [];
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
