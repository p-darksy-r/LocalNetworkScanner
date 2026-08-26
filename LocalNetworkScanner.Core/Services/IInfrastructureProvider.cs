// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

/// <summary>
/// Contrato para integrações de leitura com controladores e switches.
/// Implementações devem ser somente leitura, exigir autorização explícita e
/// devolver apenas evidência que possam suportar.
/// </summary>
public interface IInfrastructureProvider
{
    InfrastructureProviderKind Kind { get; }

    string DisplayName { get; }

    Task<InfrastructureSnapshot> CollectAsync(
        LocalNetworkInterface networkInterface,
        IReadOnlyList<NetworkDevice> devices,
        CancellationToken cancellationToken = default);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
