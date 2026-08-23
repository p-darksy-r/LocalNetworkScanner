// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

/// <summary>
/// Serviço DNS-SD correlacionado com um dispositivo a partir de PTR, SRV e A/AAAA.
/// </summary>
public sealed class MdnsServiceObservation
{
    public required string InstanceName { get; init; }
    public string? ServiceType { get; init; }
    public int? Port { get; init; }
    public string? Transport { get; init; }
    public string? Endpoint { get; init; }
    public required string EvidenceSource { get; init; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
