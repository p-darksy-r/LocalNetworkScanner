// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;

namespace LocalNetworkScanner.Core.Models;

public enum NetworkMapNodeKind
{
    NetworkSegment,
    LocalHost,
    Gateway,
    ManagedSwitch,
    Device,
    LldpNeighbor
}

public sealed class NetworkMapNode
{
    public required string Id { get; init; }

    public required NetworkMapNodeKind Kind { get; init; }

    public required string Label { get; init; }

    public string Subtitle { get; init; } = string.Empty;

    public IPAddress? IpAddress { get; init; }

    public string? MacAddress { get; init; }

    public string? DeviceType { get; init; }

    public int? VlanId { get; init; }

    public string RiskLevel { get; init; } = "Baixo";

    public bool IsOnline { get; init; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
