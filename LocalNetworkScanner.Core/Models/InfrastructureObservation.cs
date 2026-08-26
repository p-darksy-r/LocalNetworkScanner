// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;

namespace LocalNetworkScanner.Core.Models;

/// <summary>
/// Evidência de infraestrutura associada a um dispositivo. Os valores são
/// telemetria do controlador/switch e não uma afirmação de ligação física sem
/// a confiança correspondente.
/// </summary>
public sealed class InfrastructureObservation
{
    public required InfrastructureProviderKind Provider { get; init; }

    public required string Source { get; init; }

    public IPAddress? IpAddress { get; init; }

    public string? MacAddress { get; init; }

    public string? SwitchAddress { get; init; }

    public string? SwitchName { get; init; }

    public int? SwitchPort { get; init; }

    public string? SwitchInterface { get; init; }

    public int? VlanId { get; init; }

    public int? PortPvid { get; init; }

    public string? AccessPointName { get; init; }

    public string? AccessPointMacAddress { get; init; }

    public int? SignalDbm { get; init; }

    public int? WifiChannel { get; init; }

    public string? WifiRadio { get; init; }

    public ConfidenceLevel Confidence { get; init; } = ConfidenceLevel.Unknown;

    public string Evidence { get; init; } = string.Empty;
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
