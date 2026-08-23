// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;

namespace LocalNetworkScanner.Core.Models;

public sealed class DiscoveryObservation
{
    public required IPAddress IpAddress { get; init; }
    public required DiscoveryMethod Method { get; init; }
    public string? Hostname { get; init; }
    public string? Server { get; init; }
    public string? Location { get; init; }
    public string? Manufacturer { get; init; }
    public string? Model { get; init; }
    public string? FriendlyName { get; init; }
    public string? SerialNumber { get; init; }
    public string? Description { get; init; }
    public string? DeviceType { get; init; }
    public string? OperatingSystem { get; init; }
    public string? ServiceType { get; init; }
    public int? ServicePort { get; init; }
    public string? ServiceTransport { get; init; }
    public string? UniqueServiceName { get; init; }
    public bool HasDirectAddressEvidence { get; init; }
    public string EvidenceSource { get; init; } = "Descoberta de rede";
    public ConfidenceLevel Confidence { get; init; } = ConfidenceLevel.Low;
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
