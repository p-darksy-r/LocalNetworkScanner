// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

public sealed class DeviceIdentityEvidence
{
    public required DiscoveryMethod Method { get; init; }
    public required string Source { get; init; }
    public ConfidenceLevel Confidence { get; init; }
    public string? Manufacturer { get; init; }
    public string? Model { get; init; }
    public string? FriendlyName { get; init; }
    public string? SerialNumber { get; init; }
    public string? Firmware { get; init; }
    public string? HardwareRevision { get; init; }
    public string? Description { get; init; }
    public string? DeviceType { get; init; }
    public string? OperatingSystem { get; init; }
    public string? Endpoint { get; init; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
