// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;

namespace LocalNetworkScanner.Core.Models;

public enum NmapDiscoveryStatus
{
    Success,
    Unavailable,
    Failed
}

public sealed class NmapDiscoveryResult
{
    public required NmapDiscoveryStatus Status { get; init; }

    public required string Message { get; init; }

    public IReadOnlyList<NmapHostObservation> Hosts { get; init; } = [];

    public bool IsSuccess => Status == NmapDiscoveryStatus.Success;
}

public sealed class NmapHostObservation
{
    public required IPAddress IpAddress { get; init; }

    public string State { get; init; } = "unknown";

    public string? Hostname { get; init; }

    public string? MacAddress { get; init; }

    public string? MacVendor { get; init; }

    public string? OperatingSystem { get; init; }

    public int? OperatingSystemAccuracy { get; init; }

    public IReadOnlyList<NmapPortObservation> Ports { get; init; } = [];
}

public sealed class NmapPortObservation
{
    public required int Port { get; init; }

    public string Protocol { get; init; } = "tcp";

    public string State { get; init; } = "unknown";

    public string? ServiceName { get; init; }

    public string? Product { get; init; }

    public string? Version { get; init; }

    public string? ExtraInfo { get; init; }

    public string? DeviceType { get; init; }

    public string? OperatingSystem { get; init; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
