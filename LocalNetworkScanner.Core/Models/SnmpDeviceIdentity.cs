// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;

namespace LocalNetworkScanner.Core.Models;

public enum SnmpDeviceIdentityStatus
{
    Unavailable,
    Available
}

public sealed class SnmpDeviceIdentity
{
    public required IPAddress IpAddress { get; init; }

    public required SnmpDeviceIdentityStatus Status { get; init; }

    public bool Success => Status == SnmpDeviceIdentityStatus.Available;

    public string? UnavailableReason { get; init; }

    public string? Manufacturer { get; init; }

    public string? Model { get; init; }

    public string? Name { get; init; }

    public string? SerialNumber { get; init; }

    public string? Description { get; init; }

    public string? OperatingSystemHint { get; init; }

    public string? SystemObjectIdentifier { get; init; }

    public int? EntityIndex { get; init; }

    public string? HardwareRevision { get; init; }

    public string? FirmwareRevision { get; init; }

    public string? SoftwareRevision { get; init; }

    public IReadOnlyDictionary<string, string> Oids { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public IReadOnlyList<string> Evidence { get; init; } = [];
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
