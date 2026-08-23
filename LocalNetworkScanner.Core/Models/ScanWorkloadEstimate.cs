// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

public enum ScanWorkloadLevel
{
    Normal,
    High,
    Extreme
}

public sealed record ScanWorkloadEstimate
{
    public required int AddressCount { get; init; }

    public required int DiscoveryPortCount { get; init; }

    public required int FullPortCount { get; init; }

    public required long MaximumDiscoveryTcpAttempts { get; init; }

    public required long MaximumFullTcpAttempts { get; init; }

    public required long MaximumServiceProbeAttempts { get; init; }

    public required int MaximumUpnpDescriptionAttempts { get; init; }

    public required long MaximumBuiltInTcpAttempts { get; init; }

    public required bool HasAdditionalNmapTraffic { get; init; }

    public required ScanWorkloadLevel Level { get; init; }

    public bool RequiresExplicitConfirmation => Level != ScanWorkloadLevel.Normal;
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
