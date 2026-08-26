// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

public sealed class NetworkScanResult
{
    public required LocalNetworkInterface NetworkInterface { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required int AddressesScanned { get; init; }
    public required IReadOnlyList<NetworkDevice> Devices { get; init; }
    public SnmpTopologySnapshot? SnmpTopology { get; init; }
    public InfrastructureSnapshot? Infrastructure { get; init; }
    public bool IsPartial { get; init; }
    public IReadOnlyList<ScanDiagnostic> Diagnostics { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
    public TimeSpan Duration => CompletedAt - StartedAt;

    public NetworkScanResult WithAdditionalDiagnostic(ScanDiagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        return new NetworkScanResult
        {
            NetworkInterface = NetworkInterface,
            StartedAt = StartedAt,
            CompletedAt = CompletedAt,
            AddressesScanned = AddressesScanned,
            Devices = Devices,
            SnmpTopology = SnmpTopology,
            Infrastructure = Infrastructure,
            IsPartial = IsPartial,
            Diagnostics = Diagnostics.Append(diagnostic).ToArray(),
            Warnings = Warnings
        };
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
