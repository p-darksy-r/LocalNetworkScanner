namespace LocalNetworkScanner.Core.Models;

public sealed class NetworkScanResult
{
    public required LocalNetworkInterface NetworkInterface { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required int AddressesScanned { get; init; }
    public required IReadOnlyList<NetworkDevice> Devices { get; init; }
    public SnmpTopologySnapshot? SnmpTopology { get; init; }
    public bool IsPartial { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = [];
    public TimeSpan Duration => CompletedAt - StartedAt;
}
