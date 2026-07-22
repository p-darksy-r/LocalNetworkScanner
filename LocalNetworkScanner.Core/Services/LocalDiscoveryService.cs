// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class LocalDiscoveryService
{
    private readonly SsdpDiscoveryService _ssdp = new();
    private readonly MdnsDiscoveryService _mdns = new();
    private readonly WsDiscoveryService _wsDiscovery = new();

    public async Task<IReadOnlyList<DiscoveryObservation>> DiscoverAsync(
        int timeoutMs,
        CancellationToken cancellationToken)
        => await DiscoverAsync(timeoutMs, null, cancellationToken);

    public async Task<IReadOnlyList<DiscoveryObservation>> DiscoverAsync(
        int timeoutMs,
        System.Net.IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        Task<IReadOnlyList<DiscoveryObservation>> ssdpTask =
            _ssdp.DiscoverAsync(timeoutMs, localAddress, cancellationToken);
        Task<IReadOnlyList<DiscoveryObservation>> mdnsTask =
            _mdns.DiscoverAsync(timeoutMs, localAddress, cancellationToken);
        Task<IReadOnlyList<DiscoveryObservation>> wsDiscoveryTask =
            _wsDiscovery.DiscoverAsync(timeoutMs, localAddress, cancellationToken);

        await Task.WhenAll(ssdpTask, mdnsTask, wsDiscoveryTask);
        return (await ssdpTask)
            .Concat(await mdnsTask)
            .Concat(await wsDiscoveryTask)
            .ToList();
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
