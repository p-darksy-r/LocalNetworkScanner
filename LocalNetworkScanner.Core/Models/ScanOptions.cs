// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

using System.Net;

public sealed class ScanOptions
{
    public ScanProfile Profile { get; init; } = ScanProfile.Standard;
    public int MaximumHostConcurrency { get; init; } = 96;
    public int MaximumPortConcurrency { get; init; } = 48;
    public int PingTimeoutMs { get; init; } = 550;
    public int ConnectTimeoutMs { get; init; } = 350;
    public int DiscoveryTimeoutMs { get; init; } = 1_200;
    public bool EnableIcmp { get; init; } = true;
    public bool EnableTcpDiscovery { get; init; } = true;
    public bool EnableArp { get; init; } = true;
    public bool EnableMulticastDiscovery { get; init; } = true;
    public bool EnableUpnpDescription { get; init; } = true;
    public bool EnableNetBiosDiscovery { get; init; } = true;
    public bool EnableSnmpDeviceDiscovery { get; init; }
    public bool EnableSnmpTopology { get; init; }
    public IPAddress? SnmpSwitchAddress { get; init; }
    public string? SnmpCommunity { get; init; }
    public int SnmpTimeoutMs { get; init; } = 900;
    public bool EnableNmapDiscovery { get; init; }
    public string? NmapExecutablePath { get; init; }
    public int NmapTimeoutMs { get; init; } = 120_000;
    public bool EnableServiceProbes { get; init; } = true;
    public IReadOnlyList<int> Ports { get; init; } = Services.ServiceCatalog.StandardPorts;
    public IReadOnlyList<int> DiscoveryPorts { get; init; } = Services.ServiceCatalog.DiscoveryPorts;

    public static ScanOptions ForProfile(ScanProfile profile)
    {
        return profile switch
        {
            ScanProfile.Quick => new ScanOptions
            {
                Profile = profile,
                PingTimeoutMs = 350,
                ConnectTimeoutMs = 250,
                DiscoveryTimeoutMs = 800,
                EnableUpnpDescription = false,
                EnableNetBiosDiscovery = false,
                EnableServiceProbes = false,
                Ports = Services.ServiceCatalog.QuickPorts
            },
            ScanProfile.Deep => new ScanOptions
            {
                Profile = profile,
                MaximumHostConcurrency = 64,
                MaximumPortConcurrency = 64,
                PingTimeoutMs = 750,
                ConnectTimeoutMs = 500,
                DiscoveryTimeoutMs = 1_800,
                Ports = Services.ServiceCatalog.DeepPorts
            },
            _ => new ScanOptions { Profile = ScanProfile.Standard }
        };
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
