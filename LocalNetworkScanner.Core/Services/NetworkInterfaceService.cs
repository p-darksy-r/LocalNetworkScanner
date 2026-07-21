using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Globalization;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class NetworkInterfaceService
{
    private readonly WifiSignalService _wifiSignalService = new();
    private readonly VlanDetectionService _vlanDetectionService = new();

    public async Task<IReadOnlyList<LocalNetworkInterface>> GetActiveInterfacesAsync(
        CancellationToken cancellationToken = default)
    {
        List<(NetworkInterface Adapter, IPInterfaceProperties Properties)> candidates = [];

        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            try
            {
                candidates.Add((adapter, adapter.GetIPProperties()));
            }
            catch (NetworkInformationException)
            {
                // Interfaces virtuais podem desaparecer durante a enumeração.
            }
        }

        Task<IReadOnlyList<WifiConnectionInfo>> wifiTask =
            _wifiSignalService.GetConnectionsAsync(cancellationToken);
        Task<IReadOnlyDictionary<string, (int VlanId, ConfidenceLevel Confidence)>> vlanTask =
            _vlanDetectionService.DetectAsync(
                candidates.Select(item => (item.Adapter.Name, item.Adapter.Description)),
                cancellationToken);

        await Task.WhenAll(wifiTask, vlanTask);
        IReadOnlyList<WifiConnectionInfo> wifiConnections = await wifiTask;
        IReadOnlyDictionary<string, (int VlanId, ConfidenceLevel Confidence)> vlans = await vlanTask;

        List<LocalNetworkInterface> interfaces = [];
        foreach ((NetworkInterface adapter, IPInterfaceProperties properties) in candidates)
        {
            IPAddress? gateway = properties.GatewayAddresses
                .Select(item => item.Address)
                .FirstOrDefault(address =>
                    address.AddressFamily == AddressFamily.InterNetwork &&
                    !address.Equals(IPAddress.Any));

            WifiConnectionInfo? wifi = wifiConnections.FirstOrDefault(item =>
                string.Equals(item.Name, adapter.Name, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(item.Description, adapter.Description, StringComparison.OrdinalIgnoreCase));

            (long received, long sent) = GetStatistics(adapter);

            foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork ||
                    IPAddress.IsLoopback(unicast.Address) ||
                    unicast.IPv4Mask is null)
                {
                    continue;
                }

                vlans.TryGetValue(adapter.Name, out (int VlanId, ConfidenceLevel Confidence) vlan);
                interfaces.Add(new LocalNetworkInterface
                {
                    Id = adapter.Id,
                    Name = adapter.Name,
                    Description = adapter.Description,
                    IpAddress = unicast.Address,
                    SubnetMask = unicast.IPv4Mask,
                    GatewayAddress = gateway,
                    MacAddress = FormatMac(adapter.GetPhysicalAddress()),
                    InterfaceType = adapter.NetworkInterfaceType,
                    SpeedBitsPerSecond = adapter.Speed,
                    DnsAddresses = properties.DnsAddresses
                        .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
                        .ToList(),
                    SupportsMulticast = adapter.SupportsMulticast,
                    BytesReceived = received,
                    BytesSent = sent,
                    Ssid = wifi?.Ssid,
                    Bssid = wifi?.Bssid,
                    WifiSignalPercent = wifi?.SignalPercent,
                    WifiChannel = wifi?.Channel,
                    WifiRadioType = wifi?.RadioType,
                    VlanId = vlan.VlanId == 0 ? null : vlan.VlanId,
                    VlanConfidence = vlan.Confidence
                });
            }
        }

        return interfaces
            .OrderByDescending(item => item.GatewayAddress is not null)
            .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static (long Received, long Sent) GetStatistics(NetworkInterface adapter)
    {
        try
        {
            IPv4InterfaceStatistics statistics = adapter.GetIPv4Statistics();
            return (statistics.BytesReceived, statistics.BytesSent);
        }
        catch (NetworkInformationException)
        {
            return (0, 0);
        }
    }

    private static string FormatMac(PhysicalAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return bytes.Length == 0
            ? string.Empty
            : string.Join(":", bytes.Select(value => value.ToString("X2", CultureInfo.InvariantCulture)));
    }
}
