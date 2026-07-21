using System.Net;
using System.Net.NetworkInformation;

namespace LocalNetworkScanner.Core.Models;

public sealed class LocalNetworkInterface
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string Description { get; init; }

    public required IPAddress IpAddress { get; init; }

    public required IPAddress SubnetMask { get; init; }

    public IPAddress? GatewayAddress { get; init; }

    public required string MacAddress { get; init; }

    public required NetworkInterfaceType InterfaceType { get; init; }

    public long SpeedBitsPerSecond { get; init; }

    public IReadOnlyList<IPAddress> DnsAddresses { get; init; } = [];

    public bool SupportsMulticast { get; init; }

    public long BytesReceived { get; init; }

    public long BytesSent { get; init; }

    public string? Ssid { get; set; }

    public string? Bssid { get; set; }

    public int? WifiSignalPercent { get; set; }

    public int? WifiChannel { get; set; }

    public string? WifiRadioType { get; set; }

    public int? VlanId { get; set; }

    public ConfidenceLevel VlanConfidence { get; set; }

    public int PrefixLength => Utilities.IpAddressHelper.GetPrefixLength(SubnetMask);

    public bool IsWireless => InterfaceType == NetworkInterfaceType.Wireless80211;

    public double SpeedMbps => SpeedBitsPerSecond <= 0 ? 0 : SpeedBitsPerSecond / 1_000_000d;

    public string NetworkCidr => $"{Utilities.IpAddressHelper.GetNetworkAddress(IpAddress, SubnetMask)}/{PrefixLength}";

    public string DisplayName => $"{Name} — {IpAddress}/{PrefixLength}";

    public string WifiSummary => !IsWireless
        ? "Ligação por cabo/virtual"
        : WifiSignalPercent.HasValue
            ? $"{Ssid ?? "Wi-Fi"} · {WifiSignalPercent}% · canal {WifiChannel?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "?"}"
            : $"{Ssid ?? "Wi-Fi"} · sinal indisponível";

    public override string ToString() => DisplayName;
}
