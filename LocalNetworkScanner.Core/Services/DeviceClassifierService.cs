using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class DeviceClassifierService
{
    public void Classify(NetworkDevice device, LocalNetworkInterface networkInterface)
    {
        HashSet<int> ports = device.Ports.Select(item => item.Port).ToHashSet();
        string searchable = $"{device.Hostname} {device.NetBiosName} {device.Manufacturer} " +
            $"{device.SsdpServer} {device.WsDiscoveryTypes}";
        searchable = searchable.ToLowerInvariant();

        device.DeviceType = device.DiscoveryMethods.HasFlag(DiscoveryMethod.LocalHost)
            ? "Este computador"
            : device.IpAddress.Equals(networkInterface.GatewayAddress)
                ? "Gateway / router"
            : ports.Contains(9100) || ports.Contains(631) || searchable.Contains("printer")
                ? "Impressora"
                : ports.Contains(554) || searchable.Contains("camera")
                    ? "Câmara / vídeo IP"
                    : ports.Contains(32400)
                        ? "Servidor multimédia"
                        : ports.Contains(445) && (ports.Contains(2049) || ports.Contains(548))
                            ? "NAS / armazenamento"
                            : ports.Contains(3389) || ports.Contains(5985) || ports.Contains(5986) ||
                              !string.IsNullOrWhiteSpace(device.NetBiosName)
                                ? "Computador Windows"
                                : ports.Contains(22) && (ports.Contains(80) || ports.Contains(443))
                                    ? "Servidor / appliance"
                                    : ports.Contains(1883) || ports.Contains(8883) || searchable.Contains("esp")
                                        ? "IoT / automação"
                                        : ports.Any(ServiceCatalog.IsHttpPort)
                                            ? "Dispositivo com interface Web"
                                            : "Dispositivo de rede";

        device.OsGuess = device.DiscoveryMethods.HasFlag(DiscoveryMethod.LocalHost)
            ? OperatingSystem.IsWindows() ? "Windows (host local)" : Environment.OSVersion.Platform.ToString()
            : device.ReplyTtl switch
            {
                null => "Indeterminado",
                <= 64 => "Possível Unix/Linux (heurística TTL)",
                <= 128 => "Possível Windows (heurística TTL)",
                _ => "Possível appliance de rede (heurística TTL)"
            };
    }
}
