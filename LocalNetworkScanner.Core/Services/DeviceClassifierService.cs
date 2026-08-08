// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class DeviceClassifierService
{
    public void Classify(NetworkDevice device, LocalNetworkInterface networkInterface)
    {
        HashSet<int> ports = device.Ports.Select(item => item.Port).ToHashSet();
        string searchable = $"{device.Hostname} {device.NetBiosName} {device.Manufacturer} " +
            $"{device.Model} {device.FriendlyName} {device.IdentityDescription} " +
            $"{device.SsdpServer} {device.SsdpServiceType} {device.WsDiscoveryTypes} " +
            $"{string.Join(' ', device.MdnsNames)} " +
            $"{string.Join(' ', device.Ports.Select(port => port.Banner))}";
        searchable = searchable.ToLowerInvariant();

        string inferredType = device.DiscoveryMethods.HasFlag(DiscoveryMethod.LocalHost)
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

        bool hasExplicitDeviceType = device.IdentityEvidence.Any(evidence =>
            evidence.Confidence >= ConfidenceLevel.Medium &&
            !string.IsNullOrWhiteSpace(evidence.DeviceType));
        if (!hasExplicitDeviceType ||
            device.DeviceType.Equals("Dispositivo de rede", StringComparison.Ordinal))
        {
            device.DeviceType = inferredType;
        }

        string inferredOperatingSystem = device.DiscoveryMethods.HasFlag(DiscoveryMethod.LocalHost)
            ? OperatingSystem.IsWindows() ? "Windows (host local)" : Environment.OSVersion.Platform.ToString()
            : device.ReplyTtl switch
            {
                null => "Indeterminado",
                <= 64 => "Possível Unix/Linux (heurística TTL)",
                <= 128 => "Possível Windows (heurística TTL)",
                _ => "Possível appliance de rede (heurística TTL)"
            };
        bool hasExplicitOperatingSystem = device.IdentityEvidence.Any(evidence =>
            evidence.Confidence >= ConfidenceLevel.Medium &&
            !string.IsNullOrWhiteSpace(evidence.OperatingSystem));
        if (!hasExplicitOperatingSystem || device.OsGuess.Equals("Indeterminado", StringComparison.Ordinal))
            device.OsGuess = inferredOperatingSystem;
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
