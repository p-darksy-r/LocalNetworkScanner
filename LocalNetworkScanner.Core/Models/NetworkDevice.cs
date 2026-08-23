// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;

namespace LocalNetworkScanner.Core.Models;

public sealed class NetworkDevice
{
    public required IPAddress IpAddress { get; init; }

    public bool IsOnline { get; set; }

    public string? Alias { get; set; }

    public string? Notes { get; set; }

    public bool IsFavorite { get; set; }

    public long? ResponseTimeMs { get; set; }

    public int? ReplyTtl { get; set; }

    public string? Hostname { get; set; }

    public string? MacAddress { get; set; }

    public string? Manufacturer { get; set; }

    public string? MacAssignee { get; set; }

    public string? MacRegistry { get; set; }

    public string? MacAssignmentPrefix { get; set; }

    public string? Model { get; set; }

    public string? FriendlyName { get; set; }

    public string? SerialNumber { get; set; }

    public string? Firmware { get; set; }

    public string? HardwareRevision { get; set; }

    public string? IdentityDescription { get; set; }

    public ConfidenceLevel IdentityConfidence { get; set; }

    public List<DeviceIdentityEvidence> IdentityEvidence { get; set; } = [];

    public bool IsLocallyAdministeredMac { get; set; }

    public bool IsRandomizedMac
    {
        get => IsLocallyAdministeredMac;
        set => IsLocallyAdministeredMac = value;
    }

    public DiscoveryMethod DiscoveryMethods { get; set; }

    public List<PortScanResult> Ports { get; set; } = [];

    public List<string> MdnsNames { get; set; } = [];

    public List<MdnsServiceObservation> MdnsServices { get; set; } = [];

    public string? SsdpServer { get; set; }

    public string? SsdpLocation { get; set; }

    public string? SsdpServiceType { get; set; }

    public string? SsdpUniqueServiceName { get; set; }

    public string? SnmpDescription { get; set; }

    public string? SnmpObjectIdentifier { get; set; }

    public string? NmapSummary { get; set; }

    public string? NetBiosName { get; set; }

    public string? Workgroup { get; set; }

    public string? WsDiscoveryTypes { get; set; }

    public string? WsDiscoveryAddresses { get; set; }

    public string DeviceType { get; set; } = "Dispositivo de rede";

    public string OsGuess { get; set; } = "Indeterminado";

    public string RiskLevel { get; set; } = "Baixo";

    public int RiskScore { get; set; }

    public List<string> SecurityFindings { get; set; } = [];

    public List<string> ObservedProtocols { get; set; } = [];

    public TopologyAssessment Topology { get; set; } = new();

    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;

    public bool IsNew { get; set; }

    public bool HistoryCompared { get; set; }

    public List<string> Changes { get; set; } = [];

    public string IpAddressText => IpAddress.ToString();

    public string HostnameDisplay => string.IsNullOrWhiteSpace(Hostname) ? "—" : Hostname;

    public string MacDisplay => string.IsNullOrWhiteSpace(MacAddress) ? "—" : MacAddress;

    public string ManufacturerDisplay => string.IsNullOrWhiteSpace(Manufacturer) ? "Desconhecido" : Manufacturer;

    public string MacAssigneeDisplay => string.IsNullOrWhiteSpace(MacAssignee) ? "Desconhecido" : MacAssignee;

    public string ModelDisplay => string.IsNullOrWhiteSpace(Model) ? "Desconhecido" : Model;

    public string FriendlyNameDisplay => string.IsNullOrWhiteSpace(FriendlyName) ? "—" : FriendlyName;

    public string IdentityConfidenceDisplay => IdentityConfidence switch
    {
        ConfidenceLevel.High => "Alta",
        ConfidenceLevel.Medium => "Média",
        ConfidenceLevel.Low => "Baixa",
        _ => "Sem evidência"
    };

    public string ResponseTimeDisplay => ResponseTimeMs.HasValue ? $"{ResponseTimeMs.Value} ms" : "—";

    public string OpenPortsText => Ports.Count == 0
        ? "—"
        : string.Join(", ", Ports.OrderBy(port => port.Port).Select(port => $"{port.Port}/{port.Protocol.ToLowerInvariant()}"));

    public string DiscoveryText => DiscoveryMethods == DiscoveryMethod.None
        ? "—"
        : string.Join(" + ", Enum.GetValues<DiscoveryMethod>()
            .Where(method => method != DiscoveryMethod.None && DiscoveryMethods.HasFlag(method))
            .Select(method => method.ToString().ToUpperInvariant()));

    public string ProtocolsText => ObservedProtocols.Count == 0
        ? "—"
        : string.Join(", ", ObservedProtocols);

    public string TopologyText => Topology.Summary;

    public string HistoryText => !HistoryCompared
        ? "Não comparado"
        : IsNew
            ? "Novo"
            : Changes.Count > 0 ? "Alterado" : "Conhecido";

    public string IdentityDisplay => !string.IsNullOrWhiteSpace(Alias)
        ? Alias
        : !string.IsNullOrWhiteSpace(FriendlyName)
            ? FriendlyName
        : string.IsNullOrWhiteSpace(Hostname)
            ? string.IsNullOrWhiteSpace(NetBiosName) ? IpAddressText : NetBiosName
            : Hostname;
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
