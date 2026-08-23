// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Core.Utilities;
using LocalNetworkScanner.Wpf.Infrastructure;
using System.Globalization;

namespace LocalNetworkScanner.Wpf.ViewModels;

public sealed class DeviceRowViewModel : ObservableObject
{
    private NetworkDevice _device;
    private bool _isAliasDirty;
    private bool _isNotesDirty;
    private bool _isFavoriteDirty;

    public DeviceRowViewModel(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        _device = device;
    }

    public NetworkDevice Device => _device;

    public string StatusText => _device.IsOnline ? "Online" : "Offline";
    public string IpAddress => _device.IpAddressText;
    public uint IpSortKey => IpAddressHelper.ToUInt32(_device.IpAddress);
    public string Hostname => _device.IdentityDisplay;
    public string HostnameTechnical => _device.HostnameDisplay;
    public string NetBiosName => string.IsNullOrWhiteSpace(_device.NetBiosName) ? "—" : _device.NetBiosName;
    public string Workgroup => string.IsNullOrWhiteSpace(_device.Workgroup) ? "—" : _device.Workgroup;
    public string WsDiscovery => string.IsNullOrWhiteSpace(_device.WsDiscoveryTypes)
        ? "—"
        : _device.WsDiscoveryTypes;
    public string MacAddress => _device.MacDisplay;
    public string Manufacturer => _device.ManufacturerDisplay;
    public string MacAssignee => _device.MacAssigneeDisplay;
    public string MacAssignment => BuildMacAssignment();
    public string Model => _device.ModelDisplay;
    public string FriendlyName => ValueOrDash(_device.FriendlyName);
    public string SerialNumber => ValueOrDash(_device.SerialNumber);
    public string Firmware => ValueOrDash(_device.Firmware);
    public string HardwareRevision => ValueOrDash(_device.HardwareRevision);
    public string IdentityDescription => ValueOrDash(_device.IdentityDescription);
    public string IdentityConfidence => _device.IdentityConfidenceDisplay;
    public string SsdpServiceType => ValueOrDash(_device.SsdpServiceType);
    public string SsdpUniqueServiceName => ValueOrDash(_device.SsdpUniqueServiceName);
    public string SsdpEndpoint => BuildEndpoint(_device.SsdpServer, _device.SsdpLocation);
    public string MdnsServiceSummary => BuildMdnsServiceSummary(_device.MdnsServices);
    public string MdnsServiceSearchText => BuildMdnsServiceSearchText(_device.MdnsServices);
    public string SnmpIdentity => BuildEndpoint(_device.SnmpDescription, _device.SnmpObjectIdentifier);
    public string NmapIdentity => ValueOrDash(_device.NmapSummary);
    public string ResponseTime => _device.ResponseTimeDisplay;
    public long ResponseTimeSortKey => _device.ResponseTimeMs ?? long.MaxValue;
    public string DeviceType => _device.DeviceType;
    public string OsGuess => _device.OsGuess;
    public string RiskLevel => _device.RiskLevel;
    public string RiskDisplay => $"{_device.RiskLevel} · {_device.RiskScore}/100";
    public int RiskScore => _device.RiskScore;
    public string Discovery => _device.DiscoveryText;
    public string Protocols => _device.ProtocolsText;
    public string OpenPorts => _device.OpenPortsText;
    public int OpenPortCount => _device.Ports.Count;
    public string Topology => _device.TopologyText;
    public string History => _device.HistoryText;
    public string ReplyTtl => _device.ReplyTtl?.ToString(CultureInfo.CurrentCulture) ?? "—";
    public string FirstSeen => _device.FirstSeen.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);
    public string LastSeen => _device.LastSeen.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);
    public string Vlan => _device.Topology.VlanId.HasValue
        ? $"VLAN {_device.Topology.VlanId}"
        : _device.Topology.SwitchPortPvid.HasValue
            ? $"VLAN não confirmada · PVID da porta {_device.Topology.SwitchPortPvid} (apenas referência)"
            : "VLAN não confirmada";
    public string Layer2 => _device.Topology.SameLayer2Segment switch
    {
        true => "Mesmo segmento L2",
        false => "Segmento L2 diferente",
        null => "Segmento L2 indeterminado"
    };
    public string SameSwitch => _device.Topology.SamePhysicalSwitch switch
    {
        true => "Mesmo switch físico",
        false => "Switch físico diferente",
        null => _device.Topology.ObservedOnManagedBridge
            ? "MAC observado na FDB do switch; ligação física não confirmada"
            : "Switch físico indeterminado"
    };
    public string Layer2Confidence => ConfidenceToText(_device.Topology.Layer2Confidence);
    public string VlanConfidence => ConfidenceToText(_device.Topology.VlanConfidence);
    public string SwitchEvidence => _device.Topology.SwitchEvidence;
    public string RandomizedMac => _device.IsRandomizedMac ? "Sim" : "Não";

    public IReadOnlyList<PortScanResult> Ports => _device.Ports;
    public IReadOnlyList<string> SecurityFindings => _device.SecurityFindings;
    public IReadOnlyList<string> Changes => _device.Changes;
    public IReadOnlyList<string> MdnsNames => _device.MdnsNames;
    public IReadOnlyList<string> IdentityEvidenceLines => _device.IdentityEvidence
        .OrderByDescending(evidence => evidence.Confidence)
        .ThenBy(evidence => evidence.Source, StringComparer.CurrentCultureIgnoreCase)
        .Select(BuildIdentityEvidenceLine)
        .ToArray();

    public string IdentitySearchText => string.Join(' ', IdentityEvidenceLines);

    public bool IsOnline => _device.IsOnline;
    public bool IsNew => _device.IsNew;
    public bool IsMetadataDirty => _isAliasDirty || _isNotesDirty || _isFavoriteDirty;

    public bool IsFavorite
    {
        get => _device.IsFavorite;
        set
        {
            if (_device.IsFavorite == value)
                return;

            _device.IsFavorite = value;
            MarkMetadataDirty(ref _isFavoriteDirty);
            OnPropertyChanged();
        }
    }

    public string Alias
    {
        get => _device.Alias ?? string.Empty;
        set
        {
            if (string.Equals(_device.Alias, value, StringComparison.Ordinal))
                return;

            _device.Alias = value;
            MarkMetadataDirty(ref _isAliasDirty);
            OnPropertyChanged();
            OnPropertyChanged(nameof(Hostname));
        }
    }

    public string Notes
    {
        get => _device.Notes ?? string.Empty;
        set
        {
            if (string.Equals(_device.Notes, value, StringComparison.Ordinal))
                return;

            _device.Notes = value;
            MarkMetadataDirty(ref _isNotesDirty);
            OnPropertyChanged();
        }
    }
    public bool HasSecurityFindings => _device.SecurityFindings.Count > 0;
    public bool HasChanges => _device.Changes.Count > 0;
    public bool HasPorts => _device.Ports.Count > 0;
    public bool HasIdentityEvidence => _device.IdentityEvidence.Count > 0;
    public bool HasMacAddress => MacAddressService.TryNormalizeDeviceAddress(_device.MacAddress, out _);
    public bool CanOpenWeb => _device.Ports.Any(item => ServiceCatalog.IsHttpPort(item.Port));
    public bool CanOpenExplorer => _device.Ports.Any(item => item.Port is 139 or 445);
    public bool CanOpenRemoteDesktop => _device.Ports.Any(item => item.Port == 3389);

    public void Update(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);

        if (_isAliasDirty)
            device.Alias = _device.Alias;
        if (_isNotesDirty)
            device.Notes = _device.Notes;
        if (_isFavoriteDirty)
            device.IsFavorite = _device.IsFavorite;

        _device = device;
        OnAllPropertiesChanged();
    }

    public void MarkMetadataSaved()
    {
        if (!IsMetadataDirty)
            return;

        _isAliasDirty = false;
        _isNotesDirty = false;
        _isFavoriteDirty = false;
        OnPropertyChanged(nameof(IsMetadataDirty));
    }

    private void MarkMetadataDirty(ref bool field)
    {
        bool wasDirty = IsMetadataDirty;
        field = true;
        if (!wasDirty)
            OnPropertyChanged(nameof(IsMetadataDirty));
    }

    private static string ConfidenceToText(ConfidenceLevel confidence) => confidence switch
    {
        ConfidenceLevel.High => "Confiança alta",
        ConfidenceLevel.Medium => "Confiança média",
        ConfidenceLevel.Low => "Confiança baixa",
        _ => "Sem evidência suficiente"
    };

    private string BuildMacAssignment()
    {
        List<string> parts = [];
        if (!string.IsNullOrWhiteSpace(_device.MacRegistry))
            parts.Add(_device.MacRegistry);
        if (!string.IsNullOrWhiteSpace(_device.MacAssignmentPrefix))
            parts.Add($"prefixo {_device.MacAssignmentPrefix}");

        return parts.Count == 0 ? "—" : string.Join(" · ", parts);
    }

    private static string BuildEndpoint(string? primary, string? secondary)
    {
        if (string.IsNullOrWhiteSpace(primary))
            return ValueOrDash(secondary);
        if (string.IsNullOrWhiteSpace(secondary) ||
            string.Equals(primary, secondary, StringComparison.OrdinalIgnoreCase))
        {
            return primary;
        }

        return $"{primary} · {secondary}";
    }

    private static string BuildMdnsServiceSummary(
        IReadOnlyList<MdnsServiceObservation> services)
    {
        if (services.Count == 0)
            return "—";

        const int maximumVisibleServices = 8;
        IEnumerable<string> visible = services
            .Take(maximumVisibleServices)
            .Select(service =>
            {
                List<string> parts = [service.InstanceName];
                if (!string.IsNullOrWhiteSpace(service.ServiceType))
                    parts.Add(service.ServiceType);
                if (!string.IsNullOrWhiteSpace(service.Endpoint))
                    parts.Add(service.Endpoint);
                else if (service.Port.HasValue)
                    parts.Add(string.IsNullOrWhiteSpace(service.Transport)
                        ? service.Port.Value.ToString(CultureInfo.InvariantCulture)
                        : $"{service.Transport}/{service.Port.Value.ToString(CultureInfo.InvariantCulture)}");
                return string.Join(" · ", parts);
            });

        string summary = string.Join(Environment.NewLine, visible);
        return services.Count <= maximumVisibleServices
            ? summary
            : $"{summary}{Environment.NewLine}+{services.Count - maximumVisibleServices:N0} serviços";
    }

    private static string BuildMdnsServiceSearchText(
        IReadOnlyList<MdnsServiceObservation> services) => string.Join(
            ' ',
            services.SelectMany(service => new[]
            {
                service.InstanceName,
                service.ServiceType,
                service.Port?.ToString(CultureInfo.InvariantCulture),
                service.Transport,
                service.Endpoint,
                service.EvidenceSource
            }).Where(value => !string.IsNullOrWhiteSpace(value)));

    private static string BuildIdentityEvidenceLine(DeviceIdentityEvidence evidence)
    {
        List<string> details = [];
        AddEvidenceDetail(details, "fabricante", evidence.Manufacturer);
        AddEvidenceDetail(details, "modelo", evidence.Model);
        AddEvidenceDetail(details, "nome", evidence.FriendlyName);
        AddEvidenceDetail(details, "série", evidence.SerialNumber);
        AddEvidenceDetail(details, "firmware", evidence.Firmware);
        AddEvidenceDetail(details, "hardware", evidence.HardwareRevision);
        AddEvidenceDetail(details, "descrição", evidence.Description);
        AddEvidenceDetail(details, "tipo", evidence.DeviceType);
        AddEvidenceDetail(details, "SO", evidence.OperatingSystem);
        AddEvidenceDetail(details, "origem", evidence.Endpoint);

        string heading = $"{evidence.Source} · {MethodToText(evidence.Method)} · " +
            ConfidenceToText(evidence.Confidence);
        return details.Count == 0
            ? heading
            : $"{heading}: {string.Join(" · ", details)}";
    }

    private static void AddEvidenceDetail(List<string> details, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            details.Add($"{label}: {value}");
    }

    private static string MethodToText(DiscoveryMethod method) => method switch
    {
        DiscoveryMethod.Icmp => "ICMP",
        DiscoveryMethod.Tcp => "TCP",
        DiscoveryMethod.Arp => "ARP/IEEE",
        DiscoveryMethod.Mdns => "mDNS/DNS-SD",
        DiscoveryMethod.Ssdp => "SSDP/UPnP",
        DiscoveryMethod.NetBios => "NetBIOS",
        DiscoveryMethod.WsDiscovery => "WS-Discovery",
        DiscoveryMethod.Snmp => "SNMP",
        DiscoveryMethod.Nmap => "Nmap",
        DiscoveryMethod.LocalHost => "Windows local",
        _ => method.ToString()
    };

    private static string ValueOrDash(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "—" : value;
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
