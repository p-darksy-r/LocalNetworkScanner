// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Wpf.Infrastructure;
using System.Globalization;

namespace LocalNetworkScanner.Wpf.ViewModels;

public sealed class DeviceRowViewModel : ObservableObject
{
    private NetworkDevice _device;

    public DeviceRowViewModel(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        _device = device;
    }

    public NetworkDevice Device => _device;

    public string StatusText => _device.IsOnline ? "Online" : "Offline";
    public string IpAddress => _device.IpAddressText;
    public string Hostname => _device.IdentityDisplay;
    public string HostnameTechnical => _device.HostnameDisplay;
    public string NetBiosName => string.IsNullOrWhiteSpace(_device.NetBiosName) ? "—" : _device.NetBiosName;
    public string Workgroup => string.IsNullOrWhiteSpace(_device.Workgroup) ? "—" : _device.Workgroup;
    public string WsDiscovery => string.IsNullOrWhiteSpace(_device.WsDiscoveryTypes)
        ? "—"
        : _device.WsDiscoveryTypes;
    public string MacAddress => _device.MacDisplay;
    public string Manufacturer => _device.ManufacturerDisplay;
    public string ResponseTime => _device.ResponseTimeDisplay;
    public string DeviceType => _device.DeviceType;
    public string OsGuess => _device.OsGuess;
    public string RiskLevel => _device.RiskLevel;
    public string RiskDisplay => $"{_device.RiskLevel} · {_device.RiskScore}/100";
    public int RiskScore => _device.RiskScore;
    public string Discovery => _device.DiscoveryText;
    public string Protocols => _device.ProtocolsText;
    public string OpenPorts => _device.OpenPortsText;
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

    public bool IsOnline => _device.IsOnline;
    public bool IsNew => _device.IsNew;
    public bool IsFavorite
    {
        get => _device.IsFavorite;
        set
        {
            if (_device.IsFavorite == value)
                return;

            _device.IsFavorite = value;
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
            OnPropertyChanged();
        }
    }
    public bool HasSecurityFindings => _device.SecurityFindings.Count > 0;
    public bool HasChanges => _device.Changes.Count > 0;
    public bool HasPorts => _device.Ports.Count > 0;
    public bool HasMacAddress => MacAddressService.TryNormalizeDeviceAddress(_device.MacAddress, out _);
    public bool CanOpenWeb => _device.Ports.Any(item => ServiceCatalog.IsHttpPort(item.Port));
    public bool CanOpenExplorer => _device.Ports.Any(item => item.Port is 139 or 445);
    public bool CanOpenRemoteDesktop => _device.Ports.Any(item => item.Port == 3389);

    public void Update(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        _device = device;
        OnAllPropertiesChanged();
    }

    private static string ConfidenceToText(ConfidenceLevel confidence) => confidence switch
    {
        ConfidenceLevel.High => "Confiança alta",
        ConfidenceLevel.Medium => "Confiança média",
        ConfidenceLevel.Low => "Confiança baixa",
        _ => "Sem evidência suficiente"
    };
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
