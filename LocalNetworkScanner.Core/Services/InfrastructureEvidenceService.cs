// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

/// <summary>Aplica telemetria de infraestrutura sem substituir evidência mais forte.</summary>
public sealed class InfrastructureEvidenceService
{
    public void Apply(
        InfrastructureSnapshot snapshot,
        IReadOnlyList<NetworkDevice> devices)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(devices);

        Dictionary<IPAddress, NetworkDevice> byIp = devices
            .GroupBy(device => device.IpAddress)
            .ToDictionary(group => group.Key, group => group.First());
        Dictionary<string, NetworkDevice> byMac = devices
            .Select(device => (Device: device, Mac: NormalizeMac(device.MacAddress)))
            .Where(item => item.Mac is not null)
            .GroupBy(item => item.Mac!, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() == 1)
            .ToDictionary(group => group.Key, group => group.Single().Device,
                StringComparer.OrdinalIgnoreCase);

        foreach (InfrastructureObservation observation in snapshot.Observations)
        {
            NetworkDevice? device = FindDevice(observation, byIp, byMac);
            if (device is null)
                continue;

            device.DiscoveryMethods |= DiscoveryMethod.Infrastructure;
            device.InfrastructureEvidence.Add(observation);
            ApplyTopology(device, observation);
            ApplyWifi(device, observation);
        }
    }

    public static IReadOnlyList<InfrastructureObservation> FromSnmp(
        SnmpTopologySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        string source = $"SNMP FDB ({snapshot.SwitchName ?? snapshot.SwitchAddress.ToString()})";
        return snapshot.MacTable.Values
            .SelectMany(values => values)
            .Select(observation => new InfrastructureObservation
            {
                Provider = InfrastructureProviderKind.GenericSnmp,
                Source = source,
                MacAddress = observation.MacAddress,
                SwitchAddress = snapshot.SwitchAddress.ToString(),
                SwitchName = snapshot.SwitchName,
                SwitchPort = observation.BridgePort,
                SwitchInterface = observation.InterfaceName,
                VlanId = observation.VlanId,
                PortPvid = observation.PortPvid,
                Confidence = ConfidenceLevel.High,
                Evidence = "O switch devolveu uma entrada FDB SNMP para este MAC."
            })
            .ToArray();
    }

    private static NetworkDevice? FindDevice(
        InfrastructureObservation observation,
        IReadOnlyDictionary<IPAddress, NetworkDevice> byIp,
        IReadOnlyDictionary<string, NetworkDevice> byMac)
    {
        if (observation.IpAddress is not null &&
            byIp.TryGetValue(observation.IpAddress, out NetworkDevice? byAddress))
        {
            string? observedMac = NormalizeMac(observation.MacAddress);
            string? deviceMac = NormalizeMac(byAddress.MacAddress);
            return observedMac is not null &&
                   deviceMac is not null &&
                   !string.Equals(observedMac, deviceMac, StringComparison.OrdinalIgnoreCase)
                ? null
                : byAddress;
        }

        string? mac = NormalizeMac(observation.MacAddress);
        return mac is not null && byMac.TryGetValue(mac, out NetworkDevice? byAddressMac)
            ? byAddressMac
            : null;
    }

    private static void ApplyTopology(NetworkDevice device, InfrastructureObservation observation)
    {
        TopologyAssessment topology = device.Topology;
        if (!string.IsNullOrWhiteSpace(observation.SwitchAddress))
        {
            topology.SwitchAddress = observation.SwitchAddress;
            topology.ObservedOnManagedBridge = true;
        }
        topology.SwitchName ??= observation.SwitchName;
        topology.SwitchPort ??= observation.SwitchPort;
        topology.SwitchInterface ??= observation.SwitchInterface;
        topology.SwitchPortPvid ??= observation.PortPvid;
        if (observation.SwitchAddress is not null || observation.SwitchPort.HasValue)
            topology.SwitchConfidence = Max(topology.SwitchConfidence, observation.Confidence);

        if (observation.VlanId.HasValue &&
            (!topology.VlanId.HasValue || observation.Confidence >= topology.VlanConfidence))
        {
            topology.VlanId = observation.VlanId;
            topology.VlanConfidence = observation.Confidence;
        }

        string details = string.IsNullOrWhiteSpace(observation.Evidence)
            ? observation.Source
            : $"{observation.Source}: {observation.Evidence}";
        topology.SwitchEvidence = string.IsNullOrWhiteSpace(topology.SwitchEvidence)
            ? details
            : $"{topology.SwitchEvidence} {details}";
    }

    private static void ApplyWifi(NetworkDevice device, InfrastructureObservation observation)
    {
        device.WifiAccessPoint ??= observation.AccessPointName;
        device.WifiAccessPointMacAddress ??= NormalizeMac(observation.AccessPointMacAddress);
        device.WifiSignalDbm ??= observation.SignalDbm;
        device.WifiChannel ??= observation.WifiChannel;
        device.WifiRadio ??= observation.WifiRadio;
    }

    private static string? NormalizeMac(string? value) =>
        MacAddressService.TryNormalizeDeviceAddress(value, out string normalized)
            ? normalized
            : null;

    private static ConfidenceLevel Max(ConfidenceLevel first, ConfidenceLevel second) =>
        first >= second ? first : second;
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
