using System.Globalization;
using System.Net;
using System.Net.Sockets;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class NetworkTopologyMapService
{
    public NetworkMap Build(NetworkScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        LocalNetworkInterface network = result.NetworkInterface;
        string segmentId = CreateNodeId(NetworkMapNodeKind.NetworkSegment, network.NetworkCidr);
        string localId = CreateNodeId(NetworkMapNodeKind.LocalHost, network.IpAddress.ToString());
        Dictionary<string, NetworkMapNode> nodes = new(StringComparer.Ordinal);
        List<NetworkMapEdge> edges = [];
        List<string> warnings = [.. result.Warnings];

        AddNode(nodes, new NetworkMapNode
        {
            Id = segmentId,
            Kind = NetworkMapNodeKind.NetworkSegment,
            Label = network.NetworkCidr,
            Subtitle = network.Name,
            VlanId = network.VlanId,
            RiskLevel = "Baixo",
            IsOnline = true,
            DeviceType = "Segmento IP"
        });

        NetworkDevice? localDevice = FindDevice(result.Devices, network.IpAddress);
        AddNode(nodes, CreateHostNode(
            localId,
            NetworkMapNodeKind.LocalHost,
            localDevice,
            network.IpAddress,
            network.MacAddress,
            "Este computador",
            network.Name,
            network.VlanId));
        AddMembershipEdge(edges, segmentId, localId, network.NetworkCidr);

        string? gatewayId = null;
        if (network.GatewayAddress is not null)
        {
            gatewayId = CreateNodeId(
                NetworkMapNodeKind.Gateway,
                network.GatewayAddress.ToString());
            NetworkDevice? gatewayDevice = FindDevice(result.Devices, network.GatewayAddress);
            SnmpTopologySnapshot? gatewaySnapshot = result.SnmpTopology?.SwitchAddress.Equals(
                network.GatewayAddress) == true
                ? result.SnmpTopology
                : null;
            bool gatewayIsManagedSwitch = gatewaySnapshot is not null || result.Devices.Any(device =>
                device.Topology.ObservedOnManagedBridge &&
                IPAddress.TryParse(device.Topology.SwitchAddress, out IPAddress? switchAddress) &&
                switchAddress.Equals(network.GatewayAddress));
            AddNode(nodes, new NetworkMapNode
            {
                Id = gatewayId,
                Kind = NetworkMapNodeKind.Gateway,
                Label = FirstNonEmpty(
                    gatewayDevice?.IdentityDisplay,
                    gatewaySnapshot?.SwitchName,
                    "Gateway"),
                Subtitle = gatewayIsManagedSwitch
                    ? FirstNonEmpty(
                        gatewaySnapshot?.SwitchDescription,
                        "Gateway e switch gerido consultado por SNMP")
                    : "Rota predefinida da interface",
                IpAddress = network.GatewayAddress,
                MacAddress = gatewayDevice?.MacAddress,
                DeviceType = gatewayIsManagedSwitch
                    ? "Gateway / switch gerido"
                    : gatewayDevice?.DeviceType ?? "Gateway",
                VlanId = gatewayDevice?.Topology.VlanId,
                RiskLevel = gatewayDevice?.RiskLevel ?? "Baixo",
                IsOnline = gatewayDevice?.IsOnline ?? gatewaySnapshot is not null
            });
            AddMembershipEdgeIfApplicable(
                edges,
                segmentId,
                gatewayId,
                network.GatewayAddress,
                network);
            edges.Add(new NetworkMapEdge
            {
                SourceId = localId,
                TargetId = gatewayId,
                Kind = NetworkMapEdgeKind.DefaultRoute,
                Label = "Rota predefinida",
                Evidence = "Gateway configurado pelo sistema operativo para a interface selecionada; não confirma disponibilidade atual nem cablagem física.",
                Confidence = ConfidenceLevel.High
            });
        }

        Dictionary<IPAddress, string> switchNodeIds = BuildSwitchNodes(
            result,
            nodes,
            edges,
            segmentId,
            network,
            gatewayId);

        HashSet<IPAddress> roleAddresses = [network.IpAddress];
        if (network.GatewayAddress is not null)
            roleAddresses.Add(network.GatewayAddress);
        roleAddresses.UnionWith(switchNodeIds.Keys);

        Dictionary<IPAddress, string> deviceNodeIds = [];
        foreach (NetworkDevice device in result.Devices
                     .Where(device => !roleAddresses.Contains(device.IpAddress))
                     .OrderBy(device => IpAddressHelper.ToUInt32(device.IpAddress)))
        {
            string deviceId = CreateNodeId(
                NetworkMapNodeKind.Device,
                device.IpAddress.ToString());
            deviceNodeIds[device.IpAddress] = deviceId;
            AddNode(nodes, CreateHostNode(
                deviceId,
                NetworkMapNodeKind.Device,
                device,
                device.IpAddress,
                device.MacAddress,
                device.IdentityDisplay,
                BuildDeviceSubtitle(device),
                device.Topology.VlanId));
            AddMembershipEdgeIfApplicable(
                edges,
                segmentId,
                deviceId,
                device.IpAddress,
                network);
        }

        Dictionary<IPAddress, string> addressToNode = new(deviceNodeIds);
        addressToNode[network.IpAddress] = localId;
        if (network.GatewayAddress is not null && gatewayId is not null)
            addressToNode[network.GatewayAddress] = gatewayId;

        AddDeviceEvidenceEdges(
            result,
            addressToNode,
            switchNodeIds,
            localId,
            edges);
        AddLldpNeighbors(result.SnmpTopology, nodes, edges, switchNodeIds);

        AddWarning(warnings,
            "As ligações de pertença ao segmento representam endereçamento IP, não cablagem.");
        AddWarning(warnings,
            "ARP é evidência de resolução na camada 2, mas proxy ARP é possível e o switch físico permanece indeterminado.");
        AddWarning(warnings,
            "Uma FDB SNMP mostra onde um MAC foi aprendido; a porta pode ser acesso, uplink, trunk, AP ou bridge remota e não prova ligação física direta.");
        if (result.SnmpTopology is not null && result.SnmpTopology.LldpNeighbors.Count == 0)
        {
            AddWarning(warnings,
                "O switch consultado não devolveu vizinhos LLDP; a topologia física não é completada por inferência.");
        }
        if (result.IsPartial)
            AddWarning(warnings, "Mapa gerado a partir de um scan parcial.");

        return new NetworkMap
        {
            NetworkCidr = network.NetworkCidr,
            GeneratedAt = result.CompletedAt,
            Nodes = nodes.Values.ToArray(),
            Edges = edges,
            Warnings = warnings.Distinct(StringComparer.Ordinal).ToArray()
        };
    }

    public static string CreateNodeId(NetworkMapNodeKind kind, string identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);
        string prefix = kind switch
        {
            NetworkMapNodeKind.NetworkSegment => "segment",
            NetworkMapNodeKind.LocalHost => "local",
            NetworkMapNodeKind.Gateway => "gateway",
            NetworkMapNodeKind.ManagedSwitch => "switch",
            NetworkMapNodeKind.Device => "device",
            NetworkMapNodeKind.LldpNeighbor => "lldp",
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        return $"{prefix}:{identity.Trim()}";
    }

    private static Dictionary<IPAddress, string> BuildSwitchNodes(
        NetworkScanResult result,
        Dictionary<string, NetworkMapNode> nodes,
        List<NetworkMapEdge> edges,
        string segmentId,
        LocalNetworkInterface network,
        string? gatewayId)
    {
        Dictionary<IPAddress, string> switchIds = [];
        Dictionary<IPAddress, (string? Name, string? Description)> switches = [];
        if (result.SnmpTopology is not null)
        {
            switches[result.SnmpTopology.SwitchAddress] = (
                result.SnmpTopology.SwitchName,
                result.SnmpTopology.SwitchDescription);
        }

        foreach (NetworkDevice device in result.Devices)
        {
            if (!device.Topology.ObservedOnManagedBridge ||
                !IPAddress.TryParse(device.Topology.SwitchAddress, out IPAddress? address))
            {
                continue;
            }
            switches.TryAdd(address, (device.Topology.SwitchName, null));
        }

        foreach ((IPAddress address, (string? name, string? description)) in switches
                     .OrderBy(item => IpAddressHelper.ToUInt32(item.Key)))
        {
            if (network.GatewayAddress?.Equals(address) == true && gatewayId is not null)
            {
                switchIds[address] = gatewayId;
                continue;
            }

            string id = CreateNodeId(NetworkMapNodeKind.ManagedSwitch, address.ToString());
            switchIds[address] = id;
            NetworkDevice? switchDevice = FindDevice(result.Devices, address);
            AddNode(nodes, new NetworkMapNode
            {
                Id = id,
                Kind = NetworkMapNodeKind.ManagedSwitch,
                Label = FirstNonEmpty(name, switchDevice?.IdentityDisplay, address.ToString()),
                Subtitle = FirstNonEmpty(description, switchDevice?.DeviceType, "Switch consultado por SNMP"),
                IpAddress = address,
                MacAddress = switchDevice?.MacAddress,
                DeviceType = "Switch gerido",
                VlanId = switchDevice?.Topology.VlanId,
                RiskLevel = switchDevice?.RiskLevel ?? "Baixo",
                IsOnline = true
            });
            AddMembershipEdgeIfApplicable(edges, segmentId, id, address, network);
        }

        return switchIds;
    }

    private static void AddDeviceEvidenceEdges(
        NetworkScanResult result,
        IReadOnlyDictionary<IPAddress, string> addressToNode,
        IReadOnlyDictionary<IPAddress, string> switchNodeIds,
        string localId,
        List<NetworkMapEdge> edges)
    {
        foreach (NetworkDevice device in result.Devices)
        {
            if (!addressToNode.TryGetValue(device.IpAddress, out string? deviceId) ||
                deviceId == localId)
            {
                continue;
            }

            bool hasFdbEvidence = false;
            if (result.SnmpTopology is not null &&
                !string.IsNullOrWhiteSpace(device.MacAddress) &&
                result.SnmpTopology.MacTable.TryGetValue(
                    MacAddressService.Normalize(device.MacAddress),
                    out IReadOnlyList<SwitchPortObservation>? observations) &&
                switchNodeIds.TryGetValue(
                    result.SnmpTopology.SwitchAddress,
                    out string? queriedSwitchId))
            {
                foreach (SwitchPortObservation observation in observations
                             .Where(_ => queriedSwitchId != deviceId))
                {
                    hasFdbEvidence = true;
                    edges.Add(CreateFdbEdge(queriedSwitchId, deviceId, observation));
                }
            }
            else if (device.Topology.ObservedOnManagedBridge &&
                     IPAddress.TryParse(device.Topology.SwitchAddress, out IPAddress? switchAddress) &&
                     switchNodeIds.TryGetValue(switchAddress, out string? switchId))
            {
                hasFdbEvidence = true;
                edges.Add(new NetworkMapEdge
                {
                    SourceId = switchId,
                    TargetId = deviceId,
                    Kind = NetworkMapEdgeKind.MacLearned,
                    Label = FormatLearnedPort(
                        device.Topology.SwitchPort,
                        device.Topology.SwitchInterface),
                    Evidence = device.Topology.SwitchEvidence,
                    Confidence = device.Topology.SwitchConfidence
                });
            }

            bool arpObserved =
                device.DiscoveryMethods.HasFlag(DiscoveryMethod.Arp) &&
                !string.IsNullOrWhiteSpace(device.MacAddress);
            if (arpObserved)
            {
                edges.Add(new NetworkMapEdge
                {
                    SourceId = localId,
                    TargetId = deviceId,
                    Kind = NetworkMapEdgeKind.Layer2Observed,
                    Label = "ARP observado",
                    Evidence = "O endereço foi resolvido para um MAC na interface local. É compatível com alcance L2 direto, mas proxy ARP é possível e não identifica o switch físico.",
                    Confidence = ConfidenceLevel.Medium
                });
            }
            else if (!hasFdbEvidence && device.IsOnline)
            {
                edges.Add(new NetworkMapEdge
                {
                    SourceId = localId,
                    TargetId = deviceId,
                    Kind = NetworkMapEdgeKind.IpReachability,
                    Label = "Alcance IP inferido",
                    Evidence = $"O dispositivo respondeu através de {FormatDiscovery(device.DiscoveryMethods)}; o caminho, a VLAN e a ligação física não foram observados.",
                    Confidence = ConfidenceLevel.Low
                });
            }
        }
    }

    private static NetworkMapEdge CreateFdbEdge(
        string switchId,
        string deviceId,
        SwitchPortObservation observation)
    {
        string port = !string.IsNullOrWhiteSpace(observation.InterfaceName)
            ? observation.InterfaceName
            : $"porta lógica {observation.BridgePort.ToString(CultureInfo.InvariantCulture)}";
        string vlan = observation.VlanId.HasValue
            ? $", VLAN confirmada {observation.VlanId.Value.ToString(CultureInfo.InvariantCulture)}"
            : string.Empty;
        return new NetworkMapEdge
        {
            SourceId = switchId,
            TargetId = deviceId,
            Kind = NetworkMapEdgeKind.MacLearned,
            Label = $"MAC aprendido · {port}",
            Evidence = $"A FDB SNMP contém o MAC em {port}{vlan}. A entrada pode apontar para acesso, uplink, trunk, AP ou bridge remota; não prova ligação física direta.",
            Confidence = ConfidenceLevel.High
        };
    }

    private static void AddLldpNeighbors(
        SnmpTopologySnapshot? snapshot,
        Dictionary<string, NetworkMapNode> nodes,
        List<NetworkMapEdge> edges,
        IReadOnlyDictionary<IPAddress, string> switchNodeIds)
    {
        if (snapshot is null ||
            !switchNodeIds.TryGetValue(snapshot.SwitchAddress, out string? switchId))
        {
            return;
        }

        foreach (LldpNeighborObservation neighbor in snapshot.LldpNeighbors)
        {
            string identity = string.Join(":",
                snapshot.SwitchAddress,
                neighbor.TimeMark.ToString(CultureInfo.InvariantCulture),
                neighbor.LocalPortNumber.ToString(CultureInfo.InvariantCulture),
                neighbor.RemoteIndex.ToString(CultureInfo.InvariantCulture));
            string neighborId = CreateNodeId(NetworkMapNodeKind.LldpNeighbor, identity);
            string localPort = FirstNonEmpty(
                neighbor.LocalPortDescription,
                neighbor.LocalPortId,
                $"porta LLDP {neighbor.LocalPortNumber.ToString(CultureInfo.InvariantCulture)}");
            string remotePort = FirstNonEmpty(
                neighbor.PortDescription,
                neighbor.PortId,
                "porta remota não anunciada");
            AddNode(nodes, new NetworkMapNode
            {
                Id = neighborId,
                Kind = NetworkMapNodeKind.LldpNeighbor,
                Label = FirstNonEmpty(neighbor.SystemName, neighbor.ChassisId, "Vizinho LLDP"),
                Subtitle = $"{localPort} ↔ {remotePort}",
                MacAddress = IsMacAddress(neighbor.ChassisId) ? neighbor.ChassisId : null,
                DeviceType = "Vizinho LLDP",
                RiskLevel = "Baixo",
                IsOnline = true
            });
            edges.Add(new NetworkMapEdge
            {
                SourceId = switchId,
                TargetId = neighborId,
                Kind = NetworkMapEdgeKind.LldpNeighbor,
                Label = $"LLDP · {localPort}",
                Evidence = $"O agente LLDP do switch registou este anúncio na porta local {neighbor.LocalPortNumber.ToString(CultureInfo.InvariantCulture)} (timeMark {neighbor.TimeMark.ToString(CultureInfo.InvariantCulture)}, remIndex {neighbor.RemoteIndex.ToString(CultureInfo.InvariantCulture)}). Confirma a observação LLDP, não autentica a identidade anunciada.",
                Confidence = ConfidenceLevel.High
            });
        }
    }

    private static NetworkMapNode CreateHostNode(
        string id,
        NetworkMapNodeKind kind,
        NetworkDevice? device,
        IPAddress address,
        string? fallbackMac,
        string fallbackLabel,
        string fallbackSubtitle,
        int? vlanId) => new()
        {
            Id = id,
            Kind = kind,
            Label = FirstNonEmpty(device?.IdentityDisplay, fallbackLabel, address.ToString()),
            Subtitle = device is null ? fallbackSubtitle : BuildDeviceSubtitle(device),
            IpAddress = address,
            MacAddress = FirstNonEmptyOrNull(device?.MacAddress, fallbackMac),
            DeviceType = device?.DeviceType,
            VlanId = vlanId,
            RiskLevel = device?.RiskLevel ?? "Baixo",
            IsOnline = device?.IsOnline ?? kind == NetworkMapNodeKind.LocalHost
        };

    private static void AddMembershipEdge(
        List<NetworkMapEdge> edges,
        string segmentId,
        string targetId,
        string networkCidr) => edges.Add(new NetworkMapEdge
        {
            SourceId = segmentId,
            TargetId = targetId,
            Kind = NetworkMapEdgeKind.Contains,
            Label = "Endereço no segmento",
            Evidence = $"O endereço pertence matematicamente a {networkCidr}; isto não representa uma ligação física.",
            Confidence = ConfidenceLevel.High
        });

    private static void AddMembershipEdgeIfApplicable(
        List<NetworkMapEdge> edges,
        string segmentId,
        string targetId,
        IPAddress address,
        LocalNetworkInterface network)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork &&
            IpAddressHelper.IsInSameSubnet(address, network.IpAddress, network.SubnetMask))
        {
            AddMembershipEdge(edges, segmentId, targetId, network.NetworkCidr);
        }
    }

    private static string BuildDeviceSubtitle(NetworkDevice device)
    {
        List<string> parts = [device.IpAddress.ToString()];
        if (!string.IsNullOrWhiteSpace(device.DeviceType))
            parts.Add(device.DeviceType);
        if (!string.IsNullOrWhiteSpace(device.Manufacturer))
            parts.Add(device.Manufacturer);
        return string.Join(" · ", parts);
    }

    private static string FormatLearnedPort(int? bridgePort, string? interfaceName)
    {
        if (!string.IsNullOrWhiteSpace(interfaceName))
            return $"MAC aprendido · {interfaceName}";
        return bridgePort.HasValue
            ? $"MAC aprendido · porta lógica {bridgePort.Value.ToString(CultureInfo.InvariantCulture)}"
            : "MAC aprendido na FDB";
    }

    private static string FormatDiscovery(DiscoveryMethod methods)
    {
        string[] observed = Enum.GetValues<DiscoveryMethod>()
            .Where(method => method != DiscoveryMethod.None && methods.HasFlag(method))
            .Select(method => method.ToString().ToUpperInvariant())
            .ToArray();
        return observed.Length == 0 ? "uma observação de rede" : string.Join(" + ", observed);
    }

    private static bool IsMacAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        string candidate = value.Trim();
        if (candidate.Length == 12)
            return candidate.All(IsAsciiHexDigit);

        if (candidate.Length != 17)
            return false;
        char separator = candidate[2];
        if (separator is not (':' or '-'))
            return false;

        for (int index = 0; index < candidate.Length; index++)
        {
            if ((index + 1) % 3 == 0)
            {
                if (candidate[index] != separator)
                    return false;
            }
            else if (!IsAsciiHexDigit(candidate[index]))
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsAsciiHexDigit(char value) =>
        value is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f';

    private static NetworkDevice? FindDevice(
        IReadOnlyList<NetworkDevice> devices,
        IPAddress address) => devices.FirstOrDefault(device => device.IpAddress.Equals(address));

    private static void AddNode(
        Dictionary<string, NetworkMapNode> nodes,
        NetworkMapNode node) => nodes.TryAdd(node.Id, node);

    private static void AddWarning(List<string> warnings, string warning)
    {
        if (!warnings.Contains(warning, StringComparer.Ordinal))
            warnings.Add(warning);
    }

    private static string FirstNonEmpty(params string?[] values) =>
        values.First(value => !string.IsNullOrWhiteSpace(value))!;

    private static string? FirstNonEmptyOrNull(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
}
