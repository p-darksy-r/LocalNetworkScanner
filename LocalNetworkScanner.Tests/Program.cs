// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Formats.Asn1;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using System.Windows;
using System.Windows.Controls;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Core.Utilities;
using LocalNetworkScanner.Wpf;
using LocalNetworkScanner.Wpf.Controls;
using LocalNetworkScanner.Wpf.ViewModels;

List<(string Name, Func<Task> Run)> tests =
[
    ("IPv4 round-trip", () => Sync(() =>
    {
        IPAddress address = IPAddress.Parse("192.168.42.17");
        Equal(address, IpAddressHelper.FromUInt32(IpAddressHelper.ToUInt32(address)));
    })),
    ("CIDR and subnet", () => Sync(() =>
    {
        (IPAddress address, int prefix) = IpAddressHelper.ParseCidr("192.168.42.123/24");
        Equal(IPAddress.Parse("192.168.42.123"), address);
        Equal(24, prefix);
        Equal(IPAddress.Parse("192.168.42.0"),
            IpAddressHelper.GetNetworkAddress(address, IpAddressHelper.PrefixToMask(prefix)));
    })),
    ("Usable range", () => Sync(() =>
    {
        IReadOnlyList<IPAddress> range = new IpRangeService().GenerateFromCidr("10.4.0.0/30");
        Equal(2, range.Count);
        Equal("10.4.0.1", range[0].ToString());
        Equal("10.4.0.2", range[1].ToString());
        Throws<ArgumentOutOfRangeException>(() =>
            new IpRangeService().GenerateFromCidr("10.4.0.0/30", maximumAddresses: 0));
    })),
    ("Public target rejected", () => Sync(() =>
    {
        Throws<InvalidOperationException>(() =>
            ScanRequestValidator.Validate([IPAddress.Parse("8.8.8.8")], ScanOptions.ForProfile(ScanProfile.Quick)));
    })),
    ("Port specification", () => Sync(() =>
    {
        Equal("22,80,81,82,443", string.Join(',', ServiceCatalog.ParsePortSpecification("443,80-82,22")));
        Throws<FormatException>(() => ServiceCatalog.ParsePortSpecification("0,70000"));
    })),
    ("Diagnostic contract and sanitization", () => Sync(() =>
    {
        ScanDiagnostic diagnostic = new(
            "lns-dev-099",
            DiagnosticCategory.Device,
            DiagnosticSeverity.Warning,
            "MAC inválido\nrecebido",
            "Confirma a tabela ARP.",
            "192.168.1.20",
            new Dictionary<string, string>
            {
                ["mac"] = "00:11:22:33:44:55",
                ["community"] = "private-value",
                ["password"] = "private-value",
                ["token"] = "private-value"
            });

        Equal("LNS-DEV-099", diagnostic.Code);
        Equal("MAC inválido recebido", diagnostic.Message);
        Equal(1, diagnostic.Context.Count);
        Equal("00:11:22:33:44:55", diagnostic.Context["mac"]);
        True(!diagnostic.Context.ContainsKey("community"), "A community SNMP não pode aparecer no contexto.");
        Throws<ArgumentException>(() => _ = new ScanDiagnostic(
            "LNS-APP-099",
            DiagnosticCategory.User,
            DiagnosticSeverity.Error,
            "Inválido",
            "Corrigir"));

        ScanDiagnostic redacted = new(
            "LNS-APP-098",
            DiagnosticCategory.Application,
            DiagnosticSeverity.Error,
            "Falha segura.",
            "Corrigir.",
            "--token=example-secret",
            new Dictionary<string, string>
            {
                ["endpoint"] = "https://alice:password@example.invalid/path?api_key=secret-key",
                ["api_key"] = "also-secret"
            });
        Equal("--token=<redacted>", redacted.Target);
        Equal(
            "https://<redacted>:<redacted>@example.invalid/path?api_key=<redacted>",
            redacted.Context["endpoint"]);
        True(!redacted.Context.ContainsKey("api_key"), "Uma API key não pode aparecer no contexto.");
    })),
    ("Diagnostic mapper preserves origin", () => Sync(() =>
    {
        ScanDiagnostic input = DiagnosticCatalog.InvalidCidr("192.168.1.999/24");
        Equal(input, DiagnosticMapper.FromException(new ScanFormatException(input)));
        Equal(DiagnosticCatalog.FileOperationFailedCode,
            DiagnosticMapper.FromException(new IOException("sensitive detail"), "report.json").Code);
        Equal(DiagnosticCatalog.AccessDeniedCode,
            DiagnosticMapper.FromException(new UnauthorizedAccessException(), "report.json").Code);
        Equal(DiagnosticCatalog.NetworkOperationFailedCode,
            DiagnosticMapper.FromException(new HttpRequestException(), "IEEE OUI").Code);
        Equal(DiagnosticCatalog.NetworkOperationFailedCode,
            DiagnosticMapper.FromException(new TaskCanceledException(), "IEEE OUI").Code);
        Equal(DiagnosticCatalog.NetworkOperationFailedCode,
            DiagnosticMapper.FromException(new TimeoutException(), "192.168.1.20").Code);
        Equal(DiagnosticCatalog.NetworkOperationFailedCode,
            DiagnosticMapper.FromException(new Win32Exception(53), "rede").Code);
        Equal(DiagnosticCatalog.OperationCancelledCode,
            DiagnosticMapper.FromException(new OperationCanceledException(), "scan").Code);
        Equal(DiagnosticCatalog.UnexpectedApplicationErrorCode,
            DiagnosticMapper.FromException(new ArgumentException("internal bug"), "motor").Code);
        Equal(DiagnosticCatalog.UnexpectedApplicationErrorCode,
            DiagnosticMapper.FromException(new InvalidProgramException("sensitive detail"), "UI").Code);
    })),
    ("Optional diagnostics preserve scan results", () => Sync(() =>
    {
        NetworkScanResult original = CreateTopologyExportResult();
        ScanDiagnostic warning = DiagnosticCatalog.OptionalFileOperationFailed(
            "histórico local",
            "guardar snapshot");
        NetworkScanResult updated = original.WithAdditionalDiagnostic(warning);

        Equal(original.Devices, updated.Devices);
        Equal(original.Diagnostics.Count + 1, updated.Diagnostics.Count);
        Equal(DiagnosticSeverity.Warning, updated.Diagnostics[^1].Severity);
        Equal(false, updated.Diagnostics[^1].IsFatal);
    })),
    ("Diagnostic catalog has stable unique codes", () => Sync(() =>
    {
        string[] codes = typeof(DiagnosticCatalog)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral &&
                            field.FieldType == typeof(string) &&
                            field.Name.EndsWith("Code", StringComparison.Ordinal))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToArray();

        Equal(25, codes.Length);
        Equal(codes.Length, codes.Distinct(StringComparer.Ordinal).Count());
        True(codes.All(code => code.Length == 11 && code.StartsWith("LNS-", StringComparison.Ordinal)),
            "Todos os códigos públicos devem seguir o contrato LNS-CAT-NNN.");
    })),
    ("MAC identity validation", () => Sync(() =>
    {
        True(MacAddressService.TryNormalizeDeviceAddress("00-11-22-33-44-55", out string normalized),
            "Um MAC unicast válido deveria ser aceite.");
        Equal("00:11:22:33:44:55", normalized);
        True(MacAddressService.TryNormalizeDeviceAddress("0011.2233.4455", out normalized),
            "O formato Cisco deveria ser aceite.");
        Equal("00:11:22:33:44:55", normalized);
        True(!MacAddressService.TryNormalizeDeviceAddress("00:00:00:00:00:00", out _), "MAC zero deve ser rejeitado.");
        True(!MacAddressService.TryNormalizeDeviceAddress("FF:FF:FF:FF:FF:FF", out _), "Broadcast deve ser rejeitado.");
        True(!MacAddressService.TryNormalizeDeviceAddress("01:00:5E:00:00:01", out _), "Multicast deve ser rejeitado.");
        True(!MacAddressService.TryNormalizeDeviceAddress("00:11-22:33-44:55", out _), "Separadores mistos devem ser rejeitados.");
        True(!MacAddressService.TryNormalizeDeviceAddress("0:01122334455", out _), "Separadores mal posicionados devem ser rejeitados.");
        True(!MacAddressService.TryNormalizeDeviceAddress("not-a-mac", out _), "Texto arbitrário deve ser rejeitado.");
    })),
    ("Invalid MAC is quarantined end-to-end", async () =>
    {
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.70"),
            IsOnline = true,
            MacAddress = "0:01122334455",
            Manufacturer = "Untrusted",
            IsRandomizedMac = true,
            DiscoveryMethods = DiscoveryMethod.Arp
        };

        string? observed = NetworkScannerService.NormalizeDeviceMacIdentity(device);
        Equal("0:01122334455", observed);
        Equal<string?>(null, device.MacAddress);
        Equal<string?>(null, device.Manufacturer);
        Equal(false, device.IsRandomizedMac);
        True(!device.DiscoveryMethods.HasFlag(DiscoveryMethod.Arp),
            "Um MAC inválido não pode preservar evidência ARP.");

        device.Topology = new TopologyInferenceService().Assess(device, CreateInterface());
        Equal<bool?>(null, device.Topology.SameLayer2Segment);
        Equal(false, new DeviceRowViewModel(device).HasMacAddress);

        NetworkScanResult result = new()
        {
            NetworkInterface = CreateInterface(),
            StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
            CompletedAt = DateTimeOffset.UtcNow,
            AddressesScanned = 1,
            Devices = [device]
        };
        NetworkMap map = new NetworkTopologyMapService().Build(result);
        Equal(0, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.Layer2Observed));

        NetworkDevice missing = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.71"),
            DiscoveryMethods = DiscoveryMethod.Tcp
        };
        Equal<string?>(null, NetworkScannerService.NormalizeDeviceMacIdentity(missing));
        Equal(DiscoveryMethod.Tcp, missing.DiscoveryMethods);

        ScanFormatException exception = await ThrowsAsync<ScanFormatException>(() =>
            new WakeOnLanService().SendAsync("0:01122334455", IPAddress.Broadcast));
        Equal(DiagnosticCatalog.InvalidMacAddressCode, exception.Diagnostic.Code);
    }),
    ("Product identity follows assembly version", () => Sync(() =>
    {
        string expectedVersion = typeof(NetworkDevice).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        Equal(expectedVersion, ProductIdentity.Version);
        Equal($"LocalNetworkScanner/{expectedVersion}", ProductIdentity.UserAgent);
    })),
    ("IEEE OUI CSV", () => Sync(() =>
    {
        string path = Path.Combine(Path.GetTempPath(), $"local-network-scanner-oui-{Guid.NewGuid():N}.csv");
        try
        {
            File.WriteAllText(
                path,
                "Registry,Assignment,Organization Name,Organization Address\n" +
                "MA-L,001122,\"Example Networks, Inc.\",\"Lisboa, Portugal\"\n",
                new UTF8Encoding(false));

            MacVendorService service = new(path);
            Equal("Example Networks, Inc.", service.Lookup("00:11:22:33:44:55"));
        }
        finally
        {
            File.Delete(path);
        }
    })),
    ("NetBIOS request", () => Sync(() =>
    {
        byte[] request = NetBiosDiscoveryService.BuildNodeStatusRequest();
        Equal(50, request.Length);
        Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(4, 2)));
        Equal((ushort)0x21, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(46, 2)));
    })),
    ("NetBIOS response", () => Sync(() =>
    {
        NetBiosInfo? info = NetBiosDiscoveryService.ParseNodeStatusResponse(BuildNetBiosResponse(), 7);
        NotNull(info);
        Equal("MY-PC", info!.ComputerName);
        Equal("WORKGROUP", info.Workgroup);
        Equal("00:11:22:33:44:55", info.MacAddress);
        Equal(null, NetBiosDiscoveryService.ParseNodeStatusResponse(BuildNetBiosResponse(), 8));
    })),
    ("WS-Discovery response", () => Sync(() =>
    {
        const string messageId = "urn:uuid:11111111-2222-3333-4444-555555555555";
        byte[] xml = Encoding.UTF8.GetBytes(
            $"<e:Envelope xmlns:e='urn:e' xmlns:d='urn:d' xmlns:a='urn:a'><e:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action><a:RelatesTo>{messageId}</a:RelatesTo></e:Header><e:Body><d:ProbeMatches><d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter</d:Types><d:XAddrs>http://192.168.1.9/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>");
        IReadOnlyList<WsDiscoveryMatch> matches = WsDiscoveryService.ParseResponse(
            xml,
            messageId,
            IPAddress.Parse("192.168.1.200"));
        Equal(1, matches.Count);
        Equal(IPAddress.Parse("192.168.1.9"), matches[0].Address);
        Equal("dn:NetworkVideoTransmitter", matches[0].Types);
        Equal("http://192.168.1.9/onvif/device_service", matches[0].XAddresses);
        Equal(0, WsDiscoveryService.ParseResponse(
            xml,
            "urn:uuid:wrong",
            IPAddress.Parse("192.168.1.200")).Count);
    })),
    ("SNMP request and response", () => Sync(() =>
    {
        byte[] request = SnmpClientService.BuildRequest(42, "public", "1.3.6.1.2.1.1.5.0", useGetNext: false);
        True(request.Length > 20, "O pedido SNMP deveria conter um PDU completo.");
        SnmpResponse response = SnmpClientService.ParseResponse(BuildSnmpResponse());
        Equal(42, response.RequestId);
        Equal(1, response.Version);
        Equal("public", response.Community);
        Equal(0, response.ErrorStatus);
        NotNull(response.Variable);
        Equal("1.3.6.1.2.1.1.5.0", response.Variable!.Oid);
        Equal("switch-core", response.Variable.TextValue);
    })),
    ("LLDP remote index and binary identifiers", () => Sync(() =>
    {
        const string firstIndex = ".100.7.1";
        const string secondIndex = ".100.7.2";
        IReadOnlyList<LldpNeighborObservation> neighbors = SnmpTopologyService.ParseLldpNeighbors(
            [
                new SnmpVariable(SnmpTopologyService.LldpLocalPortSubtypeRoot + ".7", 5, null)
            ],
            [
                new SnmpVariable(
                    SnmpTopologyService.LldpLocalPortIdRoot + ".7",
                    null,
                    "Gi1/0/7",
                    Encoding.ASCII.GetBytes("Gi1/0/7"))
            ],
            [
                new SnmpVariable(
                    SnmpTopologyService.LldpLocalPortDescriptionRoot + ".7",
                    null,
                    "Uplink de distribuição")
            ],
            [
                new SnmpVariable(SnmpTopologyService.LldpRemoteChassisSubtypeRoot + firstIndex, 4, null),
                new SnmpVariable(SnmpTopologyService.LldpRemoteChassisSubtypeRoot + secondIndex, 4, null),
                new SnmpVariable(SnmpTopologyService.LldpRemoteChassisSubtypeRoot + ".100.7", 4, null),
                new SnmpVariable(SnmpTopologyService.LldpRemoteChassisSubtypeRoot + ".100.5000.3", 4, null)
            ],
            [
                new SnmpVariable(
                    SnmpTopologyService.LldpRemoteChassisIdRoot + firstIndex,
                    null,
                    null,
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                new SnmpVariable(
                    SnmpTopologyService.LldpRemoteChassisIdRoot + secondIndex,
                    null,
                    null,
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            ],
            [
                new SnmpVariable(SnmpTopologyService.LldpRemotePortSubtypeRoot + firstIndex, 5, null),
                new SnmpVariable(SnmpTopologyService.LldpRemotePortSubtypeRoot + secondIndex, 5, null)
            ],
            [
                new SnmpVariable(
                    SnmpTopologyService.LldpRemotePortIdRoot + firstIndex,
                    null,
                    "Ethernet1/1",
                    Encoding.ASCII.GetBytes("Ethernet1/1")),
                new SnmpVariable(
                    SnmpTopologyService.LldpRemotePortIdRoot + secondIndex,
                    null,
                    "Ethernet1/2",
                    Encoding.ASCII.GetBytes("Ethernet1/2"))
            ],
            [],
            [
                new SnmpVariable(SnmpTopologyService.LldpRemoteSystemNameRoot + firstIndex, null, "dist-a"),
                new SnmpVariable(SnmpTopologyService.LldpRemoteSystemNameRoot + secondIndex, null, "dist-a"),
                new SnmpVariable(SnmpTopologyService.LldpRemoteSystemNameRoot + ".4000000000.8.1", null, "edge-z")
            ],
            []);

        Equal(3, neighbors.Count);
        Equal(100u, neighbors[0].TimeMark);
        Equal(7, neighbors[0].LocalPortNumber);
        Equal(1, neighbors[0].RemoteIndex);
        Equal(2, neighbors[1].RemoteIndex);
        Equal("00:11:22:33:44:55", neighbors[0].ChassisId);
        Equal("Gi1/0/7", neighbors[0].LocalPortId);
        Equal(5, neighbors[0].LocalPortIdSubtype);
        Equal(4_000_000_000u, neighbors[2].TimeMark);
    })),
    ("mDNS A record", () => Sync(() =>
    {
        IReadOnlyList<(IPAddress Address, string? Hostname)> records =
            MdnsDiscoveryService.ParseAddressRecords(BuildMdnsResponse());
        Equal(1, records.Count);
        Equal("printer.local", records[0].Hostname);
        Equal(IPAddress.Parse("192.168.1.50"), records[0].Address);
    })),
    ("Risk score", () => Sync(() =>
    {
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.20"),
            Ports =
            [
                new PortScanResult { Port = 23 },
                new PortScanResult { Port = 2375 }
            ]
        };
        new SecurityAssessmentService().Assess(device);
        Equal("Alto", device.RiskLevel);
        True(device.RiskScore >= 60, "A pontuação deveria refletir serviços críticos.");
    })),
    ("Topology evidence", () => Sync(() =>
    {
        LocalNetworkInterface network = CreateInterface();
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.20"),
            MacAddress = "00:11:22:33:44:55",
            DiscoveryMethods = DiscoveryMethod.Arp
        };
        TopologyAssessment assessment = new TopologyInferenceService().Assess(device, network);
        Equal(true, assessment.SameLayer2Segment);
        Equal(null, assessment.SamePhysicalSwitch);
    })),
    ("NetBIOS MAC is not ARP evidence", () => Sync(() =>
    {
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.21"),
            MacAddress = "00:11:22:33:44:66",
            DiscoveryMethods = DiscoveryMethod.NetBios
        };
        TopologyAssessment assessment = new TopologyInferenceService().Assess(device, CreateInterface());
        Equal(null, assessment.SameLayer2Segment);
    })),
    ("SNMP FDB does not prove physical switch", () => Sync(() =>
    {
        LocalNetworkInterface network = CreateInterface();
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.30"),
            MacAddress = "00:11:22:33:44:77"
        };
        SnmpTopologySnapshot snapshot = new()
        {
            SwitchAddress = IPAddress.Parse("192.168.1.2"),
            SwitchName = "core-switch",
            MacTable = new Dictionary<string, IReadOnlyList<SwitchPortObservation>>(StringComparer.OrdinalIgnoreCase)
            {
                ["00:11:22:33:44:77"] =
                [
                    new SwitchPortObservation
                    {
                        MacAddress = "00:11:22:33:44:77",
                        BridgePort = 7,
                        InterfaceName = "Gi1/0/7",
                        VlanId = 20,
                        PortPvid = 1,
                        ForwardingDatabaseId = 200
                    }
                ]
            }
        };
        new SnmpTopologyService().Apply(snapshot, [device], network);
        Equal(true, device.Topology.ObservedOnManagedBridge);
        Equal(null, device.Topology.SamePhysicalSwitch);
        Equal(20, device.Topology.VlanId);
        Equal(1, device.Topology.SwitchPortPvid);
    })),
    ("Network map preserves evidence semantics", () => Sync(() =>
    {
        LocalNetworkInterface network = CreateInterface();
        NetworkDevice arpDevice = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.30"),
            Hostname = "workstation",
            MacAddress = "00:11:22:33:44:77",
            IsOnline = true,
            DiscoveryMethods = DiscoveryMethod.Arp,
            RiskLevel = "Médio",
            Topology = new TopologyAssessment
            {
                SameIpSubnet = true,
                SameLayer2Segment = true,
                Layer2Confidence = ConfidenceLevel.Medium,
                ObservedOnManagedBridge = true,
                SwitchAddress = "192.168.1.2",
                SwitchConfidence = ConfidenceLevel.High
            }
        };
        NetworkDevice routedDevice = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.40"),
            IsOnline = true,
            DiscoveryMethods = DiscoveryMethod.Icmp
        };
        SnmpTopologySnapshot snapshot = new()
        {
            SwitchAddress = IPAddress.Parse("192.168.1.2"),
            SwitchName = "access-a",
            MacTable = new Dictionary<string, IReadOnlyList<SwitchPortObservation>>(StringComparer.OrdinalIgnoreCase)
            {
                ["00:11:22:33:44:77"] =
                [
                    new SwitchPortObservation
                    {
                        MacAddress = "00:11:22:33:44:77",
                        BridgePort = 7,
                        InterfaceName = "Gi1/0/7"
                    },
                    new SwitchPortObservation
                    {
                        MacAddress = "00:11:22:33:44:77",
                        BridgePort = 48,
                        InterfaceName = "Gi1/0/48"
                    }
                ]
            },
            LldpNeighbors =
            [
                CreateLldpNeighbor(500, 7, 1, "dist-a"),
                CreateLldpNeighbor(500, 7, 2, "dist-a")
            ]
        };
        NetworkScanResult result = new()
        {
            NetworkInterface = network,
            StartedAt = new DateTimeOffset(2026, 7, 21, 10, 0, 0, TimeSpan.Zero),
            CompletedAt = new DateTimeOffset(2026, 7, 21, 10, 0, 5, TimeSpan.Zero),
            AddressesScanned = 254,
            Devices = [arpDevice, routedDevice],
            SnmpTopology = snapshot
        };

        NetworkTopologyMapService service = new();
        NetworkMap map = service.Build(result);
        NetworkMap second = service.Build(result);

        Equal(network.NetworkCidr, map.NetworkCidr);
        Equal(result.CompletedAt, map.GeneratedAt);
        Equal(
            string.Join('|', map.Nodes.Select(node => node.Id)),
            string.Join('|', second.Nodes.Select(node => node.Id)));
        Equal(2, map.Nodes.Count(node => node.Kind == NetworkMapNodeKind.LldpNeighbor));
        Equal(1, map.Nodes.Count(node =>
            node.Kind == NetworkMapNodeKind.LldpNeighbor && node.MacAddress is not null));
        Equal(2, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.LldpNeighbor));
        Equal(2, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.MacLearned));
        Equal(1, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.Layer2Observed));
        Equal(1, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.IpReachability));
        True(map.Edges
                .Where(edge => edge.Kind == NetworkMapEdgeKind.MacLearned)
                .All(edge => edge.Evidence.Contains("não prova ligação física direta", StringComparison.Ordinal)),
            "Uma entrada FDB nunca pode ser apresentada como prova de ligação física.");

        HashSet<string> nodeIds = map.Nodes.Select(node => node.Id).ToHashSet(StringComparer.Ordinal);
        True(map.Edges.All(edge => nodeIds.Contains(edge.SourceId) && nodeIds.Contains(edge.TargetId)),
            "Todas as ligações do mapa devem referenciar nós existentes.");
    })),
    ("Network map rejects fabricated topology", () => Sync(() =>
    {
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.50"),
            IsOnline = true,
            DiscoveryMethods = DiscoveryMethod.Tcp,
            Topology = new TopologyAssessment
            {
                ObservedOnManagedBridge = true,
                SwitchAddress = "not-an-ip",
                SamePhysicalSwitch = true
            }
        };
        NetworkScanResult result = new()
        {
            NetworkInterface = CreateInterface(),
            StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
            CompletedAt = DateTimeOffset.UtcNow,
            AddressesScanned = 1,
            Devices = [device]
        };

        NetworkMap map = new NetworkTopologyMapService().Build(result);
        Equal(0, map.Nodes.Count(node => node.Kind == NetworkMapNodeKind.ManagedSwitch));
        Equal(0, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.MacLearned));
        Equal(1, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.IpReachability));
    })),
    ("Gateway and managed switch share one node", () => Sync(() =>
    {
        LocalNetworkInterface network = CreateInterface();
        NetworkDevice gatewayDevice = new()
        {
            IpAddress = network.GatewayAddress!,
            MacAddress = "00:01:02:03:04:05",
            IsOnline = true,
            DiscoveryMethods = DiscoveryMethod.Arp
        };
        SnmpTopologySnapshot snapshot = new()
        {
            SwitchAddress = network.GatewayAddress!,
            SwitchName = "router-switch",
            MacTable = new Dictionary<string, IReadOnlyList<SwitchPortObservation>>(StringComparer.OrdinalIgnoreCase)
            {
                ["00:01:02:03:04:05"] =
                [
                    new SwitchPortObservation
                    {
                        MacAddress = "00:01:02:03:04:05",
                        BridgePort = 1
                    }
                ]
            },
            LldpNeighbors = [CreateLldpNeighbor(10, 1, 1, "access-b")]
        };
        NetworkScanResult result = new()
        {
            NetworkInterface = network,
            StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
            CompletedAt = DateTimeOffset.UtcNow,
            AddressesScanned = 1,
            Devices = [gatewayDevice],
            SnmpTopology = snapshot
        };

        NetworkMap map = new NetworkTopologyMapService().Build(result);
        NetworkMapNode[] nodesAtGateway = map.Nodes
            .Where(node => node.IpAddress?.Equals(network.GatewayAddress) == true)
            .ToArray();
        Equal(1, nodesAtGateway.Length);
        Equal(NetworkMapNodeKind.Gateway, nodesAtGateway[0].Kind);
        Equal("Gateway / switch gerido", nodesAtGateway[0].DeviceType);
        Equal(0, map.Nodes.Count(node => node.Kind == NetworkMapNodeKind.ManagedSwitch));
        Equal(0, map.Edges.Count(edge =>
            edge.Kind == NetworkMapEdgeKind.MacLearned && edge.SourceId == edge.TargetId));
        Equal(1, map.Edges.Count(edge =>
            edge.Kind == NetworkMapEdgeKind.LldpNeighbor &&
            edge.SourceId == nodesAtGateway[0].Id));
    })),
    ("History comparison state", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        try
        {
            NetworkDevice device = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.40"),
                MacAddress = "0:01122334455"
            };
            Equal("Não comparado", device.HistoryText);
            NetworkScanResult result = new()
            {
                NetworkInterface = CreateInterface(),
                StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
                CompletedAt = DateTimeOffset.UtcNow,
                AddressesScanned = 1,
                Devices = [device]
            };

            await new NetworkHistoryService(directory).ApplyAndSaveAsync(result);
            Equal(true, device.HistoryCompared);
            Equal(true, device.IsNew);
            Equal("Novo", device.HistoryText);
            string snapshot = await File.ReadAllTextAsync(Directory.GetFiles(directory, "*.json").Single());
            True(!snapshot.Contains("0:01122334455", StringComparison.Ordinal),
                "Um MAC inválido não pode ser persistido no histórico.");
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("HTML export escapes content", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "report.html");
        try
        {
            NetworkScanResult result = new()
            {
                NetworkInterface = CreateInterface(),
                StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
                CompletedAt = DateTimeOffset.UtcNow,
                AddressesScanned = 1,
                IsPartial = true,
                Devices =
                [
                    new NetworkDevice
                    {
                        IpAddress = IPAddress.Parse("192.168.1.20"),
                        Alias = "<script>alert(1)</script>"
                    }
                ]
            };
            await new ExportService().ExportHtmlAsync(result, path);
            string html = await File.ReadAllTextAsync(path);
            True(html.Contains("&lt;script&gt;", StringComparison.Ordinal), "O alias deve ser escapado.");
            True(!html.Contains("<script>alert", StringComparison.Ordinal), "HTML inseguro encontrado.");
            True(html.Contains("RESULTADO PARCIAL", StringComparison.Ordinal), "O HTML deve identificar um resultado parcial.");
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("CSV export neutralizes formulas", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "report.csv");
        try
        {
            NetworkScanResult result = new()
            {
                NetworkInterface = CreateInterface(),
                StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
                CompletedAt = DateTimeOffset.UtcNow,
                AddressesScanned = 1,
                IsPartial = true,
                Devices =
                [
                    new NetworkDevice
                    {
                        IpAddress = IPAddress.Parse("192.168.1.20"),
                        Alias = "=WEBSERVICE(\"https://example.invalid\")",
                        Notes = "  @SUM(1+1)"
                    }
                ]
            };

            await new ExportService().ExportCsvAsync(result, path);
            string csv = await File.ReadAllTextAsync(path);
            True(csv.Contains("\"'=WEBSERVICE(\"\"https://example.invalid\"\")\"", StringComparison.Ordinal),
                "Uma fórmula no alias deve ser neutralizada.");
            True(csv.Contains("\"'  @SUM(1+1)\"", StringComparison.Ordinal),
                "Uma fórmula depois de espaços deve ser neutralizada.");
            True(csv.Contains("\"Sim\";\"Não\"", StringComparison.Ordinal),
                "O CSV deve identificar um resultado parcial.");
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("JSON export includes topology schema", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "report.json");
        try
        {
            NetworkScanResult result = CreateTopologyExportResult();
            await new ExportService().ExportJsonAsync(result, path);

            await using FileStream stream = File.OpenRead(path);
            using JsonDocument document = await JsonDocument.ParseAsync(stream);
            JsonElement root = document.RootElement;
            Equal(3, root.GetProperty("schemaVersion").GetInt32());
            JsonElement diagnostics = root.GetProperty("scan").GetProperty("diagnostics");
            Equal(1, diagnostics.GetArrayLength());
            Equal(DiagnosticCatalog.InvalidMacAddressCode,
                diagnostics[0].GetProperty("code").GetString());
            True(diagnostics[0].GetProperty("recommendedAction").GetString()?.Length > 0,
                "O JSON deve incluir a ação recomendada.");
            JsonElement map = root.GetProperty("topologyMap");
            True(map.GetProperty("nodes").GetArrayLength() >= 3,
                "O JSON deveria conter os nós do mapa de topologia.");
            Equal("Layer2Observed", map.GetProperty("edges")
                .EnumerateArray()
                .First(edge => edge.GetProperty("kind").GetString() == "Layer2Observed")
                .GetProperty("kind")
                .GetString());
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("GraphML export is valid and preserves evidence", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "topology.graphml");
        try
        {
            NetworkScanResult result = CreateTopologyExportResult();
            await new ExportService().ExportGraphMlAsync(result, path);

            XDocument document = XDocument.Load(path);
            XNamespace graphMl = "http://graphml.graphdrawing.org/xmlns";
            XElement[] nodes = document.Descendants(graphMl + "node").ToArray();
            XElement[] edges = document.Descendants(graphMl + "edge").ToArray();
            HashSet<string> nodeIds = nodes
                .Select(node => (string?)node.Attribute("id"))
                .Where(id => id is not null)
                .Select(id => id!)
                .ToHashSet(StringComparer.Ordinal);

            True(nodes.Length >= 3, "O GraphML deveria conter os nós da rede.");
            True(edges.Length >= 3, "O GraphML deveria conter ligações com evidência.");
            True(edges.All(edge =>
                    nodeIds.Contains((string?)edge.Attribute("source") ?? string.Empty) &&
                    nodeIds.Contains((string?)edge.Attribute("target") ?? string.Empty)),
                "As referências source/target do GraphML devem apontar para nós existentes.");
            True(document.Descendants(graphMl + "data")
                    .Any(data => (string?)data.Attribute("key") == "e_evidence" &&
                                 data.Value.Contains("proxy ARP", StringComparison.Ordinal)),
                "O GraphML deveria preservar a explicação da evidência.");
            True(document.Descendants(graphMl + "data")
                    .Any(data => (string?)data.Attribute("key") == "g_diagnostics" &&
                                 data.Value.Contains(DiagnosticCatalog.InvalidMacAddressCode, StringComparison.Ordinal)),
                "O GraphML deveria preservar os códigos de diagnóstico.");
            True(document.ToString().Contains("printer &lt;lab&gt;&amp;", StringComparison.Ordinal),
                "Os rótulos não confiáveis devem ser escapados no XML.");
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("WPF selected-device and topology rendering smoke", () => RunOnSta(() =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "topology.png");
        App application = new();
        application.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        application.InitializeComponent();
        MainWindow window = new()
        {
            Opacity = 0,
            ShowActivated = false,
            ShowInTaskbar = false
        };
        TopologyWindow? topologyWindow = null;
        try
        {
            NetworkScanResult result = CreateTopologyExportResult();
            DeviceRowViewModel row = new(result.Devices[0]);
            window.ViewModel.Devices.Add(row);
            window.ViewModel.SelectedDevice = row;
            window.Show();
            window.Hide();
            window.Measure(new Size(1_440, 880));
            window.Arrange(new Rect(0, 0, 1_440, 880));
            window.UpdateLayout();

            result.Devices[0].ResponseTimeMs = 7;
            row.Update(result.Devices[0]);
            window.UpdateLayout();
            Equal("7 ms", row.ResponseTime);

            Equal("Rápido", window.ViewModel.Profiles[0].DisplayName);
            Equal("Normal", window.ViewModel.Profiles[1].DisplayName);
            Equal("Avançado", window.ViewModel.Profiles[2].DisplayName);
            Equal(ScanProfile.Deep, window.ViewModel.Profiles[2].Value);

            Button? topologyButton = window.FindName("OpenTopologyButton") as Button;
            NotNull(topologyButton);
            var topologyBinding = topologyButton!.GetBindingExpression(UIElement.IsEnabledProperty);
            NotNull(topologyBinding);
            topologyBinding!.UpdateTarget();
            True(
                !topologyButton!.IsEnabled,
                $"A topologia deve estar desativada antes de existir mapa. " +
                $"HasTopologyMap={window.ViewModel.HasTopologyMap}; " +
                $"DataContext={topologyButton.DataContext?.GetType().Name ?? "null"}; " +
                $"Binding={topologyBinding.Status}.");

            NetworkMap map = new NetworkTopologyMapService().Build(result);
            typeof(MainViewModel)
                .GetProperty(nameof(MainViewModel.TopologyMap))!
                .SetValue(window.ViewModel, map);
            topologyBinding.UpdateTarget();
            window.UpdateLayout();
            True(topologyButton.IsEnabled, "A topologia deve ficar disponível depois do scan.");

            topologyWindow = new TopologyWindow(window.ViewModel)
            {
                Opacity = 0,
                ShowActivated = false,
                ShowInTaskbar = false
            };
            topologyWindow.Show();
            topologyWindow.Hide();
            topologyWindow.Measure(new Size(1_240, 760));
            topologyWindow.Arrange(new Rect(0, 0, 1_240, 760));
            topologyWindow.UpdateLayout();
            Equal(window.ViewModel, topologyWindow.DataContext);
            NetworkTopologyControl? optionalTopology =
                topologyWindow.FindName("TopologyGraph") as NetworkTopologyControl;
            NotNull(optionalTopology);
            Equal(map, optionalTopology!.Map);

            NetworkTopologyControl topology = new()
            {
                Width = 900,
                Height = 500,
                Map = new NetworkTopologyMapService().Build(result)
            };
            topology.Measure(new Size(900, 500));
            topology.Arrange(new Rect(0, 0, 900, 500));
            topology.UpdateLayout();
            topology.FitToView();
            Directory.CreateDirectory(directory);
            topology.ExportVisiblePng(path);
            True(new FileInfo(path).Length > 1_000, "O mapa WPF deveria produzir um PNG não vazio.");
        }
        finally
        {
            topologyWindow?.Close();
            window.Close();
            window.DataContext = null;
            window.ViewModel.Dispose();
            application.Shutdown();
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }))
];

int passed = 0;
foreach ((string name, Func<Task> run) in tests)
{
    try
    {
        await run();
        passed++;
        Console.WriteLine($"PASS  {name}");
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"FAIL  {name}: {exception.Message}");
    }
}

Console.WriteLine($"\n{passed}/{tests.Count} testes concluídos com sucesso.");
return passed == tests.Count ? 0 : 1;

static Task Sync(Action action)
{
    action();
    return Task.CompletedTask;
}

static Task RunOnSta(Action action)
{
    TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    Thread thread = new(() =>
    {
        try
        {
            action();
            completion.SetResult();
        }
        catch (Exception exception)
        {
            completion.SetException(exception);
        }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    return completion.Task;
}

static LocalNetworkInterface CreateInterface() => new()
{
    Id = "test-interface",
    Name = "Ethernet",
    Description = "Interface de teste",
    IpAddress = IPAddress.Parse("192.168.1.10"),
    SubnetMask = IPAddress.Parse("255.255.255.0"),
    GatewayAddress = IPAddress.Parse("192.168.1.1"),
    MacAddress = "00:AA:BB:CC:DD:EE",
    InterfaceType = NetworkInterfaceType.Ethernet,
    SpeedBitsPerSecond = 1_000_000_000
};

static NetworkScanResult CreateTopologyExportResult()
{
    NetworkDevice device = new()
    {
        IpAddress = IPAddress.Parse("192.168.1.20"),
        Alias = "printer <lab>&",
        MacAddress = "00:11:22:33:44:55",
        IsOnline = true,
        DiscoveryMethods = DiscoveryMethod.Arp,
        Topology = new TopologyAssessment
        {
            SameIpSubnet = true,
            SameLayer2Segment = true,
            Layer2Confidence = ConfidenceLevel.Medium
        }
    };
    return new NetworkScanResult
    {
        NetworkInterface = CreateInterface(),
        StartedAt = new DateTimeOffset(2026, 7, 21, 10, 0, 0, TimeSpan.Zero),
        CompletedAt = new DateTimeOffset(2026, 7, 21, 10, 0, 1, TimeSpan.Zero),
        AddressesScanned = 1,
        Devices = [device],
        Diagnostics = [DiagnosticCatalog.InvalidMacAddress(device.IpAddressText, "invalid-mac")]
    };
}

static LldpNeighborObservation CreateLldpNeighbor(
    uint timeMark,
    int localPortNumber,
    int remoteIndex,
    string systemName) => new()
    {
        TimeMark = timeMark,
        LocalPortNumber = localPortNumber,
        RemoteIndex = remoteIndex,
        LocalPortId = $"Gi1/0/{localPortNumber}",
        PortId = $"Ethernet1/{remoteIndex}",
        SystemName = systemName,
        ChassisIdSubtype = 4,
        ChassisId = remoteIndex == 2 ? "abcdefabcdef-router" : "00:AA:BB:CC:DD:EE"
    };

static byte[] BuildNetBiosResponse()
{
    byte[] data = new byte[43];
    data[0] = 2;
    WriteName(data.AsSpan(1, 18), "MY-PC", 0x00, false);
    WriteName(data.AsSpan(19, 18), "WORKGROUP", 0x00, true);
    new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }.CopyTo(data, 37);

    byte[] packet = new byte[12 + 2 + 10 + data.Length];
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), 7);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), 0x8500);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6, 2), 1);
    int offset = 12;
    packet[offset++] = 0xC0;
    packet[offset++] = 0x0C;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset, 2), 0x21);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 2, 2), 1);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 8, 2), (ushort)data.Length);
    offset += 10;
    data.CopyTo(packet, offset);
    return packet;
}

static void WriteName(Span<byte> target, string name, byte suffix, bool isGroup)
{
    target[..15].Fill((byte)' ');
    Encoding.ASCII.GetBytes(name).CopyTo(target);
    target[15] = suffix;
    BinaryPrimitives.WriteUInt16BigEndian(target[16..18], isGroup ? (ushort)0x8000 : (ushort)0);
}

static byte[] BuildMdnsResponse()
{
    using MemoryStream stream = new();
    byte[] header = new byte[12];
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), 1);
    stream.Write(header);
    foreach (string label in new[] { "printer", "local" })
    {
        stream.WriteByte((byte)label.Length);
        stream.Write(Encoding.ASCII.GetBytes(label));
    }
    stream.WriteByte(0);
    stream.Write([0, 1, 0, 1]);
    stream.Write([0, 0, 0, 60]);
    stream.Write([0, 4, 192, 168, 1, 50]);
    return stream.ToArray();
}

static byte[] BuildSnmpResponse()
{
    Asn1Tag responseTag = new(TagClass.ContextSpecific, 2, isConstructed: true);
    AsnWriter writer = new(AsnEncodingRules.BER);
    writer.PushSequence();
    writer.WriteInteger(1);
    writer.WriteOctetString(Encoding.ASCII.GetBytes("public"));
    writer.PushSequence(responseTag);
    writer.WriteInteger(42);
    writer.WriteInteger(0);
    writer.WriteInteger(0);
    writer.PushSequence();
    writer.PushSequence();
    writer.WriteObjectIdentifier("1.3.6.1.2.1.1.5.0");
    writer.WriteOctetString(Encoding.ASCII.GetBytes("switch-core"));
    writer.PopSequence();
    writer.PopSequence();
    writer.PopSequence(responseTag);
    writer.PopSequence();
    return writer.Encode();
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException($"Esperado '{expected}', obtido '{actual}'.");
}

static void True(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

static void NotNull(object? value)
{
    if (value is null)
        throw new InvalidOperationException("O valor não deveria ser nulo.");
}

static void Throws<TException>(Action action)
    where TException : Exception
{
    try
    {
        action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException($"Era esperada a exceção {typeof(TException).Name}.");
}

static async Task<TException> ThrowsAsync<TException>(Func<Task> action)
    where TException : Exception
{
    try
    {
        await action();
    }
    catch (TException exception)
    {
        return exception;
    }

    throw new InvalidOperationException($"Era esperada a exceção {typeof(TException).Name}.");
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
