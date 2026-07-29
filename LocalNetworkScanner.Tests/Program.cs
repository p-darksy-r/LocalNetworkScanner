// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Formats.Asn1;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
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
using LocalNetworkScanner.Wpf.Infrastructure;
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
    ("ICMP source binding rejects invalid routes without fallback", async () =>
    {
        PingScannerService scanner = new();

        PingProbeResult incompatibleSource = await scanner.ProbeAsync(
            IPAddress.Loopback,
            timeoutMs: 50,
            IPAddress.IPv6Loopback,
            CancellationToken.None);
        Equal(false, incompatibleSource.Success);
        Equal<long?>(null, incompatibleSource.RoundtripTimeMs);
        Equal<int?>(null, incompatibleSource.ReplyTtl);

        if (OperatingSystem.IsWindows())
        {
            PingProbeResult loopback = await scanner.ProbeAsync(
                IPAddress.Loopback,
                timeoutMs: 1_000,
                IPAddress.Loopback,
                CancellationToken.None);
            Equal(loopback.Success, loopback.RoundtripTimeMs.HasValue);
            Equal(loopback.Success, loopback.ReplyTtl.HasValue);
        }

        await ThrowsAsync<ArgumentNullException>(() =>
            scanner.ProbeAsync(
                null!,
                timeoutMs: 50,
                IPAddress.Loopback,
                CancellationToken.None));
        await ThrowsAsync<ArgumentOutOfRangeException>(() =>
            scanner.ProbeAsync(
                IPAddress.Loopback,
                timeoutMs: 0,
                IPAddress.Loopback,
                CancellationToken.None));

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        await ThrowsAsync<OperationCanceledException>(() =>
            scanner.ProbeAsync(
                IPAddress.Loopback,
                timeoutMs: 50,
                IPAddress.Loopback,
                cancellation.Token));

        MethodInfo? sourceBoundOverload = typeof(PingScannerService).GetMethod(
            nameof(PingScannerService.ProbeAsync),
            [
                typeof(IPAddress),
                typeof(int),
                typeof(IPAddress),
                typeof(CancellationToken)
            ]);
        NotNull(sourceBoundOverload);
        Equal("sourceAddress", sourceBoundOverload!.GetParameters()[2].Name);
    }),
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
        Equal(DiagnosticCatalog.ApplicationControlBlockedCode,
            DiagnosticMapper.FromException(new Win32Exception(4_551), "LocalNetworkScanner.exe").Code);
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

        Equal(26, codes.Length);
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
    ("WPF advanced integer validation", () => Sync(() =>
    {
        IntegerRangeValidationRule rule = new()
        {
            FieldName = "Timeout",
            Minimum = 50,
            Maximum = 30_000
        };
        CultureInfo culture = CultureInfo.GetCultureInfo("pt-PT");
        Equal(false, rule.Validate(string.Empty, culture).IsValid);
        Equal(false, rule.Validate("abc", culture).IsValid);
        Equal(false, rule.Validate("49", culture).IsValid);
        Equal(true, rule.Validate("50", culture).IsValid);
        Equal(true, rule.Validate("30000", culture).IsValid);
        Equal(false, rule.Validate("30001", culture).IsValid);
    })),
    ("Device rows expose typed sort keys", () => Sync(() =>
    {
        DeviceRowViewModel lowerIp = new(new NetworkDevice
        {
            IpAddress = IPAddress.Parse("192.168.1.2"),
            ResponseTimeMs = 9,
            RiskScore = 20,
            Ports = [new PortScanResult { Port = 80, Protocol = "TCP" }]
        });
        DeviceRowViewModel higherIp = new(new NetworkDevice
        {
            IpAddress = IPAddress.Parse("192.168.1.10"),
            ResponseTimeMs = 100,
            RiskScore = 80,
            Ports =
            [
                new PortScanResult { Port = 22, Protocol = "TCP" },
                new PortScanResult { Port = 443, Protocol = "TCP" }
            ]
        });
        DeviceRowViewModel noPing = new(new NetworkDevice
        {
            IpAddress = IPAddress.Parse("192.168.1.20")
        });

        True(lowerIp.IpSortKey < higherIp.IpSortKey, "A ordenação de IP deve ser numérica.");
        True(lowerIp.ResponseTimeSortKey < higherIp.ResponseTimeSortKey,
            "A ordenação de ping deve usar milissegundos.");
        Equal(long.MaxValue, noPing.ResponseTimeSortKey);
        True(lowerIp.RiskScore < higherIp.RiskScore, "O risco deve ser ordenado pela pontuação.");
        True(lowerIp.OpenPortCount < higherIp.OpenPortCount,
            "As portas devem ser ordenadas pela contagem.");
    })),
    ("TLS state is evidence-based and JSON-stable", () => Sync(() =>
    {
        PortScanResult conventionalTlsPort = new()
        {
            Port = 443,
            ServiceName = ServiceCatalog.GetServiceName(443)
        };
        Equal(TlsProbeStatus.NotProbed, conventionalTlsPort.TlsStatus);
        Equal<bool?>(null, conventionalTlsPort.IsEncrypted);
        Equal("\u004E\u00E3o verificado", conventionalTlsPort.TlsStatusDisplay);

        using (JsonDocument document = JsonDocument.Parse(
                   JsonSerializer.Serialize(conventionalTlsPort)))
        {
            JsonElement root = document.RootElement;
            Equal("NotProbed", root.GetProperty("TlsStatus").GetString());
            Equal(JsonValueKind.Null, root.GetProperty("IsEncrypted").ValueKind);
        }

        PortScanResult confirmed = new()
        {
            Port = 8443,
            TlsStatus = TlsProbeStatus.HandshakeSucceeded,
            TlsProtocol = "TLS 1.3"
        };
        Equal<bool?>(true, confirmed.IsEncrypted);
        Equal("TLS 1.3 confirmado", confirmed.TlsStatusDisplay);

        PortScanResult failed = new()
        {
            Port = 443,
            TlsStatus = TlsProbeStatus.HandshakeFailed,
            TlsFailureReason = "handshake rejeitado"
        };
        Equal<bool?>(null, failed.IsEncrypted);
        Equal("Indeterminado (handshake rejeitado)", failed.TlsStatusDisplay);

        PortScanResult failedWithoutReason = new()
        {
            Port = 443,
            TlsStatus = TlsProbeStatus.HandshakeFailed
        };
        Equal<bool?>(null, failedWithoutReason.IsEncrypted);
        Equal("Indeterminado (falha)", failedWithoutReason.TlsStatusDisplay);
    })),
    ("Topology filters distinguish infrastructure clients and alerts", () => Sync(() =>
    {
        NetworkMapNode gateway = new()
        {
            Id = "gateway",
            Kind = NetworkMapNodeKind.Gateway,
            Label = "Gateway",
            RiskLevel = "Baixo",
            IsOnline = true
        };
        NetworkMapNode client = new()
        {
            Id = "client",
            Kind = NetworkMapNodeKind.Device,
            Label = "Portátil",
            DeviceType = "Computador Windows",
            RiskLevel = "Baixo",
            IsOnline = true
        };
        NetworkMapNode alert = new()
        {
            Id = "alert",
            Kind = NetworkMapNodeKind.Device,
            Label = "Câmara",
            DeviceType = "Câmara / vídeo IP",
            RiskLevel = "Alto",
            IsOnline = true
        };

        Equal(true, NetworkTopologyControl.IsNodeVisible(gateway, TopologyFilterMode.Infrastructure));
        Equal(false, NetworkTopologyControl.IsNodeVisible(gateway, TopologyFilterMode.Clients));
        Equal(true, NetworkTopologyControl.IsNodeVisible(client, TopologyFilterMode.Clients));
        Equal(false, NetworkTopologyControl.IsNodeVisible(client, TopologyFilterMode.Alerts));
        Equal(true, NetworkTopologyControl.IsNodeVisible(alert, TopologyFilterMode.Alerts));
    })),
    ("Topology filters preserve matching nodes and ancestor context", () => Sync(() =>
    {
        NetworkMapNode unrelated = new()
        {
            Id = "unrelated",
            Kind = NetworkMapNodeKind.Gateway,
            Label = "Gateway sem liga\u00E7\u00E3o"
        };
        NetworkMapNode client = new()
        {
            Id = "client",
            Kind = NetworkMapNodeKind.Device,
            Label = "Port\u00E1til",
            DeviceType = "Computador Windows"
        };
        NetworkMapNode network = new()
        {
            Id = "network",
            Kind = NetworkMapNodeKind.NetworkSegment,
            Label = "192.168.1.0/24"
        };
        NetworkMapNode managedSwitch = new()
        {
            Id = "switch",
            Kind = NetworkMapNodeKind.ManagedSwitch,
            Label = "Switch principal"
        };
        NetworkMapNode gateway = new()
        {
            Id = "gateway",
            Kind = NetworkMapNodeKind.Gateway,
            Label = "Gateway"
        };
        NetworkMap map = new()
        {
            NetworkCidr = "192.168.1.0/24",
            GeneratedAt = DateTimeOffset.UnixEpoch,
            Nodes = [unrelated, client, network, managedSwitch, gateway],
            Edges =
            [
                new NetworkMapEdge
                {
                    SourceId = "network",
                    TargetId = "gateway",
                    Kind = NetworkMapEdgeKind.Contains,
                    Label = "cont\u00E9m",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "gateway",
                    TargetId = "switch",
                    Kind = NetworkMapEdgeKind.Layer2Observed,
                    Label = "liga",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "switch",
                    TargetId = "client",
                    Kind = NetworkMapEdgeKind.Layer2Observed,
                    Label = "liga",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "client",
                    TargetId = "gateway",
                    Kind = NetworkMapEdgeKind.IpReachability,
                    Label = "ciclo",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "ghost",
                    TargetId = "client",
                    Kind = NetworkMapEdgeKind.Layer2Observed,
                    Label = "origem desconhecida",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "client",
                    TargetId = "missing",
                    Kind = NetworkMapEdgeKind.Layer2Observed,
                    Label = "destino desconhecido",
                    Evidence = "teste"
                }
            ]
        };

        IReadOnlyList<NetworkMapNode> visible = NetworkTopologyControl.GetVisibleNodes(
            map,
            TopologyFilterMode.Clients,
            out int matchingCount);

        Equal(1, matchingCount);
        Equal("client,network,switch,gateway", string.Join(',', visible.Select(node => node.Id)));
        Equal(true, NetworkTopologyControl.IsNodeVisible(client, TopologyFilterMode.Clients));
        Equal(false, NetworkTopologyControl.IsNodeVisible(network, TopologyFilterMode.Clients));
        Equal(false, NetworkTopologyControl.IsNodeVisible(managedSwitch, TopologyFilterMode.Clients));
        Equal(false, NetworkTopologyControl.IsNodeVisible(gateway, TopologyFilterMode.Clients));

        IReadOnlyList<NetworkMapNode> all = NetworkTopologyControl.GetVisibleNodes(
            map,
            TopologyFilterMode.All,
            out int allMatchingCount);
        Equal(map.Nodes.Count, allMatchingCount);
        Equal(
            string.Join(',', map.Nodes.Select(node => node.Id)),
            string.Join(',', all.Select(node => node.Id)));
    })),
    ("ARP neighbor table parsing", () => Sync(() =>
    {
        const string output =
            "Interface: 192.168.1.10 --- 0x5\n" +
            "  Internet Address      Physical Address      Type\n" +
            "  192.168.1.1           00-11-22-33-44-55     dynamic\n" +
            "  192.168.1.250         01-00-5e-00-00-01     static\n" +
            "192.168.1.20 dev eth0 lladdr 00:AA:BB:CC:DD:EE REACHABLE\n" +
            "999.168.1.30 dev eth0 lladdr 00:10:20:30:40:50 STALE\n";

        IReadOnlyDictionary<IPAddress, string> neighbors =
            MacAddressService.ParseNeighborTable(output);
        Equal(2, neighbors.Count);
        Equal("00:11:22:33:44:55", neighbors[IPAddress.Parse("192.168.1.1")]);
        Equal("00:AA:BB:CC:DD:EE", neighbors[IPAddress.Parse("192.168.1.20")]);
        True(!neighbors.ContainsKey(IPAddress.Parse("192.168.1.250")),
            "Uma entrada multicast não pode ser aceite como identidade ARP.");
    })),
    ("ARP scan session caches table and addresses", async () =>
    {
        int tableReads = 0;
        int activeResolutions = 0;
        MacAddressService service = new(
            (_, _) =>
            {
                Interlocked.Increment(ref tableReads);
                return Task.FromResult<string?>(
                    "192.168.1.20  00-11-22-33-44-55  dynamic");
            },
            (address, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>(address.Equals(IPAddress.Parse("192.168.1.30"))
                    ? "00-AA-BB-CC-DD-01"
                    : "01:00:5E:00:00:01");
            },
            maximumActiveConcurrency: 2);
        await using MacAddressService.ScanSession session =
            service.CreateScanSession(CreateInterface());

        IPAddress tableAddress = IPAddress.Parse("192.168.1.20");
        string?[] tableResults = await Task.WhenAll(
            session.ResolveAsync(tableAddress, CancellationToken.None),
            session.ResolveAsync(tableAddress, CancellationToken.None));
        True(tableResults.All(value => value == "00:11:22:33:44:55"),
            "A tabela de vizinhos deveria resolver o endereço sem SendARP.");

        IPAddress activeAddress = IPAddress.Parse("192.168.1.30");
        string?[] activeResults = await Task.WhenAll(
            session.ResolveAsync(activeAddress, CancellationToken.None),
            session.ResolveAsync(activeAddress, CancellationToken.None));
        True(activeResults.All(value => value == "00:AA:BB:CC:DD:01"),
            "A resolução ativa deveria ser normalizada e reutilizada.");

        IPAddress invalidAddress = IPAddress.Parse("192.168.1.40");
        Equal<string?>(null, await session.ResolveAsync(invalidAddress, CancellationToken.None));
        Equal<string?>(null, await session.ResolveAsync(invalidAddress, CancellationToken.None));
        Equal("00:AA:BB:CC:DD:EE",
            await session.ResolveAsync(CreateInterface().IpAddress, CancellationToken.None));
        Equal<string?>(null,
            await session.ResolveAsync(IPAddress.Parse("10.0.0.20"), CancellationToken.None));

        Equal(1, Volatile.Read(ref tableReads));
        Equal(2, Volatile.Read(ref activeResolutions));
    }),
    ("ARP scan session propagates cancellation", async () =>
    {
        int activeResolutions = 0;
        TaskCompletionSource tableStarted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();
        MacAddressService service = new(
            async (_, token) =>
            {
                tableStarted.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return null;
            },
            (_, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>(null);
            });
        await using MacAddressService.ScanSession session =
            service.CreateScanSession(CreateInterface(), cancellation.Token);

        Task<string?> resolution = session.ResolveAsync(
            IPAddress.Parse("192.168.1.50"),
            CancellationToken.None);
        await tableStarted.Task;
        cancellation.Cancel();
        await ThrowsAsync<OperationCanceledException>(async () => _ = await resolution);
        Equal(0, Volatile.Read(ref activeResolutions));
    }),
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
    ("Bundled IEEE vendor database integrity", () => Sync(() =>
    {
        const string resourceName = "LocalNetworkScanner.Core.Data.ieee-mac-vendors.tsv.gz";
        using Stream? resource = typeof(MacVendorService).Assembly.GetManifestResourceStream(resourceName);
        NotNull(resource);

        using MemoryStream compressed = new();
        resource!.CopyTo(compressed);
        string resourceHash = Convert.ToHexString(
            SHA256.HashData(compressed.ToArray())).ToLowerInvariant();
        Equal(
            "26ec00a8b4d3a965e79d031780d064263452ed319fad917b80ce305905605003",
            resourceHash);

        compressed.Position = 0;
        using GZipStream gzip = new(compressed, CompressionMode.Decompress);
        using StreamReader reader = new(gzip, new UTF8Encoding(false));
        Dictionary<string, string> metadata = new(StringComparer.Ordinal);
        Dictionary<string, int> registryCounts = new(StringComparer.Ordinal)
        {
            ["MA-L"] = 0,
            ["MA-M"] = 0,
            ["MA-S"] = 0,
            ["IAB"] = 0
        };
        Dictionary<string, int> prefixOccurrences = new(StringComparer.Ordinal);
        int entries = 0;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.StartsWith('#'))
            {
                int separator = line.IndexOf('=');
                if (separator > 2)
                    metadata[line[2..separator]] = line[(separator + 1)..];
                continue;
            }

            string[] columns = line.Split('\t', 3);
            Equal(3, columns.Length);
            True(registryCounts.ContainsKey(columns[0]), $"Registo IEEE inesperado: {columns[0]}.");
            int expectedPrefixLength = columns[0] switch
            {
                "MA-L" => 6,
                "MA-M" => 7,
                _ => 9
            };
            Equal(expectedPrefixLength, columns[1].Length);
            True(
                columns[1].All(character =>
                    character is >= '0' and <= '9' or >= 'A' and <= 'F'),
                $"Prefixo IEEE inválido: {columns[1]}.");
            True(!string.IsNullOrWhiteSpace(columns[2]), "A organização IEEE não pode estar vazia.");

            entries++;
            registryCounts[columns[0]]++;
            prefixOccurrences[columns[1]] =
                prefixOccurrences.GetValueOrDefault(columns[1]) + 1;
        }

        Equal(58_019, entries);
        Equal(58_016, prefixOccurrences.Count);
        Equal(39_829, registryCounts["MA-L"]);
        Equal(6_503, registryCounts["MA-M"]);
        Equal(7_112, registryCounts["MA-S"]);
        Equal(4_575, registryCounts["IAB"]);
        Equal("LocalNetworkScanner.IEEE-MAC-Vendors/v1", metadata["format"]);
        Equal("2026-07-28", metadata["snapshotDate"]);
        Equal("58019", metadata["entries"]);
        Equal("58016", metadata["uniquePrefixes"]);
        Equal(2, prefixOccurrences["0001C8"]);
        Equal(3, prefixOccurrences["080030"]);
        Equal(
            2,
            prefixOccurrences.Count(item => item.Value > 1));
    })),
    ("Bundled IEEE vendor lookup coverage", () => Sync(() =>
    {
        string missingOverride = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"),
            "missing-vendors.tsv.gz");
        MacVendorService service = new(missingOverride);

        Equal(false, service.HasExternalDatabase);
        Equal(false, service.DatabaseInfo.IsDegraded);
        Equal("Incorporada", service.DatabaseInfo.Source);
        Equal(new DateOnly(2026, 7, 28), service.DatabaseInfo.SnapshotDate);
        Equal(58_019, service.DatabaseInfo.EntryCount);
        Equal(58_016, service.DatabaseInfo.UniquePrefixCount);
        Equal(39_829, service.DatabaseInfo.RegistryCounts["MA-L"]);
        Equal(6_503, service.DatabaseInfo.RegistryCounts["MA-M"]);
        Equal(7_112, service.DatabaseInfo.RegistryCounts["MA-S"]);
        Equal(4_575, service.DatabaseInfo.RegistryCounts["IAB"]);

        MacVendorMatch? large = service.LookupDetailed("00:0C:29:12:34:56");
        NotNull(large);
        Equal("VMware, Inc.", large!.Organization);
        Equal("MA-L", large.Registry);
        Equal(24, large.PrefixLength);

        MacVendorMatch? medium = service.LookupDetailed("C8:5C:E2:7A:BC:DE");
        NotNull(medium);
        Equal("SYNERGY SYSTEMS AND SOLUTIONS", medium!.Organization);
        Equal("MA-M", medium.Registry);
        Equal(28, medium.PrefixLength);

        MacVendorMatch? small = service.LookupDetailed("8C:1F:64:AF:A1:23");
        NotNull(small);
        Equal("DATA ELECTRONIC DEVICES, INC", small!.Organization);
        Equal("MA-S", small.Registry);
        Equal(36, small.PrefixLength);

        MacVendorMatch? legacy = service.LookupDetailed("00:50:C2:00:31:23");
        NotNull(legacy);
        Equal("Microsoft", legacy!.Organization);
        Equal("IAB", legacy.Registry);
        Equal(36, legacy.PrefixLength);
    })),
    ("Vendor lookup uses the longest prefix and parses quoted Unicode CSV", () => Sync(() =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "vendors.csv");
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(
                path,
                "Registry,Assignment,Organization Name,Organization Address\n" +
                "MA-L,00FFEE,\"Parent, S.A. – Lisboa\",Portugal\n" +
                "MA-M,00FFEEA,\"Médio & Filhos\",Portugal\n" +
                "MA-S,00FFEEABC,\"Específico, Lda.\",Portugal\n" +
                "IAB,00FFEEABD,\"Legado, Lda.\",Portugal\n",
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            MacVendorService service = new(path);
            Equal(true, service.HasExternalDatabase);
            Equal(4, service.DatabaseInfo.EntryCount);
            Equal(4, service.DatabaseInfo.UniquePrefixCount);

            MacVendorMatch? small = service.LookupDetailed("00:FF:EE:AB:C0:01");
            NotNull(small);
            Equal("Específico, Lda.", small!.Organization);
            Equal("MA-S", small.Registry);
            Equal("00FFEEABC", small.Prefix);
            Equal(36, small.PrefixLength);

            MacVendorMatch? legacy = service.LookupDetailed("00:FF:EE:AB:D0:01");
            NotNull(legacy);
            Equal("Legado, Lda.", legacy!.Organization);
            Equal("IAB", legacy.Registry);

            MacVendorMatch? medium = service.LookupDetailed("00:FF:EE:AF:00:01");
            NotNull(medium);
            Equal("Médio & Filhos", medium!.Organization);
            Equal("MA-M", medium.Registry);
            Equal(28, medium.PrefixLength);

            MacVendorMatch? large = service.LookupDetailed("00:FF:EE:BF:00:01");
            NotNull(large);
            Equal("Parent, S.A. – Lisboa", large!.Organization);
            Equal("MA-L", large.Registry);
            Equal(24, large.PrefixLength);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    })),
    ("Historical vendor duplicates aggregate deterministically", () => Sync(() =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string firstPath = Path.Combine(directory, "duplicates-a.tsv");
        string secondPath = Path.Combine(directory, "duplicates-b.tsv");
        try
        {
            Directory.CreateDirectory(directory);
            string header = "Registry\tAssignment\tOrganization Name\n";
            File.WriteAllText(
                firstPath,
                header +
                "MA-L\t00FFEE\tÁrvore Networks\n" +
                "MA-L\t00FFEE\tZeta, S.A.\n" +
                "MA-L\t00FFEE\tÁrvore Networks\n",
                new UTF8Encoding(false));
            File.WriteAllText(
                secondPath,
                header +
                "MA-L\t00FFEE\tZeta, S.A.\n" +
                "MA-L\t00FFEE\tÁrvore Networks\n" +
                "MA-L\t00FFEE\tÁrvore Networks\n",
                new UTF8Encoding(false));

            MacVendorService first = new(firstPath);
            MacVendorService second = new(secondPath);
            const string macAddress = "00:FF:EE:12:34:56";
            string? firstOrganization = first.Lookup(macAddress);
            string? secondOrganization = second.Lookup(macAddress);

            Equal("Zeta, S.A. / Árvore Networks", firstOrganization);
            Equal(firstOrganization, secondOrganization);
            Equal(3, first.DatabaseInfo.EntryCount);
            Equal(1, first.DatabaseInfo.UniquePrefixCount);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    })),
    ("Vendor lookup rejects non-global MAC identities", () => Sync(() =>
    {
        string missingOverride = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"),
            "missing-vendors.tsv.gz");
        MacVendorService service = new(missingOverride);

        Equal("MAC privado/aleatório", service.Lookup("02:00:00:00:00:01"));
        Equal<string?>(null, service.LookupDetailed("02:00:00:00:00:01")?.Organization);
        Equal<string?>(null, service.Lookup("01:00:5E:00:00:01"));
        Equal<string?>(null, service.Lookup("not-a-mac"));
        Equal<string?>(null, service.Lookup("00:00:00:00:00:00"));
        Equal<string?>(null, service.Lookup("FF:FF:FF:FF:FF:FF"));
    })),
    ("Corrupt external vendor database falls back to bundled snapshot", () => Sync(() =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "vendors.tsv");
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(
                path,
                "Registry\tAssignment\tOrganization Name\n" +
                "MA-L\tINVALID\tCorrupt entry\n",
                new UTF8Encoding(false));

            MacVendorService service = new(path);
            Equal(false, service.HasExternalDatabase);
            Equal("Incorporada", service.DatabaseInfo.Source);
            Equal(false, service.DatabaseInfo.IsDegraded);
            True(
                !string.IsNullOrWhiteSpace(service.ExternalDatabaseError),
                "A rejeição da base externa deveria ficar disponível para diagnóstico.");
            Equal("VMware, Inc.", service.Lookup("00:0C:29:12:34:56"));
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    })),
    ("Vendor lookups are safe under concurrency", async () =>
    {
        string missingOverride = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"),
            "missing-vendors.tsv.gz");
        MacVendorService service = new(missingOverride);
        string?[] results = await Task.WhenAll(
            Enumerable.Range(0, 512).Select(index => Task.Run(() =>
                (index % 4) switch
                {
                    0 => service.Lookup("00:0C:29:12:34:56"),
                    1 => service.Lookup("C8:5C:E2:7A:BC:DE"),
                    2 => service.Lookup("8C:1F:64:AF:A1:23"),
                    _ => service.Lookup("00:50:C2:00:31:23")
                })));

        Equal(128, results.Count(value => value == "VMware, Inc."));
        Equal(128, results.Count(value => value == "SYNERGY SYSTEMS AND SOLUTIONS"));
        Equal(128, results.Count(value => value == "DATA ELECTRONIC DEVICES, INC"));
        Equal(128, results.Count(value => value == "Microsoft"));
    }),
    ("Optional IEEE update is complete and atomic", async () =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string databasePath = Path.Combine(directory, "vendor-database.tsv.gz");
        IReadOnlyList<OuiDatabaseSource> sources =
        [
            new(
                "MA-L",
                "mal.csv",
                "https://fixtures.invalid/mal.csv",
                6,
                1,
                10,
                4_096),
            new(
                "MA-M",
                "mam.csv",
                "https://fixtures.invalid/mam.csv",
                7,
                1,
                10,
                4_096),
            new(
                "MA-S",
                "mas.csv",
                "https://fixtures.invalid/mas.csv",
                9,
                1,
                10,
                4_096),
            new(
                "IAB",
                "iab.csv",
                "https://fixtures.invalid/iab.csv",
                9,
                1,
                10,
                4_096)
        ];
        Dictionary<string, string> initialBodies = new(StringComparer.Ordinal)
        {
            ["/mal.csv"] = VendorCsv("MA-L", "00FFEE", "Inicial MA-L"),
            ["/mam.csv"] = VendorCsv("MA-M", "00FFEEA", "Inicial MA-M"),
            ["/mas.csv"] = VendorCsv("MA-S", "00FFEEABC", "Inicial,\nMA-S"),
            ["/iab.csv"] = VendorCsv("IAB", "00FFEEABD", "Inicial IAB")
        };

        try
        {
            Directory.CreateDirectory(directory);
            List<string> requests = [];
            using HttpClient initialClient = new(new StubHttpMessageHandler(
                (request, _) =>
                {
                    string path = request.RequestUri!.AbsolutePath;
                    requests.Add(path);
                    return Task.FromResult(CsvResponse(initialBodies[path]));
                }));
            OuiDatabaseService initialUpdater = new(
                initialClient,
                databasePath,
                sources);
            string updatedPath = await initialUpdater.UpdateAsync();

            Equal(Path.GetFullPath(databasePath), updatedPath);
            Equal(true, File.Exists(databasePath));
            Equal(4, requests.Count);
            Equal(4, requests.Distinct(StringComparer.Ordinal).Count());
            True(
                initialClient.DefaultRequestHeaders.UserAgent.Any(item =>
                    item.Product?.Name == ProductIdentity.Name),
                "O updater deveria identificar o produto no User-Agent.");
            Equal(0, Directory.GetDirectories(directory, ".vendor-update-*").Length);

            MacVendorService updated = new(databasePath);
            Equal(true, updated.HasExternalDatabase);
            Equal(4, updated.DatabaseInfo.EntryCount);
            Equal(4, updated.DatabaseInfo.UniquePrefixCount);
            Equal("Inicial, MA-S", updated.Lookup("00:FF:EE:AB:C0:01"));
            Equal("Inicial MA-M", updated.Lookup("00:FF:EE:AF:00:01"));
            Equal("Inicial MA-L", updated.Lookup("00:FF:EE:BF:00:01"));
            Equal("Inicial IAB", updated.Lookup("00:FF:EE:AB:D0:01"));
            Throws<InvalidDataException>(() =>
                MacVendorService.ValidateCompleteDatabaseFile(databasePath, "Teste parcial"));

            byte[] originalDatabase = await File.ReadAllBytesAsync(databasePath);
            Dictionary<string, string> replacementBodies = new(StringComparer.Ordinal)
            {
                ["/mal.csv"] = VendorCsv("MA-L", "00FFEE", "Substituição MA-L"),
                ["/mam.csv"] = VendorCsv("MA-M", "00FFEEA", "Substituição MA-M"),
                ["/mas.csv"] = VendorCsv("MA-S", "00FFEEABC", "Substituição MA-S"),
                ["/iab.csv"] = VendorCsv("IAB", "00FFEEABD", "Substituição IAB")
            };
            using HttpClient failingClient = new(new StubHttpMessageHandler(
                (request, _) =>
                {
                    string path = request.RequestUri!.AbsolutePath;
                    if (path == "/mas.csv")
                    {
                        return Task.FromResult(
                            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
                    }

                    return Task.FromResult(CsvResponse(replacementBodies[path]));
                }));
            OuiDatabaseService failingUpdater = new(
                failingClient,
                databasePath,
                sources,
                Path.Combine(directory, "legacy-oui.csv"));

            await ThrowsAsync<HttpRequestException>(() => failingUpdater.UpdateAsync());
            Equal(
                Convert.ToHexString(SHA256.HashData(originalDatabase)),
                Convert.ToHexString(SHA256.HashData(
                    await File.ReadAllBytesAsync(databasePath))));
            Equal(0, Directory.GetDirectories(directory, ".vendor-update-*").Length);
            Equal(
                "Inicial, MA-S",
                new MacVendorService(databasePath).Lookup("00:FF:EE:AB:C0:01"));

            string legacyPath = Path.Combine(directory, "legacy-oui.csv");
            await File.WriteAllTextAsync(
                legacyPath,
                VendorCsv("MA-L", "001122", "Legado"));
            Equal(true, failingUpdater.ResetLocalDatabase());
            Equal(false, File.Exists(databasePath));
            Equal(false, File.Exists(legacyPath));
            Equal(false, failingUpdater.ResetLocalDatabase());
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
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
    ("mDNS compressed DNS-SD records preserve typed evidence", () => Sync(() =>
    {
        byte[] packet = BuildCompressedDnsSdResponse();
        True(
            MdnsDiscoveryService.IsValidResponse(packet, sourcePort: 5353),
            "Uma resposta mDNS autoritativa com ID zero e origem 5353 deveria ser aceite.");

        byte[] queryPacket = (byte[])packet.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(queryPacket.AsSpan(2, 2), 0);
        True(!MdnsDiscoveryService.IsValidResponse(queryPacket, sourcePort: 5353),
            "Uma query UDP não pode ser acumulada como resposta mDNS.");

        byte[] foreignTransaction = (byte[])packet.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(foreignTransaction.AsSpan(0, 2), 7);
        True(!MdnsDiscoveryService.IsValidResponse(foreignTransaction, sourcePort: 5353),
            "Uma transação alheia não pode ser acumulada.");

        byte[] unsupportedOpcode = (byte[])packet.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(unsupportedOpcode.AsSpan(2, 2), 0x8800);
        True(!MdnsDiscoveryService.IsValidResponse(unsupportedOpcode, sourcePort: 5353),
            "Um opcode DNS não suportado deve ser rejeitado.");
        True(!MdnsDiscoveryService.IsValidResponse(packet, sourcePort: 9999),
            "A resposta deve ter origem na porta mDNS.");

        MdnsDiscoveryService.MdnsMessage message = MdnsDiscoveryService.ParseMessage(packet);

        Equal(5, message.Records.Count);

        MdnsDiscoveryService.MdnsResourceRecord pointer =
            message.Records.Single(record => record.Type == 12);
        Equal("_ipp._tcp.local", pointer.Owner);
        Equal("Office Printer._ipp._tcp.local", pointer.DomainName);
        Equal((ushort)1, pointer.RecordClass);
        Equal(120u, pointer.TimeToLive);

        MdnsDiscoveryService.MdnsResourceRecord service =
            message.Records.Single(record => record.Type == 33);
        Equal("Office Printer._ipp._tcp.local", service.Owner);
        Equal("printer.local", service.DomainName);
        Equal((ushort?)631, service.Port);
        Equal((ushort?)0, service.Priority);
        Equal((ushort?)5, service.Weight);

        MdnsDiscoveryService.MdnsResourceRecord text =
            message.Records.Single(record => record.Type == 16);
        NotNull(text.Text);
        Equal("ty=Laser,note=Lab", string.Join(',', text.Text!));

        MdnsDiscoveryService.MdnsResourceRecord ipv4 =
            message.Records.Single(record => record.Type == 1);
        Equal((ushort)1, ipv4.RecordClass);
        Equal(0u, ipv4.TimeToLive);
        Equal(IPAddress.Parse("192.168.1.50"), ipv4.Address);

        MdnsDiscoveryService.MdnsResourceRecord ipv6 =
            message.Records.Single(record => record.Type == 28);
        Equal(IPAddress.Parse("fd00::50"), ipv6.Address);
        Equal(60u, ipv6.TimeToLive);

        IReadOnlyList<(IPAddress Address, string? Hostname)> addresses =
            MdnsDiscoveryService.ParseAddressRecords(packet);
        Equal(2, addresses.Count);
        True(
            addresses.Any(record =>
                record.Address.Equals(IPAddress.Parse("192.168.1.50")) &&
                record.Hostname == "printer.local"),
            "O registo A comprimido deveria manter o hostname.");
        True(
            addresses.Any(record =>
                record.Address.Equals(IPAddress.Parse("fd00::50")) &&
                record.Hostname == "printer.local"),
            "O registo AAAA comprimido deveria manter o hostname.");

        IReadOnlyList<DiscoveryObservation> observations =
            MdnsDiscoveryService.CorrelateRecords(message.Records);
        Equal(2, observations.Count);
        Equal(IPAddress.Parse("fd00::50"), observations[0].IpAddress);
        Equal("printer.local", observations[0].Hostname);
        Equal("Office Printer._ipp._tcp.local", observations[1].Hostname);
        True(
            observations.All(observation =>
                !observation.IpAddress.Equals(IPAddress.Parse("192.168.1.50"))),
            "Um registo com TTL zero não pode criar uma observação final.");

        MdnsDiscoveryService.MdnsResourceRecord addressEvidence = new(
            "camera.local",
            1,
            1,
            120,
            Address: IPAddress.Parse("192.168.1.80"));
        MdnsDiscoveryService.MdnsResourceRecord serviceEvidence = new(
            "Front Door._rtsp._tcp.local",
            33,
            1,
            120,
            DomainName: "camera.local",
            Port: 554);
        MdnsDiscoveryService.MdnsResourceRecord serviceGoodbye =
            serviceEvidence with { TimeToLive = 0 };
        IReadOnlyList<DiscoveryObservation> hostOnly =
            MdnsDiscoveryService.CorrelateRecords(
                [addressEvidence, serviceEvidence, serviceGoodbye]);
        Equal(1, hostOnly.Count);
        Equal("camera.local", hostOnly[0].Hostname);

        MdnsDiscoveryService.MdnsResourceRecord addressGoodbye =
            addressEvidence with { TimeToLive = 0 };
        Equal(
            0,
            MdnsDiscoveryService.CorrelateRecords(
                [addressEvidence, serviceEvidence, addressGoodbye]).Count);
    })),
    ("mDNS parser and query limits fail closed", () => Sync(() =>
    {
        byte[] excessiveQuestions = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(excessiveQuestions.AsSpan(4, 2), 65);
        Equal(0, MdnsDiscoveryService.ParseMessage(excessiveQuestions).Records.Count);

        byte[] excessiveRecords = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(excessiveRecords.AsSpan(6, 2), 257);
        Equal(0, MdnsDiscoveryService.ParseMessage(excessiveRecords).Records.Count);

        byte[] oversizedPacket = new byte[(16 * 1024) + 1];
        Equal(0, MdnsDiscoveryService.ParseMessage(oversizedPacket).Records.Count);

        byte[] cyclicPointer = new byte[18];
        BinaryPrimitives.WriteUInt16BigEndian(cyclicPointer.AsSpan(4, 2), 1);
        cyclicPointer[12] = 0xC0;
        cyclicPointer[13] = 0x0C;
        Equal(0, MdnsDiscoveryService.ParseMessage(cyclicPointer).Records.Count);

        byte[] truncatedPointer = new byte[13];
        BinaryPrimitives.WriteUInt16BigEndian(truncatedPointer.AsSpan(4, 2), 1);
        truncatedPointer[12] = 0xC0;
        Equal(0, MdnsDiscoveryService.ParseMessage(truncatedPointer).Records.Count);

        Throws<ArgumentException>(() => MdnsDiscoveryService.BuildQuery(" "));
        Throws<ArgumentOutOfRangeException>(() =>
            MdnsDiscoveryService.BuildQuery("_ipp._tcp.local", 0));
        Throws<ArgumentException>(() =>
            MdnsDiscoveryService.BuildQuery($"{new string('a', 64)}.local"));
        Throws<ArgumentException>(() =>
            MdnsDiscoveryService.BuildQuery(
                string.Join('.', Enumerable.Repeat(new string('a', 63), 4))));

        byte[] serviceQuery = MdnsDiscoveryService.BuildQuery("_ipp._tcp.local.", 33);
        Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(serviceQuery.AsSpan(4, 2)));
        Equal((ushort)33, BinaryPrimitives.ReadUInt16BigEndian(
            serviceQuery.AsSpan(serviceQuery.Length - 4, 2)));
        Equal((ushort)0x8001, BinaryPrimitives.ReadUInt16BigEndian(
            serviceQuery.AsSpan(serviceQuery.Length - 2, 2)));

        byte[] pointerQuery = MdnsDiscoveryService.BuildQuery("_ipp._tcp.local");
        Equal((ushort)12, BinaryPrimitives.ReadUInt16BigEndian(
            pointerQuery.AsSpan(pointerQuery.Length - 4, 2)));
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
    ("History preserves identity across IP and MAC transitions", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        try
        {
            NetworkHistoryService history = new(directory);
            DateTimeOffset firstSeen = new(2026, 7, 20, 10, 0, 0, TimeSpan.Zero);
            NetworkDevice first = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.40"),
                Hostname = "printer",
                FirstSeen = firstSeen,
                LastSeen = firstSeen
            };
            await history.ApplyAndSaveAsync(CreateResult([first], firstSeen));

            NetworkDevice gainedMac = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.40"),
                Hostname = "printer",
                MacAddress = "00:11:22:33:44:55",
                FirstSeen = firstSeen.AddHours(1),
                LastSeen = firstSeen.AddHours(1)
            };
            await history.ApplyAndSaveAsync(CreateResult([gainedMac], firstSeen.AddHours(1)));
            Equal(false, gainedMac.IsNew);
            Equal(firstSeen, gainedMac.FirstSeen);

            NetworkDevice movedIp = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.41"),
                Hostname = "printer",
                MacAddress = "00:11:22:33:44:55",
                FirstSeen = firstSeen.AddHours(2),
                LastSeen = firstSeen.AddHours(2)
            };
            await history.ApplyAndSaveAsync(CreateResult([movedIp], firstSeen.AddHours(2)));
            Equal(false, movedIp.IsNew);
            Equal(firstSeen, movedIp.FirstSeen);
            True(movedIp.Changes.Any(change => change.Contains("IP mudou", StringComparison.Ordinal)),
                "Uma mudança de IP do mesmo MAC deveria ficar registada.");

            NetworkDevice reusedIp = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.41"),
                Hostname = "other-device",
                MacAddress = "00:11:22:33:44:66",
                FirstSeen = firstSeen.AddHours(3),
                LastSeen = firstSeen.AddHours(3)
            };
            await history.ApplyAndSaveAsync(CreateResult([reusedIp], firstSeen.AddHours(3)));
            Equal(true, reusedIp.IsNew);
            Equal(firstSeen.AddHours(3), reusedIp.FirstSeen);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("History migrates network anchors and clears only its files", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        try
        {
            NetworkHistoryService history = new(directory);
            DateTimeOffset capturedAt = new(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);
            NetworkDevice gatewayWithoutMac = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.1"),
                Hostname = "gateway"
            };
            NetworkDevice stableClient = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.20"),
                MacAddress = "00:11:22:33:44:55",
                FirstSeen = capturedAt,
                LastSeen = capturedAt
            };
            await history.ApplyAndSaveAsync(
                CreateResult([gatewayWithoutMac, stableClient], capturedAt));

            NetworkDevice gatewayWithMac = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.1"),
                Hostname = "gateway",
                MacAddress = "00:AA:BB:CC:DD:01"
            };
            NetworkDevice sameClient = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.20"),
                MacAddress = "00:11:22:33:44:55",
                FirstSeen = capturedAt.AddHours(1),
                LastSeen = capturedAt.AddHours(1)
            };
            await history.ApplyAndSaveAsync(
                CreateResult([gatewayWithMac, sameClient], capturedAt.AddHours(1)));
            Equal(false, sameClient.IsNew);
            Equal(capturedAt, sameClient.FirstSeen);
            Equal(1, Directory.GetFiles(directory, "*.json").Length);

            string unrelated = Path.Combine(directory, "keep.txt");
            string temporary = Directory.GetFiles(directory, "*.json").Single() + ".tmp-orphan";
            await File.WriteAllTextAsync(unrelated, "keep");
            await File.WriteAllTextAsync(temporary, "temporary");
            Equal(2, await history.ClearAsync());
            Equal(false, Directory.EnumerateFiles(directory, "*.json").Any());
            Equal(true, File.Exists(unrelated));
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("Device metadata follows MAC and rejects IP reuse", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "devices.json");
        try
        {
            using DeviceMetadataService metadata = new(path);
            NetworkDevice original = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.30"),
                MacAddress = "00:10:20:30:40:50",
                Alias = "NAS principal",
                Notes = "Armário técnico",
                IsFavorite = true
            };
            await metadata.SaveAsync(original, "192.168.1.0/24");

            NetworkDevice moved = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.31"),
                MacAddress = "00:10:20:30:40:50"
            };
            NetworkScanResult movedResult = CreateResult([moved], DateTimeOffset.UtcNow);
            await metadata.ApplyAsync(movedResult);
            Equal("NAS principal", moved.Alias);
            Equal("Armário técnico", moved.Notes);
            Equal(true, moved.IsFavorite);

            NetworkDevice reusedIp = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.30"),
                MacAddress = "00:10:20:30:40:60"
            };
            await metadata.ApplyAsync(CreateResult([reusedIp], DateTimeOffset.UtcNow.AddMinutes(1)));
            Equal<string?>(null, reusedIp.Alias);
            Equal(false, reusedIp.IsFavorite);
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
            result.Devices[0].Ports =
            [
                new PortScanResult { Port = 443 },
                new PortScanResult
                {
                    Port = 8443,
                    TlsStatus = TlsProbeStatus.HandshakeSucceeded,
                    TlsProtocol = "TLS 1.3"
                }
            ];
            await new ExportService().ExportJsonAsync(result, path);

            await using FileStream stream = File.OpenRead(path);
            using JsonDocument document = await JsonDocument.ParseAsync(stream);
            JsonElement root = document.RootElement;
            Equal(4, root.GetProperty("schemaVersion").GetInt32());
            JsonElement diagnostics = root.GetProperty("scan").GetProperty("diagnostics");
            Equal(1, diagnostics.GetArrayLength());
            Equal(DiagnosticCatalog.InvalidMacAddressCode,
                diagnostics[0].GetProperty("code").GetString());
            True(diagnostics[0].GetProperty("recommendedAction").GetString()?.Length > 0,
                "O JSON deve incluir a ação recomendada.");
            JsonElement ports = root.GetProperty("devices")[0].GetProperty("ports");
            Equal("NotProbed", ports[0].GetProperty("TlsStatus").GetString());
            Equal(JsonValueKind.Null, ports[0].GetProperty("IsEncrypted").ValueKind);
            Equal("HandshakeSucceeded", ports[1].GetProperty("TlsStatus").GetString());
            Equal(true, ports[1].GetProperty("IsEncrypted").GetBoolean());
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
    ("Support export excludes network identifiers", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "support.json");
        try
        {
            NetworkScanResult result = CreateTopologyExportResult();
            result.Devices[0].Hostname = "host-secret.example";
            result.Devices[0].Notes = "note-secret";
            result.NetworkInterface.Ssid = "ssid-secret";
            result.NetworkInterface.Bssid = "02:AA:BB:CC:DD:EE";

            await new ExportService().ExportSupportJsonAsync(result, path);
            string json = await File.ReadAllTextAsync(path);
            foreach (string secret in new[]
                     {
                         "192.168.1.",
                         "00:11:22:33:44:55",
                         "00:AA:BB:CC:DD:EE",
                         "02:AA:BB:CC:DD:EE",
                         "printer <lab>&",
                         "host-secret.example",
                         "note-secret",
                         "ssid-secret",
                         "Interface de teste",
                         "invalid-mac"
                     })
            {
                True(!json.Contains(secret, StringComparison.OrdinalIgnoreCase),
                    $"O relatório de suporte expôs o identificador '{secret}'.");
            }

            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            Equal(1, root.GetProperty("schemaVersion").GetInt32());
            Equal("LocalNetworkScanner.Support", root.GetProperty("reportType").GetString());
            Equal(false, root.GetProperty("privacy").GetProperty("containsNetworkIdentifiers").GetBoolean());
            Equal(1, root.GetProperty("devices").GetProperty("total").GetInt32());
            Equal(
                DiagnosticCatalog.InvalidMacAddressCode,
                root.GetProperty("diagnostics")[0].GetProperty("code").GetString());
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

if (tests.Count == 0)
{
    Console.Error.WriteLine("FAIL  A suite de testes não contém casos registados.");
    return 1;
}

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

static NetworkScanResult CreateResult(
    IReadOnlyList<NetworkDevice> devices,
    DateTimeOffset completedAt) => new()
    {
        NetworkInterface = CreateInterface(),
        StartedAt = completedAt.AddSeconds(-1),
        CompletedAt = completedAt,
        AddressesScanned = Math.Max(1, devices.Count),
        Devices = devices
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

static byte[] BuildCompressedDnsSdResponse()
{
    using MemoryStream stream = new();
    byte[] header = new byte[12];
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2, 2), 0x8400);
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), 5);
    stream.Write(header);

    List<(int LengthOffset, int DataOffset, int DataEnd)> recordData = [];

    int serviceTypeOffset = checked((int)stream.Position);
    WriteDnsName(stream, "_ipp", "_tcp", "local");
    int pointerLengthOffset = WriteDnsRecordHeader(
        stream,
        type: 12,
        recordClass: 0x8001,
        timeToLive: 120);
    int pointerDataOffset = checked((int)stream.Position);
    WriteDnsLabel(stream, "Office Printer");
    WriteDnsPointer(stream, serviceTypeOffset);
    recordData.Add((
        pointerLengthOffset,
        pointerDataOffset,
        checked((int)stream.Position)));

    int instanceOffset = checked((int)stream.Position);
    WriteDnsLabel(stream, "Office Printer");
    WriteDnsPointer(stream, serviceTypeOffset);
    int serviceLengthOffset = WriteDnsRecordHeader(
        stream,
        type: 33,
        recordClass: 0x8001,
        timeToLive: 120);
    int serviceDataOffset = checked((int)stream.Position);
    WriteDnsUInt16(stream, 0);
    WriteDnsUInt16(stream, 5);
    WriteDnsUInt16(stream, 631);
    int hostOffset = checked((int)stream.Position);
    WriteDnsName(stream, "printer", "local");
    recordData.Add((
        serviceLengthOffset,
        serviceDataOffset,
        checked((int)stream.Position)));

    WriteDnsPointer(stream, instanceOffset);
    int textLengthOffset = WriteDnsRecordHeader(
        stream,
        type: 16,
        recordClass: 0x8001,
        timeToLive: 120);
    int textDataOffset = checked((int)stream.Position);
    WriteDnsText(stream, "ty=Laser");
    WriteDnsText(stream, "note=Lab");
    recordData.Add((
        textLengthOffset,
        textDataOffset,
        checked((int)stream.Position)));

    WriteDnsPointer(stream, hostOffset);
    int addressLengthOffset = WriteDnsRecordHeader(
        stream,
        type: 1,
        recordClass: 0x8001,
        timeToLive: 0);
    int addressDataOffset = checked((int)stream.Position);
    stream.Write(IPAddress.Parse("192.168.1.50").GetAddressBytes());
    recordData.Add((
        addressLengthOffset,
        addressDataOffset,
        checked((int)stream.Position)));

    WriteDnsPointer(stream, hostOffset);
    int addressV6LengthOffset = WriteDnsRecordHeader(
        stream,
        type: 28,
        recordClass: 1,
        timeToLive: 60);
    int addressV6DataOffset = checked((int)stream.Position);
    stream.Write(IPAddress.Parse("fd00::50").GetAddressBytes());
    recordData.Add((
        addressV6LengthOffset,
        addressV6DataOffset,
        checked((int)stream.Position)));

    byte[] packet = stream.ToArray();
    foreach ((int lengthOffset, int dataOffset, int dataEnd) in recordData)
    {
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(lengthOffset, 2),
            checked((ushort)(dataEnd - dataOffset)));
    }

    return packet;
}

static int WriteDnsRecordHeader(
    MemoryStream stream,
    ushort type,
    ushort recordClass,
    uint timeToLive)
{
    WriteDnsUInt16(stream, type);
    WriteDnsUInt16(stream, recordClass);
    Span<byte> ttl = stackalloc byte[4];
    BinaryPrimitives.WriteUInt32BigEndian(ttl, timeToLive);
    stream.Write(ttl);
    int lengthOffset = checked((int)stream.Position);
    WriteDnsUInt16(stream, 0);
    return lengthOffset;
}

static void WriteDnsName(MemoryStream stream, params string[] labels)
{
    foreach (string label in labels)
        WriteDnsLabel(stream, label);

    stream.WriteByte(0);
}

static void WriteDnsLabel(MemoryStream stream, string label)
{
    byte[] bytes = Encoding.UTF8.GetBytes(label);
    stream.WriteByte(checked((byte)bytes.Length));
    stream.Write(bytes);
}

static void WriteDnsPointer(MemoryStream stream, int offset)
{
    True(offset is >= 0 and < 0x4000, "O offset DNS deve caber num ponteiro comprimido.");
    WriteDnsUInt16(stream, checked((ushort)(0xC000 | offset)));
}

static void WriteDnsText(MemoryStream stream, string text)
{
    byte[] bytes = Encoding.UTF8.GetBytes(text);
    stream.WriteByte(checked((byte)bytes.Length));
    stream.Write(bytes);
}

static void WriteDnsUInt16(MemoryStream stream, ushort value)
{
    Span<byte> buffer = stackalloc byte[2];
    BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
    stream.Write(buffer);
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

static string VendorCsv(string registry, string assignment, string organization) =>
    "Registry,Assignment,Organization Name,Organization Address\n" +
    $"{registry},{assignment},\"{organization.Replace("\"", "\"\"", StringComparison.Ordinal)}\"," +
    "\"Rua de Teste, Lisboa\"\n";

static HttpResponseMessage CsvResponse(string body) => new(HttpStatusCode.OK)
{
    Content = new StringContent(
        body,
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        "text/csv")
};

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

internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<
        HttpRequestMessage,
        CancellationToken,
        Task<HttpResponseMessage>> _handler;

    public StubHttpMessageHandler(
        Func<
            HttpRequestMessage,
            CancellationToken,
            Task<HttpResponseMessage>> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _handler = handler;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken) =>
        _handler(request, cancellationToken);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
