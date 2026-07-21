using System.Collections.Concurrent;
using System.Net;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class NetworkScannerService
{
    private readonly PingScannerService _pingScanner;
    private readonly HostnameResolverService _hostnameResolver;
    private readonly PortScannerService _portScanner;
    private readonly MacAddressService _macAddressService;
    private readonly MacVendorService _macVendorService;
    private readonly LocalDiscoveryService _localDiscoveryService;
    private readonly TopologyInferenceService _topologyInferenceService;
    private readonly DeviceClassifierService _deviceClassifierService;
    private readonly SecurityAssessmentService _securityAssessmentService;
    private readonly NetBiosDiscoveryService _netBiosDiscoveryService;
    private readonly SnmpTopologyService _snmpTopologyService;

    public NetworkScannerService(
        PingScannerService? pingScanner = null,
        HostnameResolverService? hostnameResolver = null,
        PortScannerService? portScanner = null,
        MacAddressService? macAddressService = null,
        MacVendorService? macVendorService = null,
        LocalDiscoveryService? localDiscoveryService = null,
        TopologyInferenceService? topologyInferenceService = null,
        DeviceClassifierService? deviceClassifierService = null,
        SecurityAssessmentService? securityAssessmentService = null,
        NetBiosDiscoveryService? netBiosDiscoveryService = null,
        SnmpTopologyService? snmpTopologyService = null)
    {
        _pingScanner = pingScanner ?? new PingScannerService();
        _hostnameResolver = hostnameResolver ?? new HostnameResolverService();
        _portScanner = portScanner ?? new PortScannerService();
        _macAddressService = macAddressService ?? new MacAddressService();
        _macVendorService = macVendorService ?? new MacVendorService();
        _localDiscoveryService = localDiscoveryService ?? new LocalDiscoveryService();
        _topologyInferenceService = topologyInferenceService ?? new TopologyInferenceService();
        _deviceClassifierService = deviceClassifierService ?? new DeviceClassifierService();
        _securityAssessmentService = securityAssessmentService ?? new SecurityAssessmentService();
        _netBiosDiscoveryService = netBiosDiscoveryService ?? new NetBiosDiscoveryService();
        _snmpTopologyService = snmpTopologyService ?? new SnmpTopologyService();
    }

    public async Task<NetworkScanResult> ScanAsync(
        IReadOnlyList<IPAddress> addresses,
        LocalNetworkInterface networkInterface,
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        ArgumentNullException.ThrowIfNull(networkInterface);
        ArgumentNullException.ThrowIfNull(options);
        ScanRequestValidator.Validate(addresses, options);

        DateTimeOffset startedAt = DateTimeOffset.UtcNow;
        ConcurrentDictionary<IPAddress, NetworkDevice> devices = [];
        HashSet<IPAddress> allowedAddresses = addresses.ToHashSet();
        int completedHosts = 0;
        int onlineHosts = 0;

        Task<IReadOnlyList<DiscoveryObservation>> multicastTask = options.EnableMulticastDiscovery
            ? _localDiscoveryService.DiscoverAsync(
                options.DiscoveryTimeoutMs,
                networkInterface.IpAddress,
                cancellationToken)
            : Task.FromResult<IReadOnlyList<DiscoveryObservation>>([]);

        ParallelOptions discoveryOptions = new()
        {
            MaxDegreeOfParallelism = Math.Max(1, options.MaximumHostConcurrency),
            CancellationToken = cancellationToken
        };

        progress?.Report(new ScanProgress(
            "Descoberta",
            0,
            addresses.Count,
            0,
            "A combinar ICMP, TCP, ARP, mDNS e SSDP..."));

        await Parallel.ForEachAsync(addresses, discoveryOptions, async (address, token) =>
        {
            NetworkDevice? device = null;
            if (address.Equals(networkInterface.IpAddress))
            {
                device = CreateOnlineDevice(address, DiscoveryMethod.LocalHost);
            }
            else
            {
                Task<PingProbeResult> pingTask = options.EnableIcmp
                    ? _pingScanner.ProbeAsync(address, options.PingTimeoutMs, token)
                    : Task.FromResult(new PingProbeResult(false, null, null));
                Task<int?> tcpTask = options.EnableTcpDiscovery
                    ? _portScanner.FindAnyOpenPortAsync(
                        address,
                        options.DiscoveryPorts,
                        options.ConnectTimeoutMs,
                        networkInterface.IpAddress,
                        token)
                    : Task.FromResult<int?>(null);
                Task<string?> arpTask = options.EnableArp
                    ? _macAddressService.ResolveAsync(address, networkInterface, token)
                    : Task.FromResult<string?>(null);

                await Task.WhenAll(pingTask, tcpTask, arpTask);
                PingProbeResult ping = await pingTask;
                int? discoveryPort = await tcpTask;
                string? discoveredMac = await arpTask;

                if (ping.Success || discoveryPort.HasValue || !string.IsNullOrWhiteSpace(discoveredMac))
                {
                    DiscoveryMethod methods = DiscoveryMethod.None;
                    if (ping.Success)
                        methods |= DiscoveryMethod.Icmp;
                    if (discoveryPort.HasValue)
                        methods |= DiscoveryMethod.Tcp;
                    if (!string.IsNullOrWhiteSpace(discoveredMac))
                        methods |= DiscoveryMethod.Arp;

                    device = CreateOnlineDevice(address, methods);
                    device.ResponseTimeMs = ping.RoundtripTimeMs;
                    device.ReplyTtl = ping.ReplyTtl;
                    device.MacAddress = discoveredMac;
                }
            }

            if (device is not null && devices.TryAdd(address, device))
                Interlocked.Increment(ref onlineHosts);

            int completed = Interlocked.Increment(ref completedHosts);
            if (device is not null || completed == addresses.Count || completed % Math.Max(1, addresses.Count / 100) == 0)
            {
                progress?.Report(new ScanProgress(
                    "Descoberta",
                    completed,
                    addresses.Count,
                    Volatile.Read(ref onlineHosts),
                    device is null ? $"A analisar {address}" : $"Encontrado {address}",
                    device));
            }
        });

        foreach (DiscoveryObservation observation in await multicastTask)
        {
            if (!allowedAddresses.Contains(observation.IpAddress))
                continue;

            NetworkDevice device = devices.GetOrAdd(observation.IpAddress, address =>
            {
                Interlocked.Increment(ref onlineHosts);
                return CreateOnlineDevice(address, observation.Method);
            });
            device.DiscoveryMethods |= observation.Method;

            if (observation.Method == DiscoveryMethod.Mdns && !string.IsNullOrWhiteSpace(observation.Hostname))
            {
                if (!device.MdnsNames.Contains(observation.Hostname, StringComparer.OrdinalIgnoreCase))
                    device.MdnsNames.Add(observation.Hostname);
                device.Hostname ??= observation.Hostname;
            }

            if (observation.Method == DiscoveryMethod.Ssdp)
            {
                device.SsdpServer ??= observation.Server;
                device.SsdpLocation ??= observation.Location;
            }

            if (observation.Method == DiscoveryMethod.WsDiscovery)
            {
                device.WsDiscoveryTypes ??= observation.Server;
                device.WsDiscoveryAddresses ??= observation.Location;
            }
        }

        List<NetworkDevice> onlineDevices = devices.Values.ToList();
        int enriched = 0;
        ParallelOptions enrichmentOptions = new()
        {
            MaxDegreeOfParallelism = Math.Min(16, Math.Max(1, options.MaximumHostConcurrency)),
            CancellationToken = cancellationToken
        };

        await Parallel.ForEachAsync(onlineDevices, enrichmentOptions, async (device, token) =>
        {
            Task<string?> hostnameTask = device.DiscoveryMethods.HasFlag(DiscoveryMethod.LocalHost)
                ? Task.FromResult<string?>(Dns.GetHostName())
                : _hostnameResolver.ResolveAsync(device.IpAddress, 1_200, token);
            bool shouldResolveMacWithArp = options.EnableArp && string.IsNullOrWhiteSpace(device.MacAddress);
            Task<string?> macTask = shouldResolveMacWithArp
                ? _macAddressService.ResolveAsync(device.IpAddress, networkInterface, token)
                : Task.FromResult(device.MacAddress);
            Task<NetBiosInfo?> netBiosTask = options.EnableNetBiosDiscovery
                ? _netBiosDiscoveryService.ProbeAsync(
                    device.IpAddress,
                    Math.Max(250, options.ConnectTimeoutMs + 150),
                    networkInterface.IpAddress,
                    token)
                : Task.FromResult<NetBiosInfo?>(null);
            Task<IReadOnlyList<PortScanResult>> portsTask = _portScanner.ScanAsync(
                device.IpAddress,
                options.Ports,
                options.ConnectTimeoutMs,
                options.MaximumPortConcurrency,
                options.EnableServiceProbes,
                networkInterface.IpAddress,
                token);

            await Task.WhenAll(hostnameTask, macTask, netBiosTask, portsTask);
            device.Hostname ??= await hostnameTask;
            device.MacAddress = await macTask;
            if (shouldResolveMacWithArp && !string.IsNullOrWhiteSpace(device.MacAddress))
                device.DiscoveryMethods |= DiscoveryMethod.Arp;
            NetBiosInfo? netBios = await netBiosTask;
            if (netBios is not null)
            {
                device.NetBiosName = netBios.ComputerName;
                device.Workgroup = netBios.Workgroup;
                device.Hostname ??= netBios.ComputerName;
                device.MacAddress ??= netBios.MacAddress;
                device.DiscoveryMethods |= DiscoveryMethod.NetBios;
            }
            device.Ports = (await portsTask).ToList();

            device.IsRandomizedMac = MacVendorService.IsLocallyAdministered(device.MacAddress);
            device.Manufacturer = _macVendorService.Lookup(device.MacAddress);
            device.Topology = _topologyInferenceService.Assess(device, networkInterface);
            _deviceClassifierService.Classify(device, networkInterface);
            _securityAssessmentService.Assess(device);
            device.ObservedProtocols = GetObservedProtocols(device);
            device.LastSeen = DateTimeOffset.UtcNow;

            int current = Interlocked.Increment(ref enriched);
            progress?.Report(new ScanProgress(
                "Enriquecimento",
                current,
                onlineDevices.Count,
                onlineDevices.Count,
                $"Detalhes concluídos para {device.IpAddress}",
                device));
        });

        string? snmpWarning = null;
        SnmpTopologySnapshot? snmpTopology = null;
        if (options.EnableSnmpTopology)
        {
            progress?.Report(new ScanProgress(
                "Topologia SNMP",
                0,
                1,
                onlineDevices.Count,
                $"A consultar a tabela MAC do switch {options.SnmpSwitchAddress}..."));

            snmpTopology = await _snmpTopologyService.ReadAsync(
                new SnmpTopologyOptions
                {
                    SwitchAddress = options.SnmpSwitchAddress!,
                    Community = options.SnmpCommunity!,
                    TimeoutMs = options.SnmpTimeoutMs
                },
                networkInterface.IpAddress,
                cancellationToken);

            if (snmpTopology is null)
            {
                snmpWarning =
                    "O switch SNMP não respondeu ou rejeitou as credenciais; a aplicação manteve a topologia inferida.";
            }
            else
            {
                _snmpTopologyService.Apply(snmpTopology, onlineDevices, networkInterface);
                progress?.Report(new ScanProgress(
                    "Topologia SNMP",
                    1,
                    1,
                    onlineDevices.Count,
                    $"Tabela MAC recebida: {snmpTopology.MacTable.Count:N0} entradas; " +
                    $"{snmpTopology.LldpNeighbors.Count:N0} vizinhos LLDP."));
            }
        }

        List<NetworkDevice> ordered = onlineDevices
            .OrderBy(device => IpAddressHelper.ToUInt32(device.IpAddress))
            .ToList();

        DateTimeOffset completedAt = DateTimeOffset.UtcNow;
        progress?.Report(new ScanProgress(
            "Concluído",
            addresses.Count,
            addresses.Count,
            ordered.Count,
            $"Scan concluído: {ordered.Count} dispositivos."));

        return new NetworkScanResult
        {
            NetworkInterface = networkInterface,
            StartedAt = startedAt,
            CompletedAt = completedAt,
            AddressesScanned = addresses.Count,
            Devices = ordered,
            SnmpTopology = snmpTopology,
            Warnings = BuildWarnings(networkInterface, snmpWarning)
        };
    }

    private static NetworkDevice CreateOnlineDevice(IPAddress address, DiscoveryMethod method) => new()
    {
        IpAddress = address,
        IsOnline = true,
        DiscoveryMethods = method
    };

    private static List<string> GetObservedProtocols(NetworkDevice device)
    {
        HashSet<string> protocols = new(StringComparer.OrdinalIgnoreCase);
        if (device.DiscoveryMethods.HasFlag(DiscoveryMethod.Icmp))
            protocols.Add("ICMP");
        if (device.DiscoveryMethods.HasFlag(DiscoveryMethod.Arp))
            protocols.Add("ARP");
        if (device.DiscoveryMethods.HasFlag(DiscoveryMethod.Tcp) || device.Ports.Count > 0)
            protocols.Add("TCP");
        if (device.DiscoveryMethods.HasFlag(DiscoveryMethod.Mdns))
            protocols.Add("mDNS");
        if (device.DiscoveryMethods.HasFlag(DiscoveryMethod.Ssdp))
            protocols.Add("SSDP/UPnP");
        if (device.DiscoveryMethods.HasFlag(DiscoveryMethod.NetBios))
            protocols.Add("NBNS/NetBIOS");
        if (device.DiscoveryMethods.HasFlag(DiscoveryMethod.WsDiscovery))
            protocols.Add("WS-Discovery");

        foreach (string service in device.Ports
                     .Select(port => port.ServiceName)
                     .Where(name => !name.Equals("desconhecido", StringComparison.OrdinalIgnoreCase)))
        {
            protocols.Add(service.ToUpperInvariant());
        }

        return protocols.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<string> BuildWarnings(
        LocalNetworkInterface networkInterface,
        string? snmpWarning)
    {
        List<string> warnings =
        [
            "O mesmo segmento L2 é inferido por ARP. A FDB consultada por SNMP mostra onde um MAC foi aprendido, mas essa porta pode ser um uplink/trunk; não é apresentada como prova do mesmo switch físico.",
            "O scan identifica protocolos por descoberta, portas e banners; captura de pacotes completa requer um driver como Npcap."
        ];

        if (networkInterface.VlanId is null)
            warnings.Add("A VLAN da interface não foi exposta pelo sistema operativo; não é inventado um ID sem evidência.");
        if (networkInterface.IsWireless && networkInterface.WifiSignalPercent is null)
            warnings.Add("O sistema não devolveu a intensidade do Wi-Fi; RSSI por dispositivo exige telemetria do access point/controlador.");
        if (!string.IsNullOrWhiteSpace(snmpWarning))
            warnings.Add(snmpWarning);

        return warnings;
    }
}
