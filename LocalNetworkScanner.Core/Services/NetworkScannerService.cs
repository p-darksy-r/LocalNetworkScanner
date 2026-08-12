// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Net;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class NetworkScannerService
{
    internal const int MaximumUpnpEnrichmentAttempts = 32;
    private const int MaximumUpnpEnrichmentConcurrency = 4;
    private const int MaximumUpnpEnrichmentTimeMs = 8_000;

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
    private readonly SnmpDeviceDiscoveryService _snmpDeviceDiscoveryService;
    private readonly UpnpDescriptionService _upnpDescriptionService;
    private readonly DeviceIdentityService _deviceIdentityService;
    private readonly NmapDiscoveryService _nmapDiscoveryService;
    private readonly Func<IPAddress, int, IPAddress?, CancellationToken, Task<PingProbeResult>> _pingProbe;
    private readonly Func<IPAddress, IReadOnlyList<int>, int, IPAddress?, CancellationToken, Task<int?>>
        _tcpDiscoveryProbe;

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
        SnmpTopologyService? snmpTopologyService = null,
        SnmpDeviceDiscoveryService? snmpDeviceDiscoveryService = null,
        UpnpDescriptionService? upnpDescriptionService = null,
        DeviceIdentityService? deviceIdentityService = null,
        NmapDiscoveryService? nmapDiscoveryService = null)
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
        _snmpDeviceDiscoveryService = snmpDeviceDiscoveryService ?? new SnmpDeviceDiscoveryService();
        _upnpDescriptionService = upnpDescriptionService ?? new UpnpDescriptionService();
        _deviceIdentityService = deviceIdentityService ?? new DeviceIdentityService();
        _nmapDiscoveryService = nmapDiscoveryService ?? new NmapDiscoveryService();
        _pingProbe = (address, timeoutMs, sourceAddress, cancellationToken) =>
            _pingScanner.ProbeAsync(address, timeoutMs, sourceAddress, cancellationToken);
        _tcpDiscoveryProbe = (address, ports, timeoutMs, localAddress, cancellationToken) =>
            _portScanner.FindAnyOpenPortAsync(
                address,
                ports,
                timeoutMs,
                localAddress,
                cancellationToken);
    }

    internal NetworkScannerService(
        MacAddressService macAddressService,
        Func<IPAddress, int, IPAddress?, CancellationToken, Task<PingProbeResult>> pingProbe,
        Func<IPAddress, IReadOnlyList<int>, int, IPAddress?, CancellationToken, Task<int?>>
            tcpDiscoveryProbe)
        : this(macAddressService: macAddressService)
    {
        ArgumentNullException.ThrowIfNull(pingProbe);
        ArgumentNullException.ThrowIfNull(tcpDiscoveryProbe);

        _pingProbe = pingProbe;
        _tcpDiscoveryProbe = tcpDiscoveryProbe;
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
        ConcurrentDictionary<IPAddress, string> invalidMacAddresses = [];
        HashSet<IPAddress> allowedAddresses = addresses.ToHashSet();
        await using MacAddressService.ScanSession? macScanSession = options.EnableArp
            ? _macAddressService.CreateScanSession(networkInterface, cancellationToken)
            : null;
        if (macScanSession is not null)
            await macScanSession.InitializeAsync(cancellationToken);

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
                    ? _pingProbe(
                        address,
                        options.PingTimeoutMs,
                        networkInterface.IpAddress,
                        token)
                    : Task.FromResult(new PingProbeResult(false, null, null));
                Task<int?> tcpTask = options.EnableTcpDiscovery
                    ? _tcpDiscoveryProbe(
                        address,
                        options.DiscoveryPorts,
                        options.ConnectTimeoutMs,
                        networkInterface.IpAddress,
                        token)
                    : Task.FromResult<int?>(null);

                await Task.WhenAll(pingTask, tcpTask);
                PingProbeResult ping = await pingTask;
                int? discoveryPort = await tcpTask;
                bool confirmedByProbe = ping.Success || discoveryPort.HasValue;
                MacAddressResolution? macResolution = options.EnableArp
                    ? await macScanSession!.ResolveWithEvidenceAsync(address, token)
                    : null;
                bool confirmedByActiveArp = macResolution?.ConfirmsReachability == true;

                if (confirmedByProbe || confirmedByActiveArp)
                {
                    DiscoveryMethod methods = DiscoveryMethod.None;
                    if (ping.Success)
                        methods |= DiscoveryMethod.Icmp;
                    if (discoveryPort.HasValue)
                        methods |= DiscoveryMethod.Tcp;
                    if (confirmedByActiveArp)
                        methods |= DiscoveryMethod.Arp;

                    device = CreateOnlineDevice(address, methods);
                    device.ResponseTimeMs = ping.RoundtripTimeMs;
                    device.ReplyTtl = ping.ReplyTtl;
                    device.MacAddress = macResolution?.MacAddress;
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

        IReadOnlyList<DiscoveryObservation> multicastObservations = (await multicastTask)
            .Where(observation => allowedAddresses.Contains(observation.IpAddress))
            .ToArray();
        if (options.EnableUpnpDescription)
        {
            multicastObservations = await EnrichUpnpObservationsAsync(
                multicastObservations,
                options.DiscoveryTimeoutMs,
                cancellationToken);
        }

        foreach (DiscoveryObservation observation in multicastObservations)
        {
            if (!devices.ContainsKey(observation.IpAddress) &&
                !CanPromoteMulticastObservation(observation))
            {
                // Um A/AAAA mDNS é conteúdo autoanunciado. Sem um datagrama cuja
                // origem seja o próprio endereço, mantém-se apenas como metadata
                // para dispositivos já confirmados e nunca inicia sondagens.
                continue;
            }

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
                device.SsdpServiceType = JoinDistinctMetadata(
                    device.SsdpServiceType,
                    observation.ServiceType);
                device.SsdpUniqueServiceName = JoinDistinctMetadata(
                    device.SsdpUniqueServiceName,
                    observation.UniqueServiceName);
            }

            if (observation.Method == DiscoveryMethod.WsDiscovery)
            {
                device.WsDiscoveryTypes ??= observation.Server;
                device.WsDiscoveryAddresses ??= observation.Location;
            }

            _deviceIdentityService.AddObservation(device, observation);
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
            Task<MacAddressResolution?> macTask = shouldResolveMacWithArp
                ? macScanSession!.ResolveWithEvidenceAsync(device.IpAddress, token)
                : Task.FromResult<MacAddressResolution?>(null);
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
            MacAddressResolution? macResolution = await macTask;
            if (shouldResolveMacWithArp)
                device.MacAddress = macResolution?.MacAddress;
            if (macResolution?.ConfirmsReachability == true)
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

            string? invalidMac = NormalizeDeviceMacIdentity(device);
            if (invalidMac is not null)
            {
                invalidMacAddresses[device.IpAddress] = invalidMac;
            }
            else if (device.MacAddress is not null)
            {
                device.IsLocallyAdministeredMac = MacVendorService.IsLocallyAdministered(device.MacAddress);
                _deviceIdentityService.AddMacVendor(
                    device,
                    _macVendorService.LookupDetailed(device.MacAddress));
            }
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

        int snmpIdentityAttempts = 0;
        int snmpIdentityResponders = 0;
        if (options.EnableSnmpDeviceDiscovery)
        {
            snmpIdentityAttempts = onlineDevices.Count;
            int snmpCompleted = 0;
            ParallelOptions snmpOptions = new()
            {
                MaxDegreeOfParallelism = Math.Min(8, Math.Max(1, options.MaximumHostConcurrency)),
                CancellationToken = cancellationToken
            };

            await Parallel.ForEachAsync(onlineDevices, snmpOptions, async (device, token) =>
            {
                SnmpDeviceIdentity identity = await _snmpDeviceDiscoveryService.DiscoverAsync(
                    device.IpAddress,
                    options.SnmpCommunity!,
                    options.SnmpTimeoutMs,
                    retries: 0,
                    localAddress: networkInterface.IpAddress,
                    cancellationToken: token);
                if (identity.Success)
                {
                    Interlocked.Increment(ref snmpIdentityResponders);
                    device.DiscoveryMethods |= DiscoveryMethod.Snmp;
                    device.SnmpDescription = identity.Description;
                    device.SnmpObjectIdentifier = identity.SystemObjectIdentifier;
                    _deviceIdentityService.AddEvidence(device, new DeviceIdentityEvidence
                    {
                        Method = DiscoveryMethod.Snmp,
                        Source = identity.EntityIndex.HasValue
                            ? $"SNMP v2c ENTITY-MIB (índice {identity.EntityIndex.Value})"
                            : "SNMP v2c MIB-II",
                        Confidence = identity.EntityIndex.HasValue
                            ? ConfidenceLevel.High
                            : ConfidenceLevel.Medium,
                        Manufacturer = identity.Manufacturer,
                        Model = identity.Model,
                        FriendlyName = identity.Name,
                        SerialNumber = identity.SerialNumber,
                        Firmware = JoinNonEmpty(identity.FirmwareRevision, identity.SoftwareRevision),
                        HardwareRevision = identity.HardwareRevision,
                        Description = identity.Description,
                        OperatingSystem = identity.OperatingSystemHint,
                        Endpoint = device.IpAddressText
                    });
                }

                int current = Interlocked.Increment(ref snmpCompleted);
                progress?.Report(new ScanProgress(
                    "Identidade SNMP",
                    current,
                    onlineDevices.Count,
                    onlineDevices.Count,
                    identity.Success
                        ? $"Identidade SNMP recebida de {device.IpAddress}"
                        : $"Sem identidade SNMP em {device.IpAddress}",
                    identity.Success ? device : null));
            });
        }

        NmapDiscoveryStatus? nmapStatus = null;
        string? nmapStatusMessage = null;
        if (options.EnableNmapDiscovery && onlineDevices.Count > 0)
        {
            IReadOnlyList<IPAddress> nmapTargets = onlineDevices
                .Select(device => device.IpAddress)
                .Where(IsConventionalPrivateAddress)
                .Distinct()
                .ToArray();
            IReadOnlyList<int> nmapPorts = onlineDevices
                .SelectMany(device => device.Ports)
                .Where(port => port.State.Equals("Aberta", StringComparison.OrdinalIgnoreCase))
                .Select(port => port.Port)
                .Distinct()
                .OrderBy(port => port)
                .Take(128)
                .ToArray();
            if (nmapPorts.Count == 0)
                nmapPorts = options.DiscoveryPorts.Take(128).ToArray();

            if (nmapTargets.Count > 0)
            {
                DateTimeOffset nmapDeadline = DateTimeOffset.UtcNow.AddMilliseconds(options.NmapTimeoutMs);
                foreach (IPAddress[] targetBatch in nmapTargets.Chunk(256))
                {
                    TimeSpan remaining = nmapDeadline - DateTimeOffset.UtcNow;
                    if (remaining < TimeSpan.FromSeconds(5))
                    {
                        nmapStatus = NmapDiscoveryStatus.Failed;
                        nmapStatusMessage = "O orçamento global do Nmap terminou antes de todos os lotes.";
                        break;
                    }

                    progress?.Report(new ScanProgress(
                        "Nmap opcional",
                        0,
                        targetBatch.Length,
                        onlineDevices.Count,
                        $"A enriquecer {targetBatch.Length} dispositivo(s) com o Nmap instalado localmente..."));
                    NmapDiscoveryResult nmapResult = await _nmapDiscoveryService.DiscoverAsync(
                        targetBatch,
                        nmapPorts,
                        options.NmapExecutablePath,
                        remaining,
                        cancellationToken);
                    nmapStatus = nmapResult.Status;
                    nmapStatusMessage = nmapResult.Message;
                    if (!nmapResult.IsSuccess)
                        break;

                    ApplyNmapObservations(nmapResult.Hosts, devices);
                    progress?.Report(new ScanProgress(
                        "Nmap opcional",
                        targetBatch.Length,
                        targetBatch.Length,
                        onlineDevices.Count,
                        nmapResult.Message));
                }
            }
        }

        bool snmpUnavailable = false;
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
                snmpUnavailable = true;
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

        foreach (NetworkDevice device in onlineDevices)
        {
            _deviceClassifierService.Classify(device, networkInterface);
            _securityAssessmentService.Assess(device);
            device.ObservedProtocols = GetObservedProtocols(device);
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

        IReadOnlyList<ScanDiagnostic> diagnostics = BuildDiagnostics(
            networkInterface,
            ordered,
            options.EnableArp && macScanSession is not null && !macScanSession.IsNeighborBaselineAvailable,
            options.SnmpSwitchAddress,
            snmpUnavailable,
            snmpIdentityAttempts,
            snmpIdentityResponders,
            nmapStatus,
            nmapStatusMessage,
            invalidMacAddresses);

        return new NetworkScanResult
        {
            NetworkInterface = networkInterface,
            StartedAt = startedAt,
            CompletedAt = completedAt,
            AddressesScanned = addresses.Count,
            Devices = ordered,
            SnmpTopology = snmpTopology,
            Diagnostics = diagnostics,
            Warnings = diagnostics.Select(item => item.Message).ToArray()
        };
    }

    private static NetworkDevice CreateOnlineDevice(IPAddress address, DiscoveryMethod method) => new()
    {
        IpAddress = address,
        IsOnline = true,
        DiscoveryMethods = method
    };

    internal static bool CanPromoteMulticastObservation(DiscoveryObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        return observation.Method != DiscoveryMethod.Mdns ||
               observation.HasDirectAddressEvidence;
    }

    private async Task<IReadOnlyList<DiscoveryObservation>> EnrichUpnpObservationsAsync(
        IReadOnlyList<DiscoveryObservation> observations,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        DiscoveryObservation[] enriched = observations.ToArray();
        IReadOnlyList<int> candidateIndexes = SelectUpnpEnrichmentCandidates(enriched);
        if (candidateIndexes.Count == 0)
            return enriched;

        using CancellationTokenSource budget =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(Math.Clamp(timeoutMs, 500, MaximumUpnpEnrichmentTimeMs));
        ParallelOptions options = new()
        {
            MaxDegreeOfParallelism = MaximumUpnpEnrichmentConcurrency,
            CancellationToken = budget.Token
        };
        try
        {
            await Parallel.ForEachAsync(
                candidateIndexes,
                options,
                async (index, token) =>
                {
                    enriched[index] = await _upnpDescriptionService.EnrichAsync(
                        enriched[index],
                        timeoutMs,
                        token);
                });
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // O orçamento global terminou; preserva os enriquecimentos já concluídos.
        }

        return enriched;
    }

    internal static IReadOnlyList<int> SelectUpnpEnrichmentCandidates(
        IReadOnlyList<DiscoveryObservation> observations)
    {
        ArgumentNullException.ThrowIfNull(observations);

        return Enumerable.Range(0, observations.Count)
            .Where(index =>
                observations[index].Method == DiscoveryMethod.Ssdp &&
                UpnpDescriptionService.TryCreateSafeDescriptionUri(
                    observations[index].Location,
                    observations[index].IpAddress,
                    out _))
            .Take(MaximumUpnpEnrichmentAttempts)
            .ToArray();
    }

    internal void ApplyNmapObservations(
        IReadOnlyList<NmapHostObservation> observations,
        IReadOnlyDictionary<IPAddress, NetworkDevice> devices)
    {
        foreach (NmapHostObservation observation in observations)
        {
            if (!devices.TryGetValue(observation.IpAddress, out NetworkDevice? device))
                continue;

            device.DiscoveryMethods |= DiscoveryMethod.Nmap;
            device.Hostname ??= observation.Hostname;
            if (string.IsNullOrWhiteSpace(device.MacAddress) &&
                MacAddressService.TryNormalizeDeviceAddress(observation.MacAddress, out string normalizedMac))
            {
                device.MacAddress = normalizedMac;
                device.IsLocallyAdministeredMac = MacVendorService.IsLocallyAdministered(normalizedMac);
                _deviceIdentityService.AddMacVendor(device, _macVendorService.LookupDetailed(normalizedMac));
            }

            foreach (NmapPortObservation nmapPort in observation.Ports.Where(port =>
                         port.State.Equals("open", StringComparison.OrdinalIgnoreCase)))
            {
                PortScanResult? existing = device.Ports.FirstOrDefault(port => port.Port == nmapPort.Port);
                if (existing is null)
                {
                    existing = new PortScanResult
                    {
                        Port = nmapPort.Port,
                        Protocol = "TCP",
                        State = "Aberta",
                        ServiceName = nmapPort.ServiceName ?? ServiceCatalog.GetServiceName(nmapPort.Port)
                    };
                    device.Ports.Add(existing);
                }
                else if (!string.IsNullOrWhiteSpace(nmapPort.ServiceName))
                {
                    existing.ServiceName = nmapPort.ServiceName;
                }

                string? versionEvidence = JoinNonEmpty(
                    nmapPort.Product,
                    nmapPort.Version,
                    nmapPort.ExtraInfo);
                if (!string.IsNullOrWhiteSpace(versionEvidence))
                    existing.Banner = $"Nmap: {versionEvidence}";
            }

            string[] products = observation.Ports
                .Select(port => JoinNonEmpty(port.Product, port.Version))
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(5)
                .ToArray()!;
            string? serviceSummary = products.Length == 0 ? null : string.Join("; ", products);
            string? macVendorSummary = string.IsNullOrWhiteSpace(observation.MacVendor)
                ? null
                : $"vendor MAC anunciado pelo Nmap: {observation.MacVendor}";
            device.NmapSummary = JoinNonEmpty(serviceSummary, macVendorSummary);
            string? deviceType = observation.Ports
                .Select(port => port.DeviceType)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
            string? operatingSystem = observation.OperatingSystem ?? observation.Ports
                .Select(port => port.OperatingSystem)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

            _deviceIdentityService.AddEvidence(device, new DeviceIdentityEvidence
            {
                Method = DiscoveryMethod.Nmap,
                Source = "Nmap local (TCP connect/version-light)",
                Confidence = ConfidenceLevel.Medium,
                Manufacturer = null,
                // A service product is software/banner evidence, not a physical device model.
                Model = null,
                FriendlyName = observation.Hostname,
                DeviceType = deviceType,
                OperatingSystem = operatingSystem,
                Description = device.NmapSummary,
                Endpoint = observation.IpAddress.ToString()
            });
        }
    }

    private static bool IsConventionalPrivateAddress(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return bytes.Length == 4 &&
            (bytes[0] == 10 ||
             bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
             bytes[0] == 192 && bytes[1] == 168);
    }

    private static string? JoinNonEmpty(params string?[] values)
    {
        string[] selected = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!.Trim())
            .ToArray();
        return selected.Length == 0 ? null : string.Join(' ', selected);
    }

    private static string? JoinDistinctMetadata(string? current, string? candidate)
    {
        string[] values = new[] { current, candidate }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .SelectMany(value => value!.Split(
                ';',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(16)
            .ToArray();
        if (values.Length == 0)
            return null;

        string combined = string.Join("; ", values);
        return combined.Length <= 2_048 ? combined : combined[..2_048];
    }

    internal static string? NormalizeDeviceMacIdentity(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);

        string? observedMac = device.MacAddress;
        if (string.IsNullOrWhiteSpace(observedMac))
            return null;

        if (MacAddressService.TryNormalizeDeviceAddress(observedMac, out string normalizedMac))
        {
            device.MacAddress = normalizedMac;
            return null;
        }

        device.MacAddress = null;
        device.MacAssignee = null;
        device.MacRegistry = null;
        device.MacAssignmentPrefix = null;
        device.IsLocallyAdministeredMac = false;
        device.IdentityEvidence.RemoveAll(evidence => evidence.Method == DiscoveryMethod.Arp);
        device.Manufacturer = device.IdentityEvidence
            .Where(evidence => !string.IsNullOrWhiteSpace(evidence.Manufacturer))
            .OrderByDescending(evidence => evidence.Confidence)
            .Select(evidence => evidence.Manufacturer)
            .FirstOrDefault();
        device.IdentityConfidence = device.IdentityEvidence.Count == 0
            ? ConfidenceLevel.Unknown
            : device.IdentityEvidence.Max(evidence => evidence.Confidence);
        device.DiscoveryMethods &= ~DiscoveryMethod.Arp;
        return observedMac;
    }

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
        if (device.DiscoveryMethods.HasFlag(DiscoveryMethod.Snmp))
            protocols.Add("SNMP");
        if (device.DiscoveryMethods.HasFlag(DiscoveryMethod.Nmap))
            protocols.Add("Nmap");

        foreach (string service in device.Ports
                     .Select(port => port.ServiceName)
                     .Where(name => !name.Equals("desconhecido", StringComparison.OrdinalIgnoreCase)))
        {
            protocols.Add(service.ToUpperInvariant());
        }

        return protocols.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static IReadOnlyList<ScanDiagnostic> BuildDiagnostics(
        LocalNetworkInterface networkInterface,
        IReadOnlyList<NetworkDevice> devices,
        bool arpBaselineUnavailable,
        IPAddress? snmpSwitchAddress,
        bool snmpUnavailable,
        int snmpIdentityAttempts,
        int snmpIdentityResponders,
        NmapDiscoveryStatus? nmapStatus,
        string? nmapStatusMessage,
        IReadOnlyDictionary<IPAddress, string> invalidMacAddresses)
    {
        List<ScanDiagnostic> diagnostics =
        [
            DiagnosticCatalog.Layer2Inference(),
            DiagnosticCatalog.PacketCaptureUnavailable()
        ];

        if (devices.Count == 0)
            diagnostics.Add(DiagnosticCatalog.NoDevicesFound(networkInterface.NetworkCidr));
        if (networkInterface.VlanId is null)
            diagnostics.Add(DiagnosticCatalog.VlanUnavailable(networkInterface.Name));
        if (networkInterface.IsWireless && networkInterface.WifiSignalPercent is null)
            diagnostics.Add(DiagnosticCatalog.WifiTelemetryUnavailable(networkInterface.Name));
        if (arpBaselineUnavailable)
            diagnostics.Add(DiagnosticCatalog.ArpBaselineUnavailable(networkInterface.Name));
        if (snmpUnavailable)
            diagnostics.Add(DiagnosticCatalog.SnmpUnavailable(snmpSwitchAddress?.ToString()));
        if (snmpIdentityAttempts > 0 && snmpIdentityResponders == 0)
            diagnostics.Add(DiagnosticCatalog.SnmpDeviceIdentityUnavailable(snmpIdentityAttempts));
        if (nmapStatus == NmapDiscoveryStatus.Unavailable)
            diagnostics.Add(DiagnosticCatalog.NmapUnavailable(nmapStatusMessage));
        else if (nmapStatus == NmapDiscoveryStatus.Failed)
            diagnostics.Add(DiagnosticCatalog.NmapScanFailed(nmapStatusMessage));

        foreach (NetworkDevice device in devices)
        {
            string target = device.IpAddressText;
            if (invalidMacAddresses.TryGetValue(device.IpAddress, out string? invalidMac))
                diagnostics.Add(DiagnosticCatalog.InvalidMacAddress(target, invalidMac));

            if (!string.IsNullOrWhiteSpace(device.MacAddress))
            {
                if (device.IsRandomizedMac)
                {
                    diagnostics.Add(DiagnosticCatalog.RandomizedMacAddress(target, device.MacAddress));
                }
                else if (string.IsNullOrWhiteSpace(device.MacAssignee))
                {
                    diagnostics.Add(DiagnosticCatalog.UnknownManufacturer(target, device.MacAddress));
                }
            }

            if (device.DeviceType.Equals("Dispositivo de rede", StringComparison.Ordinal))
                diagnostics.Add(DiagnosticCatalog.UnrecognizedDevice(target));

            int manufacturerValues = device.IdentityEvidence
                .Select(evidence => evidence.Manufacturer)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            int modelValues = device.IdentityEvidence
                .Select(evidence => evidence.Model)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            if (manufacturerValues > 1 || modelValues > 1)
            {
                diagnostics.Add(DiagnosticCatalog.IdentityConflict(
                    target,
                    manufacturerValues + modelValues));
            }
        }

        return diagnostics;
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
