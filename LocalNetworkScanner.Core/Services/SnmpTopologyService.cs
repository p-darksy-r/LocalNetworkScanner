using System.Globalization;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class SnmpTopologyService
{
    private const string SysDescriptionOid = "1.3.6.1.2.1.1.1.0";
    private const string SysNameOid = "1.3.6.1.2.1.1.5.0";
    private const string BasePortIfIndexRoot = "1.3.6.1.2.1.17.1.4.1.2";
    private const string ClassicFdbPortRoot = "1.3.6.1.2.1.17.4.3.1.2";
    private const string QBridgeFdbPortRoot = "1.3.6.1.2.1.17.7.1.2.2.1.2";
    private const string QBridgePvidRoot = "1.3.6.1.2.1.17.7.1.4.5.1.1";
    private const string VlanFdbIdRoot = "1.3.6.1.2.1.17.7.1.4.2.1.3";
    private const string InterfaceNameRoot = "1.3.6.1.2.1.31.1.1.1.1";
    internal const string LldpLocalPortSubtypeRoot = "1.0.8802.1.1.2.1.3.7.1.2";
    internal const string LldpLocalPortIdRoot = "1.0.8802.1.1.2.1.3.7.1.3";
    internal const string LldpLocalPortDescriptionRoot = "1.0.8802.1.1.2.1.3.7.1.4";
    internal const string LldpRemoteChassisSubtypeRoot = "1.0.8802.1.1.2.1.4.1.1.4";
    internal const string LldpRemoteChassisIdRoot = "1.0.8802.1.1.2.1.4.1.1.5";
    internal const string LldpRemotePortSubtypeRoot = "1.0.8802.1.1.2.1.4.1.1.6";
    internal const string LldpRemotePortIdRoot = "1.0.8802.1.1.2.1.4.1.1.7";
    internal const string LldpRemotePortDescriptionRoot = "1.0.8802.1.1.2.1.4.1.1.8";
    internal const string LldpRemoteSystemNameRoot = "1.0.8802.1.1.2.1.4.1.1.9";
    internal const string LldpRemoteSystemDescriptionRoot = "1.0.8802.1.1.2.1.4.1.1.10";
    private const int MaximumWalkVariables = 4_096;

    public async Task<SnmpTopologySnapshot?> ReadAsync(
        SnmpTopologyOptions options,
        System.Net.IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        using CancellationTokenSource deadline =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));

        try
        {
            return await ReadCoreAsync(
                options,
                localAddress,
                deadline.Token,
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or SocketException or AsnContentException or
                InvalidDataException or FormatException or OverflowException or ArgumentException)
        {
            return null;
        }
    }

    private static async Task<SnmpTopologySnapshot?> ReadCoreAsync(
        SnmpTopologyOptions options,
        System.Net.IPAddress? localAddress,
        CancellationToken cancellationToken,
        CancellationToken externalCancellationToken)
    {
        SnmpClientService client = new(
            options.SwitchAddress,
            localAddress,
            options.Community,
            options.TimeoutMs,
            options.Retries);

        SnmpVariable? description = await client.GetAsync(SysDescriptionOid, cancellationToken);
        if (description is null)
            return null;

        SnmpVariable? name = await client.GetAsync(SysNameOid, cancellationToken);
        IReadOnlyList<SnmpVariable> portIndexes = await client.WalkAsync(
            BasePortIfIndexRoot,
            MaximumWalkVariables,
            cancellationToken);
        IReadOnlyList<SnmpVariable> interfaceNames = await client.WalkAsync(
            InterfaceNameRoot,
            MaximumWalkVariables,
            cancellationToken);
        IReadOnlyList<SnmpVariable> pvids = await client.WalkAsync(
            QBridgePvidRoot,
            MaximumWalkVariables,
            cancellationToken);
        IReadOnlyList<SnmpVariable> vlanFdbIds = await client.WalkAsync(
            VlanFdbIdRoot,
            MaximumWalkVariables,
            cancellationToken);
        IReadOnlyList<SnmpVariable> forwardingEntries = await client.WalkAsync(
            QBridgeFdbPortRoot,
            MaximumWalkVariables,
            cancellationToken);

        bool qBridge = forwardingEntries.Count > 0;
        if (!qBridge)
        {
            forwardingEntries = await client.WalkAsync(
                ClassicFdbPortRoot,
                MaximumWalkVariables,
                cancellationToken);
        }

        IReadOnlyList<LldpNeighborObservation> lldpNeighbors =
            await ReadLldpNeighborsAsync(
                client,
                cancellationToken,
                externalCancellationToken);

        Dictionary<int, int> bridgeToInterface = ParseIntegerTable(
            portIndexes,
            BasePortIfIndexRoot);
        Dictionary<int, string> interfaceNamesByIndex = ParseTextTable(
            interfaceNames,
            InterfaceNameRoot);
        Dictionary<int, int> pvidByBridgePort = ParseIntegerTable(pvids, QBridgePvidRoot);
        Dictionary<int, HashSet<int>> vlansByFdbId = ParseVlanFdbMap(vlanFdbIds);
        Dictionary<string, List<SwitchPortObservation>> macTable =
            new(StringComparer.OrdinalIgnoreCase);

        foreach (SnmpVariable variable in forwardingEntries)
        {
            if (!variable.IntegerValue.HasValue || variable.IntegerValue <= 0)
                continue;

            (string? mac, int? forwardingDatabaseId) = qBridge
                ? ParseQBridgeMac(variable.Oid)
                : ParseClassicMac(variable.Oid);
            if (mac is null)
                continue;

            int bridgePort = variable.IntegerValue.Value;
            bridgeToInterface.TryGetValue(bridgePort, out int interfaceIndex);
            interfaceNamesByIndex.TryGetValue(interfaceIndex, out string? interfaceName);
            int? vlanId = null;
            if (forwardingDatabaseId.HasValue &&
                vlansByFdbId.TryGetValue(forwardingDatabaseId.Value, out HashSet<int>? mappedVlans) &&
                mappedVlans.Count == 1)
            {
                vlanId = mappedVlans.Single();
            }
            pvidByBridgePort.TryGetValue(bridgePort, out int pvid);

            SwitchPortObservation observation = new()
            {
                MacAddress = mac,
                BridgePort = bridgePort,
                InterfaceIndex = interfaceIndex == 0 ? null : interfaceIndex,
                InterfaceName = interfaceName,
                VlanId = vlanId is >= 1 and <= 4094 ? vlanId : null,
                PortPvid = pvid is >= 1 and <= 4094 ? pvid : null,
                ForwardingDatabaseId = forwardingDatabaseId
            };

            if (!macTable.TryGetValue(mac, out List<SwitchPortObservation>? entries))
            {
                entries = [];
                macTable[mac] = entries;
            }
            if (!entries.Any(item =>
                    item.BridgePort == observation.BridgePort &&
                    item.ForwardingDatabaseId == observation.ForwardingDatabaseId))
            {
                entries.Add(observation);
            }
        }

        return new SnmpTopologySnapshot
        {
            SwitchAddress = options.SwitchAddress,
            SwitchName = name?.TextValue,
            SwitchDescription = description.TextValue,
            MacTable = macTable.ToDictionary(
                item => item.Key,
                item => (IReadOnlyList<SwitchPortObservation>)item.Value,
                StringComparer.OrdinalIgnoreCase),
            LldpNeighbors = lldpNeighbors
        };
    }

    private static async Task<IReadOnlyList<LldpNeighborObservation>> ReadLldpNeighborsAsync(
        SnmpClientService client,
        CancellationToken cancellationToken,
        CancellationToken externalCancellationToken)
    {
        try
        {
            IReadOnlyList<SnmpVariable> localPortSubtypes = await client.WalkAsync(
                LldpLocalPortSubtypeRoot,
                MaximumWalkVariables,
                cancellationToken);
            IReadOnlyList<SnmpVariable> localPortIds = await client.WalkAsync(
                LldpLocalPortIdRoot,
                MaximumWalkVariables,
                cancellationToken);
            IReadOnlyList<SnmpVariable> localPortDescriptions = await client.WalkAsync(
                LldpLocalPortDescriptionRoot,
                MaximumWalkVariables,
                cancellationToken);
            IReadOnlyList<SnmpVariable> chassisSubtypes = await client.WalkAsync(
                LldpRemoteChassisSubtypeRoot,
                MaximumWalkVariables,
                cancellationToken);
            IReadOnlyList<SnmpVariable> chassisIds = await client.WalkAsync(
                LldpRemoteChassisIdRoot,
                MaximumWalkVariables,
                cancellationToken);
            IReadOnlyList<SnmpVariable> portSubtypes = await client.WalkAsync(
                LldpRemotePortSubtypeRoot,
                MaximumWalkVariables,
                cancellationToken);
            IReadOnlyList<SnmpVariable> portIds = await client.WalkAsync(
                LldpRemotePortIdRoot,
                MaximumWalkVariables,
                cancellationToken);
            IReadOnlyList<SnmpVariable> portDescriptions = await client.WalkAsync(
                LldpRemotePortDescriptionRoot,
                MaximumWalkVariables,
                cancellationToken);
            IReadOnlyList<SnmpVariable> systemNames = await client.WalkAsync(
                LldpRemoteSystemNameRoot,
                MaximumWalkVariables,
                cancellationToken);
            IReadOnlyList<SnmpVariable> systemDescriptions = await client.WalkAsync(
                LldpRemoteSystemDescriptionRoot,
                MaximumWalkVariables,
                cancellationToken);

            return ParseLldpNeighbors(
                localPortSubtypes,
                localPortIds,
                localPortDescriptions,
                chassisSubtypes,
                chassisIds,
                portSubtypes,
                portIds,
                portDescriptions,
                systemNames,
                systemDescriptions);
        }
        catch (OperationCanceledException) when (!externalCancellationToken.IsCancellationRequested)
        {
            // LLDP is optional enrichment. Preserve the already collected FDB snapshot
            // when the global 30 second topology deadline is exhausted.
            return [];
        }
    }

    public void Apply(
        SnmpTopologySnapshot snapshot,
        IReadOnlyList<NetworkDevice> devices,
        LocalNetworkInterface networkInterface)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(networkInterface);

        foreach (NetworkDevice device in devices)
        {
            string deviceMac = NormalizeMac(device.MacAddress);
            if (string.IsNullOrWhiteSpace(deviceMac) ||
                !snapshot.MacTable.TryGetValue(
                    deviceMac,
                    out IReadOnlyList<SwitchPortObservation>? observations) ||
                observations.Count == 0)
            {
                continue;
            }

            SwitchPortObservation? singleObservation = observations.Count == 1
                ? observations[0]
                : null;
            device.Topology.SwitchAddress = snapshot.SwitchAddress.ToString();
            device.Topology.SwitchName = snapshot.SwitchName;
            device.Topology.SwitchPort = singleObservation?.BridgePort;
            device.Topology.SwitchInterface = singleObservation?.InterfaceName;
            device.Topology.SwitchPortPvid = singleObservation?.PortPvid;
            device.Topology.SwitchConfidence = ConfidenceLevel.High;
            device.Topology.ObservedOnManagedBridge = true;

            int[] confirmedVlans = observations
                .Where(item => item.VlanId.HasValue)
                .Select(item => item.VlanId!.Value)
                .Distinct()
                .ToArray();
            if (confirmedVlans.Length == 1)
            {
                device.Topology.VlanId = confirmedVlans[0];
                device.Topology.VlanConfidence = ConfidenceLevel.High;
            }

            device.Topology.SamePhysicalSwitch = null;
            string switchLabel = snapshot.SwitchName ?? snapshot.SwitchAddress.ToString();
            device.Topology.SwitchEvidence = singleObservation is not null
                ? $"SNMP confirmou que o MAC foi aprendido na FDB de {switchLabel}, porta lógica {singleObservation.BridgePort}{FormatInterface(singleObservation.InterfaceName)}. A entrada pode ser uma porta de acesso, uplink, trunk, AP ou bridge remota; por isso não prova ligação física ao mesmo switch."
                : $"SNMP encontrou o MAC em {observations.Count} entradas da FDB de {switchLabel}. O caminho é ambíguo e não prova ligação física ao mesmo switch.";
        }
    }

    internal static IReadOnlyList<LldpNeighborObservation> ParseLldpNeighbors(
        IReadOnlyList<SnmpVariable> localPortSubtypes,
        IReadOnlyList<SnmpVariable> localPortIds,
        IReadOnlyList<SnmpVariable> localPortDescriptions,
        IReadOnlyList<SnmpVariable> chassisSubtypes,
        IReadOnlyList<SnmpVariable> chassisIds,
        IReadOnlyList<SnmpVariable> portSubtypes,
        IReadOnlyList<SnmpVariable> portIds,
        IReadOnlyList<SnmpVariable> portDescriptions,
        IReadOnlyList<SnmpVariable> systemNames,
        IReadOnlyList<SnmpVariable> systemDescriptions)
    {
        ArgumentNullException.ThrowIfNull(localPortSubtypes);
        ArgumentNullException.ThrowIfNull(localPortIds);
        ArgumentNullException.ThrowIfNull(localPortDescriptions);
        ArgumentNullException.ThrowIfNull(chassisSubtypes);
        ArgumentNullException.ThrowIfNull(chassisIds);
        ArgumentNullException.ThrowIfNull(portSubtypes);
        ArgumentNullException.ThrowIfNull(portIds);
        ArgumentNullException.ThrowIfNull(portDescriptions);
        ArgumentNullException.ThrowIfNull(systemNames);
        ArgumentNullException.ThrowIfNull(systemDescriptions);

        Dictionary<int, SnmpVariable> localSubtypes = ParseSingleIndexTable(
            localPortSubtypes,
            LldpLocalPortSubtypeRoot);
        Dictionary<int, SnmpVariable> localIds = ParseSingleIndexTable(
            localPortIds,
            LldpLocalPortIdRoot);
        Dictionary<int, SnmpVariable> localDescriptions = ParseSingleIndexTable(
            localPortDescriptions,
            LldpLocalPortDescriptionRoot);
        Dictionary<LldpRemoteIndex, SnmpVariable> chassisSubtypeByIndex = ParseLldpTable(
            chassisSubtypes,
            LldpRemoteChassisSubtypeRoot);
        Dictionary<LldpRemoteIndex, SnmpVariable> chassisIdByIndex = ParseLldpTable(
            chassisIds,
            LldpRemoteChassisIdRoot);
        Dictionary<LldpRemoteIndex, SnmpVariable> portSubtypeByIndex = ParseLldpTable(
            portSubtypes,
            LldpRemotePortSubtypeRoot);
        Dictionary<LldpRemoteIndex, SnmpVariable> portIdByIndex = ParseLldpTable(
            portIds,
            LldpRemotePortIdRoot);
        Dictionary<LldpRemoteIndex, SnmpVariable> portDescriptionByIndex = ParseLldpTable(
            portDescriptions,
            LldpRemotePortDescriptionRoot);
        Dictionary<LldpRemoteIndex, SnmpVariable> systemNameByIndex = ParseLldpTable(
            systemNames,
            LldpRemoteSystemNameRoot);
        Dictionary<LldpRemoteIndex, SnmpVariable> systemDescriptionByIndex = ParseLldpTable(
            systemDescriptions,
            LldpRemoteSystemDescriptionRoot);

        HashSet<LldpRemoteIndex> indexes = [];
        indexes.UnionWith(chassisSubtypeByIndex.Keys);
        indexes.UnionWith(chassisIdByIndex.Keys);
        indexes.UnionWith(portSubtypeByIndex.Keys);
        indexes.UnionWith(portIdByIndex.Keys);
        indexes.UnionWith(portDescriptionByIndex.Keys);
        indexes.UnionWith(systemNameByIndex.Keys);
        indexes.UnionWith(systemDescriptionByIndex.Keys);

        List<LldpNeighborObservation> result = [];
        foreach (LldpRemoteIndex index in indexes
                     .OrderBy(item => item.TimeMark)
                     .ThenBy(item => item.LocalPortNumber)
                     .ThenBy(item => item.RemoteIndex))
        {
            chassisSubtypeByIndex.TryGetValue(index, out SnmpVariable? chassisSubtype);
            chassisIdByIndex.TryGetValue(index, out SnmpVariable? chassisId);
            portSubtypeByIndex.TryGetValue(index, out SnmpVariable? portSubtype);
            portIdByIndex.TryGetValue(index, out SnmpVariable? portId);
            portDescriptionByIndex.TryGetValue(index, out SnmpVariable? portDescription);
            systemNameByIndex.TryGetValue(index, out SnmpVariable? systemName);
            systemDescriptionByIndex.TryGetValue(index, out SnmpVariable? systemDescription);
            localIds.TryGetValue(index.LocalPortNumber, out SnmpVariable? localPortId);
            localSubtypes.TryGetValue(index.LocalPortNumber, out SnmpVariable? localPortSubtype);
            localDescriptions.TryGetValue(
                index.LocalPortNumber,
                out SnmpVariable? localPortDescription);

            int? chassisSubtypeValue = chassisSubtype?.IntegerValue;
            int? portSubtypeValue = portSubtype?.IntegerValue;
            result.Add(new LldpNeighborObservation
            {
                TimeMark = index.TimeMark,
                LocalPortNumber = index.LocalPortNumber,
                RemoteIndex = index.RemoteIndex,
                LocalPortIdSubtype = localPortSubtype?.IntegerValue,
                LocalPortId = DecodeLldpIdentifier(
                    localPortId,
                    localPortSubtype?.IntegerValue,
                    isChassis: false),
                LocalPortDescription = localPortDescription?.TextValue,
                ChassisIdSubtype = chassisSubtypeValue,
                ChassisId = DecodeLldpIdentifier(chassisId, chassisSubtypeValue, isChassis: true),
                PortIdSubtype = portSubtypeValue,
                PortId = DecodeLldpIdentifier(portId, portSubtypeValue, isChassis: false),
                PortDescription = portDescription?.TextValue,
                SystemName = systemName?.TextValue,
                SystemDescription = systemDescription?.TextValue
            });
        }

        return result;
    }

    private static Dictionary<int, SnmpVariable> ParseSingleIndexTable(
        IReadOnlyList<SnmpVariable> variables,
        string root)
    {
        Dictionary<int, SnmpVariable> result = [];
        foreach (SnmpVariable variable in variables)
        {
            int[] suffix = GetOidSuffix(variable.Oid, root);
            if (suffix.Length == 1 && suffix[0] is >= 1 and <= 4096)
                result.TryAdd(suffix[0], variable);
        }
        return result;
    }

    private static Dictionary<LldpRemoteIndex, SnmpVariable> ParseLldpTable(
        IReadOnlyList<SnmpVariable> variables,
        string root)
    {
        Dictionary<LldpRemoteIndex, SnmpVariable> result = [];
        foreach (SnmpVariable variable in variables)
        {
            uint[] suffix = GetUnsignedOidSuffix(variable.Oid, root);
            if (suffix.Length != 3 ||
                suffix[1] is < 1 or > 4096 ||
                suffix[2] is < 1 or > int.MaxValue)
            {
                continue;
            }

            result.TryAdd(new LldpRemoteIndex(
                suffix[0],
                (int)suffix[1],
                (int)suffix[2]), variable);
        }
        return result;
    }

    private static string? DecodeLldpIdentifier(
        SnmpVariable? variable,
        int? subtype,
        bool isChassis)
    {
        if (variable is null)
            return null;

        byte[]? bytes = variable.OctetValue;
        if (bytes is null || bytes.Length == 0)
            return variable.TextValue;

        int macSubtype = isChassis ? 4 : 3;
        int networkSubtype = isChassis ? 5 : 4;
        if (subtype == macSubtype && bytes.Length == 6)
            return string.Join(":", bytes.Select(value =>
                value.ToString("X2", CultureInfo.InvariantCulture)));

        if (subtype == networkSubtype && bytes.Length > 1)
        {
            int addressFamily = bytes[0];
            int addressLength = bytes.Length - 1;
            if ((addressFamily == 1 && addressLength == 4) ||
                (addressFamily == 2 && addressLength == 16))
            {
                return new IPAddress(bytes.AsSpan(1).ToArray()).ToString();
            }
        }

        try
        {
            string text = new UTF8Encoding(false, true)
                .GetString(bytes)
                .Trim('\0', ' ', '\r', '\n', '\t');
            if (text.Length > 0 && text.All(character => !char.IsControl(character)))
                return text;
        }
        catch (DecoderFallbackException)
        {
            // Binary identifiers are rendered losslessly as hexadecimal below.
        }

        return Convert.ToHexString(bytes);
    }

    private static Dictionary<int, int> ParseIntegerTable(
        IReadOnlyList<SnmpVariable> variables,
        string root)
    {
        Dictionary<int, int> result = [];
        foreach (SnmpVariable variable in variables)
        {
            int[] suffix = GetOidSuffix(variable.Oid, root);
            if (suffix.Length == 1 && variable.IntegerValue.HasValue)
                result[suffix[0]] = variable.IntegerValue.Value;
        }
        return result;
    }

    private static Dictionary<int, string> ParseTextTable(
        IReadOnlyList<SnmpVariable> variables,
        string root)
    {
        Dictionary<int, string> result = [];
        foreach (SnmpVariable variable in variables)
        {
            int[] suffix = GetOidSuffix(variable.Oid, root);
            if (suffix.Length == 1 && !string.IsNullOrWhiteSpace(variable.TextValue))
                result[suffix[0]] = variable.TextValue;
        }
        return result;
    }

    private static Dictionary<int, HashSet<int>> ParseVlanFdbMap(
        IReadOnlyList<SnmpVariable> variables)
    {
        Dictionary<int, HashSet<int>> result = [];
        foreach (SnmpVariable variable in variables)
        {
            int[] suffix = GetOidSuffix(variable.Oid, VlanFdbIdRoot);
            if (suffix.Length != 2 || !variable.IntegerValue.HasValue)
                continue;

            int vlanId = suffix[1];
            int forwardingDatabaseId = variable.IntegerValue.Value;
            if (vlanId is < 1 or > 4094 || forwardingDatabaseId < 0)
                continue;

            if (!result.TryGetValue(forwardingDatabaseId, out HashSet<int>? vlans))
            {
                vlans = [];
                result[forwardingDatabaseId] = vlans;
            }
            vlans.Add(vlanId);
        }
        return result;
    }

    private static (string? Mac, int? Vlan) ParseQBridgeMac(string oid)
    {
        int[] suffix = GetOidSuffix(oid, QBridgeFdbPortRoot);
        return suffix.Length == 7
            ? (FormatMac(suffix.AsSpan(1, 6)), suffix[0])
            : (null, null);
    }

    private static (string? Mac, int? Vlan) ParseClassicMac(string oid)
    {
        int[] suffix = GetOidSuffix(oid, ClassicFdbPortRoot);
        return suffix.Length == 6
            ? (FormatMac(suffix), null)
            : (null, null);
    }

    private static int[] GetOidSuffix(string oid, string root)
    {
        string prefix = root + ".";
        if (!oid.StartsWith(prefix, StringComparison.Ordinal))
            return [];

        string[] parts = oid[prefix.Length..].Split('.', StringSplitOptions.RemoveEmptyEntries);
        int[] values = new int[parts.Length];
        for (int index = 0; index < parts.Length; index++)
        {
            if (!int.TryParse(parts[index], NumberStyles.None, CultureInfo.InvariantCulture, out values[index]))
                return [];
        }
        return values;
    }

    private static uint[] GetUnsignedOidSuffix(string oid, string root)
    {
        string prefix = root + ".";
        if (!oid.StartsWith(prefix, StringComparison.Ordinal))
            return [];

        string[] parts = oid[prefix.Length..].Split('.', StringSplitOptions.RemoveEmptyEntries);
        uint[] values = new uint[parts.Length];
        for (int index = 0; index < parts.Length; index++)
        {
            if (!uint.TryParse(
                    parts[index],
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out values[index]))
            {
                return [];
            }
        }
        return values;
    }

    private static string? FormatMac(ReadOnlySpan<int> bytes)
    {
        if (bytes.Length != 6 || bytes.ToArray().Any(value => value is < 0 or > 255))
            return null;
        return string.Join(":", bytes.ToArray().Select(value =>
            value.ToString("X2", CultureInfo.InvariantCulture)));
    }

    private static string NormalizeMac(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : MacAddressService.Normalize(value);

    private static string FormatInterface(string? value) =>
        string.IsNullOrWhiteSpace(value) ? string.Empty : $" ({value})";

    private readonly record struct LldpRemoteIndex(
        uint TimeMark,
        int LocalPortNumber,
        int RemoteIndex);
}
