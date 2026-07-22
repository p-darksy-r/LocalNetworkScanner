// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;

namespace LocalNetworkScanner.Core.Models;

public sealed class SnmpTopologySnapshot
{
    public required IPAddress SwitchAddress { get; init; }

    public string? SwitchName { get; init; }

    public string? SwitchDescription { get; init; }

    public IReadOnlyDictionary<string, IReadOnlyList<SwitchPortObservation>> MacTable { get; init; } =
        new Dictionary<string, IReadOnlyList<SwitchPortObservation>>(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<LldpNeighborObservation> LldpNeighbors { get; init; } = [];
}

public sealed class SwitchPortObservation
{
    public required string MacAddress { get; init; }

    public required int BridgePort { get; init; }

    public int? InterfaceIndex { get; init; }

    public string? InterfaceName { get; init; }

    public int? VlanId { get; init; }

    public int? PortPvid { get; init; }

    public int? ForwardingDatabaseId { get; init; }
}

public sealed class LldpNeighborObservation
{
    public required uint TimeMark { get; init; }

    public required int LocalPortNumber { get; init; }

    public required int RemoteIndex { get; init; }

    public int? LocalPortIdSubtype { get; init; }

    public string? LocalPortId { get; init; }

    public string? LocalPortDescription { get; init; }

    public int? ChassisIdSubtype { get; init; }

    public string? ChassisId { get; init; }

    public int? PortIdSubtype { get; init; }

    public string? PortId { get; init; }

    public string? PortDescription { get; init; }

    public string? SystemName { get; init; }

    public string? SystemDescription { get; init; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
