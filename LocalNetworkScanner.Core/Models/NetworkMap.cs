namespace LocalNetworkScanner.Core.Models;

public sealed class NetworkMap
{
    public required string NetworkCidr { get; init; }

    public required DateTimeOffset GeneratedAt { get; init; }

    public required IReadOnlyList<NetworkMapNode> Nodes { get; init; }

    public required IReadOnlyList<NetworkMapEdge> Edges { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = [];
}
