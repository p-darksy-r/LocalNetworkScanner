// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

public enum NetworkMapEdgeKind
{
    Contains,
    DefaultRoute,
    Layer2Observed,
    MacLearned,
    IpReachability,
    LldpNeighbor
}

public sealed class NetworkMapEdge
{
    public required string SourceId { get; init; }

    public required string TargetId { get; init; }

    public required NetworkMapEdgeKind Kind { get; init; }

    public required string Label { get; init; }

    public required string Evidence { get; init; }

    public ConfidenceLevel Confidence { get; init; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
