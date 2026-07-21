using System.Net;

namespace LocalNetworkScanner.Core.Models;

public sealed class DiscoveryObservation
{
    public required IPAddress IpAddress { get; init; }
    public required DiscoveryMethod Method { get; init; }
    public string? Hostname { get; init; }
    public string? Server { get; init; }
    public string? Location { get; init; }
}
