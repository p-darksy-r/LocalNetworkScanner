using System.Net;

namespace LocalNetworkScanner.Core.Models;

public sealed class SnmpTopologyOptions
{
    public required IPAddress SwitchAddress { get; init; }

    public required string Community { get; init; }

    public int TimeoutMs { get; init; } = 900;

    public int Retries { get; init; } = 1;
}
