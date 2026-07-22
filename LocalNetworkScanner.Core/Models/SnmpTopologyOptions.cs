// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;

namespace LocalNetworkScanner.Core.Models;

public sealed class SnmpTopologyOptions
{
    public required IPAddress SwitchAddress { get; init; }

    public required string Community { get; init; }

    public int TimeoutMs { get; init; } = 900;

    public int Retries { get; init; } = 1;
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
