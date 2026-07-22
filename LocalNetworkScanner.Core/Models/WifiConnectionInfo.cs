// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

public sealed class WifiConnectionInfo
{
    public string? Name { get; init; }
    public string? Description { get; init; }
    public string? Ssid { get; init; }
    public string? Bssid { get; init; }
    public int? SignalPercent { get; init; }
    public int? Channel { get; init; }
    public string? RadioType { get; init; }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
