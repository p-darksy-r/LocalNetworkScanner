// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

public sealed record MacAddressResolution(
    string MacAddress,
    MacAddressResolutionSource Source)
{
    public bool ConfirmsReachability => Source is
        MacAddressResolutionSource.ActiveArp or
        MacAddressResolutionSource.CurrentReachableNeighbor;
}

public enum MacAddressResolutionSource
{
    LocalInterface,
    NeighborCache,
    ActiveArp,
    CurrentReachableNeighbor
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
