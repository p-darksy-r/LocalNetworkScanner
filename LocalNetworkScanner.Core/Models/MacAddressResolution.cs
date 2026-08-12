// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

public sealed record MacAddressResolution(
    string MacAddress,
    MacAddressResolutionSource Source)
{
    public bool ConfirmsReachability => Source == MacAddressResolutionSource.ActiveArp;
}

public enum MacAddressResolutionSource
{
    LocalInterface,
    NeighborCache,
    ActiveArp
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
