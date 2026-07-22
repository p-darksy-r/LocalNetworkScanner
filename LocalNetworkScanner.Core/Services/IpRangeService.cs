// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class IpRangeService
{
    public const int DefaultMaximumAddresses = 4_096;
    public const int AbsoluteMaximumAddresses = 65_536;

    public IReadOnlyList<IPAddress> GenerateUsableAddresses(
        IPAddress ipAddress,
        IPAddress subnetMask,
        int maximumAddresses = DefaultMaximumAddresses)
    {
        return Generate(
            IpAddressHelper.GetNetworkAddress(ipAddress, subnetMask),
            IpAddressHelper.GetPrefixLength(subnetMask),
            maximumAddresses);
    }

    public IReadOnlyList<IPAddress> GenerateFromCidr(
        string cidr,
        int maximumAddresses = DefaultMaximumAddresses)
    {
        (IPAddress address, int prefix) parsed;
        try
        {
            parsed = IpAddressHelper.ParseCidr(cidr);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw new ScanFormatException(DiagnosticCatalog.InvalidCidr(cidr), exception);
        }

        (IPAddress address, int prefix) = parsed;
        IPAddress mask = IpAddressHelper.PrefixToMask(prefix);
        return Generate(IpAddressHelper.GetNetworkAddress(address, mask), prefix, maximumAddresses);
    }

    private static IReadOnlyList<IPAddress> Generate(
        IPAddress networkAddress,
        int prefixLength,
        int maximumAddresses)
    {
        if (maximumAddresses is < 1 or > AbsoluteMaximumAddresses)
        {
            throw new ScanRangeException(
                DiagnosticCatalog.InvalidScanConfiguration(nameof(maximumAddresses)),
                nameof(maximumAddresses),
                maximumAddresses);
        }

        ulong addressCount = 1UL << (32 - prefixLength);
        ulong usableCount = prefixLength switch
        {
            32 => 1,
            31 => 2,
            _ => addressCount - 2
        };

        if (usableCount > (ulong)maximumAddresses)
        {
            throw new ScanOperationException(
                DiagnosticCatalog.RangeLimitExceeded(
                    networkAddress + "/" + prefixLength.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    usableCount > int.MaxValue ? null : (int)usableCount,
                    maximumAddresses));
        }

        uint first = IpAddressHelper.ToUInt32(networkAddress);
        if (prefixLength < 31)
            first++;

        List<IPAddress> addresses = new((int)usableCount);
        for (ulong offset = 0; offset < usableCount; offset++)
            addresses.Add(IpAddressHelper.FromUInt32(first + (uint)offset));

        return addresses;
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
