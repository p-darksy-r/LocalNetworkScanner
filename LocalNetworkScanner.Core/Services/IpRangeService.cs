using System.Net;
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
        (IPAddress address, int prefix) = IpAddressHelper.ParseCidr(cidr);
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
            throw new ArgumentOutOfRangeException(
                nameof(maximumAddresses),
                $"O limite deve estar entre 1 e {AbsoluteMaximumAddresses:N0} endereços.");
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
            throw new InvalidOperationException(
                $"A rede contém {usableCount:N0} endereços utilizáveis. " +
                $"O limite atual é {maximumAddresses:N0}; usa --max-hosts para o aumentar conscientemente.");
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
