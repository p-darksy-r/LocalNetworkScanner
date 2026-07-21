using System.Net;
using System.Net.Sockets;

namespace LocalNetworkScanner.Core.Utilities;

public static class IpAddressHelper
{
    public static uint ToUInt32(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();

        if (bytes.Length != 4)
            throw new ArgumentException("Apenas endereços IPv4 são suportados.", nameof(address));

        return ((uint)bytes[0] << 24)
             | ((uint)bytes[1] << 16)
             | ((uint)bytes[2] << 8)
             | bytes[3];
    }

    public static IPAddress FromUInt32(uint address)
    {
        return new IPAddress(
        [
            (byte)(address >> 24),
            (byte)(address >> 16),
            (byte)(address >> 8),
            (byte)address
        ]);
    }

    public static IPAddress GetNetworkAddress(IPAddress ipAddress, IPAddress subnetMask)
    {
        return FromUInt32(ToUInt32(ipAddress) & ToUInt32(subnetMask));
    }

    public static IPAddress GetBroadcastAddress(IPAddress ipAddress, IPAddress subnetMask)
    {
        uint network = ToUInt32(ipAddress) & ToUInt32(subnetMask);
        return FromUInt32(network | ~ToUInt32(subnetMask));
    }

    public static bool IsInSameSubnet(IPAddress first, IPAddress second, IPAddress subnetMask)
    {
        if (first.AddressFamily != AddressFamily.InterNetwork ||
            second.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        uint mask = ToUInt32(subnetMask);
        return (ToUInt32(first) & mask) == (ToUInt32(second) & mask);
    }

    public static int GetPrefixLength(IPAddress subnetMask)
    {
        uint mask = ToUInt32(subnetMask);
        bool foundZero = false;
        int prefix = 0;

        for (int bit = 31; bit >= 0; bit--)
        {
            bool set = (mask & (1u << bit)) != 0;
            if (set && foundZero)
                throw new ArgumentException("A máscara IPv4 não é contígua.", nameof(subnetMask));

            if (set)
                prefix++;
            else
                foundZero = true;
        }

        return prefix;
    }

    public static IPAddress PrefixToMask(int prefixLength)
    {
        if (prefixLength is < 0 or > 32)
            throw new ArgumentOutOfRangeException(nameof(prefixLength), "O prefixo deve estar entre 0 e 32.");

        uint mask = prefixLength == 0 ? 0 : uint.MaxValue << (32 - prefixLength);
        return FromUInt32(mask);
    }

    public static (IPAddress Address, int PrefixLength) ParseCidr(string cidr)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cidr);
        string[] parts = cidr.Trim().Split('/', StringSplitOptions.TrimEntries);

        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out IPAddress? address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out int prefix) ||
            prefix is < 0 or > 32)
        {
            throw new FormatException($"CIDR IPv4 inválido: '{cidr}'. Exemplo esperado: 192.168.1.0/24.");
        }

        return (address, prefix);
    }

    public static bool IsPrivate(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return bytes.Length == 4 &&
            (bytes[0] == 10 ||
             bytes[0] == 127 ||
             (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
             (bytes[0] == 192 && bytes[1] == 168) ||
             (bytes[0] == 169 && bytes[1] == 254));
    }
}
