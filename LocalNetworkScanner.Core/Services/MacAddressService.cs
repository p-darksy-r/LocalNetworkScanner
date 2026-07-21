using System.Net;
using System.Runtime.InteropServices;
using System.Globalization;
using System.Text.RegularExpressions;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed partial class MacAddressService
{
    public async Task<string?> ResolveAsync(
        IPAddress address,
        LocalNetworkInterface networkInterface,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(networkInterface);
        cancellationToken.ThrowIfCancellationRequested();

        if (address.Equals(networkInterface.IpAddress))
            return string.IsNullOrWhiteSpace(networkInterface.MacAddress) ? null : networkInterface.MacAddress;

        if (!IpAddressHelper.IsInSameSubnet(address, networkInterface.IpAddress, networkInterface.SubnetMask))
            return null;

        if (OperatingSystem.IsWindows())
        {
            string? direct = ResolveWithSendArp(address, networkInterface.IpAddress);
            if (direct is not null)
                return direct;
        }

        string? output = OperatingSystem.IsWindows()
            ? await ProcessRunner.RunAsync("arp.exe", ["-a", address.ToString()], 1_500, cancellationToken)
            : await ProcessRunner.RunAsync("ip", ["neigh", "show", address.ToString()], 1_500, cancellationToken);

        if (string.IsNullOrWhiteSpace(output))
            return null;

        Match match = MacRegex().Match(output);
        return match.Success ? Normalize(match.Value) : null;
    }

    private static string? ResolveWithSendArp(IPAddress address, IPAddress sourceAddress)
    {
        byte[] addressBytes = address.GetAddressBytes();
        byte[] sourceBytes = sourceAddress.GetAddressBytes();
        if (addressBytes.Length != 4 || sourceBytes.Length != 4)
            return null;

        byte[] mac = new byte[8];
        int length = mac.Length;
        uint destination = BitConverter.ToUInt32(addressBytes, 0);
        uint source = BitConverter.ToUInt32(sourceBytes, 0);
        int result = SendARP(destination, source, mac, ref length);

        return result == 0 && length >= 6
            ? string.Join(":", mac.Take(length).Select(value => value.ToString("X2", CultureInfo.InvariantCulture)))
            : null;
    }

    public static string Normalize(string value)
    {
        string hex = new(value.Where(Uri.IsHexDigit).ToArray());
        return hex.Length < 12
            ? value.ToUpperInvariant()
            : string.Join(":", Enumerable.Range(0, 6).Select(index => hex.Substring(index * 2, 2).ToUpperInvariant()));
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destinationIp, uint sourceIp, byte[] macAddress, ref int physicalAddressLength);

    [GeneratedRegex(@"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", RegexOptions.CultureInvariant)]
    private static partial Regex MacRegex();
}
