// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

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

    /// <summary>
    /// Valida e normaliza um MAC unicast de 48 bits adequado à identidade de um dispositivo.
    /// </summary>
    public static bool TryNormalizeDeviceAddress(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        string trimmed = value.Trim();
        if (!ValidDeviceMacRegex().IsMatch(trimmed))
            return false;

        string hex = new(trimmed
            .Where(character => character is not (':' or '-' or '.'))
            .ToArray());

        byte[] bytes = new byte[6];
        for (int index = 0; index < bytes.Length; index++)
        {
            if (!byte.TryParse(
                    hex.AsSpan(index * 2, 2),
                    System.Globalization.NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out bytes[index]))
            {
                return false;
            }
        }

        bool allZero = bytes.All(item => item == 0);
        bool allBroadcast = bytes.All(item => item == byte.MaxValue);
        bool isGroupAddress = (bytes[0] & 0x01) != 0;
        if (allZero || allBroadcast || isGroupAddress)
            return false;

        normalized = string.Join(
            ":",
            bytes.Select(item => item.ToString("X2", CultureInfo.InvariantCulture)));
        return true;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destinationIp, uint sourceIp, byte[] macAddress, ref int physicalAddressLength);

    [GeneratedRegex(
        @"(?i)(?<![0-9a-f])[0-9a-f]{2}(?<separator>[:-])(?:[0-9a-f]{2}\k<separator>){4}[0-9a-f]{2}(?![0-9a-f])",
        RegexOptions.CultureInvariant)]
    private static partial Regex MacRegex();

    [GeneratedRegex(
        @"^(?:[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})$",
        RegexOptions.CultureInvariant)]
    private static partial Regex ValidDeviceMacRegex();
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
