// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using System.Net.Sockets;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class WakeOnLanService
{
    public async Task SendAsync(
        string macAddress,
        IPAddress broadcastAddress,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(broadcastAddress);

        byte[] mac = ParseMac(macAddress);
        byte[] packet = new byte[6 + (16 * mac.Length)];
        Array.Fill(packet, (byte)0xFF, 0, 6);
        for (int repetition = 0; repetition < 16; repetition++)
            Buffer.BlockCopy(mac, 0, packet, 6 + (repetition * mac.Length), mac.Length);

        using UdpClient client = new(AddressFamily.InterNetwork)
        {
            EnableBroadcast = true
        };

        foreach (int port in new[] { 9, 7 })
        {
            await client.SendAsync(
                packet,
                new IPEndPoint(broadcastAddress, port),
                cancellationToken);
        }
    }

    private static byte[] ParseMac(string value)
    {
        if (!MacAddressService.TryNormalizeDeviceAddress(value, out string normalized))
        {
            throw new ScanFormatException(
                DiagnosticCatalog.InvalidMacAddress("Wake-on-LAN", value));
        }

        string hex = normalized.Replace(":", string.Empty, StringComparison.Ordinal);
        byte[] result = new byte[6];
        for (int index = 0; index < result.Length; index++)
            result[index] = Convert.ToByte(hex.Substring(index * 2, 2), 16);
        return result;
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
