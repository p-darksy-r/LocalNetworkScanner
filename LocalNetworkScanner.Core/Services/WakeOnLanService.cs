using System.Net;
using System.Net.Sockets;

namespace LocalNetworkScanner.Core.Services;

public sealed class WakeOnLanService
{
    public async Task SendAsync(
        string macAddress,
        IPAddress broadcastAddress,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(macAddress);
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
        string hex = new(value.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12)
            throw new FormatException("O endereço MAC deve conter 12 dígitos hexadecimais.");

        byte[] result = new byte[6];
        for (int index = 0; index < result.Length; index++)
            result[index] = Convert.ToByte(hex.Substring(index * 2, 2), 16);
        return result;
    }
}
