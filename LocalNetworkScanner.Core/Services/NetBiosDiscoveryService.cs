// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Globalization;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class NetBiosDiscoveryService
{
    private const int NetBiosNameServicePort = 137;

    public async Task<NetBiosInfo?> ProbeAsync(
        IPAddress address,
        int timeoutMs,
        CancellationToken cancellationToken)
        => await ProbeAsync(address, timeoutMs, null, cancellationToken);

    public async Task<NetBiosInfo?> ProbeAsync(
        IPAddress address,
        int timeoutMs,
        IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return null;

        using UdpClient client = new(AddressFamily.InterNetwork);
        if (localAddress is not null)
            client.Client.Bind(new IPEndPoint(localAddress, 0));
        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Math.Max(100, timeoutMs));

        try
        {
            byte[] request = BuildNodeStatusRequest(out ushort transactionId);
            await client.SendAsync(
                request,
                new IPEndPoint(address, NetBiosNameServicePort),
                timeout.Token);
            while (true)
            {
                UdpReceiveResult response = await client.ReceiveAsync(timeout.Token);
                if (!response.RemoteEndPoint.Address.Equals(address))
                    continue;

                try
                {
                    NetBiosInfo? result = ParseNodeStatusResponse(response.Buffer, transactionId);
                    if (result is not null)
                        return result;
                }
                catch (InvalidDataException)
                {
                    // Ignora datagramas estranhos até ao timeout do pedido correlacionado.
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SocketException or OperationCanceledException or InvalidDataException)
        {
            return null;
        }
    }

    internal static byte[] BuildNodeStatusRequest()
        => BuildNodeStatusRequest(out _);

    internal static byte[] BuildNodeStatusRequest(out ushort transactionId)
    {
        byte[] packet = new byte[50];
        transactionId = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue + 1);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), transactionId);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), 1);

        packet[12] = 32;
        Span<byte> netBiosName = stackalloc byte[16];
        netBiosName[0] = (byte)'*';
        for (int index = 0; index < netBiosName.Length; index++)
        {
            packet[13 + (index * 2)] = (byte)('A' + (netBiosName[index] >> 4));
            packet[14 + (index * 2)] = (byte)('A' + (netBiosName[index] & 0x0F));
        }

        packet[45] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(46, 2), 0x0021);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(48, 2), 0x0001);
        return packet;
    }

    internal static NetBiosInfo? ParseNodeStatusResponse(
        byte[] packet,
        ushort? expectedTransactionId = null)
    {
        if (packet.Length < 12)
            return null;

        ushort transactionId = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(0, 2));
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2));
        if (expectedTransactionId.HasValue && transactionId != expectedTransactionId.Value)
            return null;
        if ((flags & 0x8000) == 0 || (flags & 0x000F) != 0)
            return null;

        int questionCount = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
        int answerCount = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2));
        int offset = 12;

        for (int index = 0; index < questionCount; index++)
        {
            SkipDnsName(packet, ref offset);
            EnsureAvailable(packet, offset, 4);
            offset += 4;
        }

        for (int answer = 0; answer < answerCount; answer++)
        {
            SkipDnsName(packet, ref offset);
            EnsureAvailable(packet, offset, 10);
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));
            ushort recordClass = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 2, 2));
            ushort dataLength = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 8, 2));
            offset += 10;
            EnsureAvailable(packet, offset, dataLength);

            if (type == 0x0021 && recordClass == 0x0001)
                return ParseNodeStatusData(packet.AsSpan(offset, dataLength));

            offset += dataLength;
        }

        return null;
    }

    private static NetBiosInfo? ParseNodeStatusData(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1)
            return null;

        int nameCount = data[0];
        int required = 1 + (nameCount * 18);
        if (data.Length < required)
            throw new InvalidDataException("Resposta NetBIOS truncada.");

        string? computerName = null;
        string? workgroup = null;
        for (int index = 0; index < nameCount; index++)
        {
            ReadOnlySpan<byte> entry = data.Slice(1 + (index * 18), 18);
            string name = System.Text.Encoding.ASCII.GetString(entry[..15]).Trim();
            byte suffix = entry[15];
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(entry[16..18]);
            bool isGroup = (flags & 0x8000) != 0;

            if (!isGroup && suffix is 0x00 or 0x20 && string.IsNullOrWhiteSpace(computerName))
                computerName = name;
            if (isGroup && suffix is 0x00 or 0x1E && string.IsNullOrWhiteSpace(workgroup))
                workgroup = name;
        }

        string? macAddress = null;
        if (data.Length >= required + 6)
        {
            ReadOnlySpan<byte> mac = data.Slice(required, 6);
            if (mac.IndexOfAnyExcept((byte)0) >= 0)
                macAddress = string.Join(":", mac.ToArray().Select(value => value.ToString("X2", CultureInfo.InvariantCulture)));
        }

        return string.IsNullOrWhiteSpace(computerName) &&
               string.IsNullOrWhiteSpace(workgroup) &&
               string.IsNullOrWhiteSpace(macAddress)
            ? null
            : new NetBiosInfo
            {
                ComputerName = computerName,
                Workgroup = workgroup,
                MacAddress = macAddress
            };
    }

    private static void SkipDnsName(byte[] packet, ref int offset)
    {
        int labels = 0;
        while (true)
        {
            EnsureAvailable(packet, offset, 1);
            byte length = packet[offset++];
            if (length == 0)
                return;
            if ((length & 0xC0) == 0xC0)
            {
                EnsureAvailable(packet, offset, 1);
                offset++;
                return;
            }
            if ((length & 0xC0) != 0 || ++labels > 128)
                throw new InvalidDataException("Nome NetBIOS inválido.");

            EnsureAvailable(packet, offset, length);
            offset += length;
        }
    }

    private static void EnsureAvailable(byte[] packet, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset > packet.Length - length)
            throw new InvalidDataException("Resposta NetBIOS truncada.");
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
