using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class MdnsDiscoveryService
{
    private static readonly IPEndPoint MulticastEndpoint = new(IPAddress.Parse("224.0.0.251"), 5353);

    public async Task<IReadOnlyList<DiscoveryObservation>> DiscoverAsync(
        int timeoutMs,
        CancellationToken cancellationToken)
        => await DiscoverAsync(timeoutMs, null, cancellationToken);

    public async Task<IReadOnlyList<DiscoveryObservation>> DiscoverAsync(
        int timeoutMs,
        IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        Dictionary<IPAddress, DiscoveryObservation> observations = [];

        try
        {
            using UdpClient client = new(AddressFamily.InterNetwork);
            if (localAddress is not null)
            {
                client.Client.Bind(new IPEndPoint(localAddress, 0));
                client.Client.SetSocketOption(
                    SocketOptionLevel.IP,
                    SocketOptionName.MulticastInterface,
                    localAddress.GetAddressBytes());
            }
            byte[] query = BuildQuery("_services._dns-sd._udp.local");
            await client.SendAsync(query, MulticastEndpoint, cancellationToken);

            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(timeoutMs);

            while (!timeout.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult response = await client.ReceiveAsync(timeout.Token);
                    foreach ((IPAddress address, string? hostname) in ParseAddressRecords(response.Buffer))
                    {
                        observations[address] = new DiscoveryObservation
                        {
                            IpAddress = address,
                            Method = DiscoveryMethod.Mdns,
                            Hostname = hostname
                        };
                    }
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is SocketException or InvalidOperationException)
        {
            return [];
        }

        return observations.Values.ToList();
    }

    internal static byte[] BuildQuery(string name)
    {
        using MemoryStream stream = new();
        stream.Write(new byte[12]);
        foreach (string label in name.Split('.'))
        {
            byte[] bytes = Encoding.UTF8.GetBytes(label);
            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0);
        stream.Write([0, 12]); // PTR
        stream.Write([128, 1]); // IN + pedido de resposta unicast
        byte[] packet = stream.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), 1);
        return packet;
    }

    internal static IReadOnlyList<(IPAddress Address, string? Hostname)> ParseAddressRecords(byte[] packet)
    {
        List<(IPAddress, string?)> results = [];
        if (packet.Length < 12)
            return results;

        int questionCount = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
        int recordCount = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2)) +
                          BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(8, 2)) +
                          BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(10, 2));
        int offset = 12;

        try
        {
            for (int index = 0; index < questionCount; index++)
            {
                ReadName(packet, ref offset);
                offset += 4;
            }

            for (int index = 0; index < recordCount; index++)
            {
                string owner = ReadName(packet, ref offset).TrimEnd('.');
                if (offset + 10 > packet.Length)
                    break;

                ushort type = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));
                ushort length = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 8, 2));
                offset += 10;

                if (offset + length > packet.Length)
                    break;

                if (type == 1 && length == 4)
                {
                    IPAddress address = new(packet.AsSpan(offset, 4));
                    results.Add((address, string.IsNullOrWhiteSpace(owner) ? null : owner));
                }

                offset += length;
            }
        }
        catch (InvalidDataException)
        {
            return results;
        }

        return results;
    }

    private static string ReadName(byte[] packet, ref int offset)
    {
        StringBuilder name = new();
        int cursor = offset;
        bool jumped = false;
        int jumps = 0;

        while (cursor < packet.Length)
        {
            byte length = packet[cursor++];
            if (length == 0)
            {
                if (!jumped)
                    offset = cursor;
                return name.ToString();
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (cursor >= packet.Length || ++jumps > 20)
                    throw new InvalidDataException("Ponteiro DNS inválido.");

                int pointer = ((length & 0x3F) << 8) | packet[cursor++];
                if (!jumped)
                    offset = cursor;
                cursor = pointer;
                jumped = true;
                continue;
            }

            if (cursor + length > packet.Length)
                throw new InvalidDataException("Nome DNS truncado.");

            if (name.Length > 0)
                name.Append('.');
            name.Append(Encoding.UTF8.GetString(packet, cursor, length));
            cursor += length;

            if (!jumped)
                offset = cursor;
        }

        throw new InvalidDataException("Nome DNS sem terminador.");
    }
}
