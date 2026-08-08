// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class MdnsDiscoveryService
{
    private const string ServiceEnumerationName = "_services._dns-sd._udp.local";
    private const ushort InternetClass = 1;
    private const ushort AddressType = 1;
    private const ushort PointerType = 12;
    private const ushort TextType = 16;
    private const ushort AddressV6Type = 28;
    private const ushort ServiceType = 33;
    private const int MaximumDiscoveryTimeMs = 30_000;
    private const int MaximumPacketLength = 16 * 1024;
    private const int MaximumQuestionsPerPacket = 64;
    private const int MaximumRecordsPerPacket = 256;
    private const int MaximumNameWireLength = 255;
    private const int MaximumPointerHops = 32;
    private const int MaximumQueries = 320;
    private const int MaximumServiceTypes = 32;
    private const int MaximumInstances = 64;
    private const int MaximumHosts = 64;
    private const int MaximumEvidenceHosts = 256;
    private const int MaximumAddressesPerHost = 8;
    private const int MaximumInstancesPerHost = 8;
    private const int MaximumServiceTypesPerInstance = 8;
    private const int MaximumTxtFieldsPerInstance = 16;
    private const int MaximumIdentityValueLength = 160;
    private const int MaximumObservations = 512;
    private const int MaximumReceivedDatagrams = 512;
    private const int MaximumReceivedBytes = 2 * 1024 * 1024;
    private const int MaximumAccumulatedRecords = 4_096;

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
        cancellationToken.ThrowIfCancellationRequested();
        if (timeoutMs <= 0 ||
            (localAddress is not null && localAddress.AddressFamily != AddressFamily.InterNetwork))
        {
            return [];
        }

        MdnsEvidenceAccumulator evidence = new();
        HashSet<MdnsQuestion> sentQuestions = [];
        HashSet<string> serviceTypes = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> instances = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> hosts = new(StringComparer.OrdinalIgnoreCase);
        MulticastReceiveBudget receiveBudget = new(
            MaximumReceivedDatagrams,
            MaximumReceivedBytes,
            MaximumAccumulatedRecords);

        try
        {
            using UdpClient client = CreateDiscoveryClient(localAddress);

            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(Math.Min(timeoutMs, MaximumDiscoveryTimeMs));

            await SendOnceAsync(
                client,
                new MdnsQuestion(ServiceEnumerationName, PointerType),
                sentQuestions,
                timeout.Token);

            while (!timeout.IsCancellationRequested)
            {
                UdpReceiveResult response;
                try
                {
                    response = await client.ReceiveAsync(timeout.Token);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException)
                {
                    break;
                }

                if (!receiveBudget.TryConsumeDatagram(response.Buffer.Length))
                    break;

                if (!IsValidResponse(response))
                    continue;

                MdnsMessage message = ParseMessage(response.Buffer);
                if (message.Records.Count == 0)
                    continue;
                if (!receiveBudget.TryConsumeItems(message.Records.Count))
                    break;

                evidence.Add(message.Records, response.RemoteEndPoint.Address);
                IReadOnlyList<MdnsQuestion> followUpQuestions = FindFollowUpQuestions(
                    message.Records,
                    serviceTypes,
                    instances,
                    hosts);

                foreach (MdnsQuestion question in followUpQuestions)
                {
                    if (sentQuestions.Count >= MaximumQueries)
                        break;

                    await SendOnceAsync(client, question, sentQuestions, timeout.Token);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            // O orçamento temporal interno terminou entre a receção e uma consulta dirigida.
        }
        catch (Exception exception) when (
            exception is SocketException or InvalidOperationException or ArgumentException)
        {
            // A descoberta multicast é complementar. Preserva qualquer evidência válida
            // já recebida quando a interface ou a pilha de rede deixa de estar disponível.
        }

        return evidence.BuildObservations();
    }

    internal static byte[] BuildQuery(string name)
        => BuildQuery(name, PointerType);

    internal static byte[] BuildQuery(string name, ushort type)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (type == 0)
            throw new ArgumentOutOfRangeException(nameof(type));

        string normalizedName = NormalizeName(name);
        string[] labels = normalizedName.Split('.');
        using MemoryStream stream = new();
        stream.Write(new byte[12]);

        int wireLength = 1;
        foreach (string label in labels)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(label);
            if (bytes.Length is 0 or > 63 || wireLength + bytes.Length + 1 > MaximumNameWireLength)
                throw new ArgumentException("O nome DNS contém uma etiqueta inválida.", nameof(name));

            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
            wireLength += bytes.Length + 1;
        }

        stream.WriteByte(0);
        Span<byte> question = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(question, type);
        BinaryPrimitives.WriteUInt16BigEndian(question[2..], 0x8001); // IN + resposta unicast
        stream.Write(question);

        byte[] packet = stream.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), 1);
        return packet;
    }

    internal static IReadOnlyList<(IPAddress Address, string? Hostname)> ParseAddressRecords(byte[] packet)
    {
        ArgumentNullException.ThrowIfNull(packet);

        return ParseMessage(packet).Records
            .Where(record => record.Address is not null)
            .Select(record => (record.Address!, NullIfEmpty(record.Owner)))
            .ToList();
    }

    internal static MdnsMessage ParseMessage(byte[] packet)
    {
        ArgumentNullException.ThrowIfNull(packet);
        if (packet.Length is < 12 or > MaximumPacketLength)
            return MdnsMessage.Empty;

        int questionCount = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
        int recordCount = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2)) +
                          BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(8, 2)) +
                          BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(10, 2));
        if (questionCount > MaximumQuestionsPerPacket || recordCount > MaximumRecordsPerPacket)
            return MdnsMessage.Empty;

        List<MdnsResourceRecord> records = new(recordCount);
        int offset = 12;

        try
        {
            for (int index = 0; index < questionCount; index++)
            {
                _ = ReadName(packet, ref offset);
                EnsureAvailable(packet, offset, 4);
                offset += 4;
            }

            for (int index = 0; index < recordCount; index++)
            {
                string owner = NormalizeName(ReadName(packet, ref offset));
                EnsureAvailable(packet, offset, 10);

                ushort type = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));
                ushort recordClass =
                    (ushort)(BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 2, 2)) & 0x7FFF);
                uint timeToLive = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset + 4, 4));
                ushort length = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 8, 2));
                offset += 10;
                EnsureAvailable(packet, offset, length);

                int dataOffset = offset;
                int dataEnd = dataOffset + length;
                MdnsResourceRecord? record = ParseResourceRecord(
                    packet,
                    owner,
                    type,
                    recordClass,
                    timeToLive,
                    dataOffset,
                    dataEnd);
                if (record is not null)
                    records.Add(record);

                offset = dataEnd;
            }
        }
        catch (InvalidDataException)
        {
            // Mantém os registos completos que precedem uma secção truncada ou inválida.
        }

        return new MdnsMessage(records);
    }

    internal static IReadOnlyList<DiscoveryObservation> CorrelateRecords(
        IReadOnlyList<MdnsResourceRecord> records)
        => CorrelateRecords(records, null);

    internal static IReadOnlyList<DiscoveryObservation> CorrelateRecords(
        IReadOnlyList<MdnsResourceRecord> records,
        IPAddress? responderAddress)
    {
        ArgumentNullException.ThrowIfNull(records);

        MdnsEvidenceAccumulator evidence = new();
        evidence.Add(records, responderAddress);
        return evidence.BuildObservations();
    }

    private static bool IsValidResponse(UdpReceiveResult response) =>
        IsValidResponse(response.Buffer, response.RemoteEndPoint.Port);

    internal static bool IsValidResponse(byte[] packet, int sourcePort)
    {
        ArgumentNullException.ThrowIfNull(packet);
        if (sourcePort != MulticastEndpoint.Port ||
            packet.Length is < 12 or > MaximumPacketLength)
        {
            return false;
        }

        ushort transactionId =
            BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(0, 2));
        ushort flags =
            BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2));
        const ushort responseFlag = 0x8000;
        const ushort opcodeMask = 0x7800;

        return transactionId == 0 &&
               (flags & responseFlag) != 0 &&
               (flags & opcodeMask) == 0;
    }

    private static MdnsResourceRecord? ParseResourceRecord(
        byte[] packet,
        string owner,
        ushort type,
        ushort recordClass,
        uint timeToLive,
        int dataOffset,
        int dataEnd)
    {
        try
        {
            return type switch
            {
                AddressType when dataEnd - dataOffset == 4 =>
                    new MdnsResourceRecord(
                        owner,
                        type,
                        recordClass,
                        timeToLive,
                        Address: new IPAddress(packet.AsSpan(dataOffset, 4))),
                AddressV6Type when dataEnd - dataOffset == 16 =>
                    new MdnsResourceRecord(
                        owner,
                        type,
                        recordClass,
                        timeToLive,
                        Address: new IPAddress(packet.AsSpan(dataOffset, 16))),
                PointerType => ParsePointerRecord(
                    packet,
                    owner,
                    type,
                    recordClass,
                    timeToLive,
                    dataOffset,
                    dataEnd),
                ServiceType => ParseServiceRecord(
                    packet,
                    owner,
                    type,
                    recordClass,
                    timeToLive,
                    dataOffset,
                    dataEnd),
                TextType => ParseTextRecord(
                    packet,
                    owner,
                    type,
                    recordClass,
                    timeToLive,
                    dataOffset,
                    dataEnd),
                _ => null
            };
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    private static MdnsResourceRecord ParsePointerRecord(
        byte[] packet,
        string owner,
        ushort type,
        ushort recordClass,
        uint timeToLive,
        int dataOffset,
        int dataEnd)
    {
        int cursor = dataOffset;
        string target = NormalizeName(ReadName(packet, ref cursor));
        if (cursor != dataEnd || string.IsNullOrEmpty(target))
            throw new InvalidDataException("Registo PTR inválido.");

        return new MdnsResourceRecord(
            owner,
            type,
            recordClass,
            timeToLive,
            DomainName: target);
    }

    private static MdnsResourceRecord ParseServiceRecord(
        byte[] packet,
        string owner,
        ushort type,
        ushort recordClass,
        uint timeToLive,
        int dataOffset,
        int dataEnd)
    {
        if (dataEnd - dataOffset < 7)
            throw new InvalidDataException("Registo SRV truncado.");

        ushort priority = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(dataOffset, 2));
        ushort weight = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(dataOffset + 2, 2));
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(dataOffset + 4, 2));
        int cursor = dataOffset + 6;
        string target = NormalizeName(ReadName(packet, ref cursor));
        if (cursor != dataEnd || string.IsNullOrEmpty(target))
            throw new InvalidDataException("Alvo SRV inválido.");

        return new MdnsResourceRecord(
            owner,
            type,
            recordClass,
            timeToLive,
            DomainName: target,
            Port: port,
            Priority: priority,
            Weight: weight);
    }

    private static MdnsResourceRecord ParseTextRecord(
        byte[] packet,
        string owner,
        ushort type,
        ushort recordClass,
        uint timeToLive,
        int dataOffset,
        int dataEnd)
    {
        List<string> text = [];
        int cursor = dataOffset;
        while (cursor < dataEnd)
        {
            int length = packet[cursor++];
            if (cursor + length > dataEnd)
                throw new InvalidDataException("Registo TXT truncado.");

            text.Add(Encoding.UTF8.GetString(packet, cursor, length));
            cursor += length;
        }

        return new MdnsResourceRecord(
            owner,
            type,
            recordClass,
            timeToLive,
            Text: text);
    }

    private static IReadOnlyList<MdnsQuestion> FindFollowUpQuestions(
        IReadOnlyList<MdnsResourceRecord> records,
        HashSet<string> serviceTypes,
        HashSet<string> instances,
        HashSet<string> hosts)
    {
        List<MdnsQuestion> questions = [];

        foreach (MdnsResourceRecord record in records)
        {
            if (record.RecordClass != InternetClass ||
                record.TimeToLive == 0 ||
                record.Type != PointerType ||
                !record.Owner.Equals(ServiceEnumerationName, StringComparison.OrdinalIgnoreCase) ||
                !IsServiceTypeName(record.DomainName))
            {
                continue;
            }

            if (serviceTypes.Count < MaximumServiceTypes && serviceTypes.Add(record.DomainName!))
                questions.Add(new MdnsQuestion(record.DomainName!, PointerType));
        }

        foreach (MdnsResourceRecord record in records)
        {
            if (record.RecordClass != InternetClass ||
                record.TimeToLive == 0 ||
                record.Type != PointerType ||
                !IsServiceTypeName(record.Owner) ||
                !IsInstanceOf(record.DomainName, record.Owner))
            {
                continue;
            }

            if (serviceTypes.Count < MaximumServiceTypes && serviceTypes.Add(record.Owner))
                questions.Add(new MdnsQuestion(record.Owner, PointerType));

            AddInstanceQuestions(record.DomainName!, instances, questions);
        }

        foreach (MdnsResourceRecord record in records)
        {
            if (record.RecordClass != InternetClass || record.TimeToLive == 0)
                continue;

            if (record.Type is ServiceType or TextType &&
                TryGetServiceTypeFromInstance(record.Owner, out string serviceType))
            {
                if (serviceTypes.Count < MaximumServiceTypes && serviceTypes.Add(serviceType))
                    questions.Add(new MdnsQuestion(serviceType, PointerType));

                AddInstanceQuestions(record.Owner, instances, questions);
            }

            if (record.Type == ServiceType && IsLocalName(record.DomainName))
                AddHostQuestions(record.DomainName!, hosts, questions);
        }

        return questions;
    }

    private static void AddInstanceQuestions(
        string instance,
        HashSet<string> instances,
        List<MdnsQuestion> questions)
    {
        if (instances.Count >= MaximumInstances || !instances.Add(instance))
            return;

        questions.Add(new MdnsQuestion(instance, ServiceType));
        questions.Add(new MdnsQuestion(instance, TextType));
    }

    private static void AddHostQuestions(
        string host,
        HashSet<string> hosts,
        List<MdnsQuestion> questions)
    {
        if (hosts.Count >= MaximumHosts || !hosts.Add(host))
            return;

        questions.Add(new MdnsQuestion(host, AddressType));
        questions.Add(new MdnsQuestion(host, AddressV6Type));
    }

    private static async Task SendOnceAsync(
        UdpClient client,
        MdnsQuestion question,
        HashSet<MdnsQuestion> sentQuestions,
        CancellationToken cancellationToken)
    {
        if (sentQuestions.Count >= MaximumQueries || !sentQuestions.Add(question))
            return;

        byte[] query = BuildQuery(question.Name, question.Type);
        _ = await client.SendAsync(query, MulticastEndpoint, cancellationToken);
    }

    private static UdpClient CreateDiscoveryClient(IPAddress? localAddress)
    {
        UdpClient client = new(AddressFamily.InterNetwork);
        try
        {
            // A porta 5353 e a adesão ao grupo permitem receber respostas multicast de
            // implementações que ignoram o bit QU. SO_REUSEADDR evita excluir o serviço
            // mDNS do Windows ou outro observador que já esteja ativo.
            client.Client.ExclusiveAddressUse = false;
            client.Client.SetSocketOption(
                SocketOptionLevel.Socket,
                SocketOptionName.ReuseAddress,
                true);
            client.Client.Bind(new IPEndPoint(IPAddress.Any, MulticastEndpoint.Port));

            ConfigureMulticastInterface(client, localAddress);
            if (localAddress is null)
                client.JoinMulticastGroup(MulticastEndpoint.Address);
            else
                client.JoinMulticastGroup(MulticastEndpoint.Address, localAddress);

            return client;
        }
        catch (Exception exception) when (
            exception is SocketException or InvalidOperationException or ArgumentException)
        {
            client.Dispose();

            // Em pilhas que não permitem partilhar 5353, mantém a descoberta QU
            // funcional numa porta efémera. A pergunta continua a pedir resposta unicast.
            UdpClient fallback = new(AddressFamily.InterNetwork);
            try
            {
                fallback.Client.Bind(new IPEndPoint(localAddress ?? IPAddress.Any, 0));
                ConfigureMulticastInterface(fallback, localAddress);
                return fallback;
            }
            catch
            {
                fallback.Dispose();
                throw;
            }
        }
    }

    private static void ConfigureMulticastInterface(UdpClient client, IPAddress? localAddress)
    {
        if (localAddress is null)
            return;

        client.Client.SetSocketOption(
            SocketOptionLevel.IP,
            SocketOptionName.MulticastInterface,
            localAddress.GetAddressBytes());
    }

    private static string ReadName(byte[] packet, ref int offset)
    {
        if ((uint)offset >= (uint)packet.Length)
            throw new InvalidDataException("Nome DNS fora do pacote.");

        List<string> labels = [];
        HashSet<int> visitedPointers = [];
        int cursor = offset;
        int? endOffset = null;
        int wireLength = 1;
        int pointerHops = 0;

        while ((uint)cursor < (uint)packet.Length)
        {
            byte length = packet[cursor++];
            if (length == 0)
            {
                offset = endOffset ?? cursor;
                return string.Join('.', labels);
            }

            if ((length & 0xC0) == 0xC0)
            {
                if ((uint)cursor >= (uint)packet.Length || ++pointerHops > MaximumPointerHops)
                    throw new InvalidDataException("Ponteiro DNS inválido.");

                int pointer = ((length & 0x3F) << 8) | packet[cursor++];
                if ((uint)pointer >= (uint)packet.Length || !visitedPointers.Add(pointer))
                    throw new InvalidDataException("Ciclo num ponteiro DNS.");

                endOffset ??= cursor;
                cursor = pointer;
                continue;
            }

            if ((length & 0xC0) != 0 ||
                length > 63 ||
                cursor + length > packet.Length ||
                wireLength + length + 1 > MaximumNameWireLength)
            {
                throw new InvalidDataException("Etiqueta DNS inválida ou truncada.");
            }

            labels.Add(Encoding.UTF8.GetString(packet, cursor, length));
            cursor += length;
            wireLength += length + 1;
        }

        throw new InvalidDataException("Nome DNS sem terminador.");
    }

    private static void EnsureAvailable(byte[] packet, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset > packet.Length - length)
            throw new InvalidDataException("Pacote DNS truncado.");
    }

    private static string NormalizeName(string name)
        => name.Trim().TrimEnd('.');

    private static string? NullIfEmpty(string value)
        => string.IsNullOrWhiteSpace(value) ? null : value;

    private static bool IsLocalName(string? name)
        => !string.IsNullOrWhiteSpace(name) &&
           (name.Equals("local", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".local", StringComparison.OrdinalIgnoreCase));

    private static bool IsServiceTypeName(string? name)
    {
        if (!IsLocalName(name))
            return false;

        string[] labels = name!.Split('.');
        return labels.Length >= 3 &&
               labels[^3].StartsWith('_') &&
               (labels[^2].Equals("_tcp", StringComparison.OrdinalIgnoreCase) ||
                labels[^2].Equals("_udp", StringComparison.OrdinalIgnoreCase)) &&
               labels[^1].Equals("local", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInstanceOf(string? instance, string serviceType)
        => IsLocalName(instance) &&
           instance!.Length > serviceType.Length + 1 &&
           instance.EndsWith('.' + serviceType, StringComparison.OrdinalIgnoreCase);

    private static bool TryGetServiceTypeFromInstance(string instance, out string serviceType)
    {
        serviceType = string.Empty;
        if (!IsLocalName(instance))
            return false;

        string[] labels = instance.Split('.');
        if (labels.Length < 4)
            return false;

        for (int index = labels.Length - 2; index >= 1; index--)
        {
            if (!labels[index].Equals("_tcp", StringComparison.OrdinalIgnoreCase) &&
                !labels[index].Equals("_udp", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (index < 1 || !labels[index - 1].StartsWith('_'))
                return false;

            serviceType = string.Join('.', labels[(index - 1)..]);
            return IsServiceTypeName(serviceType);
        }

        return false;
    }

    internal sealed record MdnsMessage(IReadOnlyList<MdnsResourceRecord> Records)
    {
        public static MdnsMessage Empty { get; } = new([]);
    }

    internal sealed record MdnsResourceRecord(
        string Owner,
        ushort Type,
        ushort RecordClass,
        uint TimeToLive,
        string? DomainName = null,
        IPAddress? Address = null,
        ushort? Port = null,
        ushort? Priority = null,
        ushort? Weight = null,
        IReadOnlyList<string>? Text = null);

    private sealed record MdnsQuestion(string Name, ushort Type);

    private sealed class MdnsEvidenceAccumulator
    {
        private readonly Dictionary<string, HashSet<IPAddress>> _addressesByHost =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, HashSet<IPAddress>> _directAddressesByHost =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, HashSet<string>> _instancesByHost =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, HashSet<string>> _pointerServiceTypesByInstance =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Dictionary<string, string>> _txtFieldsByInstance =
            new(StringComparer.OrdinalIgnoreCase);

        public void Add(
            IReadOnlyList<MdnsResourceRecord> records,
            IPAddress? responderAddress)
        {
            foreach (MdnsResourceRecord record in records)
            {
                if (record.RecordClass != InternetClass)
                    continue;

                if (record.Address is not null && IsUsableAddress(record.Address))
                {
                    if (record.TimeToLive == 0)
                    {
                        RemoveValue(_addressesByHost, record.Owner, record.Address);
                        if (record.Address.Equals(responderAddress))
                        {
                            RemoveValue(
                                _directAddressesByHost,
                                record.Owner,
                                record.Address);
                        }
                        continue;
                    }

                    if (TryGetOrCreate(_addressesByHost, record.Owner, out HashSet<IPAddress> addresses) &&
                        addresses.Count < MaximumAddressesPerHost)
                    {
                        addresses.Add(record.Address);
                    }

                    if (record.Address.Equals(responderAddress) &&
                        TryGetOrCreate(
                            _directAddressesByHost,
                            record.Owner,
                            out HashSet<IPAddress> directAddresses) &&
                        directAddresses.Count < MaximumAddressesPerHost)
                    {
                        directAddresses.Add(record.Address);
                    }
                }
                else if (record.Type == ServiceType &&
                         IsLocalName(record.DomainName) &&
                         TryGetServiceTypeFromInstance(record.Owner, out _))
                {
                    if (record.TimeToLive == 0)
                    {
                        RemoveValue(_instancesByHost, record.DomainName!, record.Owner);
                        continue;
                    }

                    if (TryGetOrCreate(_instancesByHost, record.DomainName!, out HashSet<string> instances) &&
                        instances.Count < MaximumInstancesPerHost)
                    {
                        instances.Add(record.Owner);
                    }
                }
                else if (record.Type == PointerType &&
                         IsServiceTypeName(record.Owner) &&
                         IsInstanceOf(record.DomainName, record.Owner))
                {
                    if (record.TimeToLive == 0)
                    {
                        RemoveValue(
                            _pointerServiceTypesByInstance,
                            record.DomainName!,
                            record.Owner);
                        continue;
                    }

                    if (TryGetOrCreate(
                            _pointerServiceTypesByInstance,
                            record.DomainName!,
                            out HashSet<string> serviceTypes) &&
                        serviceTypes.Count < MaximumServiceTypesPerInstance)
                    {
                        serviceTypes.Add(record.Owner);
                    }
                }
                else if (record.Type == TextType &&
                         TryGetServiceTypeFromInstance(record.Owner, out _))
                {
                    if (record.TimeToLive == 0)
                    {
                        _txtFieldsByInstance.Remove(record.Owner);
                        continue;
                    }

                    IReadOnlyDictionary<string, string> fields = ParseIdentityTxtFields(record.Text);
                    if (fields.Count == 0)
                        continue;

                    if (TryGetOrCreateTxtFields(record.Owner, out Dictionary<string, string> stored))
                    {
                        foreach ((string key, string value) in fields)
                        {
                            if (stored.Count >= MaximumTxtFieldsPerInstance &&
                                !stored.ContainsKey(key))
                            {
                                break;
                            }

                            stored[key] = value;
                        }
                    }
                }
            }
        }

        public IReadOnlyList<DiscoveryObservation> BuildObservations()
        {
            List<DiscoveryObservation> observations = [];

            foreach ((string host, HashSet<IPAddress> addresses) in
                     _addressesByHost.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
            {
                foreach (IPAddress address in addresses.OrderBy(address => address.ToString(), StringComparer.Ordinal))
                {
                    if (observations.Count >= MaximumObservations)
                        return observations;

                    bool hasDirectAddressEvidence =
                        _directAddressesByHost.TryGetValue(
                            host,
                            out HashSet<IPAddress>? directAddresses) &&
                        directAddresses.Contains(address);
                    observations.Add(new DiscoveryObservation
                    {
                        IpAddress = address,
                        Method = DiscoveryMethod.Mdns,
                        Hostname = NullIfEmpty(host),
                        HasDirectAddressEvidence = hasDirectAddressEvidence,
                        EvidenceSource = hasDirectAddressEvidence
                            ? "mDNS (A/AAAA; remetente direto)"
                            : "mDNS (A/AAAA; endereço anunciado)",
                        Confidence = ConfidenceLevel.Low
                    });

                    if (!_instancesByHost.TryGetValue(host, out HashSet<string>? instances))
                        continue;

                    foreach (string instance in instances
                                 .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                                 .Take(MaximumInstancesPerHost))
                    {
                        if (observations.Count >= MaximumObservations)
                            return observations;

                        observations.Add(BuildInstanceObservation(
                            address,
                            instance,
                            hasDirectAddressEvidence));
                    }
                }
            }

            return observations;
        }

        private DiscoveryObservation BuildInstanceObservation(
            IPAddress address,
            string instance,
            bool hasDirectAddressEvidence)
        {
            string? serviceType = SelectServiceType(instance);
            _txtFieldsByInstance.TryGetValue(
                instance,
                out Dictionary<string, string>? textFields);

            string? manufacturer = SelectTxtValue(
                textFields,
                "manufacturer",
                "usb_mfg",
                "mfg");
            string? model = SelectTxtValue(
                textFields,
                "model",
                "md",
                "usb_mdl",
                "ty",
                "product");
            string? friendlyName = ExtractInstanceName(instance, serviceType);
            bool hasPointer = _pointerServiceTypesByInstance.ContainsKey(instance);
            bool hasTxt = textFields is { Count: > 0 };

            string evidenceSource = hasTxt
                ? hasPointer
                    ? "mDNS/DNS-SD (PTR/SRV/TXT/A/AAAA)"
                    : "mDNS/DNS-SD (SRV/TXT/A/AAAA)"
                : hasPointer
                    ? "mDNS/DNS-SD (PTR/SRV/A/AAAA)"
                    : "mDNS/DNS-SD (SRV/A/AAAA)";

            return new DiscoveryObservation
            {
                IpAddress = address,
                Method = DiscoveryMethod.Mdns,
                // Mantém a USN DNS-SD em Hostname por compatibilidade com consumidores
                // existentes e disponibiliza em paralelo os campos tipados de identidade.
                Hostname = NullIfEmpty(instance),
                Manufacturer = manufacturer,
                Model = model,
                FriendlyName = friendlyName,
                DeviceType = MapServiceDeviceType(serviceType),
                ServiceType = serviceType,
                UniqueServiceName = NullIfEmpty(instance),
                HasDirectAddressEvidence = hasDirectAddressEvidence,
                EvidenceSource = evidenceSource,
                Confidence = ConfidenceLevel.Medium
            };
        }

        private string? SelectServiceType(string instance)
        {
            if (_pointerServiceTypesByInstance.TryGetValue(
                    instance,
                    out HashSet<string>? serviceTypes))
            {
                string? selected = serviceTypes
                    .Where(IsServiceTypeName)
                    .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                    .FirstOrDefault();
                if (selected is not null)
                    return LimitIdentityValue(selected);
            }

            return TryGetServiceTypeFromInstance(instance, out string parsed)
                ? LimitIdentityValue(parsed)
                : null;
        }

        private bool TryGetOrCreateTxtFields(
            string instance,
            out Dictionary<string, string> fields)
        {
            if (_txtFieldsByInstance.TryGetValue(instance, out Dictionary<string, string>? existing))
            {
                fields = existing;
                return true;
            }

            if (_txtFieldsByInstance.Count >= MaximumEvidenceHosts)
            {
                fields = null!;
                return false;
            }

            fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            _txtFieldsByInstance[instance] = fields;
            return true;
        }

        private static IReadOnlyDictionary<string, string> ParseIdentityTxtFields(
            IReadOnlyList<string>? text)
        {
            Dictionary<string, string> fields = new(StringComparer.OrdinalIgnoreCase);
            if (text is null)
                return fields;

            foreach (string item in text)
            {
                int separator = item.IndexOf('=');
                if (separator <= 0)
                    continue;

                string key = item[..separator].Trim();
                if (!IsAllowedIdentityTxtKey(key))
                    continue;

                string? value = LimitIdentityValue(item[(separator + 1)..]);
                if (value is null)
                    continue;

                string canonicalKey = key.ToLowerInvariant();
                if (canonicalKey.Equals("product", StringComparison.Ordinal) &&
                    value.Length > 2 &&
                    value[0] == '(' &&
                    value[^1] == ')')
                {
                    value = LimitIdentityValue(value[1..^1]);
                    if (value is null)
                        continue;
                }

                if (fields.Count >= MaximumTxtFieldsPerInstance &&
                    !fields.ContainsKey(canonicalKey))
                {
                    break;
                }

                fields[canonicalKey] = value;
            }

            return fields;
        }

        private static bool IsAllowedIdentityTxtKey(string key)
            => key.Equals("model", StringComparison.OrdinalIgnoreCase) ||
               key.Equals("md", StringComparison.OrdinalIgnoreCase) ||
               key.Equals("ty", StringComparison.OrdinalIgnoreCase) ||
               key.Equals("product", StringComparison.OrdinalIgnoreCase) ||
               key.Equals("usb_MFG", StringComparison.OrdinalIgnoreCase) ||
               key.Equals("usb_MDL", StringComparison.OrdinalIgnoreCase) ||
               key.Equals("manufacturer", StringComparison.OrdinalIgnoreCase) ||
               key.Equals("mfg", StringComparison.OrdinalIgnoreCase);

        private static string? SelectTxtValue(
            IReadOnlyDictionary<string, string>? fields,
            params string[] preferredKeys)
        {
            if (fields is null)
                return null;

            foreach (string key in preferredKeys)
            {
                if (fields.TryGetValue(key, out string? value))
                    return LimitIdentityValue(value);
            }

            return null;
        }

        private static string? ExtractInstanceName(string instance, string? serviceType)
        {
            if (string.IsNullOrWhiteSpace(serviceType) || !IsInstanceOf(instance, serviceType))
                return null;

            int suffixLength = serviceType.Length + 1;
            return LimitIdentityValue(instance[..^suffixLength]);
        }

        private static string? LimitIdentityValue(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            string trimmed = value.Trim();
            if (trimmed.Any(char.IsControl))
                return null;

            string normalized = string.Join(
                ' ',
                trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
            if (normalized.Length == 0)
                return null;

            return normalized.Length <= MaximumIdentityValueLength
                ? normalized
                : normalized[..MaximumIdentityValueLength];
        }

        private static string? MapServiceDeviceType(string? serviceType)
        {
            if (string.IsNullOrWhiteSpace(serviceType))
                return null;

            string protocol = serviceType.Split('.')[0].ToLowerInvariant();
            return protocol switch
            {
                "_ipp" or "_ipps" or "_printer" or "_pdl-datastream" => "Impressora",
                "_scanner" or "_uscan" => "Scanner",
                "_rtsp" or "_axis-video" => "Câmara / vídeo IP",
                "_airplay" or "_raop" or "_googlecast" or "_spotify-connect" =>
                    "Reprodutor multimédia",
                "_smb" or "_afpovertcp" or "_nfs" or "_webdav" => "NAS / armazenamento",
                "_ssh" or "_sftp-ssh" or "_rdp" => "Computador / servidor",
                "_hap" or "_homekit" or "_matter" or "_mqtt" => "IoT / automação",
                "_workstation" => "Computador",
                _ => null
            };
        }

        private static void RemoveValue<TValue>(
            Dictionary<string, HashSet<TValue>> dictionary,
            string key,
            TValue value)
            where TValue : notnull
        {
            if (!dictionary.TryGetValue(key, out HashSet<TValue>? values))
                return;

            values.Remove(value);
            if (values.Count == 0)
                dictionary.Remove(key);
        }

        private static bool TryGetOrCreate<TValue>(
            Dictionary<string, HashSet<TValue>> dictionary,
            string key,
            out HashSet<TValue> values)
            where TValue : notnull
        {
            if (dictionary.TryGetValue(key, out HashSet<TValue>? existing))
            {
                values = existing;
                return true;
            }

            if (dictionary.Count >= MaximumEvidenceHosts)
            {
                values = null!;
                return false;
            }

            values = [];
            dictionary[key] = values;
            return true;
        }

        private static bool IsUsableAddress(IPAddress address)
        {
            if (IPAddress.IsLoopback(address) ||
                address.Equals(IPAddress.Any) ||
                address.Equals(IPAddress.IPv6Any) ||
                address.Equals(IPAddress.IPv6None) ||
                address.Equals(IPAddress.Broadcast))
            {
                return false;
            }

            byte[] bytes = address.GetAddressBytes();
            return address.AddressFamily switch
            {
                AddressFamily.InterNetwork => bytes[0] is > 0 and < 224,
                AddressFamily.InterNetworkV6 => !address.IsIPv6Multicast,
                _ => false
            };
        }
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
