using System.Formats.Asn1;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace LocalNetworkScanner.Core.Services;

internal sealed class SnmpClientService
{
    private static readonly Asn1Tag GetRequestTag =
        new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag GetNextRequestTag =
        new(TagClass.ContextSpecific, 1, isConstructed: true);
    private static readonly Asn1Tag ResponseTag =
        new(TagClass.ContextSpecific, 2, isConstructed: true);

    private readonly IPAddress _address;
    private readonly IPAddress? _localAddress;
    private readonly string _community;
    private readonly int _timeoutMs;
    private readonly int _retries;

    public SnmpClientService(
        IPAddress address,
        IPAddress? localAddress,
        string community,
        int timeoutMs,
        int retries)
    {
        _address = address;
        _localAddress = localAddress;
        _community = community;
        _timeoutMs = timeoutMs;
        _retries = retries;
    }

    public Task<SnmpVariable?> GetAsync(string oid, CancellationToken cancellationToken) =>
        RequestAsync(oid, useGetNext: false, cancellationToken);

    public async Task<IReadOnlyList<SnmpVariable>> WalkAsync(
        string rootOid,
        int maximumVariables,
        CancellationToken cancellationToken)
    {
        List<SnmpVariable> variables = [];
        string currentOid = rootOid;
        string prefix = rootOid + ".";

        while (variables.Count < maximumVariables)
        {
            SnmpVariable? variable = await RequestAsync(
                currentOid,
                useGetNext: true,
                cancellationToken);
            if (variable is null ||
                !variable.Oid.StartsWith(prefix, StringComparison.Ordinal) ||
                CompareOids(variable.Oid, currentOid) <= 0)
            {
                break;
            }

            variables.Add(variable);
            currentOid = variable.Oid;
        }

        return variables;
    }

    private async Task<SnmpVariable?> RequestAsync(
        string oid,
        bool useGetNext,
        CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt <= _retries; attempt++)
        {
            int requestId = RandomNumberGenerator.GetInt32(1, int.MaxValue);
            byte[] request = BuildRequest(requestId, _community, oid, useGetNext);

            try
            {
                using UdpClient client = new(AddressFamily.InterNetwork);
                if (_localAddress is not null)
                    client.Client.Bind(new IPEndPoint(_localAddress, 0));

                using CancellationTokenSource timeout =
                    CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(_timeoutMs);
                await client.SendAsync(request, new IPEndPoint(_address, 161), timeout.Token);
                while (true)
                {
                    UdpReceiveResult response = await client.ReceiveAsync(timeout.Token);
                    if (!response.RemoteEndPoint.Address.Equals(_address))
                        continue;

                    try
                    {
                        SnmpResponse parsed = ParseResponse(response.Buffer);
                        if (parsed.Version == 1 &&
                            string.Equals(parsed.Community, _community, StringComparison.Ordinal) &&
                            parsed.RequestId == requestId &&
                            parsed.ErrorStatus == 0)
                        {
                            return parsed.Variable;
                        }
                    }
                    catch (Exception exception) when (
                        exception is AsnContentException or InvalidDataException or OverflowException)
                    {
                        // Ignora datagramas que não sejam a resposta SNMP correlacionada.
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is OperationCanceledException or SocketException or AsnContentException or
                    InvalidDataException or OverflowException)
            {
                // A retry is intentional for UDP/SNMP packet loss.
            }
        }

        return null;
    }

    internal static byte[] BuildRequest(
        int requestId,
        string community,
        string oid,
        bool useGetNext)
    {
        AsnWriter writer = new(AsnEncodingRules.BER);
        writer.PushSequence();
        writer.WriteInteger(1); // SNMP v2c
        writer.WriteOctetString(Encoding.ASCII.GetBytes(community));

        Asn1Tag requestTag = useGetNext ? GetNextRequestTag : GetRequestTag;
        writer.PushSequence(requestTag);
        writer.WriteInteger(requestId);
        writer.WriteInteger(0);
        writer.WriteInteger(0);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier(oid);
        writer.WriteNull();
        writer.PopSequence();
        writer.PopSequence();
        writer.PopSequence(requestTag);
        writer.PopSequence();
        return writer.Encode();
    }

    internal static SnmpResponse ParseResponse(byte[] packet)
    {
        AsnReader root = new(packet, AsnEncodingRules.BER);
        AsnReader message = root.ReadSequence();
        int version = ToInt32(message.ReadInteger());
        string community = Encoding.ASCII.GetString(message.ReadOctetString());
        AsnReader pdu = message.ReadSequence(ResponseTag);
        int requestId = ToInt32(pdu.ReadInteger());
        int errorStatus = ToInt32(pdu.ReadInteger());
        _ = pdu.ReadInteger();
        AsnReader variableList = pdu.ReadSequence();
        if (!variableList.HasData)
            return new SnmpResponse(version, community, requestId, errorStatus, null);

        AsnReader binding = variableList.ReadSequence();
        string oid = binding.ReadObjectIdentifier();
        Asn1Tag tag = binding.PeekTag();

        if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue is >= 0 and <= 2)
        {
            _ = binding.ReadEncodedValue();
            return new SnmpResponse(version, community, requestId, errorStatus, null);
        }

        SnmpVariable variable;
        if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.Integer)
        {
            variable = new SnmpVariable(oid, ToInt32(binding.ReadInteger()), null);
        }
        else if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.OctetString)
        {
            byte[] value = binding.ReadOctetString();
            variable = new SnmpVariable(oid, null, DecodeText(value), value);
        }
        else if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.ObjectIdentifier)
        {
            variable = new SnmpVariable(oid, null, binding.ReadObjectIdentifier());
        }
        else
        {
            _ = binding.ReadEncodedValue();
            variable = new SnmpVariable(oid, null, null);
        }

        return new SnmpResponse(version, community, requestId, errorStatus, variable);
    }

    private static int CompareOids(string first, string second)
    {
        ulong[] left = ParseOid(first);
        ulong[] right = ParseOid(second);
        int length = Math.Min(left.Length, right.Length);
        for (int index = 0; index < length; index++)
        {
            int comparison = left[index].CompareTo(right[index]);
            if (comparison != 0)
                return comparison;
        }

        return left.Length.CompareTo(right.Length);
    }

    private static ulong[] ParseOid(string oid) => oid
        .Split('.', StringSplitOptions.RemoveEmptyEntries)
        .Select(part => ulong.Parse(part, CultureInfo.InvariantCulture))
        .ToArray();

    private static int ToInt32(BigInteger value)
    {
        if (value < int.MinValue || value > int.MaxValue)
            throw new InvalidDataException("Valor INTEGER SNMP fora do intervalo suportado.");
        return (int)value;
    }

    private static string? DecodeText(byte[] value)
    {
        if (value.Length == 0)
            return null;

        string text = Encoding.UTF8.GetString(value).Trim('\0', ' ', '\r', '\n', '\t');
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }
}

internal sealed record SnmpVariable(
    string Oid,
    int? IntegerValue,
    string? TextValue,
    byte[]? OctetValue = null);

internal sealed record SnmpResponse(
    int Version,
    string Community,
    int RequestId,
    int ErrorStatus,
    SnmpVariable? Variable);
