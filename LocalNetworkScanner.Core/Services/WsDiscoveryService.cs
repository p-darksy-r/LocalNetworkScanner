// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using System.Xml;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class WsDiscoveryService
{
    private const int MaximumResponseBytes = 65_507;
    private const int MaximumProbeMatches = 64;
    private const int MaximumMetadataLength = 2_048;
    private const int MaximumReceivedDatagrams = 256;
    private const int MaximumReceivedBytes = 1024 * 1024;
    private const int MaximumAccumulatedMatches = 1_024;
    private const int MaximumObservedAddresses = 256;
    private static readonly IPEndPoint MulticastEndpoint =
        new(IPAddress.Parse("239.255.255.250"), 3702);

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

        Dictionary<IPAddress, DiscoveryObservation> observations = [];
        MulticastReceiveBudget receiveBudget = new(
            MaximumReceivedDatagrams,
            MaximumReceivedBytes,
            MaximumAccumulatedMatches);
        MulticastSendBudget sendBudget = new(
            MulticastProbeTransmitter.DefaultMaximumTransmissions);

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

            string messageId = $"urn:uuid:{Guid.NewGuid():D}";
            byte[] payload = Encoding.UTF8.GetBytes(BuildProbeMessage(messageId));

            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(timeoutMs);
            _ = await MulticastProbeTransmitter.SendAsync(
                client,
                payload,
                MulticastEndpoint,
                sendBudget,
                timeout.Token);
            Task retransmissionTask = MulticastProbeTransmitter.RetransmitAsync(
                client,
                payload,
                MulticastEndpoint,
                timeoutMs,
                sendBudget,
                timeout.Token);

            try
            {
                while (!timeout.IsCancellationRequested)
                {
                    try
                    {
                        UdpReceiveResult response = await client.ReceiveAsync(timeout.Token);
                        if (!receiveBudget.TryConsumeDatagram(response.Buffer.Length))
                            break;
                        IReadOnlyList<WsDiscoveryMatch> matches = ParseResponse(
                            response.Buffer,
                            messageId,
                            response.RemoteEndPoint.Address);
                        if (!receiveBudget.TryConsumeItems(matches.Count))
                            break;
                        foreach (WsDiscoveryMatch match in matches)
                        {
                            if (!observations.ContainsKey(match.Address) &&
                                observations.Count >= MaximumObservedAddresses)
                            {
                                continue;
                            }

                            DiscoveryObservation candidate = new()
                            {
                                IpAddress = match.Address,
                                Method = DiscoveryMethod.WsDiscovery,
                                Server = match.Types,
                                Location = match.XAddresses,
                                HasDirectAddressEvidence = true,
                                EvidenceSource = "Resposta WS-Discovery",
                                Confidence = ConfidenceLevel.Low
                            };
                            observations[match.Address] = Merge(
                                observations.GetValueOrDefault(match.Address),
                                candidate);
                        }
                    }
                    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }
                }
            }
            finally
            {
                timeout.Cancel();
                await retransmissionTask;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            // O prazo interno terminou durante o envio inicial; preserva respostas parciais.
        }
        catch (Exception exception) when (
            exception is SocketException or InvalidOperationException or FormatException)
        {
            // A interface pode desaparecer durante a escuta. Mantém respostas válidas.
        }

        return observations.Values.ToList();
    }

    internal static string BuildProbeMessage()
        => BuildProbeMessage($"urn:uuid:{Guid.NewGuid():D}");

    internal static string BuildProbeMessage(string messageId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);
        return
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
            "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">" +
            "<e:Header>" +
            $"<w:MessageID>{messageId}</w:MessageID>" +
            "<w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>" +
            "<w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>" +
            "</e:Header><e:Body><d:Probe /></e:Body></e:Envelope>";
    }

    internal static IReadOnlyList<WsDiscoveryMatch> ParseResponse(
        byte[] response,
        string expectedMessageId,
        IPAddress remoteAddress)
    {
        try
        {
            if (response.Length == 0 || response.Length > MaximumResponseBytes)
                return [];

            XmlReaderSettings settings = new()
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaximumResponseBytes,
                MaxCharactersFromEntities = 0,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true
            };
            using MemoryStream stream = new(response, writable: false);
            using XmlReader reader = XmlReader.Create(stream, settings);
            XDocument document = XDocument.Load(reader, LoadOptions.None);
            string? action = FindValue(document, "Action");
            string? relatesTo = FindValue(document, "RelatesTo");
            if (action is null ||
                !action.EndsWith("/ProbeMatches", StringComparison.Ordinal) ||
                !string.Equals(relatesTo, expectedMessageId, StringComparison.OrdinalIgnoreCase))
            {
                return [];
            }

            List<WsDiscoveryMatch> results = [];
            foreach (XElement probeMatch in document.Descendants()
                         .Where(element => element.Name.LocalName == "ProbeMatch")
                         .Take(MaximumProbeMatches))
            {
                string? types = Limit(probeMatch.Descendants()
                    .FirstOrDefault(element => element.Name.LocalName == "Types")?.Value);
                string? xAddresses = Limit(probeMatch.Descendants()
                    .FirstOrDefault(element => element.Name.LocalName == "XAddrs")?.Value);

                // XAddr é metadado não autenticado. Associar o resultado ao remetente
                // impede que um anúncio faça outro IP do CIDR parecer online.
                results.Add(new WsDiscoveryMatch(
                    remoteAddress,
                    EmptyToNull(types),
                    EmptyToNull(xAddresses)));
            }

            return results;
        }
        catch (System.Xml.XmlException)
        {
            return [];
        }
    }

    private static string? FindValue(XDocument document, string localName) =>
        EmptyToNull(document.Descendants()
            .FirstOrDefault(element => element.Name.LocalName == localName)?.Value.Trim());

    private static string? EmptyToNull(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;

    private static string? Limit(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        char[] sanitized = value
            .Select(character => char.IsControl(character) ? ' ' : character)
            .ToArray();
        string compact = string.Join(
            ' ',
            new string(sanitized).Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return compact.Length <= MaximumMetadataLength
            ? compact
            : compact[..MaximumMetadataLength];
    }

    private static DiscoveryObservation Merge(
        DiscoveryObservation? existing,
        DiscoveryObservation candidate)
    {
        if (existing is null)
            return candidate;

        return new DiscoveryObservation
        {
            IpAddress = candidate.IpAddress,
            Method = DiscoveryMethod.WsDiscovery,
            Server = JoinDistinct(existing.Server, candidate.Server),
            Location = JoinDistinct(existing.Location, candidate.Location),
            ServicePort = existing.ServicePort ?? candidate.ServicePort,
            ServiceTransport = existing.ServiceTransport ?? candidate.ServiceTransport,
            HasDirectAddressEvidence = true,
            EvidenceSource = "Respostas WS-Discovery",
            Confidence = ConfidenceLevel.Low
        };
    }

    private static string? JoinDistinct(string? first, string? second)
    {
        if (string.IsNullOrWhiteSpace(first))
            return second;
        if (string.IsNullOrWhiteSpace(second) ||
            first.Split(';', StringSplitOptions.TrimEntries).Contains(
                second,
                StringComparer.OrdinalIgnoreCase))
        {
            return first;
        }

        return Limit($"{first}; {second}");
    }
}

internal sealed record WsDiscoveryMatch(IPAddress Address, string? Types, string? XAddresses);

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
