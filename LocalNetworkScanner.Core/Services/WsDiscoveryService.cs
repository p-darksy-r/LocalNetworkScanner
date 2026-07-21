using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class WsDiscoveryService
{
    private static readonly IPEndPoint MulticastEndpoint =
        new(IPAddress.Parse("239.255.255.250"), 3702);

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

            string messageId = $"urn:uuid:{Guid.NewGuid():D}";
            byte[] payload = Encoding.UTF8.GetBytes(BuildProbeMessage(messageId));
            await client.SendAsync(payload, MulticastEndpoint, cancellationToken);

            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(timeoutMs);

            while (!timeout.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult response = await client.ReceiveAsync(timeout.Token);
                    IReadOnlyList<WsDiscoveryMatch> matches = ParseResponse(
                        response.Buffer,
                        messageId,
                        response.RemoteEndPoint.Address);
                    foreach (WsDiscoveryMatch match in matches)
                    {
                        observations[match.Address] = new DiscoveryObservation
                        {
                            IpAddress = match.Address,
                            Method = DiscoveryMethod.WsDiscovery,
                            Server = match.Types,
                            Location = match.XAddresses
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
        catch (Exception exception) when (
            exception is SocketException or InvalidOperationException or FormatException)
        {
            return [];
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
            XDocument document = XDocument.Parse(Encoding.UTF8.GetString(response));
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
                         .Where(element => element.Name.LocalName == "ProbeMatch"))
            {
                string? types = probeMatch.Descendants()
                    .FirstOrDefault(element => element.Name.LocalName == "Types")?.Value.Trim();
                string? xAddresses = probeMatch.Descendants()
                    .FirstOrDefault(element => element.Name.LocalName == "XAddrs")?.Value.Trim();
                IReadOnlyList<IPAddress> addresses = ExtractAddresses(xAddresses);
                if (addresses.Count == 0)
                    addresses = [remoteAddress];

                foreach (IPAddress address in addresses.Distinct())
                {
                    results.Add(new WsDiscoveryMatch(
                        address,
                        EmptyToNull(types),
                        EmptyToNull(xAddresses)));
                }
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

    private static IReadOnlyList<IPAddress> ExtractAddresses(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return [];

        List<IPAddress> addresses = [];
        foreach (string token in value.Split(
                     [' ', '\r', '\n', '\t'],
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (Uri.TryCreate(token, UriKind.Absolute, out Uri? uri) &&
                IPAddress.TryParse(uri.Host, out IPAddress? address) &&
                address.AddressFamily == AddressFamily.InterNetwork)
            {
                addresses.Add(address);
            }
        }
        return addresses;
    }

    private static string? EmptyToNull(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;
}

internal sealed record WsDiscoveryMatch(IPAddress Address, string? Types, string? XAddresses);
