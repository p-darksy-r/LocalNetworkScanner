// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class SsdpDiscoveryService
{
    private const int MaximumDatagramBytes = 65_507;
    private const int MaximumHeaders = 128;
    private const int MaximumHeaderLineLength = 2_048;
    private const int MaximumHeaderValueLength = 1_024;
    private const int MaximumReceivedDatagrams = 512;
    private const int MaximumReceivedBytes = 2 * 1024 * 1024;
    private const int MaximumParsedAnnouncements = 512;
    private const int MaximumObservedAddresses = 256;
    private const int MaximumAnnouncementsPerAddress = 8;
    private static readonly IPEndPoint MulticastEndpoint = new(IPAddress.Parse("239.255.255.250"), 1900);

    public async Task<IReadOnlyList<DiscoveryObservation>> DiscoverAsync(
        int timeoutMs,
        CancellationToken cancellationToken)
        => await DiscoverAsync(timeoutMs, null, cancellationToken);

    public async Task<IReadOnlyList<DiscoveryObservation>> DiscoverAsync(
        int timeoutMs,
        IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        List<DiscoveryObservation> announcements = [];
        HashSet<IPAddress> observedAddresses = [];
        MulticastReceiveBudget receiveBudget = new(
            MaximumReceivedDatagrams,
            MaximumReceivedBytes,
            MaximumParsedAnnouncements);

        try
        {
            using UdpClient client = new(AddressFamily.InterNetwork);
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            if (localAddress is not null)
            {
                client.Client.Bind(new IPEndPoint(localAddress, 0));
                client.Client.SetSocketOption(
                    SocketOptionLevel.IP,
                    SocketOptionName.MulticastInterface,
                    localAddress.GetAddressBytes());
            }

            string request =
                "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 1\r\n" +
                "ST: ssdp:all\r\n\r\n";
            byte[] payload = Encoding.ASCII.GetBytes(request);
            await client.SendAsync(payload, MulticastEndpoint, cancellationToken);

            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(timeoutMs);

            while (!timeout.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult response = await client.ReceiveAsync(timeout.Token);
                    if (!receiveBudget.TryConsumeDatagram(response.Buffer.Length))
                        break;
                    Dictionary<string, string> headers = ParseHeaders(
                        Encoding.UTF8.GetString(response.Buffer));
                    if (headers.Count == 0)
                        continue;
                    if (!receiveBudget.TryConsumeItems(1))
                        break;
                    if (!observedAddresses.Contains(response.RemoteEndPoint.Address) &&
                        observedAddresses.Count >= MaximumObservedAddresses)
                    {
                        continue;
                    }
                    observedAddresses.Add(response.RemoteEndPoint.Address);
                    headers.TryGetValue("server", out string? server);
                    headers.TryGetValue("location", out string? location);
                    headers.TryGetValue("st", out string? serviceType);
                    headers.TryGetValue("usn", out string? uniqueServiceName);

                    DiscoveryObservation candidate = new()
                    {
                        IpAddress = response.RemoteEndPoint.Address,
                        Method = DiscoveryMethod.Ssdp,
                        Server = server,
                        Location = location,
                        ServiceType = serviceType,
                        UniqueServiceName = uniqueServiceName,
                        HasDirectAddressEvidence = true,
                        EvidenceSource = "Anúncio SSDP",
                        Confidence = ConfidenceLevel.Low
                    };
                    announcements.Add(candidate);
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

        return ConsolidateAnnouncements(announcements);
    }

    internal static Dictionary<string, string> ParseHeaders(string response)
    {
        Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(response) ||
            Encoding.UTF8.GetByteCount(response) > MaximumDatagramBytes)
        {
            return headers;
        }

        string[] lines = response.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0 ||
            !(lines[0].StartsWith("HTTP/1.1 200 ", StringComparison.OrdinalIgnoreCase) ||
              lines[0].StartsWith("HTTP/1.0 200 ", StringComparison.OrdinalIgnoreCase)))
        {
            return headers;
        }

        foreach (string line in lines.Skip(1).Take(MaximumHeaders))
        {
            if (line.Length > MaximumHeaderLineLength)
                continue;
            int separator = line.IndexOf(':');
            if (separator > 0)
            {
                string key = line[..separator].Trim();
                string value = SanitizeHeaderValue(line[(separator + 1)..]);
                if (key.Length is > 0 and <= 128 && value.Length > 0)
                    headers[key] = value;
            }
        }

        return headers.ContainsKey("st") || headers.ContainsKey("usn")
            ? headers
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    private static string SanitizeHeaderValue(string value)
    {
        char[] sanitized = value
            .Select(character => char.IsControl(character) ? ' ' : character)
            .ToArray();
        string compact = string.Join(
            ' ',
            new string(sanitized).Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return compact.Length <= MaximumHeaderValueLength
            ? compact
            : compact[..MaximumHeaderValueLength];
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
            Method = DiscoveryMethod.Ssdp,
            Server = existing.Server ?? candidate.Server,
            Location = existing.Location ?? candidate.Location,
            ServiceType = JoinDistinct(existing.ServiceType, candidate.ServiceType),
            UniqueServiceName = JoinDistinct(
                existing.UniqueServiceName,
                candidate.UniqueServiceName),
            HasDirectAddressEvidence = true,
            EvidenceSource = "Anúncios SSDP",
            Confidence = ConfidenceLevel.Low
        };
    }

    internal static IReadOnlyList<DiscoveryObservation> ConsolidateAnnouncements(
        IEnumerable<DiscoveryObservation> announcements)
    {
        ArgumentNullException.ThrowIfNull(announcements);
        List<DiscoveryObservation> result = [];

        foreach (IGrouping<IPAddress, DiscoveryObservation> addressGroup in announcements
                     .Where(item => item.Method == DiscoveryMethod.Ssdp)
                     .GroupBy(item => item.IpAddress)
                     .OrderBy(group => group.Key.ToString(), StringComparer.Ordinal))
        {
            List<DiscoveryObservation> retained = [];
            foreach (DiscoveryObservation candidate in addressGroup)
            {
                int existingIndex = retained.FindIndex(existing =>
                    DescribesSameEndpoint(existing, candidate));
                if (existingIndex >= 0)
                {
                    retained[existingIndex] = Merge(retained[existingIndex], candidate);
                }
                else if (retained.Count < MaximumAnnouncementsPerAddress)
                {
                    retained.Add(candidate);
                }
            }

            result.AddRange(retained);
        }

        return result;
    }

    private static bool DescribesSameEndpoint(
        DiscoveryObservation first,
        DiscoveryObservation second)
    {
        if (!string.IsNullOrWhiteSpace(first.Location) ||
            !string.IsNullOrWhiteSpace(second.Location))
        {
            return string.Equals(
                first.Location,
                second.Location,
                StringComparison.OrdinalIgnoreCase);
        }

        if (!string.IsNullOrWhiteSpace(first.UniqueServiceName) ||
            !string.IsNullOrWhiteSpace(second.UniqueServiceName))
        {
            return string.Equals(
                first.UniqueServiceName,
                second.UniqueServiceName,
                StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(first.ServiceType, second.ServiceType, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(first.Server, second.Server, StringComparison.OrdinalIgnoreCase);
    }

    private static string? JoinDistinct(string? first, string? second)
    {
        string[] values = new[] { first, second }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .SelectMany(value => value!.Split(
                ';',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(16)
            .ToArray();
        if (values.Length == 0)
            return null;

        string combined = string.Join("; ", values);
        return combined.Length <= 1_024 ? combined : combined[..1_024];
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
