using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class SsdpDiscoveryService
{
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
        Dictionary<IPAddress, DiscoveryObservation> observations = [];

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
                    Dictionary<string, string> headers = ParseHeaders(
                        Encoding.UTF8.GetString(response.Buffer));
                    headers.TryGetValue("server", out string? server);
                    headers.TryGetValue("location", out string? location);

                    observations[response.RemoteEndPoint.Address] = new DiscoveryObservation
                    {
                        IpAddress = response.RemoteEndPoint.Address,
                        Method = DiscoveryMethod.Ssdp,
                        Server = server,
                        Location = location
                    };
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

    private static Dictionary<string, string> ParseHeaders(string response)
    {
        Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
        foreach (string line in response.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = line.IndexOf(':');
            if (separator > 0)
                headers[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }

        return headers;
    }
}
