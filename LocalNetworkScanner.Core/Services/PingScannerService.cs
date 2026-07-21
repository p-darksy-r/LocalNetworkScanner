using System.Net;
using System.Net.NetworkInformation;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class PingScannerService
{
    private static readonly byte[] Payload = "LocalNetworkScanner"u8.ToArray();

    public async Task<PingProbeResult> ProbeAsync(
        IPAddress ipAddress,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        try
        {
            using Ping ping = new();
            PingOptions options = new(128, dontFragment: false);
            Task<PingReply> pingTask = ping.SendPingAsync(ipAddress, timeoutMs, Payload, options);
            PingReply reply = await pingTask.WaitAsync(
                TimeSpan.FromMilliseconds(timeoutMs + 200),
                cancellationToken);

            return reply.Status == IPStatus.Success
                ? new PingProbeResult(true, reply.RoundtripTime, reply.Options?.Ttl)
                : new PingProbeResult(false, null, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is PingException or TimeoutException or OperationCanceledException)
        {
            return new PingProbeResult(false, null, null);
        }
    }
}
