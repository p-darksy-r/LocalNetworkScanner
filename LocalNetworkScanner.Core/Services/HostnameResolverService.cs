using System.Net;

namespace LocalNetworkScanner.Core.Services;

public sealed class HostnameResolverService
{
    public async Task<string?> ResolveAsync(
        IPAddress ipAddress,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        try
        {
            IPHostEntry result = await Dns.GetHostEntryAsync(ipAddress)
                .WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), cancellationToken);

            return string.IsNullOrWhiteSpace(result.HostName) ? null : result.HostName.TrimEnd('.');
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }
}
