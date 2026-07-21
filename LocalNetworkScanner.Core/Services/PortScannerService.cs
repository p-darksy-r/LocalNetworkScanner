using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class PortScannerService
{
    private const int MaximumConcurrentDiscoveryPorts = 16;
    private const int MaximumConcurrentProbes = 256;

    private static readonly SemaphoreSlim ProbeGate = new(MaximumConcurrentProbes, MaximumConcurrentProbes);

    private readonly ServiceProbeService _serviceProbeService;

    public PortScannerService(ServiceProbeService? serviceProbeService = null)
    {
        _serviceProbeService = serviceProbeService ?? new ServiceProbeService();
    }

    public async Task<int?> FindAnyOpenPortAsync(
        IPAddress address,
        IReadOnlyList<int> ports,
        int timeoutMs,
        CancellationToken cancellationToken)
        => await FindAnyOpenPortAsync(address, ports, timeoutMs, null, cancellationToken);

    public async Task<int?> FindAnyOpenPortAsync(
        IPAddress address,
        IReadOnlyList<int> ports,
        int timeoutMs,
        IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        int[] candidates = ValidatePorts(ports);
        ValidateTimeout(timeoutMs);
        cancellationToken.ThrowIfCancellationRequested();

        if (candidates.Length == 0)
            return null;

        int foundPort = 0;
        using CancellationTokenSource stop =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        ParallelOptions options = new()
        {
            MaxDegreeOfParallelism = Math.Min(MaximumConcurrentDiscoveryPorts, candidates.Length),
            CancellationToken = stop.Token
        };

        try
        {
            await Parallel.ForEachAsync(candidates, options, async (port, token) =>
            {
                if (Volatile.Read(ref foundPort) != 0)
                    return;

                await ProbeGate.WaitAsync(token);
                try
                {
                    if (await IsOpenAsync(address, port, timeoutMs, localAddress, token) &&
                        Interlocked.CompareExchange(ref foundPort, port, 0) == 0)
                    {
                        stop.Cancel();
                    }
                }
                finally
                {
                    ProbeGate.Release();
                }
            });
        }
        catch (OperationCanceledException) when (
            Volatile.Read(ref foundPort) != 0 && !cancellationToken.IsCancellationRequested)
        {
            // Cancelamento interno: já foi encontrada uma porta, não é cancelamento do scan.
        }

        cancellationToken.ThrowIfCancellationRequested();
        int result = Volatile.Read(ref foundPort);
        return result == 0 ? null : result;
    }

    public async Task<IReadOnlyList<PortScanResult>> ScanAsync(
        IPAddress address,
        IReadOnlyList<int> ports,
        int timeoutMs,
        int maximumConcurrency,
        bool enableServiceProbes,
        CancellationToken cancellationToken)
        => await ScanAsync(
            address,
            ports,
            timeoutMs,
            maximumConcurrency,
            enableServiceProbes,
            null,
            cancellationToken);

    public async Task<IReadOnlyList<PortScanResult>> ScanAsync(
        IPAddress address,
        IReadOnlyList<int> ports,
        int timeoutMs,
        int maximumConcurrency,
        bool enableServiceProbes,
        IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        int[] candidates = ValidatePorts(ports);
        ValidateTimeout(timeoutMs);
        if (maximumConcurrency <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumConcurrency), "A concorrência deve ser superior a zero.");

        cancellationToken.ThrowIfCancellationRequested();
        if (candidates.Length == 0)
            return [];

        ConcurrentBag<PortScanResult> openPorts = [];
        ParallelOptions options = new()
        {
            MaxDegreeOfParallelism = Math.Min(
                Math.Min(maximumConcurrency, MaximumConcurrentProbes),
                candidates.Length),
            CancellationToken = cancellationToken
        };

        await Parallel.ForEachAsync(candidates, options, async (port, token) =>
        {
            await ProbeGate.WaitAsync(token);
            try
            {
                if (!await IsOpenAsync(address, port, timeoutMs, localAddress, token))
                    return;

                PortScanResult result = new()
                {
                    Port = port,
                    ServiceName = ServiceCatalog.GetServiceName(port),
                    IsEncrypted = ServiceCatalog.IsTlsPort(port)
                };

                if (enableServiceProbes)
                    await _serviceProbeService.EnrichAsync(
                        address,
                        result,
                        timeoutMs + 900,
                        localAddress,
                        token);

                openPorts.Add(result);
            }
            finally
            {
                ProbeGate.Release();
            }
        });

        return openPorts.OrderBy(result => result.Port).ToList();
    }

    public static async Task<bool> IsOpenAsync(
        IPAddress address,
        int port,
        int timeoutMs,
        CancellationToken cancellationToken)
        => await IsOpenAsync(address, port, timeoutMs, null, cancellationToken);

    public static async Task<bool> IsOpenAsync(
        IPAddress address,
        int port,
        int timeoutMs,
        IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        ValidatePort(port);
        ValidateTimeout(timeoutMs);
        cancellationToken.ThrowIfCancellationRequested();

        using Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };
        if (localAddress is not null)
            socket.Bind(new IPEndPoint(localAddress, 0));
        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutMs);

        try
        {
            await socket.ConnectAsync(address, port, timeout.Token);
            return socket.Connected;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SocketException or OperationCanceledException)
        {
            return false;
        }
    }

    private static int[] ValidatePorts(IReadOnlyList<int> ports)
    {
        ArgumentNullException.ThrowIfNull(ports);
        int[] distinct = ports.Distinct().ToArray();
        foreach (int port in distinct)
            ValidatePort(port);
        return distinct;
    }

    private static void ValidatePort(int port)
    {
        if (port is < 1 or > 65_535)
            throw new ArgumentOutOfRangeException(nameof(port), port, "A porta deve estar entre 1 e 65535.");
    }

    private static void ValidateTimeout(int timeoutMs)
    {
        if (timeoutMs <= 0)
            throw new ArgumentOutOfRangeException(nameof(timeoutMs), "O timeout deve ser superior a zero.");
    }
}
