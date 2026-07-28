// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using System.Globalization;
using System.Text.RegularExpressions;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed partial class MacAddressService
{
    private const int DefaultMaximumActiveConcurrency = 32;

    private readonly Func<LocalNetworkInterface, CancellationToken, Task<string?>> _neighborTableReader;
    private readonly Func<IPAddress, IPAddress, CancellationToken, Task<string?>> _activeResolver;
    private readonly int _maximumActiveConcurrency;

    public MacAddressService()
        : this(
            ReadNeighborTableAsync,
            ResolveWithSendArpAsync,
            DefaultMaximumActiveConcurrency)
    {
    }

    internal MacAddressService(
        Func<LocalNetworkInterface, CancellationToken, Task<string?>> neighborTableReader,
        Func<IPAddress, IPAddress, CancellationToken, Task<string?>> activeResolver,
        int maximumActiveConcurrency = DefaultMaximumActiveConcurrency)
    {
        ArgumentNullException.ThrowIfNull(neighborTableReader);
        ArgumentNullException.ThrowIfNull(activeResolver);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumActiveConcurrency);

        _neighborTableReader = neighborTableReader;
        _activeResolver = activeResolver;
        _maximumActiveConcurrency = maximumActiveConcurrency;
    }

    public async Task<string?> ResolveAsync(
        IPAddress address,
        LocalNetworkInterface networkInterface,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(networkInterface);
        await using ScanSession session = CreateScanSession(networkInterface, cancellationToken);
        return await session.ResolveAsync(address, cancellationToken);
    }

    internal ScanSession CreateScanSession(
        LocalNetworkInterface networkInterface,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(networkInterface);
        return new ScanSession(
            networkInterface,
            _neighborTableReader,
            _activeResolver,
            _maximumActiveConcurrency,
            cancellationToken);
    }

    internal static IReadOnlyDictionary<IPAddress, string> ParseNeighborTable(string? output)
    {
        Dictionary<IPAddress, string> neighbors = [];
        if (string.IsNullOrWhiteSpace(output))
            return neighbors;

        foreach (string line in output.Split('\n'))
        {
            Match ipMatch = Ipv4Regex().Match(line);
            Match macMatch = MacRegex().Match(line);
            if (!ipMatch.Success ||
                !macMatch.Success ||
                !IPAddress.TryParse(ipMatch.Value, out IPAddress? address) ||
                !TryNormalizeDeviceAddress(macMatch.Value, out string normalizedMac))
            {
                continue;
            }

            neighbors[address] = normalizedMac;
        }

        return neighbors;
    }

    private static async Task<string?> ReadNeighborTableAsync(
        LocalNetworkInterface networkInterface,
        CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            return await ProcessRunner.RunAsync(
                "arp.exe",
                ["-a", "-N", networkInterface.IpAddress.ToString()],
                2_000,
                cancellationToken);
        }

        return await ProcessRunner.RunAsync(
            "ip",
            ["neigh", "show"],
            2_000,
            cancellationToken);
    }

    private static async Task<string?> ResolveWithSendArpAsync(
        IPAddress address,
        IPAddress sourceAddress,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        cancellationToken.ThrowIfCancellationRequested();
        Task<string?> resolution = Task.Run(() =>
        {
            try
            {
                return ResolveWithSendArp(address, sourceAddress);
            }
            catch (Exception exception) when (
                exception is DllNotFoundException or EntryPointNotFoundException)
            {
                return null;
            }
        });
        return await resolution.WaitAsync(cancellationToken);
    }

    private static string? ResolveWithSendArp(IPAddress address, IPAddress sourceAddress)
    {
        byte[] addressBytes = address.GetAddressBytes();
        byte[] sourceBytes = sourceAddress.GetAddressBytes();
        if (addressBytes.Length != 4 || sourceBytes.Length != 4)
            return null;

        byte[] mac = new byte[6];
        int length = mac.Length;
        uint destination = BitConverter.ToUInt32(addressBytes, 0);
        uint source = BitConverter.ToUInt32(sourceBytes, 0);
        int result = SendARP(destination, source, mac, ref length);
        string candidate = result == 0 && length == mac.Length
            ? string.Join(":", mac.Select(value => value.ToString("X2", CultureInfo.InvariantCulture)))
            : string.Empty;
        return TryNormalizeDeviceAddress(candidate, out string normalized)
            ? normalized
            : null;
    }

    public static string Normalize(string value)
    {
        string hex = new(value.Where(Uri.IsHexDigit).ToArray());
        return hex.Length < 12
            ? value.ToUpperInvariant()
            : string.Join(":", Enumerable.Range(0, 6).Select(index => hex.Substring(index * 2, 2).ToUpperInvariant()));
    }

    /// <summary>
    /// Valida e normaliza um MAC unicast de 48 bits adequado à identidade de um dispositivo.
    /// </summary>
    public static bool TryNormalizeDeviceAddress(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        string trimmed = value.Trim();
        if (!ValidDeviceMacRegex().IsMatch(trimmed))
            return false;

        string hex = new(trimmed
            .Where(character => character is not (':' or '-' or '.'))
            .ToArray());

        byte[] bytes = new byte[6];
        for (int index = 0; index < bytes.Length; index++)
        {
            if (!byte.TryParse(
                    hex.AsSpan(index * 2, 2),
                    System.Globalization.NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out bytes[index]))
            {
                return false;
            }
        }

        bool allZero = bytes.All(item => item == 0);
        bool allBroadcast = bytes.All(item => item == byte.MaxValue);
        bool isGroupAddress = (bytes[0] & 0x01) != 0;
        if (allZero || allBroadcast || isGroupAddress)
            return false;

        normalized = string.Join(
            ":",
            bytes.Select(item => item.ToString("X2", CultureInfo.InvariantCulture)));
        return true;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destinationIp, uint sourceIp, byte[] macAddress, ref int physicalAddressLength);

    [GeneratedRegex(
        @"(?i)(?<![0-9a-f])[0-9a-f]{2}(?<separator>[:-])(?:[0-9a-f]{2}\k<separator>){4}[0-9a-f]{2}(?![0-9a-f])",
        RegexOptions.CultureInvariant)]
    private static partial Regex MacRegex();

    [GeneratedRegex(
        @"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])",
        RegexOptions.CultureInvariant)]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(
        @"^(?:[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})$",
        RegexOptions.CultureInvariant)]
    private static partial Regex ValidDeviceMacRegex();

    internal sealed class ScanSession : IAsyncDisposable
    {
        private readonly LocalNetworkInterface _networkInterface;
        private readonly Func<IPAddress, IPAddress, CancellationToken, Task<string?>> _activeResolver;
        private readonly CancellationToken _scanCancellationToken;
        private readonly SemaphoreSlim _activeGate;
        private readonly Lazy<Task<IReadOnlyDictionary<IPAddress, string>>> _neighborTable;
        private readonly ConcurrentDictionary<IPAddress, Lazy<Task<string?>>> _addressCache = [];

        internal ScanSession(
            LocalNetworkInterface networkInterface,
            Func<LocalNetworkInterface, CancellationToken, Task<string?>> neighborTableReader,
            Func<IPAddress, IPAddress, CancellationToken, Task<string?>> activeResolver,
            int maximumActiveConcurrency,
            CancellationToken scanCancellationToken)
        {
            _networkInterface = networkInterface;
            _activeResolver = activeResolver;
            _scanCancellationToken = scanCancellationToken;
            _activeGate = new SemaphoreSlim(maximumActiveConcurrency, maximumActiveConcurrency);
            _neighborTable = new Lazy<Task<IReadOnlyDictionary<IPAddress, string>>>(
                async () => ParseNeighborTable(
                    await neighborTableReader(networkInterface, scanCancellationToken)),
                LazyThreadSafetyMode.ExecutionAndPublication);
        }

        public async Task<string?> ResolveAsync(
            IPAddress address,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(address);
            cancellationToken.ThrowIfCancellationRequested();

            if (address.Equals(_networkInterface.IpAddress))
            {
                return TryNormalizeDeviceAddress(
                    _networkInterface.MacAddress,
                    out string localMac)
                    ? localMac
                    : null;
            }

            if (!IpAddressHelper.IsInSameSubnet(
                    address,
                    _networkInterface.IpAddress,
                    _networkInterface.SubnetMask))
            {
                return null;
            }

            Lazy<Task<string?>> cached = _addressCache.GetOrAdd(
                address,
                static (target, session) => new Lazy<Task<string?>>(
                    () => session.ResolveCoreAsync(target),
                    LazyThreadSafetyMode.ExecutionAndPublication),
                this);
            return await cached.Value.WaitAsync(cancellationToken);
        }

        private async Task<string?> ResolveCoreAsync(IPAddress address)
        {
            _scanCancellationToken.ThrowIfCancellationRequested();
            IReadOnlyDictionary<IPAddress, string> neighbors =
                await _neighborTable.Value.WaitAsync(_scanCancellationToken);
            if (neighbors.TryGetValue(address, out string? cachedMac))
                return cachedMac;

            await _activeGate.WaitAsync(_scanCancellationToken);
            try
            {
                string? resolved = await _activeResolver(
                    address,
                    _networkInterface.IpAddress,
                    _scanCancellationToken);
                return TryNormalizeDeviceAddress(resolved, out string normalized)
                    ? normalized
                    : null;
            }
            finally
            {
                _activeGate.Release();
            }
        }

        public async ValueTask DisposeAsync()
        {
            Task<string?>[] pending = _addressCache.Values
                .Where(value => value.IsValueCreated)
                .Select(value => value.Value)
                .ToArray();
            try
            {
                await Task.WhenAll(pending);
            }
            catch (OperationCanceledException)
            {
                // O cancelamento do scan já foi observado pelo chamador.
            }
            finally
            {
                _activeGate.Dispose();
            }
        }
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
