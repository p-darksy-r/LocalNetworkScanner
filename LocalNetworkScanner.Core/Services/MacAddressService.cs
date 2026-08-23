// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed partial class MacAddressService
{
    private const int DefaultMaximumActiveConcurrency = 32;
    private const int ErrorNotFound = 1_168;
    private const int NeighborStateStale = 4;
    private const int NeighborStateReachable = 5;
    private const byte NeighborFlagIsUnreachable = 0x02;
    private const int EthernetAddressLength = 6;
    private const int SendArpBufferLength = 8;

    private readonly Func<LocalNetworkInterface, CancellationToken, Task<string?>> _neighborTableReader;
    private readonly Func<IPAddress, IPAddress, uint?, CancellationToken, Task<string?>> _activeResolver;
    private readonly Func<LocalNetworkInterface, uint?> _interfaceIndexResolver;
    private readonly int _maximumActiveConcurrency;

    public MacAddressService()
        : this(
            ReadNeighborTableAsync,
            ResolveWithFreshNeighborAsync,
            ResolveIpv4InterfaceIndex,
            DefaultMaximumActiveConcurrency)
    {
    }

    internal MacAddressService(
        Func<LocalNetworkInterface, CancellationToken, Task<string?>> neighborTableReader,
        Func<IPAddress, IPAddress, CancellationToken, Task<string?>> activeResolver,
        int maximumActiveConcurrency = DefaultMaximumActiveConcurrency)
        : this(
            neighborTableReader,
            (address, sourceAddress, _, cancellationToken) =>
                activeResolver(address, sourceAddress, cancellationToken),
            _ => null,
            maximumActiveConcurrency)
    {
    }

    internal MacAddressService(
        Func<LocalNetworkInterface, CancellationToken, Task<string?>> neighborTableReader,
        Func<IPAddress, IPAddress, uint?, CancellationToken, Task<string?>> activeResolver,
        Func<LocalNetworkInterface, uint?> interfaceIndexResolver,
        int maximumActiveConcurrency = DefaultMaximumActiveConcurrency)
    {
        ArgumentNullException.ThrowIfNull(neighborTableReader);
        ArgumentNullException.ThrowIfNull(activeResolver);
        ArgumentNullException.ThrowIfNull(interfaceIndexResolver);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumActiveConcurrency);

        _neighborTableReader = neighborTableReader;
        _activeResolver = activeResolver;
        _interfaceIndexResolver = interfaceIndexResolver;
        _maximumActiveConcurrency = maximumActiveConcurrency;
    }

    public async Task<string?> ResolveAsync(
        IPAddress address,
        LocalNetworkInterface networkInterface,
        CancellationToken cancellationToken)
    {
        MacAddressResolution? result = await ResolveWithEvidenceAsync(
            address,
            networkInterface,
            cancellationToken);
        return result?.MacAddress;
    }

    public async Task<MacAddressResolution?> ResolveWithEvidenceAsync(
        IPAddress address,
        LocalNetworkInterface networkInterface,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(networkInterface);
        await using ScanSession session = CreateScanSession(networkInterface, cancellationToken);
        return await session.ResolveWithEvidenceAsync(address, cancellationToken);
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
            _interfaceIndexResolver(networkInterface),
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

    private static async Task<string?> ResolveWithFreshNeighborAsync(
        IPAddress address,
        IPAddress sourceAddress,
        uint? interfaceIndex,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        cancellationToken.ThrowIfCancellationRequested();
        Task<string?> resolution = Task.Run(() =>
        {
            try
            {
                return ResolveWithFreshNeighbor(
                    address,
                    sourceAddress,
                    interfaceIndex,
                    GetIpNetEntry2Native,
                    SendArpNative);
            }
            catch (Exception exception) when (
                exception is DllNotFoundException or
                    EntryPointNotFoundException or
                    BadImageFormatException)
            {
                return null;
            }
        });
        return await resolution.WaitAsync(cancellationToken);
    }

    internal static string? ResolveWithFreshNeighbor(
        IPAddress address,
        IPAddress sourceAddress,
        uint? interfaceIndex,
        GetIpNetEntry2Callback getIpNetEntry,
        SendArpCallback sendArp)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(sourceAddress);
        ArgumentNullException.ThrowIfNull(getIpNetEntry);
        ArgumentNullException.ThrowIfNull(sendArp);

        byte[] addressBytes = address.GetAddressBytes();
        byte[] sourceBytes = sourceAddress.GetAddressBytes();
        if (addressBytes.Length != 4 ||
            sourceBytes.Length != 4 ||
            sourceAddress.Equals(IPAddress.Any) ||
            interfaceIndex is null or 0)
        {
            return null;
        }

        MibIpNetRow2 row = CreateNeighborRow(addressBytes, interfaceIndex.Value);
        // A sessão captura a tabela antes dos probes. Se a entrada só existe agora,
        // nasceu durante este scan. Um estado Reachable constitui evidência recente.
        int existingEntryResult = getIpNetEntry(ref row);
        bool hadExistingEntry = existingEntryResult == 0;
        if (existingEntryResult == 0)
        {
            if (TryGetReachableNeighborMac(row, out string reachableMac))
                return reachableMac;

            // Permanent, Maximum e um Reachable marcado IsUnreachable não devem
            // ser alterados por uma tentativa de descoberta. Apenas estados
            // transitórios até Stale são candidatos a uma revalidação dirigida.
            if (row.State < 0 || row.State > NeighborStateStale)
                return null;
        }
        else if (existingEntryResult != ErrorNotFound)
        {
            return null;
        }

        byte[] mac = new byte[SendArpBufferLength];
        int length = SendArpBufferLength;
        uint destination = BitConverter.ToUInt32(addressBytes, 0);
        uint source = BitConverter.ToUInt32(sourceBytes, 0);
        int result = sendArp(destination, source, mac, ref length);
        string? candidate = result == 0 && length == EthernetAddressLength
            ? FormatEthernetAddress(mac.AsSpan(0, EthernetAddressLength))
            : null;
        if (!TryNormalizeDeviceAddress(candidate, out string normalized))
            return null;

        if (!hadExistingEntry)
            return normalized;

        // SendARP pode reutilizar ou atualizar a cache do Windows. Para uma entrada
        // preexistente que não estava Reachable, o código de retorno não basta como
        // prova de vida: a nova leitura tem de estar Reachable, sem IsUnreachable, e
        // devolver exatamente o mesmo MAC. Assim uma entrada Stale antiga nunca é
        // promovida apenas por continuar na tabela.
        MibIpNetRow2 refreshedRow = CreateNeighborRow(addressBytes, interfaceIndex.Value);
        int refreshedEntryResult = getIpNetEntry(ref refreshedRow);
        return refreshedEntryResult == 0 &&
            TryGetReachableNeighborMac(refreshedRow, out string refreshedMac) &&
            string.Equals(normalized, refreshedMac, StringComparison.Ordinal)
                ? refreshedMac
                : null;
    }

    private static MibIpNetRow2 CreateNeighborRow(
        byte[] addressBytes,
        uint interfaceIndex) =>
        new()
        {
            Address = SockaddrInet.FromIpv4Bytes(addressBytes),
            InterfaceIndex = interfaceIndex
        };

    private static bool TryGetReachableNeighborMac(
        MibIpNetRow2 row,
        out string normalized)
    {
        normalized = string.Empty;
        bool isReachable = row.State == NeighborStateReachable &&
            (row.Flags & NeighborFlagIsUnreachable) == 0;
        string? candidate = isReachable &&
            row.PhysicalAddressLength == EthernetAddressLength
                ? FormatEthernetAddress(row.GetEthernetAddress())
                : null;
        return TryNormalizeDeviceAddress(candidate, out normalized);
    }

    private static string FormatEthernetAddress(ReadOnlySpan<byte> address) =>
        string.Join(
            ":",
            address.ToArray().Select(value =>
                value.ToString("X2", CultureInfo.InvariantCulture)));

    private static uint? ResolveIpv4InterfaceIndex(
        LocalNetworkInterface networkInterface)
    {
        ArgumentNullException.ThrowIfNull(networkInterface);

        NetworkInterface[] adapters;
        try
        {
            adapters = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch (Exception exception) when (
            exception is NetworkInformationException or
                PlatformNotSupportedException)
        {
            return null;
        }

        foreach (NetworkInterface adapter in adapters)
        {
            if (TryGetAdapterId(adapter, out string? id) &&
                string.Equals(id, networkInterface.Id, StringComparison.OrdinalIgnoreCase) &&
                TryGetIpv4InterfaceIndex(adapter, out uint interfaceIndex))
            {
                return interfaceIndex;
            }
        }

        foreach (NetworkInterface adapter in adapters)
        {
            if (TryGetIpv4InterfaceIndex(
                    adapter,
                    networkInterface.IpAddress,
                    out uint interfaceIndex))
            {
                return interfaceIndex;
            }
        }

        return null;
    }

    private static bool TryGetAdapterId(NetworkInterface adapter, out string? id)
    {
        id = null;
        try
        {
            id = adapter.Id;
            return true;
        }
        catch (Exception exception) when (IsAdapterInspectionException(exception))
        {
            return false;
        }
    }

    private static bool TryGetIpv4InterfaceIndex(
        NetworkInterface adapter,
        out uint interfaceIndex)
    {
        interfaceIndex = 0;
        try
        {
            int index = adapter.GetIPProperties().GetIPv4Properties().Index;
            if (index <= 0)
                return false;

            interfaceIndex = checked((uint)index);
            return true;
        }
        catch (Exception exception) when (IsAdapterInspectionException(exception))
        {
            return false;
        }
    }

    private static bool TryGetIpv4InterfaceIndex(
        NetworkInterface adapter,
        IPAddress sourceAddress,
        out uint interfaceIndex)
    {
        interfaceIndex = 0;
        try
        {
            IPInterfaceProperties properties = adapter.GetIPProperties();
            if (!properties.UnicastAddresses.Any(item =>
                    item.Address.Equals(sourceAddress)))
            {
                return false;
            }

            int index = properties.GetIPv4Properties().Index;
            if (index <= 0)
                return false;

            interfaceIndex = checked((uint)index);
            return true;
        }
        catch (Exception exception) when (IsAdapterInspectionException(exception))
        {
            return false;
        }
    }

    private static bool IsAdapterInspectionException(Exception exception) =>
        exception is NetworkInformationException or
            PlatformNotSupportedException or
            InvalidOperationException or
            NotSupportedException or
            ObjectDisposedException or
            OverflowException;

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

    internal delegate int GetIpNetEntry2Callback(ref MibIpNetRow2 row);

    internal delegate int SendArpCallback(
        uint destinationIp,
        uint sourceIp,
        byte[] macAddress,
        ref int physicalAddressLength);

    [DllImport("iphlpapi.dll", EntryPoint = "GetIpNetEntry2", ExactSpelling = true)]
    private static extern int GetIpNetEntry2Native(ref MibIpNetRow2 row);

    [DllImport("iphlpapi.dll", EntryPoint = "SendARP", ExactSpelling = true)]
    private static extern int SendArpNative(
        uint destinationIp,
        uint sourceIp,
        byte[] macAddress,
        ref int physicalAddressLength);

    [StructLayout(LayoutKind.Explicit, Size = 28)]
    internal struct SockaddrInet
    {
        private const ushort AddressFamilyInet = 2;

        [FieldOffset(0)]
        public ushort Family;

        [FieldOffset(2)]
        public ushort Port;

        [FieldOffset(4)]
        public byte AddressByte0;

        [FieldOffset(5)]
        public byte AddressByte1;

        [FieldOffset(6)]
        public byte AddressByte2;

        [FieldOffset(7)]
        public byte AddressByte3;

        public static SockaddrInet FromIpv4Bytes(byte[] bytes)
        {
            ArgumentNullException.ThrowIfNull(bytes);
            if (bytes.Length != 4)
                throw new ArgumentException("É necessário um endereço IPv4.", nameof(bytes));

            return new SockaddrInet
            {
                Family = AddressFamilyInet,
                AddressByte0 = bytes[0],
                AddressByte1 = bytes[1],
                AddressByte2 = bytes[2],
                AddressByte3 = bytes[3]
            };
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 88)]
    internal struct MibIpNetRow2
    {
        [FieldOffset(0)]
        public SockaddrInet Address;

        [FieldOffset(28)]
        public uint InterfaceIndex;

        [FieldOffset(32)]
        public ulong InterfaceLuid;

        [FieldOffset(40)]
        public byte PhysicalAddressByte0;

        [FieldOffset(41)]
        public byte PhysicalAddressByte1;

        [FieldOffset(42)]
        public byte PhysicalAddressByte2;

        [FieldOffset(43)]
        public byte PhysicalAddressByte3;

        [FieldOffset(44)]
        public byte PhysicalAddressByte4;

        [FieldOffset(45)]
        public byte PhysicalAddressByte5;

        [FieldOffset(72)]
        public uint PhysicalAddressLength;

        [FieldOffset(76)]
        public int State;

        [FieldOffset(80)]
        public byte Flags;

        [FieldOffset(84)]
        public uint ReachabilityTime;

        public byte[] GetEthernetAddress() =>
        [
            PhysicalAddressByte0,
            PhysicalAddressByte1,
            PhysicalAddressByte2,
            PhysicalAddressByte3,
            PhysicalAddressByte4,
            PhysicalAddressByte5
        ];
    }

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

    private sealed record NeighborTableSnapshot(
        bool IsAvailable,
        IReadOnlyDictionary<IPAddress, string> Entries);

    internal sealed class ScanSession : IAsyncDisposable
    {
        private readonly LocalNetworkInterface _networkInterface;
        private readonly Func<IPAddress, IPAddress, uint?, CancellationToken, Task<string?>> _activeResolver;
        private readonly uint? _interfaceIndex;
        private readonly CancellationToken _scanCancellationToken;
        private readonly SemaphoreSlim _activeGate;
        private readonly Lazy<Task<NeighborTableSnapshot>> _neighborTable;
        private readonly ConcurrentDictionary<IPAddress, Lazy<Task<MacAddressResolution?>>> _addressCache = [];
        private readonly ConcurrentDictionary<IPAddress, Lazy<Task<MacAddressResolution?>>> _activeAddressCache = [];

        internal ScanSession(
            LocalNetworkInterface networkInterface,
            Func<LocalNetworkInterface, CancellationToken, Task<string?>> neighborTableReader,
            Func<IPAddress, IPAddress, uint?, CancellationToken, Task<string?>> activeResolver,
            uint? interfaceIndex,
            int maximumActiveConcurrency,
            CancellationToken scanCancellationToken)
        {
            _networkInterface = networkInterface;
            _activeResolver = activeResolver;
            _interfaceIndex = interfaceIndex;
            _scanCancellationToken = scanCancellationToken;
            _activeGate = new SemaphoreSlim(maximumActiveConcurrency, maximumActiveConcurrency);
            _neighborTable = new Lazy<Task<NeighborTableSnapshot>>(
                async () =>
                {
                    string? output = await neighborTableReader(
                        networkInterface,
                        scanCancellationToken);
                    return output is null
                        ? new NeighborTableSnapshot(false, new Dictionary<IPAddress, string>())
                        : new NeighborTableSnapshot(true, ParseNeighborTable(output));
                },
                LazyThreadSafetyMode.ExecutionAndPublication);
        }

        public async Task<string?> ResolveAsync(
            IPAddress address,
            CancellationToken cancellationToken)
        {
            MacAddressResolution? result = await ResolveWithEvidenceAsync(
                address,
                cancellationToken);
            return result?.MacAddress;
        }

        public bool IsNeighborBaselineAvailable { get; private set; }

        internal async Task InitializeAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            NeighborTableSnapshot snapshot =
                await _neighborTable.Value.WaitAsync(cancellationToken);
            IsNeighborBaselineAvailable = snapshot.IsAvailable;
        }

        public async Task<MacAddressResolution?> ResolveWithEvidenceAsync(
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
                    ? new MacAddressResolution(
                        localMac,
                        MacAddressResolutionSource.LocalInterface)
                    : null;
            }

            if (!IpAddressHelper.IsInSameSubnet(
                    address,
                    _networkInterface.IpAddress,
                    _networkInterface.SubnetMask))
            {
                return null;
            }

            Lazy<Task<MacAddressResolution?>> cached = _addressCache.GetOrAdd(
                address,
                static (target, session) => new Lazy<Task<MacAddressResolution?>>(
                    () => session.ResolveWithCacheCoreAsync(target),
                    LazyThreadSafetyMode.ExecutionAndPublication),
                this);
            return await cached.Value.WaitAsync(cancellationToken);
        }

        internal async Task<MacAddressResolution?> ConfirmReachabilityAsync(
            IPAddress address,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(address);
            cancellationToken.ThrowIfCancellationRequested();

            if (address.Equals(_networkInterface.IpAddress) ||
                !IpAddressHelper.IsInSameSubnet(
                    address,
                    _networkInterface.IpAddress,
                    _networkInterface.SubnetMask))
            {
                return null;
            }

            NeighborTableSnapshot snapshot =
                await _neighborTable.Value.WaitAsync(cancellationToken);
            IsNeighborBaselineAvailable = snapshot.IsAvailable;
            if (!snapshot.IsAvailable)
                return null;

            MacAddressResolution? resolution =
                await GetActiveResolutionAsync(address).WaitAsync(cancellationToken);
            return resolution is null
                ? null
                : new MacAddressResolution(
                    resolution.MacAddress,
                    MacAddressResolutionSource.CurrentReachableNeighbor);
        }

        internal async Task<MacAddressResolution?> ResolveForDiscoveryAsync(
            IPAddress address,
            CancellationToken cancellationToken)
        {
            MacAddressResolution? resolution = await ResolveWithEvidenceAsync(
                address,
                cancellationToken);
            if (resolution?.Source != MacAddressResolutionSource.NeighborCache)
                return resolution;

            return await ConfirmReachabilityAsync(address, cancellationToken) ?? resolution;
        }

        private async Task<MacAddressResolution?> ResolveWithCacheCoreAsync(IPAddress address)
        {
            _scanCancellationToken.ThrowIfCancellationRequested();
            NeighborTableSnapshot snapshot =
                await _neighborTable.Value.WaitAsync(_scanCancellationToken);
            IsNeighborBaselineAvailable = snapshot.IsAvailable;
            if (!snapshot.IsAvailable)
                return null;

            if (snapshot.Entries.TryGetValue(address, out string? cachedMac))
            {
                return new MacAddressResolution(
                    cachedMac,
                    MacAddressResolutionSource.NeighborCache);
            }

            return await GetActiveResolutionAsync(address);
        }

        private async Task<MacAddressResolution?> GetActiveResolutionAsync(IPAddress address)
        {
            Lazy<Task<MacAddressResolution?>> cached = _activeAddressCache.GetOrAdd(
                address,
                static (target, session) => new Lazy<Task<MacAddressResolution?>>(
                    () => session.ResolveActiveCoreAsync(target),
                    LazyThreadSafetyMode.ExecutionAndPublication),
                this);
            return await cached.Value.WaitAsync(_scanCancellationToken);
        }

        private async Task<MacAddressResolution?> ResolveActiveCoreAsync(IPAddress address)
        {
            _scanCancellationToken.ThrowIfCancellationRequested();
            await _activeGate.WaitAsync(_scanCancellationToken);
            try
            {
                string? resolved = await _activeResolver(
                    address,
                    _networkInterface.IpAddress,
                    _interfaceIndex,
                    _scanCancellationToken);
                return TryNormalizeDeviceAddress(resolved, out string normalized)
                    ? new MacAddressResolution(
                        normalized,
                        MacAddressResolutionSource.ActiveArp)
                    : null;
            }
            finally
            {
                _activeGate.Release();
            }
        }

        public async ValueTask DisposeAsync()
        {
            Task<MacAddressResolution?>[] pending = _addressCache.Values
                .Concat(_activeAddressCache.Values)
                .Where(value => value.IsValueCreated)
                .Select(value => value.Value)
                .Distinct()
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
