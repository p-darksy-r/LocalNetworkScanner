// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class NetworkHistoryService
{
    private const int StrongNetworkMatchScore = 300;
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };
    private readonly string _snapshotDirectory;

    public NetworkHistoryService(string? snapshotDirectory = null)
    {
        _snapshotDirectory = snapshotDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalNetworkScanner",
            "snapshots");
    }

    public async Task ApplyAndSaveAsync(
        NetworkScanResult result,
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(_snapshotDirectory);
        IReadOnlyList<NetworkKeyCandidate> networkKeys = BuildNetworkKeys(result);
        string networkKey = networkKeys[0].Key;
        string path = Path.Combine(
            _snapshotDirectory,
            $"{Sanitize(result.NetworkInterface.NetworkCidr)}-{Hash(networkKey)}.json");
        LoadedSnapshot? loaded = await FindPreviousAsync(
            result,
            networkKeys,
            path,
            cancellationToken);
        SnapshotFile? previous = loaded?.Snapshot;

        Dictionary<string, SnapshotDevice> byMac = BuildDeviceIndex(
            previous?.Devices,
            device => GetValidMac(device.MacAddress));
        Dictionary<string, SnapshotDevice> byIp = BuildDeviceIndex(
            previous?.Devices,
            device => NormalizeIp(device.IpAddress));
        HashSet<SnapshotDevice> matchedDevices = [];

        foreach (NetworkDevice device in result.Devices)
        {
            SnapshotDevice current = ToSnapshot(device);
            SnapshotDevice? old = FindPreviousDevice(
                current,
                byMac,
                byIp,
                matchedDevices);

            device.HistoryCompared = true;
            device.IsNew = old is null;
            if (old is null)
                continue;

            matchedDevices.Add(old);
            device.FirstSeen = old.FirstSeen;
            if (!string.Equals(old.IpAddress, current.IpAddress, StringComparison.OrdinalIgnoreCase))
                device.Changes.Add($"IP mudou de {old.IpAddress} para {current.IpAddress}");
            if (!string.Equals(old.Hostname, current.Hostname, StringComparison.OrdinalIgnoreCase))
                device.Changes.Add($"Hostname mudou de {old.Hostname ?? "—"} para {current.Hostname ?? "—"}");

            int[] opened = current.OpenPorts.Except(old.OpenPorts).ToArray();
            int[] closed = old.OpenPorts.Except(current.OpenPorts).ToArray();
            if (opened.Length > 0)
                device.Changes.Add($"Portas abertas: {string.Join(", ", opened)}");
            if (closed.Length > 0)
                device.Changes.Add($"Portas fechadas: {string.Join(", ", closed)}");
        }

        SnapshotFile snapshot = new()
        {
            CapturedAt = result.CompletedAt,
            NetworkCidr = result.NetworkInterface.NetworkCidr,
            NetworkKey = networkKey,
            NetworkId = string.IsNullOrWhiteSpace(previous?.NetworkId)
                ? Guid.NewGuid().ToString("N")
                : previous.NetworkId,
            NetworkAliases = BuildNetworkAliases(previous, networkKeys),
            Devices = result.Devices.Select(ToSnapshot).ToList()
        };

        string temporaryPath = path + $".tmp-{Guid.NewGuid():N}";
        try
        {
            await using (FileStream stream = File.Create(temporaryPath))
            {
                await JsonSerializer.SerializeAsync(
                    stream,
                    snapshot,
                    IndentedJsonOptions,
                    cancellationToken);
            }

            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            TryDelete(temporaryPath);
        }

        if (loaded is not null &&
            !Path.GetFullPath(loaded.Path).Equals(
                Path.GetFullPath(path),
                StringComparison.OrdinalIgnoreCase))
        {
            TryDelete(loaded.Path);
        }
    }

    /// <summary>
    /// Apaga apenas os snapshots e temporários pertencentes ao histórico.
    /// Preferências, aliases, notas e a base OUI não são afetados.
    /// </summary>
    public Task<int> ClearAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => ClearCore(cancellationToken), cancellationToken);

    private int ClearCore(CancellationToken cancellationToken)
    {
        if (!Directory.Exists(_snapshotDirectory))
            return 0;

        int deleted = 0;
        foreach (string path in Directory.EnumerateFiles(
                     _snapshotDirectory,
                     "*",
                     SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string fileName = Path.GetFileName(path);
            bool isSnapshot = fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase);
            bool isTemporary =
                fileName.Contains(".json.tmp-", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase);
            if (!isSnapshot && !isTemporary)
                continue;

            File.Delete(path);
            deleted++;
        }

        return deleted;
    }

    private async Task<LoadedSnapshot?> FindPreviousAsync(
        NetworkScanResult result,
        IReadOnlyList<NetworkKeyCandidate> networkKeys,
        string preferredPath,
        CancellationToken cancellationToken)
    {
        string networkCidr = result.NetworkInterface.NetworkCidr;
        string legacyPath = Path.Combine(
            _snapshotDirectory,
            Sanitize(networkCidr) + ".json");
        HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase)
        {
            preferredPath,
            legacyPath
        };

        string pattern = Sanitize(networkCidr) + "-*.json";
        foreach (string candidatePath in Directory.EnumerateFiles(
                     _snapshotDirectory,
                     pattern,
                     SearchOption.TopDirectoryOnly))
        {
            paths.Add(candidatePath);
        }

        List<LoadedSnapshot> matches = [];
        foreach (string candidatePath in paths)
        {
            SnapshotFile? snapshot = await LoadAsync(candidatePath, cancellationToken);
            if (snapshot is null ||
                !string.Equals(snapshot.NetworkCidr, networkCidr, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            int sharedStableMacs = CountSharedStableMacs(result.Devices, snapshot.Devices);
            int score = ScoreNetworkMatch(
                snapshot,
                networkKeys,
                candidatePath.Equals(legacyPath, StringComparison.OrdinalIgnoreCase),
                sharedStableMacs);
            if (score > 0)
            {
                matches.Add(new LoadedSnapshot(
                    snapshot,
                    candidatePath,
                    score,
                    sharedStableMacs));
            }
        }

        LoadedSnapshot[] ordered = matches
            .OrderByDescending(match => match.Score)
            .ThenByDescending(match => match.Snapshot.CapturedAt)
            .ToArray();
        if (ordered.Length == 0)
            return null;

        if (ordered.Length > 1 &&
            ordered[0].Score == ordered[1].Score &&
            ordered[0].Score < StrongNetworkMatchScore &&
            ordered[0].SharedStableMacs == 0 &&
            ordered[1].SharedStableMacs == 0 &&
            !HaveSameNetworkId(ordered[0].Snapshot, ordered[1].Snapshot))
        {
            // Dois históricos de redes com endereçamento genérico não devem ser
            // fundidos apenas porque usam o mesmo CIDR, gateway ou adaptador.
            return null;
        }

        return ordered[0];
    }

    private static async Task<SnapshotFile?> LoadAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            return null;

        try
        {
            await using FileStream stream = File.OpenRead(path);
            return await JsonSerializer.DeserializeAsync<SnapshotFile>(stream, cancellationToken: cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            return null;
        }
    }

    private static Dictionary<string, SnapshotDevice> BuildDeviceIndex(
        IEnumerable<SnapshotDevice>? devices,
        Func<SnapshotDevice, string?> keySelector)
    {
        Dictionary<string, SnapshotDevice> index = new(StringComparer.OrdinalIgnoreCase);
        if (devices is null)
            return index;

        foreach (SnapshotDevice device in devices)
        {
            string? key = keySelector(device);
            if (!string.IsNullOrWhiteSpace(key))
                index[key] = device;
        }

        return index;
    }

    private static SnapshotDevice? FindPreviousDevice(
        SnapshotDevice current,
        IReadOnlyDictionary<string, SnapshotDevice> byMac,
        IReadOnlyDictionary<string, SnapshotDevice> byIp,
        IReadOnlySet<SnapshotDevice> matchedDevices)
    {
        string? currentMac = GetValidMac(current.MacAddress);
        if (currentMac is not null &&
            byMac.TryGetValue(currentMac, out SnapshotDevice? macMatch) &&
            !matchedDevices.Contains(macMatch))
        {
            return macMatch;
        }

        string? currentIp = NormalizeIp(current.IpAddress);
        if (currentIp is null ||
            !byIp.TryGetValue(currentIp, out SnapshotDevice? ipMatch) ||
            matchedDevices.Contains(ipMatch))
        {
            return null;
        }

        string? previousMac = GetValidMac(ipMatch.MacAddress);
        return currentMac is null ||
               previousMac is null ||
               currentMac.Equals(previousMac, StringComparison.OrdinalIgnoreCase)
            ? ipMatch
            : null;
    }

    private static SnapshotDevice ToSnapshot(NetworkDevice device) => new()
    {
        IpAddress = device.IpAddressText,
        Hostname = device.Hostname,
        MacAddress = GetValidMac(device.MacAddress),
        Manufacturer = device.Manufacturer,
        OpenPorts = device.Ports.Select(port => port.Port).OrderBy(port => port).ToArray(),
        FirstSeen = device.FirstSeen,
        LastSeen = device.LastSeen
    };

    private static string? NormalizeIp(string? value)
    {
        return System.Net.IPAddress.TryParse(value, out System.Net.IPAddress? address)
            ? address.ToString()
            : null;
    }

    private static string Sanitize(string value) =>
        string.Concat(value.Select(character => Path.GetInvalidFileNameChars().Contains(character) ? '_' : character));

    private static IReadOnlyList<NetworkKeyCandidate> BuildNetworkKeys(NetworkScanResult result)
    {
        List<NetworkKeyCandidate> candidates = [];
        string networkCidr = result.NetworkInterface.NetworkCidr;
        string? gatewayMac = result.NetworkInterface.GatewayAddress is null
            ? null
            : GetValidMac(result.Devices.FirstOrDefault(device =>
                device.IpAddress.Equals(result.NetworkInterface.GatewayAddress))?.MacAddress);
        Add(gatewayMac, 400);
        Add(GetValidMac(result.NetworkInterface.Bssid), 350);
        Add(result.NetworkInterface.GatewayAddress?.ToString(), 200);
        Add(result.NetworkInterface.Id, 150);
        Add(result.NetworkInterface.IpAddress.ToString(), 100);

        return candidates;

        void Add(string? anchor, int score)
        {
            if (string.IsNullOrWhiteSpace(anchor))
                return;

            string key = $"{networkCidr}|{anchor.Trim()}".ToLowerInvariant();
            if (candidates.All(candidate =>
                    !candidate.Key.Equals(key, StringComparison.OrdinalIgnoreCase)))
            {
                candidates.Add(new NetworkKeyCandidate(key, score));
            }
        }
    }

    private static List<string> BuildNetworkAliases(
        SnapshotFile? previous,
        IReadOnlyList<NetworkKeyCandidate> current)
    {
        IEnumerable<string> previousAliases = previous?.NetworkAliases ?? [];
        return previousAliases
            .Append(previous?.NetworkKey ?? string.Empty)
            .Concat(current.Select(candidate => candidate.Key))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static int ScoreNetworkMatch(
        SnapshotFile snapshot,
        IReadOnlyList<NetworkKeyCandidate> current,
        bool isLegacyPath,
        int sharedStableMacs)
    {
        HashSet<string> snapshotKeys = new(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(snapshot.NetworkKey))
            snapshotKeys.Add(snapshot.NetworkKey);
        foreach (string alias in snapshot.NetworkAliases ?? [])
        {
            if (!string.IsNullOrWhiteSpace(alias))
                snapshotKeys.Add(alias);
        }

        int keyScore = current
            .Where(candidate => snapshotKeys.Contains(candidate.Key))
            .Select(candidate => candidate.Score)
            .DefaultIfEmpty(isLegacyPath ? 25 : 0)
            .Max();
        return keyScore + Math.Min(100, sharedStableMacs * 25);
    }

    private static int CountSharedStableMacs(
        IReadOnlyList<NetworkDevice> current,
        IReadOnlyList<SnapshotDevice> previous)
    {
        HashSet<string> currentMacs = current
            .Select(device => GetStableMac(device.MacAddress))
            .Where(mac => mac is not null)
            .Select(mac => mac!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (currentMacs.Count == 0)
            return 0;

        return previous
            .Select(device => GetStableMac(device.MacAddress))
            .Where(mac => mac is not null && currentMacs.Contains(mac))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
    }

    private static string? GetStableMac(string? value)
    {
        string? validMac = GetValidMac(value);
        return validMac is not null && !MacVendorService.IsLocallyAdministered(validMac)
            ? validMac
            : null;
    }

    private static bool HaveSameNetworkId(SnapshotFile first, SnapshotFile second) =>
        !string.IsNullOrWhiteSpace(first.NetworkId) &&
        first.NetworkId.Equals(second.NetworkId, StringComparison.OrdinalIgnoreCase);

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (IOException)
        {
            // A limpeza de um alias antigo é best-effort; o snapshot novo já é válido.
        }
        catch (UnauthorizedAccessException)
        {
            // A limpeza de um alias antigo é best-effort; o snapshot novo já é válido.
        }
    }

    private static string? GetValidMac(string? value) =>
        MacAddressService.TryNormalizeDeviceAddress(value, out string normalized)
            ? normalized
            : null;

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16].ToLowerInvariant();

    private sealed class SnapshotFile
    {
        public DateTimeOffset CapturedAt { get; set; }
        public string NetworkCidr { get; set; } = string.Empty;
        public string NetworkKey { get; set; } = string.Empty;
        public string NetworkId { get; set; } = string.Empty;
        public List<string> NetworkAliases { get; set; } = [];
        public List<SnapshotDevice> Devices { get; set; } = [];
    }

    private sealed class SnapshotDevice
    {
        public string IpAddress { get; set; } = string.Empty;
        public string? Hostname { get; set; }
        public string? MacAddress { get; set; }
        public string? Manufacturer { get; set; }
        public int[] OpenPorts { get; set; } = [];
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
    }

    private sealed record NetworkKeyCandidate(string Key, int Score);

    private sealed record LoadedSnapshot(
        SnapshotFile Snapshot,
        string Path,
        int Score,
        int SharedStableMacs);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
