// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class NetworkHistoryService
{
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
        string networkKey = BuildNetworkKey(result);
        string path = Path.Combine(
            _snapshotDirectory,
            $"{Sanitize(result.NetworkInterface.NetworkCidr)}-{Hash(networkKey)}.json");
        SnapshotFile? previous = await LoadAsync(path, cancellationToken);
        if (previous is null)
        {
            string legacyPath = Path.Combine(
                _snapshotDirectory,
                Sanitize(result.NetworkInterface.NetworkCidr) + ".json");
            previous = await LoadAsync(legacyPath, cancellationToken);
        }

        Dictionary<string, SnapshotDevice> byIdentity = previous?.Devices
            .GroupBy(GetIdentity, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Last(), StringComparer.OrdinalIgnoreCase)
            ?? new Dictionary<string, SnapshotDevice>(StringComparer.OrdinalIgnoreCase);

        foreach (NetworkDevice device in result.Devices)
        {
            SnapshotDevice current = ToSnapshot(device);
            byIdentity.TryGetValue(GetIdentity(current), out SnapshotDevice? old);

            device.HistoryCompared = true;
            device.IsNew = old is null;
            if (old is null)
                continue;

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
            Devices = result.Devices.Select(ToSnapshot).ToList()
        };

        string temporaryPath = path + ".tmp";
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

    private static string GetIdentity(SnapshotDevice device)
    {
        string? validMac = GetValidMac(device.MacAddress);
        return validMac is null
            ? $"ip:{device.IpAddress}"
            : $"mac:{validMac}";
    }

    private static string Sanitize(string value) =>
        string.Concat(value.Select(character => Path.GetInvalidFileNameChars().Contains(character) ? '_' : character));

    private static string BuildNetworkKey(NetworkScanResult result)
    {
        string? gatewayMac = result.NetworkInterface.GatewayAddress is null
            ? null
            : GetValidMac(result.Devices.FirstOrDefault(device =>
                device.IpAddress.Equals(result.NetworkInterface.GatewayAddress))?.MacAddress);
        string anchor = gatewayMac ??
            GetValidMac(result.NetworkInterface.Bssid) ??
            result.NetworkInterface.GatewayAddress?.ToString() ??
            result.NetworkInterface.Id;
        return $"{result.NetworkInterface.NetworkCidr}|{anchor}".ToLowerInvariant();
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
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
