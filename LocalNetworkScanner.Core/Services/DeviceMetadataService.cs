// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Text.Json;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class DeviceMetadataService : IDisposable
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public DeviceMetadataService(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalNetworkScanner",
            "devices.json");
    }

    public async Task ApplyAsync(
        NetworkScanResult result,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            Dictionary<string, DeviceMetadata> metadata = await LoadCoreAsync(cancellationToken);
            bool migrated = false;
            foreach (NetworkDevice device in result.Devices)
            {
                DeviceMetadata? item = FindMetadata(
                    metadata,
                    device,
                    result.NetworkInterface.NetworkCidr);
                if (item is null)
                    continue;

                device.Alias = item.Alias;
                device.Notes = item.Notes;
                device.IsFavorite = item.IsFavorite;

                DeviceMetadata enriched = EnrichIdentity(
                    item,
                    device,
                    result.NetworkInterface.NetworkCidr);
                migrated |= RemoveStaleIpAlias(metadata, item, enriched);
                foreach (string identity in GetStorageIdentities(
                             device,
                             result.NetworkInterface.NetworkCidr,
                             enriched))
                {
                    if (!metadata.TryGetValue(identity, out DeviceMetadata? existing) ||
                        !HasSameValue(existing, enriched))
                    {
                        metadata[identity] = enriched;
                        migrated = true;
                    }
                }
            }

            if (migrated)
            {
                try
                {
                    await SaveCoreAsync(metadata, cancellationToken);
                }
                catch (Exception exception) when (
                    exception is IOException or UnauthorizedAccessException)
                {
                    // A migração melhora a continuidade futura, mas uma falha de escrita
                    // não deve impedir a aplicação dos metadados já lidos neste scan.
                }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(
        NetworkDevice device,
        string networkCidr,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentException.ThrowIfNullOrWhiteSpace(networkCidr);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            Dictionary<string, DeviceMetadata> metadata = await LoadCoreAsync(cancellationToken);
            DeviceMetadata? previous = FindMetadata(metadata, device, networkCidr);
            HashSet<string> identities = GetStorageIdentities(
                device,
                networkCidr,
                previous);

            if (!device.IsFavorite && string.IsNullOrWhiteSpace(device.Alias) && string.IsNullOrWhiteSpace(device.Notes))
            {
                foreach (string identity in identities)
                    metadata.Remove(identity);
            }
            else
            {
                DeviceMetadata item = new()
                {
                    Alias = Normalize(device.Alias),
                    Notes = Normalize(device.Notes),
                    IsFavorite = device.IsFavorite,
                    UpdatedAt = DateTimeOffset.UtcNow,
                    MacAddress = GetValidMac(device.MacAddress) ?? previous?.MacAddress,
                    LastKnownIpAddress = device.IpAddressText,
                    NetworkCidr = networkCidr
                };
                RemoveStaleIpAlias(metadata, previous, item);
                foreach (string identity in GetStorageIdentities(device, networkCidr, item))
                    metadata[identity] = item;
            }

            await SaveCoreAsync(metadata, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<Dictionary<string, DeviceMetadata>> LoadCoreAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
            return new Dictionary<string, DeviceMetadata>(StringComparer.OrdinalIgnoreCase);

        try
        {
            await using FileStream stream = File.OpenRead(_path);
            Dictionary<string, DeviceMetadata>? result =
                await JsonSerializer.DeserializeAsync<Dictionary<string, DeviceMetadata>>(
                    stream,
                    cancellationToken: cancellationToken);
            return result is null
                ? new Dictionary<string, DeviceMetadata>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, DeviceMetadata>(result, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            return new Dictionary<string, DeviceMetadata>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private async Task SaveCoreAsync(
        Dictionary<string, DeviceMetadata> metadata,
        CancellationToken cancellationToken)
    {
        string? directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        string temporaryPath = _path + $".tmp-{Guid.NewGuid():N}";
        try
        {
            await using (FileStream stream = File.Create(temporaryPath))
            {
                await JsonSerializer.SerializeAsync(
                    stream,
                    metadata,
                    IndentedJsonOptions,
                    cancellationToken);
            }

            File.Move(temporaryPath, _path, overwrite: true);
        }
        finally
        {
            TryDelete(temporaryPath);
        }
    }

    private static DeviceMetadata? FindMetadata(
        IReadOnlyDictionary<string, DeviceMetadata> metadata,
        NetworkDevice device,
        string networkCidr)
    {
        string? currentMac = GetValidMac(device.MacAddress);
        if (currentMac is not null &&
            metadata.TryGetValue(GetMacIdentity(currentMac), out DeviceMetadata? macItem))
        {
            return macItem;
        }

        string ipIdentity = GetIpIdentity(networkCidr, device.IpAddressText);
        if (metadata.TryGetValue(ipIdentity, out DeviceMetadata? ipItem))
        {
            string? storedMac = GetValidMac(ipItem.MacAddress);
            if (currentMac is null ||
                storedMac is null ||
                currentMac.Equals(storedMac, StringComparison.OrdinalIgnoreCase))
            {
                return ipItem;
            }
        }

        if (currentMac is not null)
            return null;

        return metadata.Values
            .Where(item =>
                string.Equals(item.NetworkCidr, networkCidr, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(item.LastKnownIpAddress, device.IpAddressText, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(item => item.UpdatedAt)
            .FirstOrDefault();
    }

    private static HashSet<string> GetStorageIdentities(
        NetworkDevice device,
        string networkCidr,
        DeviceMetadata? metadata)
    {
        HashSet<string> identities = new(StringComparer.OrdinalIgnoreCase)
        {
            GetIpIdentity(networkCidr, device.IpAddressText)
        };

        string? mac = GetValidMac(device.MacAddress) ?? GetValidMac(metadata?.MacAddress);
        if (mac is not null)
            identities.Add(GetMacIdentity(mac));
        return identities;
    }

    private static DeviceMetadata EnrichIdentity(
        DeviceMetadata item,
        NetworkDevice device,
        string networkCidr) => new()
        {
            Alias = item.Alias,
            Notes = item.Notes,
            IsFavorite = item.IsFavorite,
            UpdatedAt = item.UpdatedAt,
            MacAddress = GetValidMac(device.MacAddress) ?? GetValidMac(item.MacAddress),
            LastKnownIpAddress = device.IpAddressText,
            NetworkCidr = networkCidr
        };

    private static bool RemoveStaleIpAlias(
        IDictionary<string, DeviceMetadata> metadata,
        DeviceMetadata? previous,
        DeviceMetadata current)
    {
        if (previous is null ||
            string.IsNullOrWhiteSpace(previous.NetworkCidr) ||
            string.IsNullOrWhiteSpace(previous.LastKnownIpAddress) ||
            string.Equals(previous.NetworkCidr, current.NetworkCidr, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(previous.LastKnownIpAddress, current.LastKnownIpAddress, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string oldIdentity = GetIpIdentity(previous.NetworkCidr, previous.LastKnownIpAddress);
        if (!metadata.TryGetValue(oldIdentity, out DeviceMetadata? existing) ||
            !HasSameValue(existing, previous))
        {
            return false;
        }

        return metadata.Remove(oldIdentity);
    }

    private static bool HasSameValue(DeviceMetadata first, DeviceMetadata second) =>
        string.Equals(first.Alias, second.Alias, StringComparison.Ordinal) &&
        string.Equals(first.Notes, second.Notes, StringComparison.Ordinal) &&
        first.IsFavorite == second.IsFavorite &&
        first.UpdatedAt == second.UpdatedAt &&
        string.Equals(first.MacAddress, second.MacAddress, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(first.LastKnownIpAddress, second.LastKnownIpAddress, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(first.NetworkCidr, second.NetworkCidr, StringComparison.OrdinalIgnoreCase);

    private static string GetMacIdentity(string macAddress) =>
        $"mac:{macAddress.Replace(":", string.Empty, StringComparison.Ordinal)}".ToLowerInvariant();

    private static string GetIpIdentity(string networkCidr, string ipAddress) =>
        $"{networkCidr}|ip:{ipAddress}".ToLowerInvariant();

    private static string? GetValidMac(string? value) =>
        MacAddressService.TryNormalizeDeviceAddress(value, out string normalized)
            ? normalized
            : null;

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (IOException)
        {
            // O ficheiro temporário será ignorado na próxima leitura.
        }
        catch (UnauthorizedAccessException)
        {
            // O ficheiro temporário será ignorado na próxima leitura.
        }
    }

    private static string? Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    public void Dispose() => _gate.Dispose();

    private sealed class DeviceMetadata
    {
        public string? Alias { get; set; }
        public string? Notes { get; set; }
        public bool IsFavorite { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
        public string? MacAddress { get; set; }
        public string? LastKnownIpAddress { get; set; }
        public string? NetworkCidr { get; set; }
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
