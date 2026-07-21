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
        Dictionary<string, DeviceMetadata> metadata = await LoadAsync(cancellationToken);
        foreach (NetworkDevice device in result.Devices)
        {
            if (!metadata.TryGetValue(GetIdentity(device, result.NetworkInterface.NetworkCidr), out DeviceMetadata? item))
                continue;

            device.Alias = item.Alias;
            device.Notes = item.Notes;
            device.IsFavorite = item.IsFavorite;
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
            string identity = GetIdentity(device, networkCidr);
            if (!device.IsFavorite && string.IsNullOrWhiteSpace(device.Alias) && string.IsNullOrWhiteSpace(device.Notes))
            {
                metadata.Remove(identity);
            }
            else
            {
                metadata[identity] = new DeviceMetadata
                {
                    Alias = Normalize(device.Alias),
                    Notes = Normalize(device.Notes),
                    IsFavorite = device.IsFavorite,
                    UpdatedAt = DateTimeOffset.UtcNow
                };
            }

            await SaveCoreAsync(metadata, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<Dictionary<string, DeviceMetadata>> LoadAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await LoadCoreAsync(cancellationToken);
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

        string temporaryPath = _path + ".tmp";
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

    private static string GetIdentity(NetworkDevice device, string networkCidr) =>
        string.IsNullOrWhiteSpace(device.MacAddress)
            ? $"{networkCidr}|ip:{device.IpAddressText}".ToLowerInvariant()
            : $"mac:{device.MacAddress.Replace(":", string.Empty, StringComparison.Ordinal)}".ToLowerInvariant();

    private static string? Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    public void Dispose() => _gate.Dispose();

    private sealed class DeviceMetadata
    {
        public string? Alias { get; set; }
        public string? Notes { get; set; }
        public bool IsFavorite { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
    }
}
