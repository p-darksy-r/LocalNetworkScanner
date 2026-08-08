// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Text.Json;
using System.IO;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Wpf.Services;

public sealed class UiSettingsService
{
    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };
    private readonly string _settingsPath;

    public UiSettingsService(string? settingsPath = null)
    {
        _settingsPath = settingsPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalNetworkScanner",
            "settings.json");
    }

    public UiSettings Load()
    {
        if (!File.Exists(_settingsPath))
            return new UiSettings();

        try
        {
            string json = File.ReadAllText(_settingsPath);
            return JsonSerializer.Deserialize<UiSettings>(json) ?? new UiSettings();
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
        {
            return new UiSettings();
        }
    }

    public void Save(UiSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        try
        {
            string? directory = Path.GetDirectoryName(_settingsPath);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            File.WriteAllText(
                _settingsPath,
                JsonSerializer.Serialize(settings, SerializerOptions));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Preferências não essenciais nunca devem impedir o fecho da aplicação.
        }
    }
}

public sealed class UiSettings
{
    public string? LastInterfaceId { get; set; }
    public string? LastInterfaceAddress { get; set; }
    public string? LastCidr { get; set; }
    public ScanProfile Profile { get; set; } = ScanProfile.Standard;
    public bool IsAdvancedMode { get; set; }
    public string CustomPorts { get; set; } = string.Empty;
    public int MaximumHosts { get; set; } = 4_096;
    public int MaximumHostConcurrency { get; set; } = 96;
    public int MaximumPortConcurrency { get; set; } = 48;
    public int PingTimeoutMs { get; set; } = 550;
    public int ConnectTimeoutMs { get; set; } = 350;
    public int DiscoveryTimeoutMs { get; set; } = 1_200;
    public bool EnableIcmp { get; set; } = true;
    public bool EnableTcpDiscovery { get; set; } = true;
    public bool EnableArp { get; set; } = true;
    public bool EnableMulticastDiscovery { get; set; } = true;
    public bool EnableUpnpDescription { get; set; } = true;
    public bool EnableNetBiosDiscovery { get; set; } = true;
    public bool EnableHistory { get; set; } = true;
    public bool EnableSnmpDeviceDiscovery { get; set; }
    public bool EnableSnmpTopology { get; set; }
    public string SnmpSwitchAddress { get; set; } = string.Empty;
    public int SnmpTimeoutMs { get; set; } = 900;
    public bool EnableNmapDiscovery { get; set; }
    public string NmapExecutablePath { get; set; } = string.Empty;
    public int NmapTimeoutMs { get; set; } = 120_000;
    public bool EnableServiceProbes { get; set; } = true;
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
