// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Globalization;
using System.Text;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class WifiSignalService
{
    public async Task<IReadOnlyList<WifiConnectionInfo>> GetConnectionsAsync(
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return [];

        string? output = await ProcessRunner.RunAsync(
            "netsh.exe",
            ["wlan", "show", "interfaces"],
            timeoutMs: 3_000,
            cancellationToken);

        return string.IsNullOrWhiteSpace(output) ? [] : Parse(output);
    }

    internal static IReadOnlyList<WifiConnectionInfo> Parse(string output)
    {
        List<Dictionary<string, string>> blocks = [];
        Dictionary<string, string>? current = null;

        foreach (string rawLine in output.Split('\n'))
        {
            string line = rawLine.Trim();
            int separator = line.IndexOf(':');
            if (separator <= 0)
                continue;

            string key = Normalize(line[..separator]);
            string value = line[(separator + 1)..].Trim();

            if (key is "name" or "nome")
            {
                current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                blocks.Add(current);
            }

            current?[key] = value;
        }

        return blocks.Select(block => new WifiConnectionInfo
        {
            Name = Get(block, "name", "nome"),
            Description = Get(block, "description", "descricao"),
            Ssid = Get(block, "ssid"),
            Bssid = Get(block, "bssid"),
            SignalPercent = ParseNumber(Get(block, "signal", "sinal")),
            Channel = ParseNumber(Get(block, "channel", "canal")),
            RadioType = Get(block, "radio type", "tipo de radio")
        }).ToList();
    }

    private static string? Get(Dictionary<string, string> values, params string[] keys)
    {
        foreach (string key in keys)
        {
            if (values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value))
                return value;
        }

        return null;
    }

    private static int? ParseNumber(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        string digits = new(value.Where(char.IsDigit).ToArray());
        return int.TryParse(digits, out int result) ? result : null;
    }

    private static string Normalize(string value)
    {
        string decomposed = value.Trim().ToLowerInvariant().Normalize(NormalizationForm.FormD);
        StringBuilder result = new();

        foreach (char character in decomposed)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(character) != UnicodeCategory.NonSpacingMark)
                result.Append(character);
        }

        return result.ToString().Normalize(NormalizationForm.FormC);
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
