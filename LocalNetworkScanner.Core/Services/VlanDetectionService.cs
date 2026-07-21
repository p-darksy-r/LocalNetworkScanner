using System.Text.Json;
using System.Text.RegularExpressions;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed partial class VlanDetectionService
{
    public async Task<IReadOnlyDictionary<string, (int VlanId, ConfidenceLevel Confidence)>> DetectAsync(
        IEnumerable<(string Name, string Description)> interfaces,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(interfaces);

        Dictionary<string, (int, ConfidenceLevel)> result =
            new(StringComparer.OrdinalIgnoreCase);

        foreach ((string name, string description) in interfaces)
        {
            Match match = VlanNameRegex().Match($"{name} {description}");
            if (match.Success && int.TryParse(match.Groups[1].Value, out int vlan) && vlan is >= 1 and <= 4094)
                result[name] = (vlan, ConfidenceLevel.Medium);
        }

        if (!OperatingSystem.IsWindows())
            return result;

        const string command =
            "$items = Get-NetAdapterAdvancedProperty -AllProperties -ErrorAction SilentlyContinue | " +
            "Where-Object { $_.RegistryKeyword -match 'VlanID' } | ForEach-Object { " +
            "[pscustomobject]@{ Name = $_.Name; Value = ($_.RegistryValue -join '') } }; " +
            "@($items) | ConvertTo-Json -Compress";

        string? json = await ProcessRunner.RunAsync(
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-Command", command],
            timeoutMs: 4_000,
            cancellationToken);

        if (string.IsNullOrWhiteSpace(json))
            return result;

        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in root.EnumerateArray())
                    ApplyItem(item);
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                // Windows PowerShell serializa uma coleção com um único item como objeto.
                ApplyItem(root);
            }

            void ApplyItem(JsonElement item)
            {
                if (item.ValueKind != JsonValueKind.Object)
                    return;

                string? name = item.TryGetProperty("Name", out JsonElement nameElement)
                    ? nameElement.GetString()
                    : null;
                string? value = item.TryGetProperty("Value", out JsonElement valueElement)
                    ? valueElement.ToString()
                    : null;

                if (!string.IsNullOrWhiteSpace(name) &&
                    int.TryParse(value, out int vlan) &&
                    vlan is >= 1 and <= 4094)
                {
                    result[name] = (vlan, ConfidenceLevel.High);
                }
            }
        }
        catch (JsonException)
        {
            // A heurística pelo nome da interface continua disponível.
        }

        return result;
    }

    [GeneratedRegex(@"(?i)\bvlan[\s:_-]*(\d{1,4})\b", RegexOptions.CultureInvariant)]
    private static partial Regex VlanNameRegex();
}
