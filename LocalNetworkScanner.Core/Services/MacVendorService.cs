using System.Text;

namespace LocalNetworkScanner.Core.Services;

public sealed class MacVendorService
{
    private readonly Dictionary<string, string> _vendors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["000C29"] = "VMware",
        ["001C42"] = "Parallels",
        ["005056"] = "VMware",
        ["080027"] = "Oracle VirtualBox",
        ["00155D"] = "Microsoft Hyper-V",
        ["001A11"] = "Google",
        ["3C5A37"] = "Google",
        ["F4F5D8"] = "Google",
        ["0017F2"] = "Apple",
        ["3C22FB"] = "Apple",
        ["F0D1A9"] = "Apple",
        ["B827EB"] = "Raspberry Pi",
        ["DCA632"] = "Raspberry Pi",
        ["E45F01"] = "Raspberry Pi",
        ["001E10"] = "Shenzhen TP-Link",
        ["50C7BF"] = "TP-Link",
        ["F4EC38"] = "TP-Link",
        ["001D7E"] = "Cisco-Linksys",
        ["2C3F0B"] = "Cisco",
        ["FC9947"] = "Cisco",
        ["001A2B"] = "Ayecom",
        ["001E58"] = "D-Link",
        ["C8BE19"] = "D-Link",
        ["000C43"] = "Ralink",
        ["0013EF"] = "Kingjon Digital",
        ["001FC6"] = "ASUSTek",
        ["08606E"] = "ASUSTek",
        ["2CFDA1"] = "ASUSTek",
        ["001B21"] = "Intel",
        ["3C970E"] = "Wistron/Intel",
        ["A4C494"] = "Intel",
        ["001E65"] = "Intel",
        ["001A4B"] = "Hewlett-Packard",
        ["3C52A1"] = "Hewlett-Packard",
        ["001B63"] = "Apple",
        ["18FE34"] = "Espressif",
        ["24A160"] = "Espressif",
        ["84F3EB"] = "Espressif",
        ["001788"] = "Philips Lighting",
        ["B0487A"] = "TP-Link",
        ["001D0F"] = "TP-Link",
        ["001F33"] = "Netgear",
        ["9C3DCF"] = "Netgear",
        ["0007AB"] = "Samsung",
        ["8C7712"] = "Samsung",
        ["001E8C"] = "ASUSTek"
    };

    public MacVendorService(string? ouiFilePath = null)
    {
        string? path = ouiFilePath ?? FindOptionalDatabase();
        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            LoadDatabase(path);
    }

    public string? Lookup(string? macAddress)
    {
        string hex = Normalize(macAddress);
        if (hex.Length < 6)
            return null;

        if (IsLocallyAdministered(macAddress))
            return "MAC privado/aleatório";

        return _vendors.TryGetValue(hex[..6], out string? vendor) ? vendor : null;
    }

    public static bool IsLocallyAdministered(string? macAddress)
    {
        string hex = Normalize(macAddress);
        return hex.Length >= 2 && byte.TryParse(hex[..2], System.Globalization.NumberStyles.HexNumber, null, out byte first) &&
            (first & 0x02) != 0;
    }

    private void LoadDatabase(string path)
    {
        try
        {
            foreach (string line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#'))
                    continue;

                string[] columns = ParseColumns(line);
                if (!TryReadAssignment(columns, out string assignment, out string organization))
                    continue;

                _vendors[assignment] = organization;
            }
        }
        catch (IOException)
        {
            // A pequena base integrada continua funcional.
        }
    }

    private static string[] ParseColumns(string line)
    {
        if (!line.Contains(','))
        {
            char separator = line.Contains('\t') ? '\t' : ';';
            return line.Split(separator, 2, StringSplitOptions.TrimEntries);
        }

        List<string> columns = [];
        StringBuilder value = new();
        bool inQuotes = false;

        for (int index = 0; index < line.Length; index++)
        {
            char character = line[index];
            if (character == '"')
            {
                if (inQuotes && index + 1 < line.Length && line[index + 1] == '"')
                {
                    value.Append('"');
                    index++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (character == ',' && !inQuotes)
            {
                columns.Add(value.ToString().Trim());
                value.Clear();
            }
            else
            {
                value.Append(character);
            }
        }

        columns.Add(value.ToString().Trim());
        return [.. columns];
    }

    private static bool TryReadAssignment(
        IReadOnlyList<string> columns,
        out string assignment,
        out string organization)
    {
        assignment = string.Empty;
        organization = string.Empty;

        // IEEE oui.csv: Registry,Assignment,Organization Name,Organization Address.
        if (columns.Count >= 3 && TryNormalizeAssignment(columns[1], out assignment))
        {
            organization = columns[2].Trim();
            return organization.Length > 0;
        }

        // Também aceita bases simples no formato prefixo,fabricante (ou TSV/;).
        if (columns.Count >= 2 && TryNormalizeAssignment(columns[0], out assignment))
        {
            organization = columns[1].Trim();
            return organization.Length > 0;
        }

        return false;
    }

    private static bool TryNormalizeAssignment(string value, out string assignment)
    {
        string normalized = Normalize(value);
        if (normalized.Length == 6)
        {
            assignment = normalized;
            return true;
        }

        assignment = string.Empty;
        return false;
    }

    private static string? FindOptionalDatabase()
    {
        string local = Path.Combine(AppContext.BaseDirectory, "data", "oui.csv");
        if (File.Exists(local))
            return local;

        string appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalNetworkScanner",
            "oui.csv");
        return File.Exists(appData) ? appData : null;
    }

    private static string Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : new string(value.Where(Uri.IsHexDigit).Select(char.ToUpperInvariant).ToArray());
}
