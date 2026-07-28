// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Collections.ObjectModel;
using System.Globalization;
using System.IO.Compression;
using System.Reflection;
using System.Text;

namespace LocalNetworkScanner.Core.Services;

public sealed class MacVendorService
{
    private const string BundledResourceName =
        "LocalNetworkScanner.Core.Data.ieee-mac-vendors.tsv.gz";
    private const int MaximumDatabaseBytes = 32 * 1024 * 1024;
    private const int MaximumDatabaseRows = 150_000;
    private const int MaximumLineLength = 8_192;
    private const string LocalAddressLabel = "MAC privado/aleatório";
    private const string PrivateAssignmentLabel =
        "Private (titular não publicado pela IEEE)";
    private static readonly int[] LookupPrefixLengths = [9, 7, 6];

    private static readonly Lazy<VendorDatabaseSnapshot> BundledDatabase = new(
        LoadBundledDatabase,
        LazyThreadSafetyMode.ExecutionAndPublication);

    private readonly VendorDatabaseSnapshot? _externalDatabase;
    private readonly bool _externalDatabaseIsAuthoritative;

    public MacVendorService(string? ouiFilePath = null)
    {
        IEnumerable<(string Path, string Source, bool RequireComplete)> candidates =
            string.IsNullOrWhiteSpace(ouiFilePath)
                ? FindOptionalDatabases()
                : [(Path.GetFullPath(ouiFilePath), "Ficheiro externo", false)];

        foreach ((string path, string source, bool requireComplete) in candidates)
        {
            if (!File.Exists(path))
                continue;

            try
            {
                VendorDatabaseSnapshot database = LoadDatabaseFile(path, source);
                if (requireComplete)
                    EnsureCompleteDatabase(database);
                if (database.Entries.Count > 0)
                {
                    _externalDatabase = database;
                    _externalDatabaseIsAuthoritative = requireComplete;
                    break;
                }
            }
            catch (Exception exception) when (
                exception is IOException or
                UnauthorizedAccessException or
                InvalidDataException or
                DecoderFallbackException)
            {
                ExternalDatabaseError = exception.Message;
            }
        }
    }

    public static VendorDatabaseInfo BundledDatabaseInfo => BundledDatabase.Value.Info;

    public static int BundledEntryCount => BundledDatabaseInfo.EntryCount;

    public static int BundledUniquePrefixCount => BundledDatabaseInfo.UniquePrefixCount;

    public VendorDatabaseInfo DatabaseInfo => _externalDatabase?.Info ?? BundledDatabaseInfo;

    public VendorDatabaseInfo DatabaseStatus => DatabaseInfo;

    public bool HasExternalDatabase => _externalDatabase is not null;

    public string? ExternalDatabaseError { get; }

    public string? Lookup(string? macAddress)
    {
        if (!MacAddressService.TryNormalizeDeviceAddress(macAddress, out string normalized))
            return null;

        if (IsLocallyAdministered(normalized))
            return LocalAddressLabel;

        return LookupDetailedCore(normalized)?.Organization;
    }

    public MacVendorMatch? LookupDetailed(string? macAddress)
    {
        if (!MacAddressService.TryNormalizeDeviceAddress(macAddress, out string normalized) ||
            IsLocallyAdministered(normalized))
        {
            return null;
        }

        return LookupDetailedCore(normalized);
    }

    public static bool IsLocallyAdministered(string? macAddress)
    {
        if (!MacAddressService.TryNormalizeDeviceAddress(macAddress, out string normalized))
            return false;

        return byte.TryParse(
                normalized.AsSpan(0, 2),
                NumberStyles.HexNumber,
                CultureInfo.InvariantCulture,
                out byte first) &&
            (first & 0x02) != 0;
    }

    private MacVendorMatch? LookupDetailedCore(string normalizedMac)
    {
        string hex = normalizedMac.Replace(":", string.Empty, StringComparison.Ordinal);
        if (_externalDatabase is not null && _externalDatabaseIsAuthoritative)
            return LookupDatabase(_externalDatabase, hex);

        foreach (int prefixLength in LookupPrefixLengths)
        {
            string prefix = hex[..prefixLength];
            if (_externalDatabase is not null &&
                _externalDatabase.Entries.TryGetValue(prefix, out VendorEntry? external))
            {
                return CreateMatch(external, prefix, _externalDatabase.Info.Source);
            }

            if (BundledDatabase.Value.Entries.TryGetValue(prefix, out VendorEntry? bundled))
                return CreateMatch(bundled, prefix, BundledDatabase.Value.Info.Source);
        }

        return null;
    }

    private static MacVendorMatch? LookupDatabase(
        VendorDatabaseSnapshot database,
        string hex)
    {
        foreach (int prefixLength in LookupPrefixLengths)
        {
            string prefix = hex[..prefixLength];
            if (database.Entries.TryGetValue(prefix, out VendorEntry? entry))
                return CreateMatch(entry, prefix, database.Info.Source);
        }

        return null;
    }

    private static MacVendorMatch CreateMatch(
        VendorEntry entry,
        string prefix,
        string source)
    {
        return new MacVendorMatch(
            entry.Organization,
            entry.Registry,
            prefix,
            prefix.Length * 4,
            source,
            entry.IsPrivate);
    }

    private static VendorDatabaseSnapshot LoadBundledDatabase()
    {
        try
        {
            Stream? resource = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream(BundledResourceName);
            if (resource is null)
                throw new InvalidDataException(
                    $"O recurso incorporado '{BundledResourceName}' não foi encontrado.");

            using (resource)
            {
                VendorDatabaseSnapshot database = LoadDatabaseStream(
                    resource,
                    compressed: true,
                    source: "Incorporada");
                EnsureCompleteDatabase(database);
                return database;
            }
        }
        catch (Exception exception) when (
            exception is IOException or
            InvalidDataException or
            DecoderFallbackException)
        {
            return VendorDatabaseSnapshot.Degraded(exception.Message);
        }
    }

    private static VendorDatabaseSnapshot LoadDatabaseFile(string path, string source)
    {
        FileInfo file = new(path);
        if (file.Length is <= 0 or > MaximumDatabaseBytes)
            throw new InvalidDataException("A base IEEE tem um tamanho inválido.");

        using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete);
        bool compressed = path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase);
        return LoadDatabaseStream(stream, compressed, source);
    }

    internal static VendorDatabaseInfo ValidateCompleteDatabaseFile(
        string path,
        string source)
    {
        VendorDatabaseSnapshot database = LoadDatabaseFile(path, source);
        EnsureCompleteDatabase(database);
        return database.Info;
    }

    internal static VendorDatabaseInfo ValidateManifestDatabaseFile(
        string path,
        string source)
    {
        VendorDatabaseSnapshot database = LoadDatabaseFile(path, source);
        if (!database.HasCompleteManifest)
        {
            throw new InvalidDataException(
                "A base IEEE gerada não contém um manifesto completo.");
        }

        return database.Info;
    }

    private static void EnsureCompleteDatabase(VendorDatabaseSnapshot database)
    {
        IReadOnlyDictionary<string, int> counts = database.Info.RegistryCounts;
        bool complete =
            database.HasCompleteManifest &&
            counts.GetValueOrDefault("MA-L") >= 30_000 &&
            counts.GetValueOrDefault("MA-M") >= 4_000 &&
            counts.GetValueOrDefault("MA-S") >= 4_000 &&
            counts.GetValueOrDefault("IAB") >= 3_000;
        if (!complete)
        {
            throw new InvalidDataException(
                "A base IEEE não contém uma snapshot completa e validada pelo manifesto de MA-L, MA-M, MA-S e IAB.");
        }
    }

    private static VendorDatabaseSnapshot LoadDatabaseStream(
        Stream sourceStream,
        bool compressed,
        string source)
    {
        using MemoryStream content = new();
        if (compressed)
        {
            using GZipStream gzip = new(
                sourceStream,
                CompressionMode.Decompress,
                leaveOpen: true);
            CopyWithLimit(gzip, content);
        }
        else
        {
            CopyWithLimit(sourceStream, content);
        }

        content.Position = 0;
        using StreamReader reader = new(
            content,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: true);
        return ParseDatabase(reader, source);
    }

    private static void CopyWithLimit(Stream source, Stream destination)
    {
        byte[] buffer = new byte[64 * 1024];
        int total = 0;
        while (true)
        {
            int count = source.Read(buffer, 0, buffer.Length);
            if (count == 0)
                break;

            total = checked(total + count);
            if (total > MaximumDatabaseBytes)
                throw new InvalidDataException("A base IEEE descomprimida excede o limite seguro.");

            destination.Write(buffer, 0, count);
        }
    }

    private static VendorDatabaseSnapshot ParseDatabase(TextReader reader, string source)
    {
        Dictionary<string, string> metadata = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, VendorAccumulator> entries = new(StringComparer.Ordinal);
        Dictionary<string, int> registryCounts = new(StringComparer.Ordinal);
        int rowCount = 0;

        foreach (string line in ReadLogicalRecords(reader))
        {
            if (line.Length > MaximumLineLength)
                throw new InvalidDataException("A base IEEE contém uma linha demasiado longa.");
            if (string.IsNullOrWhiteSpace(line))
                continue;

            if (line.StartsWith('#'))
            {
                int separator = line.IndexOf('=');
                if (separator > 2)
                {
                    metadata[line[1..separator].Trim()] =
                        line[(separator + 1)..].Trim();
                }
                continue;
            }

            string[] columns = ParseColumns(line);
            if (IsHeader(columns))
                continue;
            if (!TryReadRecord(
                    columns,
                    out string registry,
                    out string prefix,
                    out string organization))
            {
                throw new InvalidDataException("A base IEEE contém um registo inválido.");
            }

            rowCount++;
            if (rowCount > MaximumDatabaseRows)
                throw new InvalidDataException("A base IEEE excede o número máximo de registos.");

            if (!entries.TryGetValue(prefix, out VendorAccumulator? accumulator))
            {
                accumulator = new VendorAccumulator();
                entries.Add(prefix, accumulator);
            }
            accumulator.Organizations.Add(organization);
            accumulator.Registries.Add(registry);
            registryCounts[registry] = registryCounts.GetValueOrDefault(registry) + 1;
        }

        if (rowCount == 0 || entries.Count == 0)
            throw new InvalidDataException("A base IEEE não contém atribuições válidas.");

        ValidateMetadata(metadata, rowCount, entries.Count, registryCounts);

        Dictionary<string, VendorEntry> normalizedEntries = new(
            entries.Count,
            StringComparer.Ordinal);
        foreach ((string prefix, VendorAccumulator accumulator) in entries)
        {
            normalizedEntries.Add(
                prefix,
                new VendorEntry(
                    string.Join(
                        " / ",
                        accumulator.Organizations.Select(organization =>
                            organization.Equals("Private", StringComparison.OrdinalIgnoreCase)
                                ? PrivateAssignmentLabel
                                : organization)),
                    string.Join("/", accumulator.Registries),
                    accumulator.Organizations.Any(organization =>
                        organization.Equals("Private", StringComparison.OrdinalIgnoreCase))));
        }

        DateOnly? snapshotDate = null;
        if (metadata.TryGetValue("snapshotDate", out string? dateText) &&
            DateOnly.TryParseExact(
                dateText,
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out DateOnly parsedDate))
        {
            snapshotDate = parsedDate;
        }

        bool hasCompleteManifest = HasCompleteManifest(metadata);
        VendorDatabaseInfo info = new(
            source,
            snapshotDate,
            rowCount,
            entries.Count,
            new ReadOnlyDictionary<string, int>(
                new Dictionary<string, int>(registryCounts, StringComparer.Ordinal)),
            IsDegraded: false,
            FailureReason: null);
        return new VendorDatabaseSnapshot(normalizedEntries, info, hasCompleteManifest);
    }

    private static void ValidateMetadata(
        IReadOnlyDictionary<string, string> metadata,
        int rowCount,
        int uniquePrefixCount,
        IReadOnlyDictionary<string, int> registryCounts)
    {
        if (metadata.TryGetValue("format", out string? format) &&
            !format.Equals(
                "LocalNetworkScanner.IEEE-MAC-Vendors/v1",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("O formato da base IEEE não é suportado.");
        }

        ValidateMetadataCount(metadata, "entries", rowCount);
        ValidateMetadataCount(metadata, "uniquePrefixes", uniquePrefixCount);
        foreach (string registry in new[] { "MA-L", "MA-M", "MA-S", "IAB" })
        {
            ValidateMetadataCount(
                metadata,
                $"count.{registry}",
                registryCounts.GetValueOrDefault(registry));
        }
    }

    private static bool HasCompleteManifest(IReadOnlyDictionary<string, string> metadata)
    {
        if (!metadata.TryGetValue("format", out string? format) ||
            !format.Equals(
                "LocalNetworkScanner.IEEE-MAC-Vendors/v1",
                StringComparison.Ordinal) ||
            !metadata.ContainsKey("entries") ||
            !metadata.ContainsKey("uniquePrefixes") ||
            !metadata.TryGetValue("snapshotDate", out string? snapshotDate) ||
            !DateOnly.TryParseExact(
                snapshotDate,
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out _))
        {
            return false;
        }

        foreach (string registry in new[] { "MA-L", "MA-M", "MA-S", "IAB" })
        {
            if (!metadata.ContainsKey($"count.{registry}") ||
                !metadata.TryGetValue($"source.{registry}", out string? source) ||
                !Uri.TryCreate(source, UriKind.Absolute, out Uri? sourceUri) ||
                sourceUri.Scheme != Uri.UriSchemeHttps ||
                !metadata.TryGetValue($"sha256.{registry}", out string? hash) ||
                hash.Length != 64 ||
                !hash.All(Uri.IsHexDigit))
            {
                return false;
            }
        }

        return true;
    }

    private static void ValidateMetadataCount(
        IReadOnlyDictionary<string, string> metadata,
        string key,
        int expected)
    {
        if (!metadata.TryGetValue(key, out string? value))
            return;

        if (!int.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out int actual) ||
            actual != expected)
        {
            throw new InvalidDataException($"A metadata '{key}' da base IEEE é inconsistente.");
        }
    }

    internal static IEnumerable<string> ReadLogicalRecords(TextReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        StringBuilder? pending = null;
        string? physicalLine;
        while ((physicalLine = reader.ReadLine()) is not null)
        {
            if (pending is null)
            {
                bool isCsv = physicalLine.Contains(',') && !IsTabSeparated(physicalLine);
                if (!isCsv || IsCompleteCsvRecord(physicalLine))
                {
                    yield return physicalLine;
                    continue;
                }

                pending = new StringBuilder(physicalLine);
            }
            else
            {
                pending.Append('\n');
                pending.Append(physicalLine);
            }

            if (pending.Length > MaximumLineLength)
                throw new InvalidDataException("A base IEEE contém um registo demasiado longo.");
            if (!IsCompleteCsvRecord(pending.ToString()))
                continue;

            yield return pending.ToString();
            pending = null;
        }

        if (pending is not null)
            throw new InvalidDataException("A base IEEE termina num registo CSV incompleto.");
    }

    private static bool IsCompleteCsvRecord(string value)
    {
        bool inQuotes = false;
        for (int index = 0; index < value.Length; index++)
        {
            if (value[index] != '"')
                continue;

            if (inQuotes && index + 1 < value.Length && value[index + 1] == '"')
            {
                index++;
                continue;
            }

            inQuotes = !inQuotes;
        }

        return !inQuotes;
    }

    internal static string[] ParseColumns(string line)
    {
        if (IsTabSeparated(line))
            return line.Split('\t', StringSplitOptions.TrimEntries);
        if (!line.Contains(','))
            return line.Split(';', StringSplitOptions.TrimEntries);

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

        if (inQuotes)
            throw new InvalidDataException("A base IEEE contém uma linha CSV incompleta.");

        columns.Add(value.ToString().Trim());
        return [.. columns];
    }

    private static bool IsTabSeparated(string line)
    {
        int tab = line.IndexOf('\t');
        int comma = line.IndexOf(',');
        return tab >= 0 && (comma < 0 || tab < comma);
    }

    internal static bool TryReadRecord(
        IReadOnlyList<string> columns,
        out string registry,
        out string assignment,
        out string organization)
    {
        registry = string.Empty;
        assignment = string.Empty;
        organization = string.Empty;

        if (columns.Count >= 3 &&
            TryNormalizeRegistry(columns[0], out registry) &&
            TryNormalizeAssignment(columns[1], out assignment) &&
            IsExpectedPrefixLength(registry, assignment.Length))
        {
            organization = NormalizeOrganization(columns[2]);
            return organization.Length > 0;
        }

        if (columns.Count >= 2 &&
            TryNormalizeAssignment(columns[0], out assignment))
        {
            registry = assignment.Length switch
            {
                6 => "MA-L",
                7 => "MA-M",
                9 => "MA-S",
                _ => string.Empty
            };
            organization = NormalizeOrganization(columns[1]);
            return registry.Length > 0 && organization.Length > 0;
        }

        return false;
    }

    internal static bool TryNormalizeAssignment(string value, out string assignment)
    {
        StringBuilder normalized = new(value.Length);
        foreach (char character in value.Trim())
        {
            if (Uri.IsHexDigit(character))
            {
                normalized.Append(char.ToUpperInvariant(character));
            }
            else if (character is not (':' or '-' or '.' or ' ' or '\t'))
            {
                assignment = string.Empty;
                return false;
            }
        }

        if (normalized.Length is 6 or 7 or 9)
        {
            assignment = normalized.ToString();
            return true;
        }

        assignment = string.Empty;
        return false;
    }

    private static bool IsHeader(IReadOnlyList<string> columns) =>
        columns.Count > 0 &&
        (columns[0].Equals("Registry", StringComparison.OrdinalIgnoreCase) ||
         columns[0].Equals("Assignment", StringComparison.OrdinalIgnoreCase) ||
         columns[0].Equals("Prefix", StringComparison.OrdinalIgnoreCase));

    private static bool TryNormalizeRegistry(string value, out string registry)
    {
        string candidate = value.Trim().ToUpperInvariant();
        if (candidate is "MA-L" or "MA-M" or "MA-S" or "IAB")
        {
            registry = candidate;
            return true;
        }

        registry = string.Empty;
        return false;
    }

    private static bool IsExpectedPrefixLength(string registry, int length) =>
        registry switch
        {
            "MA-L" => length == 6,
            "MA-M" => length == 7,
            "MA-S" or "IAB" => length == 9,
            _ => false
        };

    private static string NormalizeOrganization(string value)
    {
        string normalized = string.Join(
            " ",
            value.Split(
                (char[]?)null,
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return normalized.Length <= 2_048 ? normalized : string.Empty;
    }

    private static IEnumerable<(string Path, string Source, bool RequireComplete)>
        FindOptionalDatabases()
    {
        string baseDirectory = AppContext.BaseDirectory;
        string localApplicationData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        string applicationData = Path.Combine(
            localApplicationData,
            "LocalNetworkScanner");

        (string Path, string Source, bool RequireComplete)[] candidates =
        [
            (OuiDatabaseService.DatabasePath, "Atualizada localmente", true),
            (
                Path.Combine(baseDirectory, "data", "vendor-database.tsv.gz"),
                "Ficheiro local",
                true),
            (Path.Combine(applicationData, "oui.csv"), "Atualização OUI legada", false),
            (Path.Combine(baseDirectory, "data", "oui.csv"), "Ficheiro OUI local", false)
        ];

        HashSet<string> yielded = new(StringComparer.OrdinalIgnoreCase);
        foreach ((string path, string source, bool requireComplete) in candidates)
        {
            string fullPath = Path.GetFullPath(path);
            if (yielded.Add(fullPath))
                yield return (fullPath, source, requireComplete);
        }
    }

    private sealed class VendorAccumulator
    {
        public SortedSet<string> Organizations { get; } = new(StringComparer.Ordinal);

        public SortedSet<string> Registries { get; } = new(StringComparer.Ordinal);
    }

    private sealed record VendorEntry(
        string Organization,
        string Registry,
        bool IsPrivate);

    private sealed record VendorDatabaseSnapshot(
        IReadOnlyDictionary<string, VendorEntry> Entries,
        VendorDatabaseInfo Info,
        bool HasCompleteManifest)
    {
        public static VendorDatabaseSnapshot Degraded(string reason) => new(
            new ReadOnlyDictionary<string, VendorEntry>(
                new Dictionary<string, VendorEntry>(StringComparer.Ordinal)),
            new VendorDatabaseInfo(
                "Incorporada",
                null,
                0,
                0,
                new ReadOnlyDictionary<string, int>(
                    new Dictionary<string, int>(StringComparer.Ordinal)),
                IsDegraded: true,
                FailureReason: reason),
            HasCompleteManifest: false);
    }
}

public sealed record VendorDatabaseInfo(
    string Source,
    DateOnly? SnapshotDate,
    int EntryCount,
    int UniquePrefixCount,
    IReadOnlyDictionary<string, int> RegistryCounts,
    bool IsDegraded,
    string? FailureReason)
{
    public string DisplayText
    {
        get
        {
            string date = SnapshotDate?.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture) ??
                "data desconhecida";
            string state = IsDegraded ? "degradada" : Source.ToLowerInvariant();
            return $"Base IEEE {state} · {EntryCount:N0} registos · " +
                $"{UniquePrefixCount:N0} prefixos · {date}";
        }
    }
}

public sealed record MacVendorMatch(
    string Organization,
    string Registry,
    string Prefix,
    int PrefixLength,
    string Source,
    bool IsPrivate);

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
