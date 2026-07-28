// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class OuiDatabaseService
{
    public const string OfficialDatabaseUrl =
        "https://standards-oui.ieee.org/oui/oui.csv";
    public const string OfficialMamDatabaseUrl =
        "https://standards-oui.ieee.org/oui28/mam.csv";
    public const string OfficialMasDatabaseUrl =
        "https://standards-oui.ieee.org/oui36/oui36.csv";
    public const string OfficialIabDatabaseUrl =
        "https://standards-oui.ieee.org/iab/iab.csv";

    private static readonly IReadOnlyList<OuiDatabaseSource> DefaultSources =
        new ReadOnlyCollection<OuiDatabaseSource>(
        [
            new(
                "MA-L",
                "oui.csv",
                OfficialDatabaseUrl,
                6,
                30_000,
                100_000,
                12 * 1024 * 1024),
            new(
                "MA-M",
                "mam.csv",
                OfficialMamDatabaseUrl,
                7,
                4_000,
                30_000,
                6 * 1024 * 1024),
            new(
                "MA-S",
                "oui36.csv",
                OfficialMasDatabaseUrl,
                9,
                4_000,
                30_000,
                6 * 1024 * 1024),
            new(
                "IAB",
                "iab.csv",
                OfficialIabDatabaseUrl,
                9,
                3_000,
                20_000,
                6 * 1024 * 1024)
        ]);
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> UpdateGates =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly HttpClient _httpClient;
    private readonly string _databasePath;
    private readonly string? _legacyDatabasePath;
    private readonly IReadOnlyList<OuiDatabaseSource> _sources;

    public OuiDatabaseService(
        HttpClient? httpClient = null,
        string? databasePath = null,
        IReadOnlyList<OuiDatabaseSource>? sources = null,
        string? legacyDatabasePath = null)
    {
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        if (_httpClient.DefaultRequestHeaders.UserAgent.Count == 0)
        {
            _httpClient.DefaultRequestHeaders.UserAgent.Add(
                new ProductInfoHeaderValue(ProductIdentity.Name, ProductIdentity.Version));
        }

        _databasePath = Path.GetFullPath(databasePath ?? DatabasePath);
        _legacyDatabasePath = legacyDatabasePath is not null
            ? Path.GetFullPath(legacyDatabasePath)
            : databasePath is null
                ? Path.GetFullPath(LegacyDatabasePath)
                : null;
        _sources = sources ?? DefaultSources;
        if (_sources.Count == 0)
            throw new ArgumentException("É necessária pelo menos uma fonte IEEE.", nameof(sources));

        HashSet<string> registries = new(StringComparer.Ordinal);
        HashSet<string> fileNames = new(StringComparer.OrdinalIgnoreCase);
        foreach (OuiDatabaseSource source in _sources)
        {
            ValidateSource(source);
            if (!registries.Add(source.Registry))
                throw new ArgumentException($"O registo '{source.Registry}' está duplicado.", nameof(sources));
            if (!fileNames.Add(source.FileName))
                throw new ArgumentException($"O ficheiro '{source.FileName}' está duplicado.", nameof(sources));
        }
        if (!registries.SetEquals(["MA-L", "MA-M", "MA-S", "IAB"]))
        {
            throw new ArgumentException(
                "A atualização tem de incluir exatamente MA-L, MA-M, MA-S e IAB.",
                nameof(sources));
        }
    }

    public static IReadOnlyList<OuiDatabaseSource> OfficialSources => DefaultSources;

    public static string DatabasePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "LocalNetworkScanner",
        "vendor-database.tsv.gz");

    public static string LegacyDatabasePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "LocalNetworkScanner",
        "oui.csv");

    public string CurrentDatabasePath => _databasePath;

    public async Task<string> UpdateAsync(
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        SemaphoreSlim gate = UpdateGates.GetOrAdd(
            _databasePath,
            static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            return await UpdateCoreAsync(progress, cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<string> UpdateCoreAsync(
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        string? targetDirectory = Path.GetDirectoryName(_databasePath);
        if (string.IsNullOrWhiteSpace(targetDirectory))
            throw new InvalidOperationException("O destino da base IEEE não tem uma pasta válida.");

        Directory.CreateDirectory(targetDirectory);
        string stagingDirectory = Path.Combine(
            targetDirectory,
            ".vendor-update-" + Guid.NewGuid().ToString("N"));
        EnsurePathIsInsideDirectory(stagingDirectory, targetDirectory);
        Directory.CreateDirectory(stagingDirectory);

        try
        {
            List<string> normalizedEntries = [];
            HashSet<string> uniqueEntries = new(StringComparer.Ordinal);
            HashSet<string> uniquePrefixes = new(StringComparer.Ordinal);
            Dictionary<string, int> counts = new(StringComparer.Ordinal);
            Dictionary<string, string> hashes = new(StringComparer.Ordinal);

            for (int index = 0; index < _sources.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                OuiDatabaseSource source = _sources[index];
                string downloadedPath = Path.Combine(stagingDirectory, source.FileName);
                await DownloadAsync(
                    source,
                    downloadedPath,
                    index,
                    progress,
                    cancellationToken);

                ValidatedSource validated = await ValidateDownloadedSourceAsync(
                    source,
                    downloadedPath,
                    cancellationToken);
                foreach (string entry in validated.Entries)
                {
                    if (!uniqueEntries.Add(entry))
                        throw new InvalidDataException(
                            $"A atualização IEEE contém o registo duplicado '{entry}'.");

                    normalizedEntries.Add(entry);
                    string[] columns = entry.Split('\t', 3);
                    uniquePrefixes.Add(columns[1]);
                }

                counts[source.Registry] = validated.Entries.Count;
                hashes[source.Registry] = validated.Sha256;
                progress?.Report((double)(index + 1) / _sources.Count * 0.9);
            }

            string stagedDatabase = Path.Combine(
                stagingDirectory,
                "vendor-database.tsv.gz");
            await WriteDatabaseAsync(
                stagedDatabase,
                normalizedEntries,
                uniquePrefixes.Count,
                counts,
                hashes,
                cancellationToken);
            VendorDatabaseInfo validatedDatabase =
                MacVendorService.ValidateManifestDatabaseFile(
                    stagedDatabase,
                    "Atualizada localmente");
            if (validatedDatabase.EntryCount != normalizedEntries.Count ||
                validatedDatabase.UniquePrefixCount != uniquePrefixes.Count ||
                _sources.Any(source =>
                    validatedDatabase.RegistryCounts.GetValueOrDefault(source.Registry) !=
                    counts[source.Registry]))
            {
                throw new InvalidDataException(
                    "A validação final da base IEEE não confirmou as contagens geradas.");
            }
            progress?.Report(0.98);

            cancellationToken.ThrowIfCancellationRequested();
            ReplaceDatabaseAtomically(stagedDatabase, _databasePath);
            progress?.Report(1);
            return _databasePath;
        }
        finally
        {
            TryDeleteDirectory(stagingDirectory);
        }
    }

    public bool ResetLocalDatabase()
    {
        SemaphoreSlim gate = UpdateGates.GetOrAdd(
            _databasePath,
            static _ => new SemaphoreSlim(1, 1));
        if (!gate.Wait(0))
            throw new InvalidOperationException("Está em curso uma atualização da base IEEE.");

        try
        {
            bool removed = false;
            if (_legacyDatabasePath is not null &&
                File.Exists(_legacyDatabasePath))
            {
                File.Delete(_legacyDatabasePath);
                removed = true;
            }

            if (File.Exists(_databasePath))
            {
                File.Delete(_databasePath);
                removed = true;
            }

            return removed;
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task DownloadAsync(
        OuiDatabaseSource source,
        string destinationPath,
        int sourceIndex,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, source.Url);
        using HttpResponseMessage response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        response.EnsureSuccessStatusCode();

        long? declaredLength = response.Content.Headers.ContentLength;
        if (declaredLength is <= 0 || declaredLength > source.MaximumBytes)
        {
            throw new InvalidDataException(
                $"{source.Registry} declarou um tamanho inesperado.");
        }

        await using Stream input = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using FileStream output = new(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        byte[] buffer = new byte[64 * 1024];
        long copied = 0;
        while (true)
        {
            int count = await input.ReadAsync(buffer, cancellationToken);
            if (count == 0)
                break;

            copied += count;
            if (copied > source.MaximumBytes)
                throw new InvalidDataException($"{source.Registry} excedeu o limite de download.");

            await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
            if (declaredLength is > 0)
            {
                double sourceProgress = Math.Clamp(
                    (double)copied / declaredLength.Value,
                    0,
                    1);
                progress?.Report(
                    (sourceIndex + sourceProgress) / _sources.Count * 0.9);
            }
        }

        await output.FlushAsync(cancellationToken);
        if (copied == 0 ||
            (declaredLength.HasValue && declaredLength.Value != copied))
            throw new InvalidDataException($"{source.Registry} foi transferido de forma incompleta.");
    }

    private static async Task<ValidatedSource> ValidateDownloadedSourceAsync(
        OuiDatabaseSource source,
        string path,
        CancellationToken cancellationToken)
    {
        byte[] bytes = await File.ReadAllBytesAsync(path, cancellationToken);
        string text = new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true).GetString(bytes);
        if (text.Length > 0 && text[0] == '\uFEFF')
            text = text[1..];

        using StringReader reader = new(text);
        using IEnumerator<string> records =
            MacVendorService.ReadLogicalRecords(reader).GetEnumerator();
        string? header = records.MoveNext() ? records.Current : null;
        string[] expectedHeader =
            ["Registry", "Assignment", "Organization Name", "Organization Address"];
        if (header is null ||
            !MacVendorService.ParseColumns(header).SequenceEqual(
                expectedHeader,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                $"{source.Registry} não contém o schema CSV oficial esperado.");
        }

        List<string> entries = [];
        HashSet<string> uniqueRows = new(StringComparer.Ordinal);
        while (records.MoveNext())
        {
            cancellationToken.ThrowIfCancellationRequested();
            string line = records.Current;
            if (string.IsNullOrWhiteSpace(line))
                continue;
            if (line.Length > 8_192)
                throw new InvalidDataException($"{source.Registry} contém uma linha demasiado longa.");

            string[] columns = MacVendorService.ParseColumns(line);
            if (columns.Length < 4 ||
                !MacVendorService.TryReadRecord(
                    columns,
                    out string registry,
                    out string assignment,
                    out string organization) ||
                !registry.Equals(source.Registry, StringComparison.Ordinal) ||
                assignment.Length != source.PrefixLength)
            {
                throw new InvalidDataException(
                    $"{source.Registry} contém uma atribuição inválida.");
            }

            string normalized = $"{registry}\t{assignment}\t{organization}";
            if (!uniqueRows.Add(normalized))
                throw new InvalidDataException(
                    $"{source.Registry} contém uma linha duplicada.");

            entries.Add(normalized);
            if (entries.Count > source.MaximumRows)
                throw new InvalidDataException(
                    $"{source.Registry} excede o máximo de registos permitido.");
        }

        if (entries.Count < source.MinimumRows)
        {
            throw new InvalidDataException(
                $"{source.Registry} contém apenas {entries.Count} registos válidos.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        byte[] digest = SHA256.HashData(bytes);
        return new ValidatedSource(
            entries,
            Convert.ToHexStringLower(digest));
    }

    private async Task WriteDatabaseAsync(
        string path,
        List<string> entries,
        int uniquePrefixCount,
        IReadOnlyDictionary<string, int> counts,
        IReadOnlyDictionary<string, string> hashes,
        CancellationToken cancellationToken)
    {
        entries.Sort(StringComparer.Ordinal);
        await using FileStream file = new(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using GZipStream gzip = new(file, CompressionLevel.Optimal, leaveOpen: false);
        await using StreamWriter writer = new(
            gzip,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            64 * 1024,
            leaveOpen: false);

        await writer.WriteLineAsync(
            "# IEEE Registration Authority public assignment data.");
        await writer.WriteLineAsync(
            "# format=LocalNetworkScanner.IEEE-MAC-Vendors/v1");
        await writer.WriteLineAsync(
            $"# snapshotDate={DateOnly.FromDateTime(DateTime.UtcNow):yyyy-MM-dd}");
        await writer.WriteLineAsync(
            $"# entries={entries.Count.ToString(CultureInfo.InvariantCulture)}");
        await writer.WriteLineAsync(
            $"# uniquePrefixes={uniquePrefixCount.ToString(CultureInfo.InvariantCulture)}");
        await writer.WriteLineAsync("# sourceCopyright=IEEE. All rights reserved.");
        await writer.WriteLineAsync(
            "# notice=Bundled for offline lookup; no IEEE endorsement implied.");

        foreach (OuiDatabaseSource source in _sources)
        {
            await writer.WriteLineAsync($"# source.{source.Registry}={source.Url}");
            await writer.WriteLineAsync(
                $"# count.{source.Registry}=" +
                counts[source.Registry].ToString(CultureInfo.InvariantCulture));
            await writer.WriteLineAsync(
                $"# sha256.{source.Registry}={hashes[source.Registry]}");
        }

        foreach (string entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await writer.WriteLineAsync(entry);
        }
        await writer.WriteLineAsync(
            "# End of IEEE Registration Authority public assignment data.");
        await writer.FlushAsync(cancellationToken);
    }

    private static void ReplaceDatabaseAtomically(string stagedPath, string destinationPath)
    {
        if (!File.Exists(destinationPath))
        {
            File.Move(stagedPath, destinationPath);
            return;
        }

        string backupPath = destinationPath + ".backup-" + Guid.NewGuid().ToString("N");
        try
        {
            File.Replace(stagedPath, destinationPath, backupPath, ignoreMetadataErrors: true);
        }
        finally
        {
            TryDeleteFile(backupPath);
        }
    }

    private static void ValidateSource(OuiDatabaseSource source)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source.Registry);
        ArgumentException.ThrowIfNullOrWhiteSpace(source.FileName);
        ArgumentException.ThrowIfNullOrWhiteSpace(source.Url);
        if (!source.FileName.Equals(Path.GetFileName(source.FileName), StringComparison.Ordinal))
            throw new ArgumentException("O nome do ficheiro IEEE não pode conter uma pasta.");
        if (!Uri.TryCreate(source.Url, UriKind.Absolute, out Uri? uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrWhiteSpace(uri.UserInfo))
        {
            throw new ArgumentException("A fonte IEEE deve usar um URL HTTPS absoluto.");
        }
        if (source.PrefixLength is not (6 or 7 or 9) ||
            source.MinimumRows <= 0 ||
            source.MaximumRows < source.MinimumRows ||
            source.MaximumBytes <= 0)
        {
            throw new ArgumentException("Os limites da fonte IEEE são inválidos.");
        }

        int expectedPrefixLength = source.Registry switch
        {
            "MA-L" => 6,
            "MA-M" => 7,
            "MA-S" or "IAB" => 9,
            _ => 0
        };
        if (source.PrefixLength != expectedPrefixLength)
            throw new ArgumentException("O registo IEEE e o comprimento do prefixo não coincidem.");
    }

    private static void EnsurePathIsInsideDirectory(string path, string parentDirectory)
    {
        string fullPath = Path.GetFullPath(path);
        string parent = Path.GetFullPath(parentDirectory).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!fullPath.StartsWith(parent, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("A pasta temporária saiu do destino esperado.");
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            // Uma limpeza posterior do sistema pode remover este staging sem afetar a base ativa.
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            // O backup é válido e pode ser removido posteriormente.
        }
    }

    private sealed record ValidatedSource(
        IReadOnlyList<string> Entries,
        string Sha256);
}

public sealed record OuiDatabaseSource(
    string Registry,
    string FileName,
    string Url,
    int PrefixLength,
    int MinimumRows,
    int MaximumRows,
    long MaximumBytes);

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
