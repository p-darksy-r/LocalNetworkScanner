// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net.Http.Headers;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class OuiDatabaseService
{
    public const string OfficialDatabaseUrl = "https://standards-oui.ieee.org/oui/oui.csv";

    private readonly HttpClient _httpClient;

    public OuiDatabaseService(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        if (_httpClient.DefaultRequestHeaders.UserAgent.Count == 0)
            _httpClient.DefaultRequestHeaders.UserAgent.Add(
                new ProductInfoHeaderValue(ProductIdentity.Name, ProductIdentity.Version));
    }

    public static string DatabasePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "LocalNetworkScanner",
        "oui.csv");

    public async Task<string> UpdateAsync(
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string path = DatabasePath;
        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        string temporaryPath = path + ".download";
        try
        {
            using HttpResponseMessage response = await _httpClient.GetAsync(
                OfficialDatabaseUrl,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);
            response.EnsureSuccessStatusCode();

            long? totalLength = response.Content.Headers.ContentLength;
            await using Stream source = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using FileStream destination = File.Create(temporaryPath);
            byte[] buffer = new byte[64 * 1024];
            long copied = 0;
            while (true)
            {
                int count = await source.ReadAsync(buffer, cancellationToken);
                if (count == 0)
                    break;
                await destination.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
                copied += count;
                if (totalLength is > 0)
                    progress?.Report(Math.Clamp((double)copied / totalLength.Value, 0, 1));
            }

            await destination.FlushAsync(cancellationToken);
            if (destination.Length < 500_000)
                throw new InvalidDataException("A base OUI recebida é inesperadamente pequena.");

            File.Move(temporaryPath, path, overwrite: true);
            progress?.Report(1);
            return path;
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
