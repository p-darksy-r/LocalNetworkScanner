// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using System.Net.Http.Headers;
using System.Xml;
using System.Xml.Linq;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class UpnpDescriptionService
{
    private const int MaximumDocumentBytes = 256 * 1024;
    private const int MaximumTextLength = 512;
    private static readonly HttpClient Client = CreateClient();

    public async Task<DiscoveryObservation> EnrichAsync(
        DiscoveryObservation observation,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (observation.Method != DiscoveryMethod.Ssdp ||
            !TryCreateSafeDescriptionUri(
                observation.Location,
                observation.IpAddress,
                out Uri? descriptionUri))
        {
            return observation;
        }

        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Math.Clamp(timeoutMs, 250, 3_000));

        try
        {
            using HttpRequestMessage request = new(HttpMethod.Get, descriptionUri);
            request.Headers.UserAgent.ParseAdd(ProductIdentity.UserAgent);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/xml", 0.9));

            using HttpResponseMessage response = await Client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token);
            if (!response.IsSuccessStatusCode ||
                response.Content.Headers.ContentLength is > MaximumDocumentBytes)
            {
                return observation;
            }

            await using Stream stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            byte[] document = await ReadLimitedAsync(stream, MaximumDocumentBytes, timeout.Token);
            if (document.Length == 0)
                return observation;

            UpnpDeviceDescription? description = ParseDescription(document);
            if (description is null)
                return observation;

            return CreateEnrichedObservation(observation, description);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is HttpRequestException or OperationCanceledException or IOException or
                XmlException or InvalidOperationException)
        {
            return observation;
        }
    }

    internal static bool TryCreateSafeDescriptionUri(
        string? location,
        IPAddress expectedAddress,
        out Uri? uri)
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(location) ||
            !Uri.TryCreate(location.Trim(), UriKind.Absolute, out Uri? candidate) ||
            candidate.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(candidate.UserInfo) ||
            !string.IsNullOrEmpty(candidate.Fragment) ||
            !IPAddress.TryParse(candidate.Host, out IPAddress? locationAddress) ||
            !locationAddress.Equals(expectedAddress) ||
            !IpAddressHelper.IsPrivate(locationAddress) ||
            candidate.Port is < 1 or > 65_535)
        {
            return false;
        }

        uri = candidate;
        return true;
    }

    internal static UpnpDeviceDescription? ParseDescription(byte[] document)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (document.Length == 0 || document.Length > MaximumDocumentBytes)
            return null;

        XmlReaderSettings settings = new()
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumDocumentBytes,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true
        };

        using MemoryStream input = new(document, writable: false);
        using XmlReader reader = XmlReader.Create(input, settings);
        XDocument xml = XDocument.Load(reader, LoadOptions.None);
        XElement? device = xml.Descendants()
            .FirstOrDefault(element => element.Name.LocalName.Equals("device", StringComparison.Ordinal));
        if (device is null)
            return null;

        string? modelName = ChildValue(device, "modelName");
        string? modelNumber = ChildValue(device, "modelNumber");
        string? model = CombineModel(modelName, modelNumber);
        UpnpDeviceDescription result = new()
        {
            FriendlyName = ChildValue(device, "friendlyName"),
            Manufacturer = ChildValue(device, "manufacturer"),
            Model = model,
            Description = ChildValue(device, "modelDescription"),
            SerialNumber = ChildValue(device, "serialNumber"),
            DeviceType = ChildValue(device, "deviceType"),
            UniqueDeviceName = ChildValue(device, "UDN"),
            PresentationUrl = ChildValue(device, "presentationURL")
        };

        return string.IsNullOrWhiteSpace(result.FriendlyName) &&
               string.IsNullOrWhiteSpace(result.Manufacturer) &&
               string.IsNullOrWhiteSpace(result.Model) &&
               string.IsNullOrWhiteSpace(result.Description) &&
               string.IsNullOrWhiteSpace(result.SerialNumber) &&
               string.IsNullOrWhiteSpace(result.DeviceType)
            ? null
            : result;
    }

    internal static DiscoveryObservation CreateEnrichedObservation(
        DiscoveryObservation observation,
        UpnpDeviceDescription description)
    {
        ArgumentNullException.ThrowIfNull(observation);
        ArgumentNullException.ThrowIfNull(description);

        return new DiscoveryObservation
        {
            IpAddress = observation.IpAddress,
            Method = observation.Method,
            Hostname = observation.Hostname,
            Server = observation.Server,
            Location = observation.Location,
            Manufacturer = description.Manufacturer,
            Model = description.Model,
            FriendlyName = description.FriendlyName,
            SerialNumber = description.SerialNumber,
            Description = description.Description ?? description.DeviceType,
            DeviceType = MapDeviceType(description.DeviceType),
            ServiceType = observation.ServiceType,
            UniqueServiceName = description.UniqueDeviceName ?? observation.UniqueServiceName,
            HasDirectAddressEvidence = observation.HasDirectAddressEvidence,
            EvidenceSource = "Descrição de dispositivo UPnP",
            Confidence = ConfidenceLevel.Medium
        };
    }

    private static async Task<byte[]> ReadLimitedAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using MemoryStream output = new(Math.Min(maximumBytes, 16 * 1024));
        byte[] buffer = new byte[8 * 1024];
        while (true)
        {
            int read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
                return output.ToArray();
            if (output.Length + read > maximumBytes)
                return [];
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    private static string? ChildValue(XElement parent, string localName)
    {
        string? value = parent.Elements()
            .FirstOrDefault(element => element.Name.LocalName.Equals(localName, StringComparison.Ordinal))?
            .Value;
        if (string.IsNullOrWhiteSpace(value))
            return null;

        char[] sanitized = value
            .Select(character => char.IsControl(character) ? ' ' : character)
            .ToArray();
        string compact = string.Join(
            ' ',
            new string(sanitized).Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return compact.Length <= MaximumTextLength ? compact : compact[..MaximumTextLength];
    }

    private static string? CombineModel(string? modelName, string? modelNumber)
    {
        if (string.IsNullOrWhiteSpace(modelName))
            return modelNumber;
        if (string.IsNullOrWhiteSpace(modelNumber) ||
            modelName.Contains(modelNumber, StringComparison.OrdinalIgnoreCase))
        {
            return modelName;
        }

        string combined = $"{modelName} ({modelNumber})";
        return combined.Length <= MaximumTextLength ? combined : combined[..MaximumTextLength];
    }

    private static string? MapDeviceType(string? deviceType)
    {
        if (string.IsNullOrWhiteSpace(deviceType))
            return null;

        string normalized = deviceType.ToLowerInvariant();
        if (normalized.Contains("internetgatewaydevice", StringComparison.Ordinal))
            return "Gateway / router";
        if (normalized.Contains("printer", StringComparison.Ordinal))
            return "Impressora";
        if (normalized.Contains("mediaserver", StringComparison.Ordinal))
            return "Servidor multimédia";
        if (normalized.Contains("mediarenderer", StringComparison.Ordinal))
            return "Reprodutor multimédia";
        if (normalized.Contains("basic", StringComparison.Ordinal))
            return "Dispositivo UPnP";
        return null;
    }

    private static HttpClient CreateClient()
    {
        HttpClientHandler handler = new()
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            UseProxy = false
        };
        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan,
            MaxResponseContentBufferSize = MaximumDocumentBytes
        };
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
