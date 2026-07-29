// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class ServiceProbeService
{
    private const int MaximumBannerBytes = 2_048;

    [SuppressMessage(
        "Security",
        "CA5359:Do not disable certificate validation",
        Justification = "A scanner must inspect self-signed LAN endpoints; policy errors are captured and reported instead of treating the connection as trusted.")]
    public async Task EnrichAsync(
        IPAddress address,
        PortScanResult result,
        int timeoutMs,
        CancellationToken cancellationToken)
        => await EnrichAsync(address, result, timeoutMs, null, cancellationToken);

    [SuppressMessage(
        "Security",
        "CA5359:Do not disable certificate validation",
        Justification = "A scanner must inspect self-signed LAN endpoints; policy errors are captured and reported instead of treating the connection as trusted.")]
    public async Task EnrichAsync(
        IPAddress address,
        PortScanResult result,
        int timeoutMs,
        IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        bool tlsHandshakeAttempted = false;
        bool tlsHandshakeSucceeded = false;
        bool expectsTls = ServiceCatalog.IsTlsPort(result.Port);
        if (expectsTls)
            ClearTlsEvidence(result);

        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutMs);

        try
        {
            using TcpClient client = new(address.AddressFamily);
            if (localAddress is not null)
                client.Client.Bind(new IPEndPoint(localAddress, 0));
            await client.ConnectAsync(address, result.Port, timeout.Token);
            await using NetworkStream networkStream = client.GetStream();

            if (expectsTls)
            {
                tlsHandshakeAttempted = true;
                SslPolicyErrors certificateErrors = SslPolicyErrors.None;
                await using SslStream sslStream = new(
                    networkStream,
                    leaveInnerStreamOpen: false,
                    (_, _, _, errors) =>
                    {
                        certificateErrors = errors;
                        return true;
                    });

                SslClientAuthenticationOptions options = new()
                {
                    TargetHost = address.ToString(),
                    EnabledSslProtocols = SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                };

                await sslStream.AuthenticateAsClientAsync(options, timeout.Token);
                tlsHandshakeSucceeded = true;
                result.TlsStatus = TlsProbeStatus.HandshakeSucceeded;
                result.TlsProtocol = sslStream.SslProtocol.ToString();
                result.CertificateTrusted = certificateErrors == SslPolicyErrors.None;
                result.CertificatePolicyErrors = certificateErrors == SslPolicyErrors.None
                    ? null
                    : certificateErrors.ToString();

                if (sslStream.RemoteCertificate is not null)
                {
                    using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(
                        sslStream.RemoteCertificate.GetRawCertData());
                    result.CertificateSubject = certificate.Subject;
                    result.CertificateIssuer = certificate.Issuer;
                    result.CertificateExpiresAt = new DateTimeOffset(certificate.NotAfter);
                }

                if (ServiceCatalog.IsHttpPort(result.Port))
                    result.Banner = await ProbeHttpAsync(sslStream, address, timeout.Token);

                return;
            }

            if (ServiceCatalog.IsHttpPort(result.Port))
            {
                result.Banner = await ProbeHttpAsync(networkStream, address, timeout.Token);
                return;
            }

            if (result.Port is 25 or 21 or 22 or 110 or 143 or 587)
                result.Banner = await ReadBannerAsync(networkStream, timeout.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            if (tlsHandshakeAttempted && !tlsHandshakeSucceeded)
            {
                ClearTlsEvidence(result);
                result.TlsStatus = TlsProbeStatus.HandshakeFailed;
                result.TlsFailureReason = GetTlsFailureReason(exception);
            }

            // A porta continua confirmada como aberta; banners e TLS são enriquecimento opcional.
        }
    }

    private static void ClearTlsEvidence(PortScanResult result)
    {
        result.TlsStatus = TlsProbeStatus.NotProbed;
        result.TlsProtocol = null;
        result.TlsFailureReason = null;
        result.CertificateSubject = null;
        result.CertificateIssuer = null;
        result.CertificateExpiresAt = null;
        result.CertificateTrusted = null;
        result.CertificatePolicyErrors = null;
    }

    private static string GetTlsFailureReason(Exception exception) => exception switch
    {
        OperationCanceledException => "tempo limite",
        AuthenticationException => "handshake rejeitado",
        IOException => "falha de transporte",
        SocketException => "falha de ligação",
        _ => "falha inesperada"
    };

    private static async Task<string?> ProbeHttpAsync(
        Stream stream,
        IPAddress address,
        CancellationToken cancellationToken)
    {
        byte[] request = Encoding.ASCII.GetBytes(
            $"HEAD / HTTP/1.0\r\nHost: {address}\r\nUser-Agent: {ProductIdentity.UserAgent}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request, cancellationToken);
        await stream.FlushAsync(cancellationToken);
        return await ReadBannerAsync(stream, cancellationToken);
    }

    private static async Task<string?> ReadBannerAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[MaximumBannerBytes];
        int count = await stream.ReadAsync(buffer, cancellationToken);
        if (count <= 0)
            return null;

        string value = Encoding.UTF8.GetString(buffer, 0, count)
            .Replace('\0', ' ')
            .Replace("\r", string.Empty)
            .Trim();

        string compact = string.Join(" | ", value.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .Take(5));
        return compact.Length > 500 ? compact[..500] : compact;
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
