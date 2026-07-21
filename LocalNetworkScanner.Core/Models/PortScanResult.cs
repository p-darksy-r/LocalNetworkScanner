namespace LocalNetworkScanner.Core.Models;

public sealed class PortScanResult
{
    public required int Port { get; init; }

    public string Protocol { get; init; } = "TCP";

    public string State { get; init; } = "Aberta";

    public string ServiceName { get; set; } = "desconhecido";

    public string? Banner { get; set; }

    public bool IsEncrypted { get; set; }

    public string? TlsProtocol { get; set; }

    public string? CertificateSubject { get; set; }

    public string? CertificateIssuer { get; set; }

    public DateTimeOffset? CertificateExpiresAt { get; set; }

    public bool? CertificateTrusted { get; set; }

    public string? CertificatePolicyErrors { get; set; }

    public string Display => $"{Port}/{Protocol.ToLowerInvariant()} {ServiceName}";
}
