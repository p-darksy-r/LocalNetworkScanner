// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace LocalNetworkScanner.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum TlsProbeStatus
{
    NotProbed,
    HandshakeSucceeded,
    HandshakeFailed
}

public sealed class PortScanResult
{
    public required int Port { get; init; }

    public string Protocol { get; init; } = "TCP";

    public string State { get; init; } = "Aberta";

    public string ServiceName { get; set; } = "desconhecido";

    public string? Banner { get; set; }

    public TlsProbeStatus TlsStatus { get; set; } = TlsProbeStatus.NotProbed;

    public bool? IsEncrypted => TlsStatus switch
    {
        TlsProbeStatus.HandshakeSucceeded => true,
        _ => null
    };

    public string? TlsProtocol { get; set; }

    public string? TlsFailureReason { get; set; }

    public string? CertificateSubject { get; set; }

    public string? CertificateIssuer { get; set; }

    public DateTimeOffset? CertificateExpiresAt { get; set; }

    public bool? CertificateTrusted { get; set; }

    public string? CertificatePolicyErrors { get; set; }

    public string TlsStatusDisplay => TlsStatus switch
    {
        TlsProbeStatus.HandshakeSucceeded when !string.IsNullOrWhiteSpace(TlsProtocol) =>
            $"{TlsProtocol} confirmado",
        TlsProbeStatus.HandshakeSucceeded => "TLS confirmado",
        TlsProbeStatus.HandshakeFailed when !string.IsNullOrWhiteSpace(TlsFailureReason) =>
            $"Indeterminado ({TlsFailureReason})",
        TlsProbeStatus.HandshakeFailed => "Indeterminado (falha)",
        _ => "Não verificado"
    };

    public string Display => $"{Port}/{Protocol.ToLowerInvariant()} {ServiceName}";
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
