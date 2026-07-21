namespace LocalNetworkScanner.Core.Models;

public sealed record PingProbeResult(bool Success, long? RoundtripTimeMs, int? ReplyTtl);
