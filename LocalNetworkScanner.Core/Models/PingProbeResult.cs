// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Models;

public sealed record PingProbeResult(bool Success, long? RoundtripTimeMs, int? ReplyTtl);

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
