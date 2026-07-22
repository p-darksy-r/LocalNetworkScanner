// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Utilities;

internal static class ProductIdentity
{
    public const string Name = "LocalNetworkScanner";

    public static string Version { get; } =
        typeof(ProductIdentity).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    public static string UserAgent { get; } = $"{Name}/{Version}";
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
