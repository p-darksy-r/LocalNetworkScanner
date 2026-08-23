// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public static class ScanWorkloadEstimator
{
    // Estes limiares classificam o máximo teórico. O scan completo de portas só é
    // executado nos dispositivos confirmados online, pelo que a carga real tende a
    // ser inferior. A estimativa serve para consentimento, não para prever duração.
    private const long HighAttemptThreshold = 1_000_000;
    private const long ExtremeAttemptThreshold = 10_000_000;
    private const int ExtremePortCount = 16_384;

    public static ScanWorkloadEstimate Estimate(int addressCount, ScanOptions options)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(addressCount);
        ArgumentNullException.ThrowIfNull(options);

        int discoveryPortCount = options.EnableTcpDiscovery
            ? options.DiscoveryPorts.Distinct().Count()
            : 0;
        int fullPortCount = options.Ports.Distinct().Count();
        long discoveryAttempts = (long)addressCount * discoveryPortCount;
        long fullAttempts = (long)addressCount * fullPortCount;
        // Cada porta aberta pode originar uma segunda ligação leve para banner/TLS.
        // Assume todas abertas para que o consentimento não subestime o pior caso.
        long serviceProbeAttempts = options.EnableServiceProbes ? fullAttempts : 0;
        int upnpDescriptionAttempts = options.EnableMulticastDiscovery && options.EnableUpnpDescription
            ? NetworkScannerService.MaximumUpnpEnrichmentAttempts
            : 0;
        long builtInAttempts = checked(
            discoveryAttempts + fullAttempts + serviceProbeAttempts + upnpDescriptionAttempts);

        ScanWorkloadLevel level = builtInAttempts >= ExtremeAttemptThreshold ||
                                  fullPortCount >= ExtremePortCount
            ? ScanWorkloadLevel.Extreme
            : builtInAttempts >= HighAttemptThreshold
                ? ScanWorkloadLevel.High
                : ScanWorkloadLevel.Normal;

        return new ScanWorkloadEstimate
        {
            AddressCount = addressCount,
            DiscoveryPortCount = discoveryPortCount,
            FullPortCount = fullPortCount,
            MaximumDiscoveryTcpAttempts = discoveryAttempts,
            MaximumFullTcpAttempts = fullAttempts,
            MaximumServiceProbeAttempts = serviceProbeAttempts,
            MaximumUpnpDescriptionAttempts = upnpDescriptionAttempts,
            MaximumBuiltInTcpAttempts = builtInAttempts,
            HasAdditionalNmapTraffic = options.EnableNmapDiscovery,
            Level = level
        };
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
