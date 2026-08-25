// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using System.Net.Sockets;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public static class ScanRequestValidator
{
    public static void Validate(IReadOnlyList<IPAddress> addresses, ScanOptions options)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        ArgumentNullException.ThrowIfNull(options);

        if (addresses.Count == 0)
            throw new ScanInputException(
                DiagnosticCatalog.InvalidScanConfiguration(nameof(addresses)),
                nameof(addresses));
        if (addresses.Count > IpRangeService.AbsoluteMaximumAddresses)
            throw new ScanInputException(
                DiagnosticCatalog.RangeLimitExceeded(
                    addressCount: addresses.Count,
                    configuredLimit: IpRangeService.AbsoluteMaximumAddresses),
                nameof(addresses));

        IPAddress? invalidAddress = addresses.FirstOrDefault(address =>
                address.AddressFamily != AddressFamily.InterNetwork ||
                !IpAddressHelper.IsPrivate(address));
        if (invalidAddress is not null)
        {
            throw new ScanOperationException(
                DiagnosticCatalog.PublicAddressScope(invalidAddress.ToString()));
        }

        ValidateRange(options.MaximumHostConcurrency, 1, 512, nameof(options.MaximumHostConcurrency));
        ValidateRange(options.MaximumPortConcurrency, 1, 512, nameof(options.MaximumPortConcurrency));
        ValidateRange(options.PingTimeoutMs, 50, 30_000, nameof(options.PingTimeoutMs));
        ValidateRange(options.ConnectTimeoutMs, 50, 30_000, nameof(options.ConnectTimeoutMs));
        ValidateRange(options.DiscoveryTimeoutMs, 100, 60_000, nameof(options.DiscoveryTimeoutMs));

        if (!options.EnableIcmp &&
            !options.EnableTcpDiscovery &&
            !options.EnableArp &&
            !options.EnableMulticastDiscovery)
        {
            throw new ScanInputException(
                DiagnosticCatalog.InvalidScanConfiguration("métodos de descoberta"),
                nameof(options));
        }

        if (options.EnableSnmpTopology || options.EnableSnmpDeviceDiscovery)
        {
            if (options.EnableSnmpTopology &&
                (options.SnmpSwitchAddress is null || !IpAddressHelper.IsPrivate(options.SnmpSwitchAddress)))
            {
                throw new ScanInputException(
                    DiagnosticCatalog.InvalidScanConfiguration(nameof(options.SnmpSwitchAddress)),
                    nameof(options));
            }
            if (string.IsNullOrWhiteSpace(options.SnmpCommunity))
                throw new ScanInputException(
                    DiagnosticCatalog.InvalidScanConfiguration("SNMP"),
                    nameof(options));
            ValidateRange(options.SnmpTimeoutMs, 100, 30_000, nameof(options.SnmpTimeoutMs));
        }

        if (options.EnableNmapDiscovery)
        {
            if (options.Profile != ScanProfile.Deep)
                throw new ScanInputException(
                    DiagnosticCatalog.InvalidScanConfiguration("Nmap requer o perfil avançado"),
                    nameof(options));
            if (!string.IsNullOrWhiteSpace(options.NmapExecutablePath) &&
                !NmapDiscoveryService.IsSafeExplicitExecutablePath(options.NmapExecutablePath))
            {
                throw new ScanInputException(
                    DiagnosticCatalog.InvalidScanConfiguration(
                        "o caminho Nmap tem de ser um nmap.exe local existente"),
                    nameof(options));
            }
            ValidateRange(options.NmapTimeoutMs, 5_000, 600_000, nameof(options.NmapTimeoutMs));
        }

        ValidatePorts(options.Ports, nameof(options.Ports));
        ValidatePorts(options.DiscoveryPorts, nameof(options.DiscoveryPorts));
    }

    private static void ValidatePorts(IReadOnlyList<int> ports, string parameterName)
    {
        if (ports.Count == 0 || ports.Any(port => port is < 1 or > 65_535))
            throw new ScanInputException(
                DiagnosticCatalog.InvalidPortSpecification(parameterName),
                parameterName);
    }

    private static void ValidateRange(int value, int minimum, int maximum, string parameterName)
    {
        if (value < minimum || value > maximum)
            throw new ScanRangeException(
                DiagnosticCatalog.InvalidScanConfiguration(parameterName),
                parameterName,
                value);
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
