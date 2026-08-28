// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;

namespace LocalNetworkScanner.Wpf.Services;

public sealed record LocalizedDiagnosticText(string Message, string RecommendedAction);

/// <summary>
/// Localizes the presentation of stable LNS diagnostics while keeping the Core
/// model and serialized exports canonical and language-neutral in structure.
/// </summary>
public static class DiagnosticLocalizationService
{
    private static readonly IReadOnlyDictionary<string, LocalizedDiagnosticText> English =
        new Dictionary<string, LocalizedDiagnosticText>(StringComparer.Ordinal)
        {
            [DiagnosticCatalog.InvalidCommandCode] = new(
                "The specified command or option is not recognized.",
                "Check --help and correct the command or option."),
            [DiagnosticCatalog.MissingOptionValueCode] = new(
                "A required option value is missing.",
                "Provide a value after the option and run the command again."),
            [DiagnosticCatalog.InvalidProfileCode] = new(
                "The specified scan profile is not valid.",
                "Use quick, standard, or advanced (deep remains accepted)."),
            [DiagnosticCatalog.InvalidInterfaceCode] = new(
                "The selected network interface does not exist or is no longer available.",
                "List the interfaces and select an active IPv4 interface."),
            [DiagnosticCatalog.InvalidCidrCode] = new(
                "The IPv4 address or CIDR prefix is not valid.",
                "Use network/prefix format, for example 192.168.1.0/24."),
            [DiagnosticCatalog.PublicAddressScopeCode] = new(
                "The scan contains public addresses and was blocked for safety.",
                "Select only a private, local, or link-local IPv4 network that you are authorized to scan."),
            [DiagnosticCatalog.RangeLimitExceededCode] = new(
                "The network exceeds the configured address limit for one scan.",
                "Reduce the CIDR or consciously increase --max-hosts within the supported limit."),
            [DiagnosticCatalog.InvalidScanConfigurationCode] = new(
                "The scan configuration contains an invalid or incompatible value.",
                "Review limits, timeouts, ports, and topology options before trying again."),
            [DiagnosticCatalog.OperationCancelledCode] = new(
                "The operation was canceled before it finished.",
                "Start it again when you want to complete the scan."),
            [DiagnosticCatalog.InvalidPortSpecificationCode] = new(
                "The port list or range is not valid.",
                "Use ports from 1 to 65535, for example 22,80,443 or 1-1024."),
            [DiagnosticCatalog.NoActiveInterfaceCode] = new(
                "No active IPv4 interface was found.",
                "Connect Wi-Fi or Ethernet, confirm that it received an IPv4 address, and try again."),
            [DiagnosticCatalog.NoDevicesFoundCode] = new(
                "The scan finished without finding online devices.",
                "Confirm the interface and CIDR; firewalls or Wi-Fi isolation may block responses."),
            [DiagnosticCatalog.SnmpUnavailableCode] = new(
                "The SNMP switch did not respond or rejected the request; inferred topology was preserved.",
                "Confirm the address, SNMP version, ACL, and community on the switch without sharing the credential."),
            [DiagnosticCatalog.VlanUnavailableCode] = new(
                "The operating system did not expose the interface VLAN.",
                "Check the switch or network controller to confirm the VLAN; the application does not invent an ID."),
            [DiagnosticCatalog.WifiTelemetryUnavailableCode] = new(
                "The operating system did not return Wi-Fi signal strength.",
                "Update the Wi-Fi driver or check the access point/controller for per-device RSSI."),
            [DiagnosticCatalog.Layer2InferenceCode] = new(
                "The layer-2 relationship is inferred: ARP and FDB do not prove a direct physical link to the same switch.",
                "Confirm physical links with LLDP, the switch configuration, and its port table."),
            [DiagnosticCatalog.NetworkOperationFailedCode] = new(
                "A network operation required by the scan failed.",
                "Confirm connectivity, the interface, firewall rules, and try again."),
            [DiagnosticCatalog.SnmpDeviceIdentityUnavailableCode] = new(
                "No device responded to the optional SNMP v2c identity query.",
                "Confirm authorization, community, and ACL; SNMP v2c sends the community unencrypted and must not be enabled on an untrusted network."),
            [DiagnosticCatalog.NmapUnavailableCode] = new(
                "Optional Nmap integration was requested, but no usable Nmap executable was found.",
                "Install Nmap separately from its official source or provide its path; the application does not redistribute it without an OEM license."),
            [DiagnosticCatalog.NmapScanFailedCode] = new(
                "Optional Nmap enrichment did not finish with valid data.",
                "Confirm the executable, permissions, firewall, and limits; retry only on an authorized network and a smaller range."),
            [DiagnosticCatalog.ArpBaselineUnavailableCode] = new(
                "Windows did not provide the ARP table baseline; active ARP confirmation was disabled for this scan.",
                "Results confirmed by ICMP, TCP, or multicast remain valid. Refresh interfaces or repeat the scan; do not disable security controls."),
            [DiagnosticCatalog.InvalidMacAddressCode] = new(
                "The device returned an invalid MAC address or one that cannot be used as a unicast identity.",
                "Confirm the ARP/ND entry and device configuration; do not use this value as an identity."),
            [DiagnosticCatalog.UnknownManufacturerCode] = new(
                "The MAC could not be associated with a known IEEE prefix assignee.",
                "The offline snapshot was already checked. For a recent global MAC, optionally check an IEEE update; for Private, local, or inconclusive entries, validate the equipment in the organization's inventory."),
            [DiagnosticCatalog.UnrecognizedDeviceCode] = new(
                "There is not enough evidence to recognize this device type.",
                "Run the advanced profile and confirm hostname, ports, services, and the authorized inventory."),
            [DiagnosticCatalog.RandomizedMacAddressCode] = new(
                "The MAC address is locally administered and may be private or randomized.",
                "Correlate the device by IP, hostname, and history; the MAC may change."),
            [DiagnosticCatalog.IdentityConflictCode] = new(
                "Conflicting manufacturer or model values were observed for this device.",
                "Compare sources and confidence; the IEEE assignee may identify only the interface or an OEM. Confirm the label or management console before using the identification."),
            [DiagnosticCatalog.UnexpectedApplicationErrorCode] = new(
                "An unexpected internal application failure occurred.",
                "Reopen the application and repeat the operation. If it persists, report the code and version. After an unexpected shutdown, review %LOCALAPPDATA%\\LocalNetworkScanner\\logs\\app.log before sharing it."),
            [DiagnosticCatalog.FileOperationFailedCode] = new(
                "A required file could not be read or saved.",
                "Confirm the path, available space, and whether the file is open in another application."),
            [DiagnosticCatalog.AccessDeniedCode] = new(
                "Windows denied access to the requested resource.",
                "Choose an allowed location or run only the operation that requires privileges with appropriate authorization."),
            [DiagnosticCatalog.PacketCaptureUnavailableCode] = new(
                "This version identifies protocols through discovery, ports, and banners; it does not include full packet capture.",
                "Treat protocols as evidence from the active scan; use a dedicated tool on an authorized network to analyze traffic."),
            [DiagnosticCatalog.ApplicationControlBlockedCode] = new(
                "A Windows Application Control policy blocked the file from running.",
                "Use a release with a trusted Authenticode signature or ask an administrator to authorize the publisher, hash, or catalog; do not disable protection to bypass the block."),
            [DiagnosticCatalog.ApplicationControlInconclusiveCode] = new(
                "Windows Application Control diagnostics did not find enough evidence of an enforcement block.",
                "Repeat with the full file path and confirm a correlated event 3077 before attributing error 4551.")
        };

    public static LocalizedDiagnosticText GetText(ScanDiagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        if (LocalizationService.CurrentLanguage != AppLanguage.EnUs)
            return new LocalizedDiagnosticText(diagnostic.Message, diagnostic.RecommendedAction);

        if (diagnostic.Code.Equals(DiagnosticCatalog.InfrastructureQueryFailedCode, StringComparison.Ordinal))
        {
            string provider = string.IsNullOrWhiteSpace(diagnostic.Target)
                ? "provider"
                : diagnostic.Target;
            return new LocalizedDiagnosticText(
                $"The optional infrastructure integration ({provider}) did not return valid data.",
                "Confirm the endpoint, authorization, TLS, and read permissions; the base scan remains valid without this telemetry.");
        }

        if (diagnostic.Code.Equals(DiagnosticCatalog.FileOperationFailedCode, StringComparison.Ordinal) &&
            diagnostic.Severity == DiagnosticSeverity.Warning)
        {
            return new LocalizedDiagnosticText(
                "An optional local-data operation could not be completed; the main result was preserved.",
                "Confirm available space, permissions, and antimalware protection before trying again.");
        }

        return English.TryGetValue(diagnostic.Code, out LocalizedDiagnosticText? localized)
            ? localized
            : new LocalizedDiagnosticText(
                LocalizationService.Translate(diagnostic.Message),
                LocalizationService.Translate(diagnostic.RecommendedAction));
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
