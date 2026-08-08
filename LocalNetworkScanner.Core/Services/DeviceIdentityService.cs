// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class DeviceIdentityService
{
    private const int MaximumEvidenceEntries = 32;
    private const int MaximumIdentityLength = 256;
    private const int MaximumDescriptionLength = 1_024;

    public void AddObservation(NetworkDevice device, DiscoveryObservation observation)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(observation);

        AddEvidence(device, new DeviceIdentityEvidence
        {
            Method = observation.Method,
            Source = Normalize(observation.EvidenceSource, MaximumIdentityLength) ?? "Descoberta de rede",
            Confidence = observation.Confidence,
            Manufacturer = Normalize(observation.Manufacturer, MaximumIdentityLength),
            Model = Normalize(observation.Model, MaximumIdentityLength),
            FriendlyName = Normalize(observation.FriendlyName, MaximumIdentityLength),
            SerialNumber = Normalize(observation.SerialNumber, MaximumIdentityLength),
            Firmware = null,
            HardwareRevision = null,
            Description = Normalize(observation.Description, MaximumDescriptionLength),
            DeviceType = Normalize(observation.DeviceType, MaximumIdentityLength),
            OperatingSystem = Normalize(observation.OperatingSystem, MaximumIdentityLength),
            Endpoint = Normalize(observation.Location, MaximumIdentityLength)
        });
    }

    public void AddEvidence(NetworkDevice device, DeviceIdentityEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(evidence);

        if (!HasIdentityValue(evidence))
            return;

        DeviceIdentityEvidence normalized = new()
        {
            Method = evidence.Method,
            Source = Normalize(evidence.Source, MaximumIdentityLength) ?? "Descoberta de rede",
            Confidence = evidence.Confidence,
            Manufacturer = Normalize(evidence.Manufacturer, MaximumIdentityLength),
            Model = Normalize(evidence.Model, MaximumIdentityLength),
            FriendlyName = Normalize(evidence.FriendlyName, MaximumIdentityLength),
            SerialNumber = Normalize(evidence.SerialNumber, MaximumIdentityLength),
            Firmware = Normalize(evidence.Firmware, MaximumIdentityLength),
            HardwareRevision = Normalize(evidence.HardwareRevision, MaximumIdentityLength),
            Description = Normalize(evidence.Description, MaximumDescriptionLength),
            DeviceType = Normalize(evidence.DeviceType, MaximumIdentityLength),
            OperatingSystem = Normalize(evidence.OperatingSystem, MaximumIdentityLength),
            Endpoint = Normalize(evidence.Endpoint, MaximumIdentityLength)
        };

        int duplicateIndex = device.IdentityEvidence.FindIndex(item =>
            IsEquivalentEvidence(item, normalized));
        if (duplicateIndex >= 0)
        {
            // Mantém uma representação canónica mesmo quando as fontes diferem apenas
            // em capitalização, para o resultado não depender da ordem de chegada.
            if (StringComparer.Ordinal.Compare(
                    GetCanonicalEvidenceKey(normalized),
                    GetCanonicalEvidenceKey(device.IdentityEvidence[duplicateIndex])) < 0)
            {
                device.IdentityEvidence[duplicateIndex] = normalized;
            }
        }
        else
        {
            device.IdentityEvidence.Add(normalized);
        }

        DeviceIdentityEvidence[] retained = OrderEvidence(device.IdentityEvidence)
            .Take(MaximumEvidenceEntries)
            .ToArray();
        device.IdentityEvidence.Clear();
        device.IdentityEvidence.AddRange(retained);

        RecomputeIdentity(device);
    }

    public void AddMacVendor(NetworkDevice device, MacVendorMatch? match)
    {
        if (match is null || string.IsNullOrWhiteSpace(match.Organization))
            return;

        device.MacAssignee = match.Organization;
        device.MacRegistry = match.Registry;
        device.MacAssignmentPrefix = $"{match.Prefix}/{match.PrefixLength}";

        AddEvidence(device, new DeviceIdentityEvidence
        {
            Method = DiscoveryMethod.Arp,
            Source = $"Base IEEE {match.Registry} ({match.Source})",
            Confidence = ConfidenceLevel.Medium,
            Manufacturer = match.Organization
        });
    }

    private static bool HasIdentityValue(DeviceIdentityEvidence evidence) =>
        !string.IsNullOrWhiteSpace(evidence.Manufacturer) ||
        !string.IsNullOrWhiteSpace(evidence.Model) ||
        !string.IsNullOrWhiteSpace(evidence.FriendlyName) ||
        !string.IsNullOrWhiteSpace(evidence.SerialNumber) ||
        !string.IsNullOrWhiteSpace(evidence.Firmware) ||
        !string.IsNullOrWhiteSpace(evidence.HardwareRevision) ||
        !string.IsNullOrWhiteSpace(evidence.Description) ||
        !string.IsNullOrWhiteSpace(evidence.DeviceType) ||
        !string.IsNullOrWhiteSpace(evidence.OperatingSystem);

    private static void RecomputeIdentity(NetworkDevice device)
    {
        SelectedIdentityField? manufacturer = SelectField(
            device.IdentityEvidence,
            evidence => evidence.Manufacturer);
        SelectedIdentityField? model = SelectField(
            device.IdentityEvidence,
            evidence => evidence.Model);
        SelectedIdentityField? friendlyName = SelectField(
            device.IdentityEvidence,
            evidence => evidence.FriendlyName);
        SelectedIdentityField? serialNumber = SelectField(
            device.IdentityEvidence,
            evidence => evidence.SerialNumber);
        SelectedIdentityField? firmware = SelectField(
            device.IdentityEvidence,
            evidence => evidence.Firmware);
        SelectedIdentityField? hardwareRevision = SelectField(
            device.IdentityEvidence,
            evidence => evidence.HardwareRevision);
        SelectedIdentityField? description = SelectField(
            device.IdentityEvidence,
            evidence => evidence.Description);
        SelectedIdentityField? deviceType = SelectField(
            device.IdentityEvidence,
            evidence => evidence.DeviceType);
        SelectedIdentityField? operatingSystem = SelectField(
            device.IdentityEvidence,
            evidence => evidence.OperatingSystem);

        device.Manufacturer = manufacturer?.Value;
        device.Model = model?.Value;
        device.FriendlyName = friendlyName?.Value;
        device.SerialNumber = serialNumber?.Value;
        device.Firmware = firmware?.Value;
        device.HardwareRevision = hardwareRevision?.Value;
        device.IdentityDescription = description?.Value;

        // DeviceType e OsGuess também recebem heurísticas do classificador. Só os
        // substituímos quando existe evidência tipada para não apagar esse fallback.
        if (deviceType is not null)
            device.DeviceType = deviceType.Value;
        if (operatingSystem is not null)
            device.OsGuess = operatingSystem.Value;

        ConfidenceLevel[] selectedConfidences =
        [
            .. GetConfidence(manufacturer),
            .. GetConfidence(model),
            .. GetConfidence(friendlyName),
            .. GetConfidence(serialNumber),
            .. GetConfidence(firmware),
            .. GetConfidence(hardwareRevision),
            .. GetConfidence(description),
            .. GetConfidence(deviceType),
            .. GetConfidence(operatingSystem)
        ];
        device.IdentityConfidence = selectedConfidences.Length == 0
            ? ConfidenceLevel.Unknown
            : selectedConfidences.Min();
    }

    private static SelectedIdentityField? SelectField(
        IReadOnlyList<DeviceIdentityEvidence> evidence,
        Func<DeviceIdentityEvidence, string?> selector)
    {
        return evidence
            .Select(item => new { Evidence = item, Value = selector(item) })
            .Where(item => !string.IsNullOrWhiteSpace(item.Value))
            .OrderByDescending(item => item.Evidence.Confidence)
            .ThenByDescending(item => GetMethodPriority(item.Evidence.Method))
            .ThenBy(item => item.Value, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Value, StringComparer.Ordinal)
            .ThenBy(item => item.Evidence.Source, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Evidence.Source, StringComparer.Ordinal)
            .ThenBy(item => item.Evidence.Endpoint, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Evidence.Endpoint, StringComparer.Ordinal)
            .Select(item => new SelectedIdentityField(
                item.Value!,
                item.Evidence.Confidence))
            .FirstOrDefault();
    }

    private static IEnumerable<ConfidenceLevel> GetConfidence(SelectedIdentityField? field)
    {
        if (field is not null)
            yield return field.Confidence;
    }

    private static IOrderedEnumerable<DeviceIdentityEvidence> OrderEvidence(
        IEnumerable<DeviceIdentityEvidence> evidence) => evidence
        .OrderByDescending(item => item.Confidence)
        .ThenByDescending(item => GetMethodPriority(item.Method))
        .ThenBy(GetCanonicalEvidenceKey, StringComparer.OrdinalIgnoreCase)
        .ThenBy(GetCanonicalEvidenceKey, StringComparer.Ordinal);

    private static bool IsEquivalentEvidence(
        DeviceIdentityEvidence first,
        DeviceIdentityEvidence second) =>
        first.Method == second.Method &&
        first.Confidence == second.Confidence &&
        Equivalent(first.Source, second.Source) &&
        Equivalent(first.Manufacturer, second.Manufacturer) &&
        Equivalent(first.Model, second.Model) &&
        Equivalent(first.FriendlyName, second.FriendlyName) &&
        Equivalent(first.SerialNumber, second.SerialNumber) &&
        Equivalent(first.Firmware, second.Firmware) &&
        Equivalent(first.HardwareRevision, second.HardwareRevision) &&
        Equivalent(first.Description, second.Description) &&
        Equivalent(first.DeviceType, second.DeviceType) &&
        Equivalent(first.OperatingSystem, second.OperatingSystem) &&
        Equivalent(first.Endpoint, second.Endpoint);

    private static bool Equivalent(string? first, string? second) =>
        string.Equals(first, second, StringComparison.OrdinalIgnoreCase);

    private static string GetCanonicalEvidenceKey(DeviceIdentityEvidence evidence) =>
        string.Join(
            '\u001F',
            evidence.Source,
            evidence.Manufacturer ?? string.Empty,
            evidence.Model ?? string.Empty,
            evidence.FriendlyName ?? string.Empty,
            evidence.SerialNumber ?? string.Empty,
            evidence.Firmware ?? string.Empty,
            evidence.HardwareRevision ?? string.Empty,
            evidence.Description ?? string.Empty,
            evidence.DeviceType ?? string.Empty,
            evidence.OperatingSystem ?? string.Empty,
            evidence.Endpoint ?? string.Empty);

    private static int GetMethodPriority(DiscoveryMethod method)
    {
        if (method.HasFlag(DiscoveryMethod.LocalHost))
            return 900;
        if (method.HasFlag(DiscoveryMethod.Snmp))
            return 800;
        if (method.HasFlag(DiscoveryMethod.Nmap))
            return 700;
        if (method.HasFlag(DiscoveryMethod.Ssdp))
            return 600;
        if (method.HasFlag(DiscoveryMethod.Mdns))
            return 500;
        if (method.HasFlag(DiscoveryMethod.WsDiscovery))
            return 400;
        if (method.HasFlag(DiscoveryMethod.NetBios))
            return 300;
        if (method.HasFlag(DiscoveryMethod.Arp))
            return 200;
        if (method.HasFlag(DiscoveryMethod.Tcp))
            return 100;
        return 0;
    }

    private static string? Normalize(string? value, int maximumLength)
    {
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
        return compact.Length <= maximumLength ? compact : compact[..maximumLength];
    }

    private sealed record SelectedIdentityField(
        string Value,
        ConfidenceLevel Confidence);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
