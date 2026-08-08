// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class SnmpDeviceDiscoveryService
{
    internal const string SystemDescriptionOid = "1.3.6.1.2.1.1.1.0";
    internal const string SystemObjectIdentifierOid = "1.3.6.1.2.1.1.2.0";
    internal const string SystemNameOid = "1.3.6.1.2.1.1.5.0";
    internal const string EntityDescriptionRoot = "1.3.6.1.2.1.47.1.1.1.1.2";
    internal const string EntityClassRoot = "1.3.6.1.2.1.47.1.1.1.1.5";
    internal const string EntityNameRoot = "1.3.6.1.2.1.47.1.1.1.1.7";
    internal const string EntityHardwareRevisionRoot = "1.3.6.1.2.1.47.1.1.1.1.8";
    internal const string EntityFirmwareRevisionRoot = "1.3.6.1.2.1.47.1.1.1.1.9";
    internal const string EntitySoftwareRevisionRoot = "1.3.6.1.2.1.47.1.1.1.1.10";
    internal const string EntitySerialNumberRoot = "1.3.6.1.2.1.47.1.1.1.1.11";
    internal const string EntityManufacturerRoot = "1.3.6.1.2.1.47.1.1.1.1.12";
    internal const string EntityModelRoot = "1.3.6.1.2.1.47.1.1.1.1.13";

    private const int ChassisEntityClass = 3;
    private const int MaximumCommunityLength = 128;
    private const int MaximumEntityCandidates = 4;
    private const int MaximumEntityClassVariables = 128;
    private const int MaximumFallbackVariablesPerColumn = 32;
    private const int MaximumOidValues = 16;
    private const int MaximumEvidenceItems = 16;
    private const int MaximumValueLength = 256;
    private const int MaximumDescriptionLength = 512;
    private const int MaximumOverallTimeoutMs = 20_000;

    private static readonly EntityColumn[] EntityColumns =
    [
        new(EntityDescriptionRoot, static (row, value) => row.Description = value),
        new(EntityNameRoot, static (row, value) => row.Name = value),
        new(EntityHardwareRevisionRoot, static (row, value) => row.HardwareRevision = value),
        new(EntityFirmwareRevisionRoot, static (row, value) => row.FirmwareRevision = value),
        new(EntitySoftwareRevisionRoot, static (row, value) => row.SoftwareRevision = value),
        new(EntitySerialNumberRoot, static (row, value) => row.SerialNumber = value),
        new(EntityManufacturerRoot, static (row, value) => row.Manufacturer = value),
        new(EntityModelRoot, static (row, value) => row.Model = value)
    ];

    public Task<SnmpDeviceIdentity> DiscoverAsync(
        IPAddress address,
        string community,
        CancellationToken cancellationToken) =>
        DiscoverAsync(address, community, timeoutMs: 900, retries: 1, localAddress: null,
            cancellationToken);

    public async Task<SnmpDeviceIdentity> DiscoverAsync(
        IPAddress address,
        string community,
        int timeoutMs,
        int retries,
        IPAddress? localAddress,
        CancellationToken cancellationToken)
    {
        ValidateArguments(address, community, timeoutMs, retries, localAddress);
        cancellationToken.ThrowIfCancellationRequested();

        Dictionary<string, string> oidValues = new(StringComparer.Ordinal);
        List<string> evidence = [];
        SnmpEntityIdentityRow? selectedEntity = null;
        SnmpVariable? systemDescription = null;
        SnmpVariable? systemObjectIdentifier = null;
        SnmpVariable? systemName = null;
        bool deadlineReached = false;

        int overallTimeoutMs = CalculateOverallTimeoutMs(timeoutMs, retries);
        using CancellationTokenSource deadline =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(overallTimeoutMs);

        SnmpClientService client = new(address, localAddress, community, timeoutMs, retries);
        try
        {
            systemDescription = await client.GetAsync(SystemDescriptionOid, deadline.Token);
            AddVariable(oidValues, systemDescription, MaximumDescriptionLength);
            systemObjectIdentifier = await client.GetAsync(
                SystemObjectIdentifierOid,
                deadline.Token);
            AddVariable(oidValues, systemObjectIdentifier, MaximumValueLength);
            systemName = await client.GetAsync(SystemNameOid, deadline.Token);
            AddVariable(oidValues, systemName, MaximumValueLength);

            bool agentResponded = systemDescription is not null ||
                                  systemObjectIdentifier is not null ||
                                  systemName is not null;
            if (agentResponded)
            {
                selectedEntity = await ReadEntityIdentityAsync(
                    client,
                    oidValues,
                    deadline.Token,
                    cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            deadlineReached = true;
        }
        catch (Exception exception) when (
            exception is SocketException or InvalidDataException or FormatException or
                OverflowException or ArgumentException)
        {
            // A falha de um agente SNMP remoto não deve interromper o restante scan.
        }

        string? systemDescriptionText = SanitizeValue(
            systemDescription?.TextValue,
            MaximumDescriptionLength);
        string? description = systemDescriptionText ??
                              SanitizeValue(
                                  selectedEntity?.Description,
                                  MaximumDescriptionLength);
        string? name = SanitizeValue(
            systemName?.TextValue ?? selectedEntity?.Name,
            MaximumValueLength);
        string? manufacturer = SanitizeValue(selectedEntity?.Manufacturer, MaximumValueLength) ??
                               InferManufacturer(systemDescriptionText);
        string? operatingSystemHint = InferOperatingSystem(systemDescriptionText);
        string? systemObjectId = SanitizeObjectIdentifier(systemObjectIdentifier?.TextValue);
        bool success = systemDescription is not null ||
                       systemObjectIdentifier is not null ||
                       systemName is not null ||
                       selectedEntity is not null;

        if (!success)
        {
            evidence.Add(deadlineReached
                ? $"SNMP v2c não devolveu identidade em {overallTimeoutMs.ToString(CultureInfo.InvariantCulture)} ms. Timeout, firewall, ACL, comunidade incorreta ou agente desativado são indistinguíveis sem mais evidência."
                : "SNMP v2c não respondeu aos OIDs de sistema. Firewall, ACL, comunidade incorreta ou agente desativado são indistinguíveis sem mais evidência.");
        }
        else
        {
            evidence.Add("O agente respondeu por SNMP v2c usando apenas a comunidade fornecida explicitamente para este pedido; o serviço não tenta outras comunidades nem a persiste.");
            AddEvidence(evidence, SystemDescriptionOid, description);
            AddEvidence(evidence, SystemNameOid, SanitizeValue(systemName?.TextValue));
            AddEvidence(evidence, SystemObjectIdentifierOid, systemObjectId);
            if (selectedEntity is not null)
            {
                evidence.Add(
                    $"ENTITY-MIB: selecionado entPhysicalIndex {selectedEntity.Index.ToString(CultureInfo.InvariantCulture)}" +
                    (selectedEntity.EntityClass == ChassisEntityClass
                        ? " identificado como chassis por entPhysicalClass."
                        : " como a primeira linha de identidade coerente; o agente não publicou um chassis inequívoco."));
                AddEvidence(evidence, EntityManufacturerRoot, manufacturer);
                AddEvidence(evidence, EntityModelRoot, selectedEntity.Model);
                AddEvidence(evidence, EntitySerialNumberRoot, selectedEntity.SerialNumber);
            }
            if (manufacturer is not null && selectedEntity?.Manufacturer is null)
                evidence.Add("Fabricante inferido apenas de uma marca escrita explicitamente em sysDescr; não foi inferido pela comunidade ou pelo endereço IP.");
            if (operatingSystemHint is not null)
                evidence.Add("Indício de sistema operativo/firmware derivado de texto explícito em sysDescr; não constitui deteção autenticada.");
            if (deadlineReached)
                evidence.Add("O orçamento global terminou depois de uma resposta parcial; apenas os valores efetivamente recebidos são apresentados.");
        }

        return new SnmpDeviceIdentity
        {
            IpAddress = address,
            Status = success
                ? SnmpDeviceIdentityStatus.Available
                : SnmpDeviceIdentityStatus.Unavailable,
            UnavailableReason = success ? null : evidence.FirstOrDefault(),
            Manufacturer = manufacturer,
            Model = SanitizeValue(selectedEntity?.Model),
            Name = name,
            SerialNumber = SanitizeValue(selectedEntity?.SerialNumber),
            Description = description,
            OperatingSystemHint = operatingSystemHint,
            SystemObjectIdentifier = systemObjectId,
            EntityIndex = selectedEntity?.Index,
            HardwareRevision = SanitizeValue(selectedEntity?.HardwareRevision),
            FirmwareRevision = SanitizeValue(selectedEntity?.FirmwareRevision),
            SoftwareRevision = SanitizeValue(selectedEntity?.SoftwareRevision),
            Oids = new ReadOnlyDictionary<string, string>(oidValues),
            Evidence = evidence.Take(MaximumEvidenceItems).ToArray()
        };
    }

    private static async Task<SnmpEntityIdentityRow?> ReadEntityIdentityAsync(
        SnmpClientService client,
        IDictionary<string, string> oidValues,
        CancellationToken cancellationToken,
        CancellationToken externalCancellationToken)
    {
        IReadOnlyList<SnmpVariable> classes = await client.WalkAsync(
            EntityClassRoot,
            MaximumEntityClassVariables,
            cancellationToken);
        Dictionary<int, SnmpEntityIdentityRow> rows = ParseEntityRows(classes, EntityClassRoot);
        int[] chassisIndexes = rows.Values
            .Where(row => row.EntityClass == ChassisEntityClass)
            .OrderBy(row => row.Index)
            .Take(MaximumEntityCandidates)
            .Select(row => row.Index)
            .ToArray();

        if (chassisIndexes.Length > 0)
        {
            foreach (int chassisIndex in chassisIndexes)
                await PopulateEntityAsync(client, rows[chassisIndex], oidValues, cancellationToken);

            SnmpEntityIdentityRow? selectedChassis = SelectEntity(
                rows.Values.Where(row => chassisIndexes.Contains(row.Index)));
            if (HasHardwareIdentity(selectedChassis))
                return selectedChassis;

            // Alguns agentes anunciam corretamente entPhysicalClass=chassis, mas só
            // publicam fabricante/modelo numa entidade física filha. Faz um fallback
            // limitado às mesmas quatro colunas já usadas abaixo e só prefere a
            // entidade alternativa quando esta acrescenta identidade de hardware.
            try
            {
                await MergeFallbackIdentityColumnsAsync(client, rows, cancellationToken);
                SnmpEntityIdentityRow? alternative = SelectEntity(
                    rows.Values.Where(row => !chassisIndexes.Contains(row.Index)));
                if (alternative is not null &&
                    (selectedChassis is null || HasHardwareIdentity(alternative)))
                {
                    await PopulateEntityAsync(client, alternative, oidValues, cancellationToken);
                    return alternative;
                }
            }
            catch (OperationCanceledException) when (
                selectedChassis is not null &&
                !externalCancellationToken.IsCancellationRequested)
            {
                // O deadline interno pode terminar durante o fallback adicional. Nesse
                // caso preserva a evidência de chassis já recebida; cancelamento pedido
                // pelo utilizador continua a propagar-se sem ser convertido em sucesso.
            }

            return selectedChassis;
        }

        await MergeFallbackIdentityColumnsAsync(client, rows, cancellationToken);

        SnmpEntityIdentityRow? selected = SelectEntity(rows.Values);
        if (selected is null)
        {
            selected = new SnmpEntityIdentityRow(1);
            await PopulateEntityAsync(client, selected, oidValues, cancellationToken);
            return selected.HasIdentity ? selected : null;
        }

        await PopulateEntityAsync(client, selected, oidValues, cancellationToken);
        return selected.HasIdentity ? selected : null;
    }

    private static async Task MergeFallbackIdentityColumnsAsync(
        SnmpClientService client,
        IDictionary<int, SnmpEntityIdentityRow> rows,
        CancellationToken cancellationToken)
    {
        await MergeFallbackColumnAsync(
            client,
            rows,
            EntityManufacturerRoot,
            static (row, value) => row.Manufacturer = value,
            cancellationToken);
        await MergeFallbackColumnAsync(
            client,
            rows,
            EntityModelRoot,
            static (row, value) => row.Model = value,
            cancellationToken);
        await MergeFallbackColumnAsync(
            client,
            rows,
            EntityDescriptionRoot,
            static (row, value) => row.Description = value,
            cancellationToken);
        await MergeFallbackColumnAsync(
            client,
            rows,
            EntityNameRoot,
            static (row, value) => row.Name = value,
            cancellationToken);
    }

    private static async Task PopulateEntityAsync(
        SnmpClientService client,
        SnmpEntityIdentityRow row,
        IDictionary<string, string> oidValues,
        CancellationToken cancellationToken)
    {
        foreach (EntityColumn column in EntityColumns)
        {
            string oid = column.Root + "." + row.Index.ToString(CultureInfo.InvariantCulture);
            SnmpVariable? variable = await client.GetAsync(oid, cancellationToken);
            string? value = SanitizeValue(
                variable?.TextValue,
                column.Root == EntityDescriptionRoot
                    ? MaximumDescriptionLength
                    : MaximumValueLength);
            if (value is null)
                continue;

            column.Assign(row, value);
            AddOidValue(oidValues, oid, value);
        }
    }

    private static async Task MergeFallbackColumnAsync(
        SnmpClientService client,
        IDictionary<int, SnmpEntityIdentityRow> rows,
        string root,
        Action<SnmpEntityIdentityRow, string> assign,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<SnmpVariable> variables = await client.WalkAsync(
            root,
            MaximumFallbackVariablesPerColumn,
            cancellationToken);
        foreach (SnmpVariable variable in variables)
        {
            int? index = ParseEntityIndex(variable.Oid, root);
            string? value = SanitizeValue(
                variable.TextValue,
                root == EntityDescriptionRoot ? MaximumDescriptionLength : MaximumValueLength);
            if (!index.HasValue || value is null)
                continue;

            if (!rows.TryGetValue(index.Value, out SnmpEntityIdentityRow? row))
            {
                row = new SnmpEntityIdentityRow(index.Value);
                rows[index.Value] = row;
            }
            assign(row, value);
        }
    }

    internal static Dictionary<int, SnmpEntityIdentityRow> ParseEntityRows(
        IReadOnlyList<SnmpVariable> variables,
        string root)
    {
        ArgumentNullException.ThrowIfNull(variables);
        ArgumentException.ThrowIfNullOrWhiteSpace(root);

        Dictionary<int, SnmpEntityIdentityRow> result = [];
        foreach (SnmpVariable variable in variables)
        {
            int? index = ParseEntityIndex(variable.Oid, root);
            if (!index.HasValue)
                continue;

            SnmpEntityIdentityRow row = new(index.Value)
            {
                EntityClass = variable.IntegerValue
            };
            result.TryAdd(index.Value, row);
        }
        return result;
    }

    internal static SnmpEntityIdentityRow? SelectEntity(
        IEnumerable<SnmpEntityIdentityRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        return rows
            .Where(row => row.HasIdentity)
            .OrderByDescending(row => row.EntityClass == ChassisEntityClass)
            .ThenByDescending(GetCoherenceScore)
            .ThenBy(row => row.Index)
            .FirstOrDefault();
    }

    internal static string? SanitizeValue(string? value, int maximumLength = MaximumValueLength)
    {
        if (string.IsNullOrWhiteSpace(value) || maximumLength < 1)
            return null;

        StringBuilder result = new(Math.Min(value.Length, maximumLength));
        bool previousWhitespace = false;
        foreach (char character in value.Normalize(NormalizationForm.FormKC))
        {
            if (result.Length >= maximumLength)
                break;
            if (char.IsControl(character) || char.IsWhiteSpace(character))
            {
                if (result.Length > 0 && !previousWhitespace)
                {
                    result.Append(' ');
                    previousWhitespace = true;
                }
                continue;
            }

            result.Append(character);
            previousWhitespace = false;
        }

        return result.ToString().Trim();
    }

    internal static string? InferOperatingSystem(string? description)
    {
        string? text = SanitizeValue(description, MaximumDescriptionLength);
        if (text is null)
            return null;

        (string Token, string Result)[] signatures =
        [
            ("Cisco IOS XE", "Cisco IOS XE"),
            ("Cisco NX-OS", "Cisco NX-OS"),
            ("Cisco IOS", "Cisco IOS"),
            ("RouterOS", "MikroTik RouterOS"),
            ("JUNOS", "Juniper Junos OS"),
            ("ArubaOS", "ArubaOS"),
            ("FortiOS", "Fortinet FortiOS"),
            ("OpenWrt", "OpenWrt"),
            ("OPNsense", "OPNsense"),
            ("pfSense", "pfSense"),
            ("Synology DiskStation", "Synology DSM"),
            ("QTS", "QNAP QTS"),
            ("VMware ESXi", "VMware ESXi"),
            ("Windows", "Microsoft Windows"),
            ("FreeBSD", "FreeBSD"),
            ("Linux", "Linux")
        ];
        return signatures.FirstOrDefault(item =>
            text.Contains(item.Token, StringComparison.OrdinalIgnoreCase)).Result;
    }

    private static int? ParseEntityIndex(string oid, string root)
    {
        string prefix = root + ".";
        if (!oid.StartsWith(prefix, StringComparison.Ordinal))
            return null;

        ReadOnlySpan<char> suffix = oid.AsSpan(prefix.Length);
        return suffix.IndexOf('.') < 0 &&
               int.TryParse(
                   suffix,
                   NumberStyles.None,
                   CultureInfo.InvariantCulture,
                   out int index) &&
               index is >= 1 and <= int.MaxValue
            ? index
            : null;
    }

    private static int GetCoherenceScore(SnmpEntityIdentityRow row)
    {
        int score = 0;
        if (row.Manufacturer is not null)
            score += 4;
        if (row.Model is not null)
            score += 4;
        if (row.SerialNumber is not null)
            score += 2;
        if (row.Name is not null)
            score++;
        if (row.Description is not null)
            score++;
        return score;
    }

    private static bool HasHardwareIdentity(SnmpEntityIdentityRow? row) =>
        row is not null &&
        (!string.IsNullOrWhiteSpace(row.Manufacturer) ||
         !string.IsNullOrWhiteSpace(row.Model) ||
         !string.IsNullOrWhiteSpace(row.SerialNumber));

    private static int CalculateOverallTimeoutMs(int timeoutMs, int retries)
    {
        long calculated = (long)timeoutMs * (retries + 1) * 16;
        return (int)Math.Clamp(calculated, 3_000, MaximumOverallTimeoutMs);
    }

    private static void ValidateArguments(
        IPAddress address,
        string community,
        int timeoutMs,
        int retries,
        IPAddress? localAddress)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(community);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("A descoberta SNMP v2c suporta um endereço IPv4 individual.", nameof(address));
        byte[] targetBytes = address.GetAddressBytes();
        if (address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.Broadcast) ||
            targetBytes[0] is >= 224)
        {
            throw new ArgumentException(
                "O destino SNMP tem de ser um endereço IPv4 unicast individual.",
                nameof(address));
        }
        if (localAddress is not null && localAddress.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("O endereço local SNMP tem de ser IPv4.", nameof(localAddress));
        if (community.Length > MaximumCommunityLength ||
            community.Any(character => character is < ' ' or > '~'))
        {
            throw new ArgumentException(
                "A comunidade SNMP deve conter entre 1 e 128 caracteres ASCII imprimíveis.",
                nameof(community));
        }
        if (timeoutMs is < 100 or > 10_000)
            throw new ArgumentOutOfRangeException(nameof(timeoutMs), "O timeout deve estar entre 100 e 10000 ms.");
        if (retries is < 0 or > 2)
            throw new ArgumentOutOfRangeException(nameof(retries), "As tentativas adicionais devem estar entre 0 e 2.");
    }

    private static void AddVariable(
        IDictionary<string, string> oidValues,
        SnmpVariable? variable,
        int maximumLength)
    {
        string? value = SanitizeValue(variable?.TextValue, maximumLength);
        if (variable is not null && value is not null)
            AddOidValue(oidValues, variable.Oid, value);
    }

    private static void AddOidValue(
        IDictionary<string, string> oidValues,
        string oid,
        string value)
    {
        if (oidValues.Count < MaximumOidValues || oidValues.ContainsKey(oid))
            oidValues[oid] = value;
    }

    private static void AddEvidence(ICollection<string> evidence, string oid, string? value)
    {
        if (value is not null && evidence.Count < MaximumEvidenceItems)
            evidence.Add($"{oid}: {value}");
    }

    private static string? SanitizeObjectIdentifier(string? value)
    {
        string? oid = SanitizeValue(value, MaximumValueLength)?.Trim('.');
        if (oid is null)
            return null;
        string[] parts = oid.Split('.', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && parts.All(part =>
            ulong.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _))
            ? string.Join('.', parts)
            : null;
    }

    private static string? InferManufacturer(string? description)
    {
        string? text = SanitizeValue(description, MaximumDescriptionLength);
        if (text is null)
            return null;

        (string Token, string Result)[] signatures =
        [
            ("Ubiquiti", "Ubiquiti"),
            ("UniFi", "Ubiquiti"),
            ("Cisco", "Cisco"),
            ("MikroTik", "MikroTik"),
            ("Juniper", "Juniper Networks"),
            ("Aruba", "HPE Aruba Networking"),
            ("Hewlett Packard Enterprise", "Hewlett Packard Enterprise"),
            ("Fortinet", "Fortinet"),
            ("Synology", "Synology"),
            ("QNAP", "QNAP"),
            ("VMware", "VMware"),
            ("Microsoft", "Microsoft")
        ];
        return signatures.FirstOrDefault(item =>
            text.Contains(item.Token, StringComparison.OrdinalIgnoreCase)).Result;
    }

    private sealed record EntityColumn(
        string Root,
        Action<SnmpEntityIdentityRow, string> Assign);
}

internal sealed class SnmpEntityIdentityRow
{
    public SnmpEntityIdentityRow(int index) => Index = index;

    public int Index { get; }

    public int? EntityClass { get; set; }

    public string? Description { get; set; }

    public string? Name { get; set; }

    public string? HardwareRevision { get; set; }

    public string? FirmwareRevision { get; set; }

    public string? SoftwareRevision { get; set; }

    public string? SerialNumber { get; set; }

    public string? Manufacturer { get; set; }

    public string? Model { get; set; }

    public bool HasIdentity => Manufacturer is not null || Model is not null ||
                               SerialNumber is not null || Name is not null ||
                               Description is not null;
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
