// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Text;
using System.Text.Json;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Xml;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class ExportService
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };

    /// <summary>
    /// Cria um relatório de suporte concebido para partilha: inclui apenas estado
    /// agregado e códigos de diagnóstico, nunca nomes, endereços ou notas da rede.
    /// </summary>
    public async Task ExportSupportJsonAsync(
        NetworkScanResult result,
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        EnsureDirectory(path);

        DiscoveryMethod[] discoveryMethods = Enum.GetValues<DiscoveryMethod>()
            .Where(method => method != DiscoveryMethod.None)
            .ToArray();
        object payload = new
        {
            schemaVersion = 1,
            reportType = "LocalNetworkScanner.Support",
            generatedAt = DateTimeOffset.UtcNow,
            privacy = new
            {
                containsNetworkIdentifiers = false,
                excluded = new[]
                {
                    "IP and MAC addresses",
                    "interface, host, switch and device names",
                    "Wi-Fi SSID and BSSID",
                    "device aliases and notes",
                    "diagnostic targets, context and raw warnings"
                }
            },
            application = new
            {
                name = ProductIdentity.Name,
                version = ProductIdentity.Version,
                runtime = RuntimeInformation.FrameworkDescription,
                osArchitecture = RuntimeInformation.OSArchitecture.ToString(),
                processArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
                osVersion = Environment.OSVersion.VersionString
            },
            scan = new
            {
                result.StartedAt,
                result.CompletedAt,
                durationMs = result.Duration.TotalMilliseconds,
                result.AddressesScanned,
                result.IsPartial,
                devicesOnline = result.Devices.Count,
                warningCount = result.Warnings.Count,
                diagnosticCount = result.Diagnostics.Count
            },
            networkCapabilities = new
            {
                interfaceType = result.NetworkInterface.InterfaceType.ToString(),
                result.NetworkInterface.IsWireless,
                speedMbps = result.NetworkInterface.SpeedMbps,
                result.NetworkInterface.SupportsMulticast,
                hasGateway = result.NetworkInterface.GatewayAddress is not null,
                dnsServerCount = result.NetworkInterface.DnsAddresses.Count,
                wifiSignalAvailable = result.NetworkInterface.WifiSignalPercent.HasValue,
                wifiChannelAvailable = result.NetworkInterface.WifiChannel.HasValue,
                vlanReportedByWindows = result.NetworkInterface.VlanId.HasValue,
                snmpTopologyCollected = result.SnmpTopology is not null
            },
            devices = new
            {
                total = result.Devices.Count,
                withMacAddress = result.Devices.Count(device =>
                    MacAddressService.TryNormalizeDeviceAddress(device.MacAddress, out _)),
                withResolvedManufacturer = result.Devices.Count(device =>
                    !string.IsNullOrWhiteSpace(device.Manufacturer)),
                withResolvedModel = result.Devices.Count(device =>
                    !string.IsNullOrWhiteSpace(device.Model)),
                withHighConfidenceIdentity = result.Devices.Count(device =>
                    device.IdentityConfidence == ConfidenceLevel.High),
                withResponseTime = result.Devices.Count(device => device.ResponseTimeMs.HasValue),
                withOpenPorts = result.Devices.Count(device => device.Ports.Count > 0),
                openPortObservations = result.Devices.Sum(device => device.Ports.Count),
                locallyAdministeredMac = result.Devices.Count(device => device.IsLocallyAdministeredMac),
                newSincePreviousScan = result.Devices.Count(device => device.HistoryCompared && device.IsNew),
                changedSincePreviousScan = result.Devices.Count(device =>
                    device.HistoryCompared && device.Changes.Count > 0),
                risk = new
                {
                    low = result.Devices.Count(device =>
                        device.RiskLevel.Equals("Baixo", StringComparison.OrdinalIgnoreCase)),
                    medium = result.Devices.Count(device =>
                        device.RiskLevel.Equals("Médio", StringComparison.OrdinalIgnoreCase)),
                    high = result.Devices.Count(device =>
                        device.RiskLevel.Equals("Alto", StringComparison.OrdinalIgnoreCase))
                },
                topology = new
                {
                    sameLayer2Confirmed = result.Devices.Count(device =>
                        device.Topology.SameLayer2Segment == true),
                    vlanConfirmed = result.Devices.Count(device => device.Topology.VlanId.HasValue),
                    managedBridgeObserved = result.Devices.Count(device =>
                        device.Topology.ObservedOnManagedBridge),
                    samePhysicalSwitchConfirmed = result.Devices.Count(device =>
                        device.Topology.SamePhysicalSwitch == true)
                },
                discovery = discoveryMethods.ToDictionary(
                    method => method.ToString(),
                    method => result.Devices.Count(device =>
                        device.DiscoveryMethods.HasFlag(method)))
            },
            diagnostics = result.Diagnostics
                .GroupBy(diagnostic => new
                {
                    diagnostic.Code,
                    diagnostic.Category,
                    diagnostic.Severity,
                    diagnostic.IsFatal
                })
                .OrderBy(group => group.Key.Code, StringComparer.Ordinal)
                .Select(group => new
                {
                    code = group.Key.Code,
                    category = group.Key.Category.ToString(),
                    severity = group.Key.Severity.ToString(),
                    isFatal = group.Key.IsFatal,
                    count = group.Count()
                })
        };

        await using FileStream stream = File.Create(path);
        await JsonSerializer.SerializeAsync(
            stream,
            payload,
            IndentedJsonOptions,
            cancellationToken);
    }

    public async Task ExportJsonAsync(
        NetworkScanResult result,
        string path,
        CancellationToken cancellationToken = default)
    {
        EnsureDirectory(path);
        NetworkMap topologyMap = new NetworkTopologyMapService().Build(result);
        object payload = new
        {
            schemaVersion = 6,
            generatedAt = DateTimeOffset.UtcNow,
            network = new
            {
                interfaceName = result.NetworkInterface.Name,
                result.NetworkInterface.NetworkCidr,
                ip = result.NetworkInterface.IpAddress.ToString(),
                gateway = result.NetworkInterface.GatewayAddress?.ToString(),
                mac = result.NetworkInterface.MacAddress,
                vlanId = result.NetworkInterface.VlanId,
                wifi = new
                {
                    result.NetworkInterface.Ssid,
                    result.NetworkInterface.Bssid,
                    signalPercent = result.NetworkInterface.WifiSignalPercent,
                    channel = result.NetworkInterface.WifiChannel
                }
            },
            scan = new
            {
                result.StartedAt,
                result.CompletedAt,
                durationMs = result.Duration.TotalMilliseconds,
                result.AddressesScanned,
                result.IsPartial,
                devicesOnline = result.Devices.Count,
                result.Warnings,
                diagnostics = result.Diagnostics.Select(diagnostic => new
                {
                    code = diagnostic.Code,
                    category = diagnostic.Category.ToString(),
                    severity = diagnostic.Severity.ToString(),
                    message = diagnostic.Message,
                    recommendedAction = diagnostic.RecommendedAction,
                    target = diagnostic.Target,
                    context = diagnostic.Context,
                    isFatal = diagnostic.IsFatal
                })
            },
            topologyMap = new
            {
                topologyMap.NetworkCidr,
                topologyMap.GeneratedAt,
                topologyMap.Warnings,
                nodes = topologyMap.Nodes.Select(node => new
                {
                    node.Id,
                    kind = node.Kind.ToString(),
                    node.Label,
                    node.Subtitle,
                    ipAddress = node.IpAddress?.ToString(),
                    node.MacAddress,
                    node.DeviceType,
                    node.VlanId,
                    node.RiskLevel,
                    node.IsOnline
                }),
                edges = topologyMap.Edges.Select(edge => new
                {
                    edge.SourceId,
                    edge.TargetId,
                    kind = edge.Kind.ToString(),
                    edge.Label,
                    edge.Evidence,
                    confidence = edge.Confidence.ToString()
                })
            },
            devices = result.Devices.Select(device => new
            {
                ip = device.IpAddress.ToString(),
                device.Alias,
                device.Notes,
                device.IsFavorite,
                device.Hostname,
                device.MacAddress,
                device.Manufacturer,
                device.MacAssignee,
                device.MacRegistry,
                device.MacAssignmentPrefix,
                device.Model,
                device.FriendlyName,
                device.SerialNumber,
                device.Firmware,
                device.HardwareRevision,
                device.IdentityDescription,
                identityConfidence = device.IdentityConfidence.ToString(),
                identityEvidence = device.IdentityEvidence.Select(evidence => new
                {
                    method = evidence.Method.ToString(),
                    evidence.Source,
                    confidence = evidence.Confidence.ToString(),
                    evidence.Manufacturer,
                    evidence.Model,
                    evidence.FriendlyName,
                    evidence.SerialNumber,
                    evidence.Firmware,
                    evidence.HardwareRevision,
                    evidence.Description,
                    evidence.DeviceType,
                    evidence.OperatingSystem,
                    evidence.Endpoint
                }),
                device.IsLocallyAdministeredMac,
                responseTimeMs = device.ResponseTimeMs,
                replyTtl = device.ReplyTtl,
                discovery = device.DiscoveryText,
                device.DeviceType,
                device.OsGuess,
                device.RiskLevel,
                device.RiskScore,
                device.SecurityFindings,
                device.ObservedProtocols,
                ports = device.Ports,
                topology = device.Topology,
                mdnsNames = device.MdnsNames,
                mdnsServices = device.MdnsServices,
                ssdp = new
                {
                    device.SsdpServer,
                    device.SsdpLocation,
                    device.SsdpServiceType,
                    device.SsdpUniqueServiceName
                },
                snmp = new { device.SnmpDescription, device.SnmpObjectIdentifier },
                nmap = device.NmapSummary,
                netbios = new { device.NetBiosName, device.Workgroup },
                wsDiscovery = new { device.WsDiscoveryTypes, device.WsDiscoveryAddresses },
                device.FirstSeen,
                device.LastSeen,
                device.HistoryCompared,
                device.IsNew,
                device.Changes
            })
        };

        await using FileStream stream = File.Create(path);
        await JsonSerializer.SerializeAsync(
            stream,
            payload,
            IndentedJsonOptions,
            cancellationToken);
    }

    public async Task ExportGraphMlAsync(
        NetworkScanResult result,
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        EnsureDirectory(path);
        NetworkMap map = new NetworkTopologyMapService().Build(result);

        FileStreamOptions fileOptions = new()
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.Asynchronous
        };
        await using FileStream stream = new(path, fileOptions);
        XmlWriterSettings settings = new()
        {
            Async = true,
            Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            Indent = true,
            CloseOutput = false
        };
        using XmlWriter writer = XmlWriter.Create(stream, settings);

        const string graphMlNamespace = "http://graphml.graphdrawing.org/xmlns";
        await writer.WriteStartDocumentAsync();
        await writer.WriteStartElementAsync(null, "graphml", graphMlNamespace);
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "g_network", "graph", "network_cidr", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "g_generated", "graph", "generated_at", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "g_warnings", "graph", "warnings", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "g_diagnostics", "graph", "diagnostics", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "n_label", "node", "label", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "n_kind", "node", "kind", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "n_subtitle", "node", "subtitle", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "n_ip", "node", "ip_address", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "n_mac", "node", "mac_address", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "n_vlan", "node", "vlan_id", "int");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "n_risk", "node", "risk_level", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "n_online", "node", "is_online", "boolean");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "e_label", "edge", "label", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "e_kind", "edge", "kind", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "e_evidence", "edge", "evidence", "string");
        await WriteGraphMlKeyAsync(writer, graphMlNamespace, "e_confidence", "edge", "confidence", "string");

        await writer.WriteStartElementAsync(null, "graph", graphMlNamespace);
        await writer.WriteAttributeStringAsync(null, "id", null, "network-topology");
        await writer.WriteAttributeStringAsync(null, "edgedefault", null, "directed");
        await WriteGraphMlDataAsync(writer, graphMlNamespace, "g_network", map.NetworkCidr);
        await WriteGraphMlDataAsync(
            writer,
            graphMlNamespace,
            "g_generated",
            map.GeneratedAt.ToString("O", CultureInfo.InvariantCulture));
        await WriteGraphMlDataAsync(
            writer,
            graphMlNamespace,
            "g_warnings",
            string.Join(Environment.NewLine, map.Warnings));
        await WriteGraphMlDataAsync(
            writer,
            graphMlNamespace,
            "g_diagnostics",
            string.Join(Environment.NewLine, result.Diagnostics.Select(FormatDiagnostic)));

        foreach (NetworkMapNode node in map.Nodes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await writer.WriteStartElementAsync(null, "node", graphMlNamespace);
            await writer.WriteAttributeStringAsync(null, "id", null, EncodeGraphMlId(node.Id));
            await WriteGraphMlDataAsync(writer, graphMlNamespace, "n_label", node.Label);
            await WriteGraphMlDataAsync(writer, graphMlNamespace, "n_kind", node.Kind.ToString());
            await WriteGraphMlDataAsync(writer, graphMlNamespace, "n_subtitle", node.Subtitle);
            await WriteGraphMlDataAsync(writer, graphMlNamespace, "n_ip", node.IpAddress?.ToString());
            await WriteGraphMlDataAsync(writer, graphMlNamespace, "n_mac", node.MacAddress);
            await WriteGraphMlDataAsync(
                writer,
                graphMlNamespace,
                "n_vlan",
                node.VlanId?.ToString(CultureInfo.InvariantCulture));
            await WriteGraphMlDataAsync(writer, graphMlNamespace, "n_risk", node.RiskLevel);
            await WriteGraphMlDataAsync(
                writer,
                graphMlNamespace,
                "n_online",
                node.IsOnline ? "true" : "false");
            await writer.WriteEndElementAsync();
        }

        for (int index = 0; index < map.Edges.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            NetworkMapEdge edge = map.Edges[index];
            await writer.WriteStartElementAsync(null, "edge", graphMlNamespace);
            await writer.WriteAttributeStringAsync(
                null,
                "id",
                null,
                $"edge-{index.ToString(CultureInfo.InvariantCulture)}");
            await writer.WriteAttributeStringAsync(null, "source", null, EncodeGraphMlId(edge.SourceId));
            await writer.WriteAttributeStringAsync(null, "target", null, EncodeGraphMlId(edge.TargetId));
            await WriteGraphMlDataAsync(writer, graphMlNamespace, "e_label", edge.Label);
            await WriteGraphMlDataAsync(writer, graphMlNamespace, "e_kind", edge.Kind.ToString());
            await WriteGraphMlDataAsync(writer, graphMlNamespace, "e_evidence", edge.Evidence);
            await WriteGraphMlDataAsync(
                writer,
                graphMlNamespace,
                "e_confidence",
                edge.Confidence.ToString());
            await writer.WriteEndElementAsync();
        }

        await writer.WriteEndElementAsync();
        await writer.WriteEndElementAsync();
        await writer.WriteEndDocumentAsync();
        await writer.FlushAsync();
    }

    public async Task ExportCsvAsync(
        NetworkScanResult result,
        string path,
        CancellationToken cancellationToken = default)
    {
        EnsureDirectory(path);
        StringBuilder csv = new();
        csv.AppendLine("Resultado parcial;Favorito;Alias;Notas;IP;Hostname;NetBIOS;Grupo de trabalho;MAC;Titular IEEE;Fabricante;Modelo;Nome anunciado;Firmware;Confiança identidade;Fontes identidade;PingMs;Descoberta;Portas;Tipo;SO provável;Protocolos;Risco;Pontuação;Topologia;Histórico");

        foreach (NetworkDevice device in result.Devices)
        {
            string[] values =
            [
                result.IsPartial ? "Sim" : "Não",
                device.IsFavorite ? "Sim" : "Não",
                device.Alias ?? string.Empty,
                device.Notes ?? string.Empty,
                device.IpAddressText,
                device.Hostname ?? string.Empty,
                device.NetBiosName ?? string.Empty,
                device.Workgroup ?? string.Empty,
                device.MacAddress ?? string.Empty,
                device.MacAssignee ?? string.Empty,
                device.Manufacturer ?? string.Empty,
                device.Model ?? string.Empty,
                device.FriendlyName ?? string.Empty,
                device.Firmware ?? string.Empty,
                device.IdentityConfidenceDisplay,
                string.Join(", ", device.IdentityEvidence.Select(evidence => evidence.Source).Distinct()),
                device.ResponseTimeMs?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                device.DiscoveryText,
                device.OpenPortsText,
                device.DeviceType,
                device.OsGuess,
                device.ProtocolsText,
                device.RiskLevel,
                device.RiskScore.ToString(System.Globalization.CultureInfo.InvariantCulture),
                device.TopologyText,
                device.HistoryText
            ];
            csv.AppendLine(string.Join(';', values.Select(EscapeCsv)));
        }

        await File.WriteAllTextAsync(path, csv.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), cancellationToken);
    }

    public async Task ExportHtmlAsync(
        NetworkScanResult result,
        string path,
        CancellationToken cancellationToken = default)
    {
#pragma warning disable CA1305 // The human-readable report intentionally follows the user's locale.
        EnsureDirectory(path);
        static string H(string? value) => System.Net.WebUtility.HtmlEncode(value ?? "—");

        StringBuilder html = new();
        html.Append(
            "<!doctype html><html lang=\"pt\"><head><meta charset=\"utf-8\">" +
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
            "<title>Relatório de rede</title><style>" +
            ":root{color-scheme:light;font-family:Segoe UI,Arial,sans-serif;color:#15243a;background:#f3f6fa}" +
            "body{max-width:1500px;margin:auto;padding:32px}h1{margin-bottom:4px}.sub{color:#58708d}" +
            ".cards{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:14px;margin:24px 0}" +
            ".card,table{background:white;border:1px solid #dbe4ee;border-radius:12px;box-shadow:0 4px 18px #1c34510d}" +
            ".card{padding:18px}.value{font-size:28px;font-weight:700}.label{color:#58708d}" +
            "table{width:100%;border-collapse:separate;border-spacing:0;overflow:hidden;font-size:13px}" +
            "th,td{text-align:left;padding:11px 12px;border-bottom:1px solid #e8eef4;vertical-align:top}" +
            "th{background:#eef4f9;color:#344e6e;position:sticky;top:0}.high{color:#b42318;font-weight:700}" +
            ".medium{color:#b54708;font-weight:700}.low{color:#067647;font-weight:700}" +
            ".warnings,.diagnostics{margin-top:24px;padding:18px;background:#fff7e8;border-left:4px solid #f79009}" +
            ".diagnostics{background:#eef6ff;border-color:#2e90fa}.diagnostic{margin:12px 0}.code{font-family:Consolas,monospace;font-weight:700}" +
            "@media(max-width:850px){body{padding:14px}.cards{grid-template-columns:1fr 1fr}.scroll{overflow:auto}}" +
            "</style></head><body>");
        string resultState = result.IsPartial ? " · RESULTADO PARCIAL / SCAN CANCELADO" : string.Empty;
        html.Append($"<h1>Local Network Scanner</h1><div class=\"sub\">{H(result.NetworkInterface.NetworkCidr)} · relatório gerado em {H(DateTimeOffset.Now.ToString("g"))}{H(resultState)}</div>");
        html.Append("<section class=\"cards\">");
        AddCard("Dispositivos", result.Devices.Count.ToString());
        AddCard("IPs analisados", result.AddressesScanned.ToString("N0"));
        AddCard("Risco alto", result.Devices.Count(device => device.RiskLevel == "Alto").ToString());
        AddCard("Duração", $"{result.Duration.TotalSeconds:F1} s");
        html.Append("</section><div class=\"scroll\"><table><thead><tr>" +
            "<th>Dispositivo</th><th>IP</th><th>Identidade</th><th>MAC / IEEE</th><th>Ping</th><th>Portas e protocolos</th><th>Risco</th><th>Topologia</th><th>Histórico</th>" +
            "</tr></thead><tbody>");

        foreach (NetworkDevice device in result.Devices)
        {
            string riskClass = device.RiskLevel.ToLowerInvariant() switch
            {
                "alto" => "high",
                "médio" => "medium",
                _ => "low"
            };
            html.Append("<tr>");
            html.Append($"<td><strong>{H(device.IdentityDisplay)}</strong><br>{H(device.DeviceType)}</td>");
            html.Append($"<td>{H(device.IpAddressText)}</td>");
            html.Append($"<td>{H(device.ManufacturerDisplay)}<br>{H(device.ModelDisplay)} · {H(device.IdentityConfidenceDisplay)}</td>");
            html.Append($"<td>{H(device.MacDisplay)}<br>{H(device.MacAssigneeDisplay)}</td>");
            html.Append($"<td>{H(device.ResponseTimeDisplay)}</td>");
            html.Append($"<td>{H(device.OpenPortsText)}<br>{H(device.ProtocolsText)}</td>");
            html.Append($"<td class=\"{riskClass}\">{H(device.RiskLevel)} · {device.RiskScore}/100</td>");
            html.Append($"<td>{H(device.TopologyText)}</td>");
            html.Append($"<td>{H(device.HistoryText)}</td></tr>");
        }

        html.Append("</tbody></table></div>");
        if (result.Diagnostics.Count > 0)
        {
            html.Append("<section class=\"diagnostics\"><strong>Diagnósticos estruturados</strong>");
            foreach (ScanDiagnostic diagnostic in result.Diagnostics)
            {
                html.Append("<article class=\"diagnostic\">");
                html.Append($"<span class=\"code\">{H(diagnostic.Code)}</span> · {H(GetSeverityLabel(diagnostic.Severity))} · {H(GetCategoryLabel(diagnostic.Category))}<br>");
                html.Append($"{H(diagnostic.Message)}<br><strong>Ação:</strong> {H(diagnostic.RecommendedAction)}");
                if (!string.IsNullOrWhiteSpace(diagnostic.Target))
                    html.Append($"<br><strong>Alvo:</strong> {H(diagnostic.Target)}");
                html.Append("</article>");
            }

            html.Append("</section>");
        }

        if (result.Warnings.Count > 0 && result.Diagnostics.Count == 0)
        {
            html.Append("<section class=\"warnings\"><strong>Limites e notas técnicas</strong><ul>");
            foreach (string warning in result.Warnings)
                html.Append($"<li>{H(warning)}</li>");
            html.Append("</ul></section>");
        }

        html.Append("</body></html>");
        await File.WriteAllTextAsync(
            path,
            html.ToString(),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            cancellationToken);

        void AddCard(string label, string value) =>
            html.Append($"<article class=\"card\"><div class=\"value\">{H(value)}</div><div class=\"label\">{H(label)}</div></article>");
#pragma warning restore CA1305
    }

    private static string EscapeCsv(string value)
    {
        // Aspas CSV não impedem fórmulas em Excel/LibreOffice. Hostnames, aliases e
        // banners vêm da rede e são dados não confiáveis, por isso neutralizamos
        // prefixos que uma folha de cálculo pode interpretar como uma fórmula.
        string safeValue = IsPotentialSpreadsheetFormula(value) ? "'" + value : value;
        return $"\"{safeValue.Replace("\"", "\"\"")}\"";
    }

    private static bool IsPotentialSpreadsheetFormula(string value)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        int index = 0;
        while (index < value.Length && char.IsWhiteSpace(value[index]))
        {
            if (value[index] is '\t' or '\r' or '\n')
                return true;
            index++;
        }

        return index < value.Length && value[index] is '=' or '+' or '-' or '@';
    }

    private static async Task WriteGraphMlKeyAsync(
        XmlWriter writer,
        string xmlNamespace,
        string id,
        string target,
        string name,
        string type)
    {
        await writer.WriteStartElementAsync(null, "key", xmlNamespace);
        await writer.WriteAttributeStringAsync(null, "id", null, id);
        await writer.WriteAttributeStringAsync(null, "for", null, target);
        await writer.WriteAttributeStringAsync(null, "attr.name", null, name);
        await writer.WriteAttributeStringAsync(null, "attr.type", null, type);
        await writer.WriteEndElementAsync();
    }

    private static async Task WriteGraphMlDataAsync(
        XmlWriter writer,
        string xmlNamespace,
        string key,
        string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;

        await writer.WriteStartElementAsync(null, "data", xmlNamespace);
        await writer.WriteAttributeStringAsync(null, "key", null, key);
        await writer.WriteStringAsync(value);
        await writer.WriteEndElementAsync();
    }

    private static string EncodeGraphMlId(string value) => XmlConvert.EncodeName(value);

    private static string FormatDiagnostic(ScanDiagnostic diagnostic)
    {
        string target = string.IsNullOrWhiteSpace(diagnostic.Target)
            ? string.Empty
            : $" | Alvo: {diagnostic.Target}";
        return $"[{diagnostic.Code}] {diagnostic.Severity}/{diagnostic.Category} | " +
            $"{diagnostic.Message} | Ação: {diagnostic.RecommendedAction}{target}";
    }

    private static string GetSeverityLabel(DiagnosticSeverity severity) => severity switch
    {
        DiagnosticSeverity.Information => "Informação",
        DiagnosticSeverity.Warning => "Aviso",
        DiagnosticSeverity.Error => "Erro",
        _ => "Crítico"
    };

    private static string GetCategoryLabel(DiagnosticCategory category) => category switch
    {
        DiagnosticCategory.User => "Utilizador",
        DiagnosticCategory.Network => "Rede",
        DiagnosticCategory.Device => "Dispositivo/dados",
        _ => "Aplicação"
    };

    private static void EnsureDirectory(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string? directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
