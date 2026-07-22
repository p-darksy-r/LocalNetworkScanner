// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public static class ServiceCatalog
{
    private static readonly IReadOnlyDictionary<int, string> Names = new Dictionary<int, string>
    {
        [20] = "ftp-data",
        [21] = "ftp",
        [22] = "ssh",
        [23] = "telnet",
        [25] = "smtp",
        [53] = "dns",
        [67] = "dhcp-server",
        [68] = "dhcp-client",
        [69] = "tftp",
        [80] = "http",
        [88] = "kerberos",
        [110] = "pop3",
        [111] = "rpcbind",
        [123] = "ntp",
        [135] = "msrpc",
        [137] = "netbios-ns",
        [138] = "netbios-dgm",
        [139] = "netbios-ssn",
        [143] = "imap",
        [161] = "snmp",
        [162] = "snmptrap",
        [389] = "ldap",
        [443] = "https",
        [445] = "smb",
        [465] = "smtps",
        [500] = "isakmp",
        [515] = "lpd",
        [548] = "afp",
        [554] = "rtsp",
        [587] = "submission",
        [631] = "ipp",
        [636] = "ldaps",
        [853] = "dns-tls",
        [993] = "imaps",
        [995] = "pop3s",
        [1080] = "socks",
        [1194] = "openvpn",
        [1433] = "mssql",
        [1521] = "oracle",
        [1701] = "l2tp",
        [1723] = "pptp",
        [1883] = "mqtt",
        [2049] = "nfs",
        [2375] = "docker",
        [2376] = "docker-tls",
        [3000] = "web-dev",
        [3128] = "http-proxy",
        [3268] = "global-catalog",
        [3306] = "mysql",
        [3389] = "rdp",
        [3478] = "stun",
        [5000] = "upnp/web",
        [5060] = "sip",
        [5222] = "xmpp",
        [5353] = "mdns",
        [5432] = "postgresql",
        [5672] = "amqp",
        [5900] = "vnc",
        [5985] = "winrm",
        [5986] = "winrm-tls",
        [6379] = "redis",
        [8000] = "http-alt",
        [8008] = "http-alt",
        [8080] = "http-proxy",
        [8081] = "http-alt",
        [8088] = "http-alt",
        [8123] = "home-assistant",
        [8443] = "https-alt",
        [8883] = "mqtt-tls",
        [8888] = "http-alt",
        [9000] = "web-admin",
        [9090] = "web-admin",
        [9100] = "jetdirect",
        [9200] = "elasticsearch",
        [9443] = "https-alt",
        [10000] = "webmin",
        [27017] = "mongodb",
        [32400] = "plex"
    };

    public static IReadOnlyList<int> DiscoveryPorts { get; } =
        [22, 53, 80, 139, 443, 445, 3389, 8080, 8443, 9100];

    public static IReadOnlyList<int> QuickPorts { get; } =
        [21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 1883, 3389, 5000, 5900, 8000, 8080, 8123, 8443, 8883, 9100];

    public static IReadOnlyList<int> StandardPorts { get; } = Names.Keys
        .Where(port => port is not (67 or 68 or 69 or 123 or 137 or 138 or 161 or 162 or 500 or 1194 or 1701 or 5353))
        .OrderBy(port => port)
        .ToArray();

    public static IReadOnlyList<int> DeepPorts { get; } = Enumerable.Range(1, 1024)
        .Concat(Names.Keys)
        .Distinct()
        .OrderBy(port => port)
        .ToArray();

    public static string GetServiceName(int port) =>
        Names.TryGetValue(port, out string? name) ? name : "desconhecido";

    public static bool IsTlsPort(int port) =>
        port is 443 or 465 or 636 or 853 or 993 or 995 or 2376 or 5986 or 8443 or 8883 or 9443;

    public static bool IsHttpPort(int port) =>
        port is 80 or 443 or 3000 or 5000 or 8000 or 8008 or 8080 or 8081 or 8088 or 8123 or 8443 or 8888 or 9000 or 9090 or 9200 or 9443 or 10000 or 32400;

    public static IReadOnlyList<int> ParsePortSpecification(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        try
        {
            return ParsePortSpecificationCore(value);
        }
        catch (FormatException exception) when (exception is not ScanFormatException)
        {
            throw new ScanFormatException(
                DiagnosticCatalog.InvalidPortSpecification(value),
                exception);
        }
    }

    private static IReadOnlyList<int> ParsePortSpecificationCore(string value)
    {
        value = value.Trim();

        if (value.Equals("quick", StringComparison.OrdinalIgnoreCase))
            return QuickPorts;
        if (value.Equals("standard", StringComparison.OrdinalIgnoreCase) || value.Equals("top", StringComparison.OrdinalIgnoreCase))
            return StandardPorts;
        if (value.Equals("deep", StringComparison.OrdinalIgnoreCase))
            return DeepPorts;
        if (value.Equals("all", StringComparison.OrdinalIgnoreCase))
            return Enumerable.Range(1, 65_535).ToArray();

        SortedSet<int> ports = [];
        foreach (string part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Contains('-'))
            {
                string[] bounds = part.Split('-', 2, StringSplitOptions.TrimEntries);
                if (bounds.Length != 2 ||
                    !int.TryParse(bounds[0], out int start) ||
                    !int.TryParse(bounds[1], out int end) ||
                    start is < 1 or > 65_535 || end is < 1 or > 65_535 || start > end)
                {
                    throw new FormatException($"Intervalo de portas inválido: '{part}'.");
                }

                for (int port = start; port <= end; port++)
                    ports.Add(port);
            }
            else if (int.TryParse(part, out int port) && port is >= 1 and <= 65_535)
            {
                ports.Add(port);
            }
            else
            {
                throw new FormatException($"Porta inválida: '{part}'.");
            }
        }

        if (ports.Count == 0)
            throw new FormatException("A lista de portas está vazia.");

        return ports.ToArray();
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
