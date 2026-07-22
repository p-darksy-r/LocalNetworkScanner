// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using System.Text;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Core.Utilities;

Console.OutputEncoding = Encoding.UTF8;
Console.Title = "Local Network Scanner";

using CancellationTokenSource cancellation = new();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
    Console.WriteLine("\nA cancelar o scan com segurança...");
};

try
{
    CliOptions cli = CliOptions.Parse(args);
    if (cli.ShowHelp)
    {
        PrintHelp();
        return;
    }

    PrintHeader();
    NetworkInterfaceService interfaceService = new();
    IReadOnlyList<LocalNetworkInterface> interfaces =
        await interfaceService.GetActiveInterfacesAsync(cancellation.Token);

    if (interfaces.Count == 0)
        throw new ScanOperationException(DiagnosticCatalog.NoActiveInterface());

    if (cli.Command.Equals("interfaces", StringComparison.OrdinalIgnoreCase))
    {
        PrintInterfaces(interfaces);
        return;
    }

    bool interactive = args.Length == 0 && !Console.IsInputRedirected;
    LocalNetworkInterface selectedInterface = SelectInterface(interfaces, cli.InterfaceSelector, interactive);
    ScanProfile profile = interactive ? AskProfile(cli.Profile) : cli.Profile;
    ScanOptions scanOptions = BuildScanOptions(profile, cli.Ports);

    IpRangeService rangeService = new();
    IReadOnlyList<IPAddress> addresses = string.IsNullOrWhiteSpace(cli.Cidr)
        ? rangeService.GenerateUsableAddresses(
            selectedInterface.IpAddress,
            selectedInterface.SubnetMask,
            cli.MaximumHosts)
        : rangeService.GenerateFromCidr(cli.Cidr, cli.MaximumHosts);

    if (addresses.Any(address => !IpAddressHelper.IsPrivate(address)))
    {
        throw new ScanOperationException(DiagnosticCatalog.PublicAddressScope(cli.Cidr));
    }

    PrintSelectedNetwork(selectedInterface, addresses.Count, profile, scanOptions.Ports.Count);

    if (interactive && !Confirm("Iniciar o scan?", defaultYes: true))
    {
        Console.WriteLine("Scan cancelado.");
        return;
    }

    Console.WriteLine("\nDescoberta iniciada. Pressiona Ctrl+C para cancelar.\n");
    object outputLock = new();
    HashSet<string> printed = new(StringComparer.OrdinalIgnoreCase);
    IProgress<ScanProgress> progress = new InlineProgress<ScanProgress>(update =>
    {
        if (update.Device is null)
            return;

        lock (outputLock)
        {
            if (!printed.Add(update.Device.IpAddressText))
                return;

            Console.WriteLine(
                $"ONLINE  {update.Device.IpAddressText,-15}  " +
                $"{update.Device.ResponseTimeDisplay,-8}  " +
                $"{update.Device.HostnameDisplay,-30}  " +
                $"{update.Device.OpenPortsText}");
        }
    });

    NetworkScannerService scanner = new();
    NetworkScanResult result = await scanner.ScanAsync(
        addresses,
        selectedInterface,
        scanOptions,
        progress,
        cancellation.Token);

    if (!cli.SkipHistory)
    {
        try
        {
            await new NetworkHistoryService().ApplyAndSaveAsync(result, cancellation.Token);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            result = result.WithAdditionalDiagnostic(
                DiagnosticCatalog.OptionalFileOperationFailed("histórico local", "guardar snapshot"));
        }
    }

    PrintResult(result);

    ExportService exportService = new();
    if (!string.IsNullOrWhiteSpace(cli.JsonPath))
    {
        await ExportSafelyAsync(
            () => exportService.ExportJsonAsync(result, cli.JsonPath, cancellation.Token),
            cli.JsonPath);
        Console.WriteLine($"JSON guardado em: {Path.GetFullPath(cli.JsonPath)}");
    }

    if (!string.IsNullOrWhiteSpace(cli.CsvPath))
    {
        await ExportSafelyAsync(
            () => exportService.ExportCsvAsync(result, cli.CsvPath, cancellation.Token),
            cli.CsvPath);
        Console.WriteLine($"CSV guardado em:  {Path.GetFullPath(cli.CsvPath)}");
    }

    if (!string.IsNullOrWhiteSpace(cli.HtmlPath))
    {
        await ExportSafelyAsync(
            () => exportService.ExportHtmlAsync(result, cli.HtmlPath, cancellation.Token),
            cli.HtmlPath);
        Console.WriteLine($"HTML guardado em: {Path.GetFullPath(cli.HtmlPath)}");
    }

    if (!string.IsNullOrWhiteSpace(cli.GraphMlPath))
    {
        await ExportSafelyAsync(
            () => exportService.ExportGraphMlAsync(result, cli.GraphMlPath, cancellation.Token),
            cli.GraphMlPath);
        Console.WriteLine($"GraphML guardado em: {Path.GetFullPath(cli.GraphMlPath)}");
    }
}
catch (OperationCanceledException)
{
    PrintDiagnostic(DiagnosticCatalog.OperationCancelled(), Console.Error);
    Environment.ExitCode = 130;
}
catch (Exception exception)
{
    ScanDiagnostic diagnostic = DiagnosticMapper.FromException(exception);
    PrintDiagnostic(diagnostic, Console.Error);
    Environment.ExitCode = GetExitCode(diagnostic);
}

static async Task ExportSafelyAsync(Func<Task> export, string path)
{
    try
    {
        await export();
    }
    catch (OperationCanceledException)
    {
        throw;
    }
    catch (Exception exception)
    {
        throw new ScanOperationException(DiagnosticMapper.FromException(exception, path), exception);
    }
}

static ScanOptions BuildScanOptions(ScanProfile profile, string? ports)
{
    ScanOptions defaults = ScanOptions.ForProfile(profile);
    return new ScanOptions
    {
        Profile = defaults.Profile,
        MaximumHostConcurrency = defaults.MaximumHostConcurrency,
        MaximumPortConcurrency = defaults.MaximumPortConcurrency,
        PingTimeoutMs = defaults.PingTimeoutMs,
        ConnectTimeoutMs = defaults.ConnectTimeoutMs,
        DiscoveryTimeoutMs = defaults.DiscoveryTimeoutMs,
        EnableIcmp = defaults.EnableIcmp,
        EnableTcpDiscovery = defaults.EnableTcpDiscovery,
        EnableArp = defaults.EnableArp,
        EnableMulticastDiscovery = defaults.EnableMulticastDiscovery,
        EnableNetBiosDiscovery = defaults.EnableNetBiosDiscovery,
        EnableServiceProbes = defaults.EnableServiceProbes,
        DiscoveryPorts = defaults.DiscoveryPorts,
        Ports = string.IsNullOrWhiteSpace(ports)
            ? defaults.Ports
            : ServiceCatalog.ParsePortSpecification(ports)
    };
}

static void PrintHeader()
{
    Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
    Console.WriteLine("║                 LOCAL NETWORK SCANNER                       ║");
    Console.WriteLine("║     Descoberta multicamada · inventário · segurança         ║");
    Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
}

static void PrintInterfaces(IReadOnlyList<LocalNetworkInterface> interfaces)
{
    Console.WriteLine("\nInterfaces IPv4 ativas:\n");
    for (int index = 0; index < interfaces.Count; index++)
    {
        LocalNetworkInterface item = interfaces[index];
        Console.WriteLine($"[{index + 1}] {item.Name} — {item.Description}");
        Console.WriteLine($"    IP/rede:   {item.IpAddress}/{item.PrefixLength} ({item.NetworkCidr})");
        Console.WriteLine($"    Gateway:   {item.GatewayAddress?.ToString() ?? "—"}");
        Console.WriteLine($"    MAC:       {(string.IsNullOrWhiteSpace(item.MacAddress) ? "—" : item.MacAddress)}");
        Console.WriteLine($"    Ligação:   {item.InterfaceType} · {item.SpeedMbps:N0} Mbps");
        Console.WriteLine($"    Wi-Fi:     {item.WifiSummary}");
        Console.WriteLine($"    VLAN:      {item.VlanId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "indisponível"} ({item.VlanConfidence})\n");
    }
}

static LocalNetworkInterface SelectInterface(
    IReadOnlyList<LocalNetworkInterface> interfaces,
    string? selector,
    bool interactive)
{
    if (!string.IsNullOrWhiteSpace(selector))
    {
        if (int.TryParse(selector, out int index) && index >= 1 && index <= interfaces.Count)
            return interfaces[index - 1];

        LocalNetworkInterface? named = interfaces.FirstOrDefault(item =>
            item.Name.Contains(selector, StringComparison.OrdinalIgnoreCase) ||
            item.Description.Contains(selector, StringComparison.OrdinalIgnoreCase));
        return named ?? throw new ScanOperationException(DiagnosticCatalog.InvalidInterface(selector));
    }

    if (!interactive)
        return interfaces[0];

    PrintInterfaces(interfaces);
    while (true)
    {
        Console.Write($"Seleciona a interface [1-{interfaces.Count}]: ");
        if (int.TryParse(Console.ReadLine(), out int index) && index >= 1 && index <= interfaces.Count)
            return interfaces[index - 1];
        Console.WriteLine("Seleção inválida.");
    }
}

static ScanProfile AskProfile(ScanProfile defaultProfile)
{
    Console.Write($"Perfil [rápido/normal/avançado] (normal): ");
    string? value = Console.ReadLine();
    return string.IsNullOrWhiteSpace(value) ? defaultProfile : CliOptions.ParseProfile(value);
}

static bool Confirm(string message, bool defaultYes)
{
    Console.Write($"{message} [{(defaultYes ? "S/n" : "s/N")}]: ");
    string? answer = Console.ReadLine()?.Trim();
    if (string.IsNullOrWhiteSpace(answer))
        return defaultYes;
    return answer.Equals("s", StringComparison.OrdinalIgnoreCase) ||
           answer.Equals("sim", StringComparison.OrdinalIgnoreCase) ||
           answer.Equals("y", StringComparison.OrdinalIgnoreCase) ||
           answer.Equals("yes", StringComparison.OrdinalIgnoreCase);
}

static void PrintSelectedNetwork(
    LocalNetworkInterface networkInterface,
    int addressCount,
    ScanProfile profile,
    int portCount)
{
    Console.WriteLine("\nConfiguração:");
    Console.WriteLine($"  Interface:  {networkInterface.Name} ({networkInterface.IpAddress})");
    Console.WriteLine($"  Rede:       {networkInterface.NetworkCidr}");
    Console.WriteLine($"  Gateway:    {networkInterface.GatewayAddress?.ToString() ?? "—"}");
    Console.WriteLine($"  VLAN:       {networkInterface.VlanId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "não exposta pelo SO"}");
    Console.WriteLine($"  Wi-Fi:      {networkInterface.WifiSummary}");
    Console.WriteLine($"  Perfil:     {profile} · {addressCount:N0} IPs · {portCount:N0} portas/host");
}

static void PrintResult(NetworkScanResult result)
{
    Console.WriteLine("\n════════════════════ RESULTADO ════════════════════");
    Console.WriteLine($"IPs analisados:       {result.AddressesScanned:N0}");
    Console.WriteLine($"Dispositivos online:  {result.Devices.Count:N0}");
    Console.WriteLine($"Duração:              {result.Duration.TotalSeconds:F1} s");

    if (result.Devices.Count > 0)
    {
        Console.WriteLine("\nIP               PING      HOSTNAME                       MAC                RISCO  PORTAS");
        Console.WriteLine(new string('─', 118));
        foreach (NetworkDevice device in result.Devices)
        {
            Console.WriteLine(
                $"{Truncate(device.IpAddressText, 15),-15}  " +
                $"{Truncate(device.ResponseTimeDisplay, 8),-8}  " +
                $"{Truncate(device.HostnameDisplay, 29),-29}  " +
                $"{Truncate(device.MacDisplay, 17),-17}  " +
                $"{device.RiskLevel,-5}  {device.OpenPortsText}");
            Console.WriteLine($"                 ↳ {device.DeviceType} · {device.DiscoveryText} · {device.TopologyText}");
            foreach (string finding in device.SecurityFindings)
                Console.WriteLine($"                   ⚠ {finding}");
        }
    }

    if (result.Diagnostics.Count > 0)
    {
        Console.WriteLine("\nDiagnósticos do scan:");
        foreach (ScanDiagnostic diagnostic in result.Diagnostics)
            PrintDiagnostic(diagnostic, Console.Out, compact: true);
    }
    else if (result.Warnings.Count > 0)
    {
        Console.WriteLine("\nLimites técnicos reportados com transparência:");
        foreach (string warning in result.Warnings)
            Console.WriteLine($"  • {warning}");
    }

    Console.WriteLine();
}

static void PrintDiagnostic(ScanDiagnostic diagnostic, TextWriter writer, bool compact = false)
{
    string severity = diagnostic.Severity switch
    {
        DiagnosticSeverity.Information => "Informação",
        DiagnosticSeverity.Warning => "Aviso",
        DiagnosticSeverity.Error => "Erro",
        _ => "Crítico"
    };
    string category = diagnostic.Category switch
    {
        DiagnosticCategory.User => "Utilizador",
        DiagnosticCategory.Network => "Rede",
        DiagnosticCategory.Device => "Dispositivo/dados",
        _ => "Aplicação"
    };
    string indent = compact ? "  " : Environment.NewLine;

    writer.WriteLine($"{indent}[{diagnostic.Code}] {severity} · Origem provável: {category}");
    writer.WriteLine($"{(compact ? "    " : string.Empty)}{diagnostic.Message}");
    writer.WriteLine($"{(compact ? "    " : string.Empty)}Ação recomendada: {diagnostic.RecommendedAction}");
    if (!string.IsNullOrWhiteSpace(diagnostic.Target))
        writer.WriteLine($"{(compact ? "    " : string.Empty)}Alvo: {diagnostic.Target}");
    if (diagnostic.Context.Count > 0)
    {
        string context = string.Join(
            ", ",
            diagnostic.Context.Select(item => $"{item.Key}={item.Value}"));
        writer.WriteLine($"{(compact ? "    " : string.Empty)}Contexto: {context}");
    }
}

static int GetExitCode(ScanDiagnostic diagnostic) => diagnostic.Category switch
{
    DiagnosticCategory.User => 2,
    DiagnosticCategory.Network => 3,
    DiagnosticCategory.Device => 4,
    _ => 1
};

static string Truncate(string value, int length) =>
    value.Length <= length ? value : value[..(length - 1)] + "…";

static void PrintHelp()
{
    Console.WriteLine(
        """
        Local Network Scanner

        Uso:
          dotnet run --project LocalNetworkScanner.Cli -- interfaces
          dotnet run --project LocalNetworkScanner.Cli -- scan [opções]

        Opções:
          -i, --interface <índice|nome>  Interface a utilizar
          --cidr <rede/prefixo>          Rede privada explícita, ex. 192.168.1.0/24
          --profile <quick|standard|advanced>
          --ports <lista>                Ex. 22,80,443 ou 1-1024 ou quick|top|deep|all
          --max-hosts <n>                Limite até 65536 (predefinição: 4096)
          --json <ficheiro>              Exportar relatório JSON
          --csv <ficheiro>               Exportar relatório CSV UTF-8
          --html <ficheiro>              Exportar relatório HTML autónomo
          --graphml <ficheiro>           Exportar grafo de topologia GraphML
          --no-history                   Não comparar/guardar snapshot local
          -h, --help                     Mostrar esta ajuda

        Sem argumentos é iniciado o modo interativo. Usa apenas em redes próprias
        ou em redes para as quais tens autorização explícita.

        Códigos de saída:
          0  Concluído (pode conter avisos não fatais LNS-*)
          1  Falha da aplicação     2  Entrada do utilizador
          3  Falha de rede          4  Falha de dispositivo/dados
          130 Operação cancelada
        """);
}

internal sealed class CliOptions
{
    public string Command { get; private set; } = "scan";
    public bool ShowHelp { get; private set; }
    public string? InterfaceSelector { get; private set; }
    public string? Cidr { get; private set; }
    public ScanProfile Profile { get; private set; } = ScanProfile.Standard;
    public string? Ports { get; private set; }
    public string? JsonPath { get; private set; }
    public string? CsvPath { get; private set; }
    public string? HtmlPath { get; private set; }
    public string? GraphMlPath { get; private set; }
    public int MaximumHosts { get; private set; } = IpRangeService.DefaultMaximumAddresses;
    public bool SkipHistory { get; private set; }

    public static CliOptions Parse(string[] arguments)
    {
        CliOptions result = new();
        int index = 0;
        if (arguments.Length > 0 && !arguments[0].StartsWith('-'))
        {
            result.Command = arguments[0].ToLowerInvariant();
            index++;
        }

        if (result.Command is "help")
            result.ShowHelp = true;
        else if (result.Command is not ("scan" or "interfaces"))
            throw new ScanInputException(DiagnosticCatalog.InvalidCommand(result.Command));

        while (index < arguments.Length)
        {
            string argument = arguments[index++];
            switch (argument)
            {
                case "-h" or "--help":
                    result.ShowHelp = true;
                    break;
                case "-i" or "--interface":
                    result.InterfaceSelector = NextValue(arguments, ref index, argument);
                    break;
                case "--cidr":
                    result.Cidr = NextValue(arguments, ref index, argument);
                    break;
                case "--profile":
                    result.Profile = ParseProfile(NextValue(arguments, ref index, argument));
                    break;
                case "--ports":
                    result.Ports = NextValue(arguments, ref index, argument);
                    break;
                case "--json":
                    result.JsonPath = NextValue(arguments, ref index, argument);
                    break;
                case "--csv":
                    result.CsvPath = NextValue(arguments, ref index, argument);
                    break;
                case "--html":
                    result.HtmlPath = NextValue(arguments, ref index, argument);
                    break;
                case "--graphml":
                    result.GraphMlPath = NextValue(arguments, ref index, argument);
                    break;
                case "--max-hosts":
                    string value = NextValue(arguments, ref index, argument);
                    if (!int.TryParse(value, out int maximum) || maximum is < 1 or > IpRangeService.AbsoluteMaximumAddresses)
                        throw new ScanInputException(
                            DiagnosticCatalog.InvalidScanConfiguration("--max-hosts"));
                    result.MaximumHosts = maximum;
                    break;
                case "--no-history":
                    result.SkipHistory = true;
                    break;
                case "--no-prompt" or "-y" or "--yes":
                    break;
                default:
                    throw new ScanInputException(DiagnosticCatalog.InvalidCommand(argument));
            }
        }

        return result;
    }

    public static ScanProfile ParseProfile(string value) => value.Trim().ToLowerInvariant() switch
    {
        "quick" or "rapido" or "rápido" => ScanProfile.Quick,
        "standard" or "normal" => ScanProfile.Standard,
        "advanced" or "avancado" or "avançado" or "deep" or "profundo" => ScanProfile.Deep,
        _ => throw new ScanInputException(DiagnosticCatalog.InvalidProfile(value))
    };

    private static string NextValue(string[] arguments, ref int index, string option)
    {
        if (index >= arguments.Length)
            throw new ScanInputException(DiagnosticCatalog.MissingOptionValue(option));
        return arguments[index++];
    }
}

internal sealed class InlineProgress<T> : IProgress<T>
{
    private readonly Action<T> _handler;

    public InlineProgress(Action<T> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _handler = handler;
    }

    public void Report(T value) => _handler(value);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
