// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Wpf;
using LocalNetworkScanner.Wpf.Controls;
using LocalNetworkScanner.Wpf.Services;
using LocalNetworkScanner.Wpf.ViewModels;

internal static class DocumentationScreenshotRenderer
{
    private const string Copyright =
        "Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.";

    public static void Render(string outputDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        Directory.CreateDirectory(outputDirectory);

        App application = new();
        application.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        application.InitializeComponent();
        string settingsDirectory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string settingsPath = Path.Combine(settingsDirectory, "settings.json");

        MainWindow? mainWindow = null;
        TopologyWindow? topologyWindow = null;
        try
        {
            NetworkScanResult result = CreateDemoResult();
            NetworkMap map = new NetworkTopologyMapService().Build(result);
            mainWindow = new MainWindow(new UiSettingsService(settingsPath))
            {
                Width = 1_600,
                Height = 960,
                ShowActivated = false,
                ShowInTaskbar = false
            };
            MainViewModel viewModel = mainWindow.ViewModel;
            viewModel.NetworkInterfaces.Clear();
            viewModel.NetworkInterfaces.Add(result.NetworkInterface);
            viewModel.SelectedNetworkInterface = result.NetworkInterface;
            viewModel.NetworkCidr = result.NetworkInterface.NetworkCidr;
            viewModel.SelectedProfile = viewModel.Profiles[1];
            viewModel.IsScanConfigurationExpanded = true;
            viewModel.IsCustomScanSettingsExpanded = false;
            viewModel.UseCustomScanSettings = false;

            SetPrivateField(viewModel, "_lastResult", result);
            InvokePrivate(viewModel, "ReplaceDevices", result.Devices);
            SetPrivateProperty(viewModel, nameof(MainViewModel.TopologyMap), map);
            SetPrivateProperty(viewModel, nameof(MainViewModel.ScannedCount), result.AddressesScanned);
            SetPrivateProperty(viewModel, nameof(MainViewModel.OnlineCount), result.Devices.Count);
            SetPrivateProperty(viewModel, nameof(MainViewModel.NewCount), result.Devices.Count(device => device.IsNew));
            SetPrivateProperty(viewModel, nameof(MainViewModel.RiskCount), result.Devices.Count(device =>
                device.RiskLevel.Equals("Alto", StringComparison.OrdinalIgnoreCase) ||
                device.RiskLevel.Equals("Médio", StringComparison.OrdinalIgnoreCase)));
            SetPrivateProperty(viewModel, nameof(MainViewModel.ElapsedText), "00:08");
            SetPrivateProperty(viewModel, nameof(MainViewModel.ProgressPercentage), 100d);
            SetPrivateProperty(viewModel, nameof(MainViewModel.ProgressPhase), "Concluído");
            SetPrivateProperty(
                viewModel,
                nameof(MainViewModel.StatusMessage),
                $"Scan concluído · {result.Devices.Count} dispositivos encontrados");
            viewModel.ExportCsvCommand.RaiseCanExecuteChanged();
            viewModel.ExportJsonCommand.RaiseCanExecuteChanged();
            viewModel.ExportHtmlCommand.RaiseCanExecuteChanged();
            viewModel.ExportSupportJsonCommand.RaiseCanExecuteChanged();
            viewModel.ExportGraphMlCommand.RaiseCanExecuteChanged();
            viewModel.SelectedDevice = viewModel.Devices.First(row => row.IpAddress == "10.42.0.20");

            RenderElement(
                mainWindow,
                Path.Combine(outputDirectory, "main-window-current.png"),
                1_600,
                960,
                "Janela principal com inventário de rede inteiramente sintético.");

            topologyWindow = new TopologyWindow(viewModel)
            {
                Width = 1_600,
                Height = 960,
                ShowActivated = false,
                ShowInTaskbar = false
            };
            PrepareTopologyWindow(topologyWindow, map, 1_600, 960);
            RenderElement(
                topologyWindow,
                Path.Combine(outputDirectory, "topology-window-current.png"),
                1_600,
                960,
                "Topologia opcional com dispositivos e relações inteiramente sintéticos.");
        }
        finally
        {
            if (topologyWindow is not null)
                topologyWindow.Close();
            if (mainWindow is not null)
                mainWindow.Close();
            application.Shutdown();
            if (Directory.Exists(settingsDirectory))
                Directory.Delete(settingsDirectory, recursive: true);
        }
    }

    private static void PrepareTopologyWindow(
        TopologyWindow window,
        NetworkMap map,
        double width,
        double height)
    {
        if (window.Content is not FrameworkElement content)
            throw new InvalidOperationException("A janela de topologia não contém uma raiz WPF renderizável.");

        content.Measure(new Size(width, height));
        content.Arrange(new Rect(0, 0, width, height));
        content.UpdateLayout();
        NetworkTopologyControl graph = (NetworkTopologyControl)window.FindName("TopologyGraph");
        graph.FitToView();
        TextBlock summary = (TextBlock)window.FindName("TopologySummaryText");
        int alertCount = map.Nodes.Count(node =>
            node.RiskLevel.Equals("Alto", StringComparison.OrdinalIgnoreCase) ||
            node.RiskLevel.Equals("Médio", StringComparison.OrdinalIgnoreCase));
        summary.Text = $"{map.Nodes.Count:N0} nós · {map.Edges.Count:N0} ligações · {alertCount:N0} com alertas";
    }

    private static void RenderElement(
        FrameworkElement element,
        string path,
        double width,
        double height,
        string description)
    {
        FrameworkElement renderTarget = element is Window { Content: FrameworkElement content }
            ? content
            : element;
        renderTarget.Measure(new Size(width, height));
        renderTarget.Arrange(new Rect(0, 0, width, height));
        renderTarget.UpdateLayout();

        DpiScale dpi = VisualTreeHelper.GetDpi(renderTarget);
        int pixelWidth = checked((int)Math.Ceiling(width * dpi.DpiScaleX));
        int pixelHeight = checked((int)Math.Ceiling(height * dpi.DpiScaleY));
        RenderTargetBitmap bitmap = new(
            pixelWidth,
            pixelHeight,
            dpi.PixelsPerInchX,
            dpi.PixelsPerInchY,
            PixelFormats.Pbgra32);
        DrawingVisual composed = new();
        using (DrawingContext drawing = composed.RenderOpen())
        {
            Brush background = Application.Current.Resources["WindowBackgroundBrush"] as Brush ?? Brushes.White;
            Rect bounds = new(0, 0, width, height);
            drawing.DrawRectangle(background, null, bounds);
            drawing.DrawRectangle(new VisualBrush(renderTarget), null, bounds);
        }
        bitmap.Render(composed);

        BitmapMetadata metadata = new("png")
        {
            Copyright = Copyright,
            Comment = description
        };
        metadata.SetQuery("/tEXt/{str=Copyright}", Copyright);
        metadata.SetQuery("/tEXt/{str=Description}", description);
        PngBitmapEncoder encoder = new();
        encoder.Frames.Add(BitmapFrame.Create(bitmap, null, metadata, null));
        using FileStream stream = File.Create(path);
        encoder.Save(stream);
    }

    private static NetworkScanResult CreateDemoResult()
    {
        LocalNetworkInterface networkInterface = new()
        {
            Id = "documentation-demo",
            Name = "Ethernet de demonstração",
            Description = "Interface sintética para imagens da documentação",
            IpAddress = IPAddress.Parse("10.42.0.10"),
            SubnetMask = IPAddress.Parse("255.255.255.0"),
            GatewayAddress = IPAddress.Parse("10.42.0.1"),
            MacAddress = "02:00:00:00:00:10",
            InterfaceType = NetworkInterfaceType.Ethernet,
            SpeedBitsPerSecond = 2_500_000_000,
            SupportsMulticast = true,
            VlanId = 10,
            VlanConfidence = ConfidenceLevel.High
        };

        List<NetworkDevice> devices =
        [
            CreateDevice(
                "10.42.0.1", "Gateway principal", "Router / gateway", "02:00:00:00:00:01",
                2, "Baixo", 8, [53, 80, 443], DiscoveryMethod.Icmp | DiscoveryMethod.Arp | DiscoveryMethod.Tcp),
            CreateDevice(
                "10.42.0.2", "Switch Core 24", "Switch gerido", "02:00:00:00:00:02",
                3, "Baixo", 12, [22, 161, 443], DiscoveryMethod.Icmp | DiscoveryMethod.Arp | DiscoveryMethod.Tcp | DiscoveryMethod.Snmp),
            CreateDevice(
                "10.42.0.3", "AP Escritório", "Ponto de acesso Wi-Fi", "02:00:00:00:00:03",
                4, "Baixo", 10, [80, 443], DiscoveryMethod.Icmp | DiscoveryMethod.Arp | DiscoveryMethod.Tcp | DiscoveryMethod.Ssdp),
            CreateDevice(
                "10.42.0.20", "PC Design", "Computador Windows", "02:00:00:00:00:20",
                7, "Baixo", 12, [135, 445, 3389], DiscoveryMethod.Icmp | DiscoveryMethod.Arp | DiscoveryMethod.Tcp | DiscoveryMethod.NetBios,
                isFavorite: true,
                isNew: true,
                manufacturer: "Microsoft",
                model: "Estação de trabalho",
                osGuess: "Windows 11"),
            CreateDevice(
                "10.42.0.30", "Impressora Piso 1", "Impressora", "02:00:00:00:00:30",
                12, "Médio", 43, [80, 443, 9100], DiscoveryMethod.Icmp | DiscoveryMethod.Arp | DiscoveryMethod.Tcp | DiscoveryMethod.Mdns | DiscoveryMethod.Ssdp,
                manufacturer: "Fabricante demonstrativo",
                model: "Laser Office"),
            CreateDevice(
                "10.42.0.40", "NAS Equipa", "NAS / armazenamento", "02:00:00:00:00:40",
                5, "Baixo", 18, [22, 443, 445], DiscoveryMethod.Icmp | DiscoveryMethod.Arp | DiscoveryMethod.Tcp | DiscoveryMethod.Mdns,
                manufacturer: "Fabricante demonstrativo",
                model: "Storage 4-Bay"),
            CreateDevice(
                "10.42.0.50", "Câmara Entrada", "Câmara IP", "02:00:00:00:00:50",
                9, "Alto", 72, [23, 80, 554], DiscoveryMethod.Icmp | DiscoveryMethod.Arp | DiscoveryMethod.Tcp | DiscoveryMethod.WsDiscovery,
                manufacturer: "Fabricante demonstrativo",
                model: "Camera PoE")
        ];

        foreach (NetworkDevice device in devices)
        {
            device.Topology = new TopologyAssessment
            {
                SameIpSubnet = true,
                SameLayer2Segment = true,
                Layer2Confidence = ConfidenceLevel.Medium,
                ObservedOnManagedBridge = !device.IpAddress.Equals(IPAddress.Parse("10.42.0.1")),
                SwitchAddress = "10.42.0.2",
                SwitchConfidence = ConfidenceLevel.High,
                VlanId = 10,
                VlanConfidence = ConfidenceLevel.High
            };
        }

        SnmpTopologySnapshot topology = new()
        {
            SwitchAddress = IPAddress.Parse("10.42.0.2"),
            SwitchName = "Switch Core 24",
            SwitchDescription = "Switch gerido de demonstração",
            MacTable = devices
                .Where(device => !device.IpAddress.Equals(IPAddress.Parse("10.42.0.1")))
                .ToDictionary(
                    device => device.MacAddress!,
                    device => (IReadOnlyList<SwitchPortObservation>)
                    [
                        new SwitchPortObservation
                        {
                            MacAddress = device.MacAddress!,
                            BridgePort = device.IpAddress.GetAddressBytes()[3],
                            InterfaceName = $"Gi1/0/{device.IpAddress.GetAddressBytes()[3]}",
                            VlanId = 10,
                            PortPvid = 10,
                            ForwardingDatabaseId = 10
                        }
                    ],
                    StringComparer.OrdinalIgnoreCase),
            LldpNeighbors =
            [
                new LldpNeighborObservation
                {
                    TimeMark = 1,
                    LocalPortNumber = 24,
                    RemoteIndex = 1,
                    LocalPortId = "Gi1/0/24",
                    ChassisIdSubtype = 4,
                    ChassisId = "02:00:00:00:01:01",
                    PortId = "uplink-1",
                    SystemName = "Gateway principal",
                    SystemDescription = "Router de demonstração"
                }
            ]
        };

        return new NetworkScanResult
        {
            NetworkInterface = networkInterface,
            StartedAt = new DateTimeOffset(2026, 8, 12, 12, 0, 0, TimeSpan.Zero),
            CompletedAt = new DateTimeOffset(2026, 8, 12, 12, 0, 8, TimeSpan.Zero),
            AddressesScanned = 254,
            Devices = devices,
            SnmpTopology = topology
        };
    }

    private static NetworkDevice CreateDevice(
        string ipAddress,
        string alias,
        string deviceType,
        string macAddress,
        long latency,
        string riskLevel,
        int riskScore,
        IReadOnlyList<int> ports,
        DiscoveryMethod discoveryMethods,
        bool isFavorite = false,
        bool isNew = false,
        string manufacturer = "Fabricante demonstrativo",
        string model = "Modelo sintético",
        string osGuess = "Indeterminado") => new()
        {
            IpAddress = IPAddress.Parse(ipAddress),
            Alias = alias,
            Hostname = alias.Replace(' ', '-').ToLowerInvariant(),
            FriendlyName = alias,
            MacAddress = macAddress,
            MacAssignee = "Prefixo local de demonstração",
            Manufacturer = manufacturer,
            Model = model,
            IdentityConfidence = ConfidenceLevel.Medium,
            DeviceType = deviceType,
            OsGuess = osGuess,
            IsOnline = true,
            IsFavorite = isFavorite,
            IsNew = isNew,
            HistoryCompared = true,
            ResponseTimeMs = latency,
            ReplyTtl = 64,
            RiskLevel = riskLevel,
            RiskScore = riskScore,
            DiscoveryMethods = discoveryMethods,
            ObservedProtocols = discoveryMethods
                .ToString()
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(value => value.ToUpperInvariant())
                .ToList(),
            Ports = ports.Select(port => new PortScanResult
            {
                Port = port,
                ServiceName = port switch
                {
                    22 => "ssh",
                    23 => "telnet",
                    53 => "dns",
                    80 => "http",
                    135 => "msrpc",
                    161 => "snmp",
                    443 => "https",
                    445 => "smb",
                    554 => "rtsp",
                    3389 => "rdp",
                    9100 => "jetdirect",
                    _ => "serviço"
                }
            }).ToList()
        };

    private static void InvokePrivate(object target, string methodName, object argument)
    {
        MethodInfo method = target.GetType().GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingMethodException(target.GetType().FullName, methodName);
        method.Invoke(target, [argument]);
    }

    private static void SetPrivateProperty<T>(object target, string propertyName, T value)
    {
        PropertyInfo property = target.GetType().GetProperty(propertyName)
            ?? throw new MissingMemberException(target.GetType().FullName, propertyName);
        property.SetValue(target, value);
    }

    private static void SetPrivateField<T>(object target, string fieldName, T value)
    {
        FieldInfo field = target.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingFieldException(target.GetType().FullName, fieldName);
        field.SetValue(target, value);
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
