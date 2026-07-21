using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Windows.Data;
using System.Windows.Threading;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Core.Utilities;
using LocalNetworkScanner.Wpf.Infrastructure;
using LocalNetworkScanner.Wpf.Services;

namespace LocalNetworkScanner.Wpf.ViewModels;

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly NetworkInterfaceService _interfaceService = new();
    private readonly IpRangeService _ipRangeService = new();
    private NetworkScannerService _scanner = new();
    private readonly NetworkHistoryService _history = new();
    private readonly DeviceMetadataService _deviceMetadata = new();
    private readonly ExportService _export = new();
    private readonly WakeOnLanService _wakeOnLan = new();
    private readonly OuiDatabaseService _ouiDatabase = new();
    private readonly NetworkTopologyMapService _topologyMapService = new();
    private readonly UserDialogService _dialogs;
    private readonly DesktopActionService _desktopActions;
    private readonly UiSettingsService _settingsService;
    private readonly UiSettings _loadedSettings;
    private readonly Dictionary<string, DeviceRowViewModel> _devicesByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, NetworkDevice> _pendingDeviceUpdates = new(StringComparer.OrdinalIgnoreCase);
    private readonly DispatcherTimer _uiTimer;

    private LocalNetworkInterface? _selectedNetworkInterface;
    private ScanProfileOption _selectedProfile;
    private DeviceFilterOption _selectedFilter;
    private DeviceRowViewModel? _selectedDevice;
    private NetworkMapNode? _selectedTopologyNode;
    private NetworkMap? _topologyMap;
    private NetworkScanResult? _lastResult;
    private CancellationTokenSource? _scanCancellation;
    private DateTimeOffset _scanStartedAt;
    private string _networkCidr = string.Empty;
    private string _searchText = string.Empty;
    private string _customPorts = string.Empty;
    private string _statusMessage = "A preparar a aplicação...";
    private string _progressPhase = "Pronto";
    private string _elapsedText = "00:00";
    private double _progressPercentage;
    private bool _isAdvancedMode;
    private bool _isTopologyView;
    private bool _isLoadingInterfaces;
    private bool _isScanning;
    private bool _isCancelling;
    private bool _suppressAutomaticCidr;
    private bool _hasInitialized;
    private bool _isSynchronizingTopologySelection;
    private int _maximumHosts = 4_096;
    private int _maximumHostConcurrency = 96;
    private int _maximumPortConcurrency = 48;
    private int _pingTimeoutMs = 550;
    private int _connectTimeoutMs = 350;
    private int _discoveryTimeoutMs = 1_200;
    private bool _enableIcmp = true;
    private bool _enableTcpDiscovery = true;
    private bool _enableArp = true;
    private bool _enableMulticastDiscovery = true;
    private bool _enableNetBiosDiscovery = true;
    private bool _enableSnmpTopology;
    private string _snmpSwitchAddress = string.Empty;
    private string _snmpCommunity = string.Empty;
    private int _snmpTimeoutMs = 900;
    private bool _enableServiceProbes = true;
    private int _scannedCount;
    private int _onlineCount;
    private int _newCount;
    private int _riskCount;
    private int _visibleDeviceCount;

    public MainViewModel(
        UserDialogService dialogs,
        DesktopActionService desktopActions,
        UiSettingsService settingsService)
    {
        ArgumentNullException.ThrowIfNull(dialogs);
        ArgumentNullException.ThrowIfNull(desktopActions);
        ArgumentNullException.ThrowIfNull(settingsService);

        _dialogs = dialogs;
        _desktopActions = desktopActions;
        _settingsService = settingsService;
        _loadedSettings = settingsService.Load();

        Profiles =
        [
            new ScanProfileOption(ScanProfile.Quick, "Rápido", "Descoberta ágil e portas essenciais"),
            new ScanProfileOption(ScanProfile.Standard, "Normal", "Equilíbrio entre velocidade e detalhe"),
            new ScanProfileOption(ScanProfile.Deep, "Profundo", "Mais portas, banners e maior tolerância")
        ];
        Filters =
        [
            new DeviceFilterOption("all", "Todos os dispositivos"),
            new DeviceFilterOption("high", "Risco alto"),
            new DeviceFilterOption("medium", "Risco médio"),
            new DeviceFilterOption("low", "Risco baixo"),
            new DeviceFilterOption("new", "Novos"),
            new DeviceFilterOption("favorite", "Favoritos"),
            new DeviceFilterOption("changed", "Alterados")
        ];

        _selectedProfile = Profiles.FirstOrDefault(item => item.Value == _loadedSettings.Profile) ?? Profiles[1];
        _selectedFilter = Filters[0];
        ApplyLoadedSettings();

        DevicesView = CollectionViewSource.GetDefaultView(Devices);
        DevicesView.Filter = FilterDevice;

        ScanCommand = new AsyncRelayCommand(ScanAsync, CanStartScan, HandleUnexpectedException);
        RefreshInterfacesCommand = new AsyncRelayCommand(
            RefreshInterfacesAsync,
            () => !IsScanning && !IsLoadingInterfaces,
            HandleUnexpectedException);
        CancelCommand = new RelayCommand(CancelScan, () => IsScanning && !IsCancelling);
        ClearResultsCommand = new RelayCommand(ClearResults, () => !IsScanning && Devices.Count > 0);
        ClearSearchCommand = new RelayCommand(() => SearchText = string.Empty, () => SearchText.Length > 0);
        ExportCsvCommand = new AsyncRelayCommand(ExportCsvAsync, CanExport, HandleUnexpectedException);
        ExportJsonCommand = new AsyncRelayCommand(ExportJsonAsync, CanExport, HandleUnexpectedException);
        ExportHtmlCommand = new AsyncRelayCommand(ExportHtmlAsync, CanExport, HandleUnexpectedException);
        ExportGraphMlCommand = new AsyncRelayCommand(ExportGraphMlAsync, CanExport, HandleUnexpectedException);
        SaveDeviceMetadataCommand = new AsyncRelayCommand(
            SaveDeviceMetadataAsync,
            () => SelectedDevice is not null && _lastResult is not null && !IsScanning,
            HandleUnexpectedException);
        WakeOnLanCommand = new AsyncRelayCommand(
            WakeOnLanAsync,
            () => SelectedDevice?.HasMacAddress == true && SelectedNetworkInterface is not null && !IsScanning,
            HandleUnexpectedException);
        UpdateOuiDatabaseCommand = new AsyncRelayCommand(
            UpdateOuiDatabaseAsync,
            () => !IsScanning && !IsLoadingInterfaces,
            HandleUnexpectedException);
        CopyIpCommand = new RelayCommand(CopyIp, () => SelectedDevice is not null);
        CopyMacCommand = new RelayCommand(CopyMac, () => SelectedDevice?.HasMacAddress == true);
        OpenWebCommand = new RelayCommand(
            () => RunDesktopAction(_desktopActions.OpenWeb, "Interface Web aberta."),
            () => SelectedDevice?.CanOpenWeb == true);
        OpenExplorerCommand = new RelayCommand(
            () => RunDesktopAction(_desktopActions.OpenExplorer, "Explorador aberto para o dispositivo."),
            () => SelectedDevice?.CanOpenExplorer == true);
        PingCommand = new RelayCommand(
            () => RunDesktopAction(_desktopActions.OpenPing, "Janela de ping aberta."),
            () => SelectedDevice is not null);
        TracerouteCommand = new RelayCommand(
            () => RunDesktopAction(_desktopActions.OpenTraceroute, "Janela de tracert aberta."),
            () => SelectedDevice is not null);
        RemoteDesktopCommand = new RelayCommand(
            () => RunDesktopAction(_desktopActions.OpenRemoteDesktop, "Ligação de Ambiente de Trabalho Remoto iniciada."),
            () => SelectedDevice?.CanOpenRemoteDesktop == true);
        ShowListViewCommand = new RelayCommand(() => IsTopologyView = false);
        ShowTopologyViewCommand = new RelayCommand(() => IsTopologyView = true);

        _uiTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(150)
        };
        _uiTimer.Tick += OnUiTimerTick;
    }

    public ObservableCollection<LocalNetworkInterface> NetworkInterfaces { get; } = [];
    public ObservableCollection<DeviceRowViewModel> Devices { get; } = [];
    public ObservableCollection<string> Warnings { get; } = [];
    public IReadOnlyList<ScanProfileOption> Profiles { get; }
    public IReadOnlyList<DeviceFilterOption> Filters { get; }
    public ICollectionView DevicesView { get; }

    public AsyncRelayCommand ScanCommand { get; }
    public AsyncRelayCommand RefreshInterfacesCommand { get; }
    public RelayCommand CancelCommand { get; }
    public RelayCommand ClearResultsCommand { get; }
    public RelayCommand ClearSearchCommand { get; }
    public AsyncRelayCommand ExportCsvCommand { get; }
    public AsyncRelayCommand ExportJsonCommand { get; }
    public AsyncRelayCommand ExportHtmlCommand { get; }
    public AsyncRelayCommand ExportGraphMlCommand { get; }
    public AsyncRelayCommand SaveDeviceMetadataCommand { get; }
    public AsyncRelayCommand WakeOnLanCommand { get; }
    public AsyncRelayCommand UpdateOuiDatabaseCommand { get; }
    public RelayCommand CopyIpCommand { get; }
    public RelayCommand CopyMacCommand { get; }
    public RelayCommand OpenWebCommand { get; }
    public RelayCommand OpenExplorerCommand { get; }
    public RelayCommand PingCommand { get; }
    public RelayCommand TracerouteCommand { get; }
    public RelayCommand RemoteDesktopCommand { get; }
    public RelayCommand ShowListViewCommand { get; }
    public RelayCommand ShowTopologyViewCommand { get; }

    public LocalNetworkInterface? SelectedNetworkInterface
    {
        get => _selectedNetworkInterface;
        set
        {
            if (!SetProperty(ref _selectedNetworkInterface, value))
                return;

            if (!_suppressAutomaticCidr && value is not null)
                NetworkCidr = value.NetworkCidr;

            OnPropertyChanged(nameof(SelectedInterfaceSummary));
            OnPropertyChanged(nameof(SelectedInterfaceWifi));
            OnPropertyChanged(nameof(SelectedInterfaceVlan));
            RaiseScanCanExecuteChanged();
            WakeOnLanCommand.RaiseCanExecuteChanged();
        }
    }

    public ScanProfileOption SelectedProfile
    {
        get => _selectedProfile;
        set
        {
            if (value is not null && SetProperty(ref _selectedProfile, value))
                OnPropertyChanged(nameof(SelectedProfileDescription));
        }
    }

    public DeviceFilterOption SelectedFilter
    {
        get => _selectedFilter;
        set
        {
            if (value is not null && SetProperty(ref _selectedFilter, value))
                RefreshFilter();
        }
    }

    public DeviceRowViewModel? SelectedDevice
    {
        get => _selectedDevice;
        set
        {
            if (SetProperty(ref _selectedDevice, value))
            {
                RaiseSelectionCanExecuteChanged();
                SynchronizeTopologySelectionFromDevice();
            }
        }
    }

    public NetworkMapNode? SelectedTopologyNode
    {
        get => _selectedTopologyNode;
        set
        {
            if (!SetProperty(ref _selectedTopologyNode, value))
                return;

            if (_isSynchronizingTopologySelection)
                return;

            string? ipAddress = value?.IpAddress?.ToString();
            DeviceRowViewModel? matchingDevice = ipAddress is not null &&
                _devicesByIp.TryGetValue(ipAddress, out DeviceRowViewModel? device)
                    ? device
                    : null;
            if (!ReferenceEquals(matchingDevice, SelectedDevice))
            {
                _isSynchronizingTopologySelection = true;
                try
                {
                    SelectedDevice = matchingDevice;
                }
                finally
                {
                    _isSynchronizingTopologySelection = false;
                }
            }
        }
    }

    public NetworkMap? TopologyMap
    {
        get => _topologyMap;
        private set
        {
            if (SetProperty(ref _topologyMap, value))
            {
                OnPropertyChanged(nameof(HasTopologyMap));
                SynchronizeTopologySelectionFromDevice();
            }
        }
    }

    public bool HasTopologyMap => TopologyMap?.Nodes.Count > 0;

    public bool IsTopologyView
    {
        get => _isTopologyView;
        set
        {
            if (!SetProperty(ref _isTopologyView, value))
                return;

            OnPropertyChanged(nameof(IsListView));
            StatusMessage = value
                ? "Vista de topologia ativa. As ligações indicam a respetiva evidência e confiança."
                : "Vista de lista ativa.";
        }
    }

    public bool IsListView => !IsTopologyView;

    public string NetworkCidr
    {
        get => _networkCidr;
        set
        {
            if (SetProperty(ref _networkCidr, value ?? string.Empty))
                RaiseScanCanExecuteChanged();
        }
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (!SetProperty(ref _searchText, value ?? string.Empty))
                return;

            RefreshFilter();
            ClearSearchCommand.RaiseCanExecuteChanged();
        }
    }

    public string CustomPorts
    {
        get => _customPorts;
        set => SetProperty(ref _customPorts, value ?? string.Empty);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    public string ProgressPhase
    {
        get => _progressPhase;
        private set => SetProperty(ref _progressPhase, value);
    }

    public string ElapsedText
    {
        get => _elapsedText;
        private set => SetProperty(ref _elapsedText, value);
    }

    public double ProgressPercentage
    {
        get => _progressPercentage;
        private set => SetProperty(ref _progressPercentage, value);
    }

    public bool IsAdvancedMode
    {
        get => _isAdvancedMode;
        set
        {
            if (!SetProperty(ref _isAdvancedMode, value))
                return;

            OnPropertyChanged(nameof(ModeLabel));
            OnPropertyChanged(nameof(SelectedProfileDescription));
        }
    }

    public bool IsLoadingInterfaces
    {
        get => _isLoadingInterfaces;
        private set
        {
            if (!SetProperty(ref _isLoadingInterfaces, value))
                return;

            OnPropertyChanged(nameof(CanEditScanSettings));
            RefreshInterfacesCommand.RaiseCanExecuteChanged();
            RaiseScanCanExecuteChanged();
        }
    }

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (!SetProperty(ref _isScanning, value))
                return;

            OnPropertyChanged(nameof(CanEditScanSettings));
            OnPropertyChanged(nameof(IsNotScanning));
            RaiseAllCanExecuteChanged();
        }
    }

    public bool IsCancelling
    {
        get => _isCancelling;
        private set
        {
            if (SetProperty(ref _isCancelling, value))
                CancelCommand.RaiseCanExecuteChanged();
        }
    }

    public int MaximumHosts
    {
        get => _maximumHosts;
        set => SetProperty(ref _maximumHosts, value);
    }

    public int MaximumHostConcurrency
    {
        get => _maximumHostConcurrency;
        set => SetProperty(ref _maximumHostConcurrency, value);
    }

    public int MaximumPortConcurrency
    {
        get => _maximumPortConcurrency;
        set => SetProperty(ref _maximumPortConcurrency, value);
    }

    public int PingTimeoutMs
    {
        get => _pingTimeoutMs;
        set => SetProperty(ref _pingTimeoutMs, value);
    }

    public int ConnectTimeoutMs
    {
        get => _connectTimeoutMs;
        set => SetProperty(ref _connectTimeoutMs, value);
    }

    public int DiscoveryTimeoutMs
    {
        get => _discoveryTimeoutMs;
        set => SetProperty(ref _discoveryTimeoutMs, value);
    }

    public bool EnableIcmp
    {
        get => _enableIcmp;
        set => SetProperty(ref _enableIcmp, value);
    }

    public bool EnableTcpDiscovery
    {
        get => _enableTcpDiscovery;
        set => SetProperty(ref _enableTcpDiscovery, value);
    }

    public bool EnableArp
    {
        get => _enableArp;
        set => SetProperty(ref _enableArp, value);
    }

    public bool EnableMulticastDiscovery
    {
        get => _enableMulticastDiscovery;
        set => SetProperty(ref _enableMulticastDiscovery, value);
    }

    public bool EnableNetBiosDiscovery
    {
        get => _enableNetBiosDiscovery;
        set => SetProperty(ref _enableNetBiosDiscovery, value);
    }

    public bool EnableSnmpTopology
    {
        get => _enableSnmpTopology;
        set => SetProperty(ref _enableSnmpTopology, value);
    }

    public string SnmpSwitchAddress
    {
        get => _snmpSwitchAddress;
        set => SetProperty(ref _snmpSwitchAddress, value ?? string.Empty);
    }

    public string SnmpCommunity
    {
        get => _snmpCommunity;
        set => SetProperty(ref _snmpCommunity, value ?? string.Empty);
    }

    public int SnmpTimeoutMs
    {
        get => _snmpTimeoutMs;
        set => SetProperty(ref _snmpTimeoutMs, value);
    }

    public bool EnableServiceProbes
    {
        get => _enableServiceProbes;
        set => SetProperty(ref _enableServiceProbes, value);
    }

    public int ScannedCount
    {
        get => _scannedCount;
        private set => SetProperty(ref _scannedCount, value);
    }

    public int OnlineCount
    {
        get => _onlineCount;
        private set => SetProperty(ref _onlineCount, value);
    }

    public int NewCount
    {
        get => _newCount;
        private set => SetProperty(ref _newCount, value);
    }

    public int RiskCount
    {
        get => _riskCount;
        private set => SetProperty(ref _riskCount, value);
    }

    public int VisibleDeviceCount
    {
        get => _visibleDeviceCount;
        private set => SetProperty(ref _visibleDeviceCount, value);
    }

    public bool CanEditScanSettings => !IsScanning && !IsLoadingInterfaces;
    public bool IsNotScanning => !IsScanning;
    public bool HasWarnings => Warnings.Count > 0;
    public string ModeLabel => IsAdvancedMode ? "Modo avançado" : "Modo simples";
    public string SelectedProfileDescription => IsAdvancedMode
        ? $"{SelectedProfile.Description}. As opções abaixo substituem o perfil."
        : SelectedProfile.Description;
    public string SelectedInterfaceSummary => SelectedNetworkInterface is null
        ? "Nenhuma interface selecionada"
        : $"{SelectedNetworkInterface.IpAddress}/{SelectedNetworkInterface.PrefixLength}  ·  " +
          $"Gateway {SelectedNetworkInterface.GatewayAddress?.ToString() ?? "—"}  ·  " +
          $"{SelectedNetworkInterface.SpeedMbps:N0} Mbps";
    public string SelectedInterfaceWifi => SelectedNetworkInterface?.WifiSummary ?? "—";
    public string SelectedInterfaceVlan => SelectedNetworkInterface?.VlanId is int vlan
        ? $"VLAN {vlan} · confiança {ConfidenceToText(SelectedNetworkInterface.VlanConfidence)}"
        : "VLAN não exposta pelo Windows";

    public async Task InitializeAsync()
    {
        if (_hasInitialized)
            return;

        _hasInitialized = true;
        await RefreshInterfacesAsync();
    }

    public void SaveSettings()
    {
        _settingsService.Save(new UiSettings
        {
            LastInterfaceId = SelectedNetworkInterface?.Id,
            LastInterfaceAddress = SelectedNetworkInterface?.IpAddress.ToString(),
            LastCidr = NetworkCidr,
            Profile = SelectedProfile.Value,
            IsAdvancedMode = IsAdvancedMode,
            CustomPorts = CustomPorts,
            MaximumHosts = MaximumHosts,
            MaximumHostConcurrency = MaximumHostConcurrency,
            MaximumPortConcurrency = MaximumPortConcurrency,
            PingTimeoutMs = PingTimeoutMs,
            ConnectTimeoutMs = ConnectTimeoutMs,
            DiscoveryTimeoutMs = DiscoveryTimeoutMs,
            EnableIcmp = EnableIcmp,
            EnableTcpDiscovery = EnableTcpDiscovery,
            EnableArp = EnableArp,
            EnableMulticastDiscovery = EnableMulticastDiscovery,
            EnableNetBiosDiscovery = EnableNetBiosDiscovery,
            EnableSnmpTopology = EnableSnmpTopology,
            SnmpSwitchAddress = SnmpSwitchAddress,
            SnmpTimeoutMs = SnmpTimeoutMs,
            EnableServiceProbes = EnableServiceProbes
        });
    }

    public void RequestCancellation() => CancelScan();

    public void Dispose()
    {
        _uiTimer.Stop();
        _uiTimer.Tick -= OnUiTimerTick;
        _scanCancellation?.Cancel();
        _scanCancellation?.Dispose();
        _scanCancellation = null;
        _deviceMetadata.Dispose();
        GC.SuppressFinalize(this);
    }

    private void ApplyLoadedSettings()
    {
        _isAdvancedMode = _loadedSettings.IsAdvancedMode;
        _customPorts = _loadedSettings.CustomPorts;
        _maximumHosts = _loadedSettings.MaximumHosts;
        _maximumHostConcurrency = _loadedSettings.MaximumHostConcurrency;
        _maximumPortConcurrency = _loadedSettings.MaximumPortConcurrency;
        _pingTimeoutMs = _loadedSettings.PingTimeoutMs;
        _connectTimeoutMs = _loadedSettings.ConnectTimeoutMs;
        _discoveryTimeoutMs = _loadedSettings.DiscoveryTimeoutMs;
        _enableIcmp = _loadedSettings.EnableIcmp;
        _enableTcpDiscovery = _loadedSettings.EnableTcpDiscovery;
        _enableArp = _loadedSettings.EnableArp;
        _enableMulticastDiscovery = _loadedSettings.EnableMulticastDiscovery;
        _enableNetBiosDiscovery = _loadedSettings.EnableNetBiosDiscovery;
        _enableSnmpTopology = _loadedSettings.EnableSnmpTopology;
        _snmpSwitchAddress = _loadedSettings.SnmpSwitchAddress;
        _snmpTimeoutMs = _loadedSettings.SnmpTimeoutMs;
        _enableServiceProbes = _loadedSettings.EnableServiceProbes;
    }

    private async Task RefreshInterfacesAsync()
    {
        if (IsScanning)
            return;

        IsLoadingInterfaces = true;
        StatusMessage = "A detetar interfaces de rede...";
        try
        {
            LocalNetworkInterface? previousSelection = SelectedNetworkInterface;
            string previousCidr = NetworkCidr;
            string? targetId = previousSelection?.Id ?? _loadedSettings.LastInterfaceId;
            IPAddress? targetAddress = previousSelection?.IpAddress;
            if (targetAddress is null &&
                IPAddress.TryParse(_loadedSettings.LastInterfaceAddress, out IPAddress? savedAddress))
            {
                targetAddress = savedAddress;
            }

            IReadOnlyList<LocalNetworkInterface> interfaces =
                await _interfaceService.GetActiveInterfacesAsync();

            _suppressAutomaticCidr = true;
            try
            {
                NetworkInterfaces.Clear();
                foreach (LocalNetworkInterface networkInterface in interfaces)
                    NetworkInterfaces.Add(networkInterface);

                SelectedNetworkInterface = interfaces.FirstOrDefault(item =>
                    string.Equals(item.Id, targetId, StringComparison.OrdinalIgnoreCase) &&
                    targetAddress is not null &&
                    item.IpAddress.Equals(targetAddress));

                // Migração segura de settings antigos: se só existe o ID do adaptador,
                // escolhe uma entrada mas não reutiliza um CIDR potencialmente pertencente
                // a outro IPv4 do mesmo adaptador.
                SelectedNetworkInterface ??= interfaces.FirstOrDefault(item =>
                    string.Equals(item.Id, targetId, StringComparison.OrdinalIgnoreCase));
                SelectedNetworkInterface ??= interfaces.Count > 0 ? interfaces[0] : null;
            }
            finally
            {
                _suppressAutomaticCidr = false;
            }

            if (SelectedNetworkInterface is null)
            {
                NetworkCidr = string.Empty;
                StatusMessage = "Não foi encontrada uma interface IPv4 ativa.";
                _dialogs.ShowError(
                    "Sem rede ativa",
                    "Liga o computador a uma rede e usa “Atualizar interfaces”.");
                return;
            }

            bool keptCurrentSelection = previousSelection is not null &&
                                        string.Equals(
                                            SelectedNetworkInterface.Id,
                                            previousSelection.Id,
                                            StringComparison.OrdinalIgnoreCase) &&
                                        SelectedNetworkInterface.IpAddress.Equals(previousSelection.IpAddress);
            bool matchesSavedSelection =
                string.Equals(
                    SelectedNetworkInterface.Id,
                    _loadedSettings.LastInterfaceId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    SelectedNetworkInterface.IpAddress.ToString(),
                    _loadedSettings.LastInterfaceAddress,
                    StringComparison.OrdinalIgnoreCase);

            NetworkCidr = keptCurrentSelection && !string.IsNullOrWhiteSpace(previousCidr)
                ? previousCidr
                : matchesSavedSelection && !string.IsNullOrWhiteSpace(_loadedSettings.LastCidr)
                    ? _loadedSettings.LastCidr!
                    : SelectedNetworkInterface.NetworkCidr;
            StatusMessage = $"Interface pronta: {SelectedNetworkInterface.Name}.";
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or System.Net.NetworkInformation.NetworkInformationException)
        {
            StatusMessage = "Não foi possível obter as interfaces de rede.";
            _dialogs.ShowError("Erro de rede", exception.Message);
        }
        finally
        {
            IsLoadingInterfaces = false;
        }
    }

    private async Task ScanAsync()
    {
        PreparedScan? prepared = PrepareScan();
        if (prepared is null)
            return;

        ClearResultsCore();
        SaveSettings();
        IsScanning = true;
        IsCancelling = false;
        _scanStartedAt = DateTimeOffset.UtcNow;
        ElapsedText = "00:00";
        ProgressPercentage = 0;
        ProgressPhase = "Preparação";
        StatusMessage = $"A iniciar scan de {prepared.Addresses.Count:N0} endereços...";
        _scanCancellation = new CancellationTokenSource();
        _uiTimer.Start();

        try
        {
            Progress<ScanProgress> progress = new(ApplyProgress);
            NetworkScanResult result = await _scanner.ScanAsync(
                prepared.Addresses,
                prepared.NetworkInterface,
                prepared.Options,
                progress,
                _scanCancellation.Token);

            FlushPendingDeviceUpdates();
            ProgressPhase = "Histórico";
            StatusMessage = "A comparar com o scan anterior...";
            await _history.ApplyAndSaveAsync(result, _scanCancellation.Token);
            await _deviceMetadata.ApplyAsync(result, _scanCancellation.Token);

            _lastResult = result;
            ReplaceDevices(result.Devices);
            UpdateTopologyMap();
            ScannedCount = result.AddressesScanned;
            OnlineCount = result.Devices.Count;
            NewCount = result.Devices.Count(item => item.IsNew);
            RiskCount = result.Devices.Count(item => item.RiskLevel is "Alto" or "Médio");
            ProgressPercentage = 100;
            ProgressPhase = "Concluído";
            StatusMessage = result.Devices.Count == 0
                ? "Scan concluído. Não foram encontrados dispositivos online."
                : $"Scan concluído: {result.Devices.Count:N0} dispositivos online em {result.Duration.TotalSeconds:F1} s.";

            foreach (string warning in result.Warnings)
                Warnings.Add(warning);
            OnPropertyChanged(nameof(HasWarnings));
        }
        catch (OperationCanceledException)
        {
            // Progress<T> publica no Dispatcher. Cede a prioridade uma vez para que
            // observações já enfileiradas entrem no snapshot parcial antes da exportação.
            await Dispatcher.Yield(DispatcherPriority.Background);
            FlushPendingDeviceUpdates();
            IReadOnlyList<NetworkDevice> partialDevices = Devices
                .Select(item => item.Device)
                .OrderBy(item => IpAddressHelper.ToUInt32(item.IpAddress))
                .ToList();
            string partialWarning =
                "Resultado parcial: o scan foi cancelado e alguns dispositivos ou detalhes podem estar em falta.";
            _lastResult = new NetworkScanResult
            {
                NetworkInterface = prepared.NetworkInterface,
                StartedAt = _scanStartedAt,
                CompletedAt = DateTimeOffset.UtcNow,
                AddressesScanned = ScannedCount,
                Devices = partialDevices,
                IsPartial = true,
                Warnings = [partialWarning]
            };
            UpdateTopologyMap();
            Warnings.Clear();
            Warnings.Add(partialWarning);
            OnPropertyChanged(nameof(HasWarnings));
            SelectedDevice ??= Devices.FirstOrDefault();
            ProgressPhase = "Cancelado";
            StatusMessage = partialDevices.Count == 0
                ? "Scan cancelado. O relatório parcial não contém dispositivos concluídos."
                : $"Scan cancelado. {partialDevices.Count:N0} resultados parciais podem ser exportados.";
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException or FormatException or IOException)
        {
            ProgressPhase = "Erro";
            StatusMessage = $"O scan não foi concluído: {exception.Message}";
            _dialogs.ShowError("Não foi possível concluir o scan", exception.Message);
        }
        finally
        {
            UpdateElapsedTime();
            _uiTimer.Stop();
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            IsCancelling = false;
            IsScanning = false;
            RefreshSummaryCounts();
        }
    }

    private PreparedScan? PrepareScan()
    {
        if (SelectedNetworkInterface is null)
        {
            _dialogs.ShowError("Interface necessária", "Seleciona uma interface de rede antes de iniciar.");
            return null;
        }

        try
        {
            ValidateAdvancedValues();
            IReadOnlyList<IPAddress> addresses = _ipRangeService.GenerateFromCidr(
                NetworkCidr,
                IsAdvancedMode ? MaximumHosts : IpRangeService.DefaultMaximumAddresses);

            if (addresses.Any(address => !IpAddressHelper.IsPrivate(address)))
            {
                throw new InvalidOperationException(
                    "Esta aplicação limita-se a redes privadas/locais. O CIDR indicado contém endereços públicos.");
            }

            if (addresses.Count > 4_096 && !_dialogs.Confirm(
                    "Scan de grande dimensão",
                    $"A rede contém {addresses.Count:N0} endereços. O scan pode demorar e gerar bastante tráfego. Continuar?"))
            {
                return null;
            }

            return new PreparedScan(
                SelectedNetworkInterface,
                addresses,
                BuildScanOptions());
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException or FormatException)
        {
            _dialogs.ShowError("Configuração inválida", exception.Message);
            return null;
        }
    }

    private ScanOptions BuildScanOptions()
    {
        ScanOptions defaults = ScanOptions.ForProfile(SelectedProfile.Value);
        if (!IsAdvancedMode)
            return defaults;

        IReadOnlyList<int> ports = string.IsNullOrWhiteSpace(CustomPorts)
            ? defaults.Ports
            : ServiceCatalog.ParsePortSpecification(CustomPorts);

        return new ScanOptions
        {
            Profile = SelectedProfile.Value,
            MaximumHostConcurrency = MaximumHostConcurrency,
            MaximumPortConcurrency = MaximumPortConcurrency,
            PingTimeoutMs = PingTimeoutMs,
            ConnectTimeoutMs = ConnectTimeoutMs,
            DiscoveryTimeoutMs = DiscoveryTimeoutMs,
            EnableIcmp = EnableIcmp,
            EnableTcpDiscovery = EnableTcpDiscovery,
            EnableArp = EnableArp,
            EnableMulticastDiscovery = EnableMulticastDiscovery,
            EnableNetBiosDiscovery = EnableNetBiosDiscovery,
            EnableSnmpTopology = EnableSnmpTopology,
            SnmpSwitchAddress = EnableSnmpTopology
                ? IPAddress.Parse(SnmpSwitchAddress)
                : null,
            SnmpCommunity = EnableSnmpTopology ? SnmpCommunity : null,
            SnmpTimeoutMs = SnmpTimeoutMs,
            EnableServiceProbes = EnableServiceProbes,
            DiscoveryPorts = defaults.DiscoveryPorts,
            Ports = ports
        };
    }

    private void ValidateAdvancedValues()
    {
        if (!IsAdvancedMode)
            return;

        ValidateRange(MaximumHosts, 1, IpRangeService.AbsoluteMaximumAddresses, "Máximo de endereços");
        ValidateRange(MaximumHostConcurrency, 1, 512, "Concorrência por host");
        ValidateRange(MaximumPortConcurrency, 1, 512, "Concorrência por porta");
        ValidateRange(PingTimeoutMs, 50, 30_000, "Timeout de ping");
        ValidateRange(ConnectTimeoutMs, 50, 30_000, "Timeout TCP");
        ValidateRange(DiscoveryTimeoutMs, 100, 30_000, "Timeout de descoberta");
        ValidateRange(SnmpTimeoutMs, 100, 30_000, "Timeout SNMP");

        if (!EnableIcmp && !EnableTcpDiscovery && !EnableMulticastDiscovery)
        {
            throw new InvalidOperationException(
                "Ativa pelo menos um método de descoberta: ICMP, TCP ou mDNS/SSDP.");
        }


        if (EnableSnmpTopology)
        {
            if (!IPAddress.TryParse(SnmpSwitchAddress, out IPAddress? switchAddress) ||
                switchAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                !IpAddressHelper.IsPrivate(switchAddress))
            {
                throw new InvalidOperationException("Indica um endereço IPv4 privado válido para o switch SNMP.");
            }

            if (string.IsNullOrWhiteSpace(SnmpCommunity))
                throw new InvalidOperationException("Indica a comunidade SNMP para consultar a tabela MAC do switch.");
        }
    }

    private static void ValidateRange(int value, int minimum, int maximum, string label)
    {
        if (value < minimum || value > maximum)
            throw new ArgumentOutOfRangeException(label, $"{label} deve estar entre {minimum:N0} e {maximum:N0}.");
    }

    private void ApplyProgress(ScanProgress update)
    {
        ProgressPhase = update.Phase;
        ProgressPercentage = update.Percentage;
        OnlineCount = update.Online;
        StatusMessage = update.Message;

        if (update.Phase.Equals("Descoberta", StringComparison.OrdinalIgnoreCase))
            ScannedCount = update.Completed;

        if (update.Device is not null)
            _pendingDeviceUpdates[update.Device.IpAddressText] = update.Device;
    }

    private void OnUiTimerTick(object? sender, EventArgs e)
    {
        UpdateElapsedTime();
        FlushPendingDeviceUpdates();
    }

    private void UpdateElapsedTime()
    {
        if (_scanStartedAt == default)
            return;

        TimeSpan elapsed = DateTimeOffset.UtcNow - _scanStartedAt;
        ElapsedText = elapsed.TotalHours >= 1
            ? elapsed.ToString(@"hh\:mm\:ss", CultureInfo.InvariantCulture)
            : elapsed.ToString(@"mm\:ss", CultureInfo.InvariantCulture);
    }

    private void FlushPendingDeviceUpdates()
    {
        if (_pendingDeviceUpdates.Count == 0)
            return;

        foreach ((string ipAddress, NetworkDevice device) in _pendingDeviceUpdates)
        {
            if (_devicesByIp.TryGetValue(ipAddress, out DeviceRowViewModel? existing))
            {
                existing.Update(device);
            }
            else
            {
                DeviceRowViewModel row = new(device);
                _devicesByIp[ipAddress] = row;
                Devices.Add(row);
            }
        }
        _pendingDeviceUpdates.Clear();

        RefreshSummaryCounts();
        UpdateVisibleDeviceCount();
        ClearResultsCommand.RaiseCanExecuteChanged();
    }

    private void ReplaceDevices(IReadOnlyList<NetworkDevice> devices)
    {
        string? selectedIp = SelectedDevice?.IpAddress;
        List<DeviceRowViewModel> finalRows = new(devices.Count);
        Dictionary<string, DeviceRowViewModel> finalByIp = new(StringComparer.OrdinalIgnoreCase);
        foreach (NetworkDevice device in devices)
        {
            string ipAddress = device.IpAddressText;
            if (!_devicesByIp.TryGetValue(ipAddress, out DeviceRowViewModel? row))
            {
                row = new DeviceRowViewModel(device);
            }
            else
            {
                row.Update(device);
            }

            finalRows.Add(row);
            finalByIp[ipAddress] = row;
        }

        for (int index = 0; index < finalRows.Count; index++)
        {
            DeviceRowViewModel row = finalRows[index];
            if (index < Devices.Count && ReferenceEquals(Devices[index], row))
                continue;

            int existingIndex = Devices.IndexOf(row);
            if (existingIndex >= 0)
                Devices.Move(existingIndex, index);
            else
                Devices.Insert(index, row);
        }
        while (Devices.Count > finalRows.Count)
            Devices.RemoveAt(Devices.Count - 1);

        _devicesByIp.Clear();
        foreach ((string ipAddress, DeviceRowViewModel row) in finalByIp)
            _devicesByIp[ipAddress] = row;

        SelectedDevice = selectedIp is not null && _devicesByIp.TryGetValue(selectedIp, out DeviceRowViewModel? selected)
            ? selected
            : Devices.FirstOrDefault();
        RefreshFilter();
        ClearResultsCommand.RaiseCanExecuteChanged();
    }

    private void RefreshSummaryCounts()
    {
        OnlineCount = Math.Max(OnlineCount, Devices.Count(item => item.IsOnline));
        NewCount = Devices.Count(item => item.IsNew);
        RiskCount = Devices.Count(item => item.RiskLevel is "Alto" or "Médio");
    }

    private void UpdateTopologyMap()
    {
        TopologyMap = _lastResult is null ? null : _topologyMapService.Build(_lastResult);
    }

    private void SynchronizeTopologySelectionFromDevice()
    {
        if (_isSynchronizingTopologySelection)
            return;

        NetworkMap? map = TopologyMap;
        DeviceRowViewModel? selectedDevice = SelectedDevice;
        if (map is null || selectedDevice is null)
        {
            if (selectedDevice is null)
                SelectedTopologyNode = null;
            return;
        }

        NetworkMapNode? matchingNode = map.Nodes.FirstOrDefault(node =>
            string.Equals(node.IpAddress?.ToString(), selectedDevice.IpAddress, StringComparison.OrdinalIgnoreCase));
        if (!ReferenceEquals(matchingNode, SelectedTopologyNode))
        {
            _isSynchronizingTopologySelection = true;
            try
            {
                SelectedTopologyNode = matchingNode;
            }
            finally
            {
                _isSynchronizingTopologySelection = false;
            }
        }
    }

    private void CancelScan()
    {
        if (!IsScanning || IsCancelling)
            return;

        IsCancelling = true;
        ProgressPhase = "A cancelar";
        StatusMessage = "A cancelar o scan com segurança...";
        _scanCancellation?.Cancel();
    }

    private void ClearResults()
    {
        if (IsScanning)
            return;

        ClearResultsCore();
        ProgressPhase = "Pronto";
        StatusMessage = "Resultados limpos. Pronto para um novo scan.";
        ElapsedText = "00:00";
    }

    private void ClearResultsCore()
    {
        Devices.Clear();
        _devicesByIp.Clear();
        _pendingDeviceUpdates.Clear();
        Warnings.Clear();
        SelectedDevice = null;
        SelectedTopologyNode = null;
        TopologyMap = null;
        _lastResult = null;
        ScannedCount = 0;
        OnlineCount = 0;
        NewCount = 0;
        RiskCount = 0;
        VisibleDeviceCount = 0;
        ProgressPercentage = 0;
        OnPropertyChanged(nameof(HasWarnings));
        RaiseAllCanExecuteChanged();
    }

    private async Task ExportCsvAsync()
    {
        NetworkScanResult? result = _lastResult;
        if (result is null)
            return;

        string? path = _dialogs.ChooseExportPath(
            "Exportar relatório CSV",
            BuildExportFileName("csv"),
            "Ficheiro CSV (*.csv)|*.csv|Todos os ficheiros (*.*)|*.*");
        if (path is null)
            return;

        try
        {
            await _export.ExportCsvAsync(result, path);
            StatusMessage = $"Relatório CSV guardado em {path}.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _dialogs.ShowError("Falha ao exportar", exception.Message);
        }
    }

    private async Task ExportJsonAsync()
    {
        NetworkScanResult? result = _lastResult;
        if (result is null)
            return;

        string? path = _dialogs.ChooseExportPath(
            "Exportar relatório JSON",
            BuildExportFileName("json"),
            "Ficheiro JSON (*.json)|*.json|Todos os ficheiros (*.*)|*.*");
        if (path is null)
            return;

        try
        {
            await _export.ExportJsonAsync(result, path);
            StatusMessage = $"Relatório JSON guardado em {path}.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _dialogs.ShowError("Falha ao exportar", exception.Message);
        }
    }

    private async Task ExportHtmlAsync()
    {
        NetworkScanResult? result = _lastResult;
        if (result is null)
            return;

        string? path = _dialogs.ChooseExportPath(
            "Exportar relatório HTML",
            BuildExportFileName("html"),
            "Página HTML (*.html)|*.html|Todos os ficheiros (*.*)|*.*");
        if (path is null)
            return;

        try
        {
            await _export.ExportHtmlAsync(result, path);
            StatusMessage = $"Relatório HTML guardado em {path}.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _dialogs.ShowError("Falha ao exportar", exception.Message);
        }
    }

    private async Task ExportGraphMlAsync()
    {
        NetworkScanResult? result = _lastResult;
        if (result is null)
            return;

        string? path = _dialogs.ChooseExportPath(
            "Guardar topologia GraphML",
            BuildExportFileName("graphml"),
            "Mapa GraphML (*.graphml)|*.graphml|Todos os ficheiros (*.*)|*.*");
        if (path is null)
            return;

        try
        {
            await _export.ExportGraphMlAsync(result, path);
            StatusMessage = $"Topologia GraphML guardada em {path}.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _dialogs.ShowError("Falha ao guardar GraphML", exception.Message);
        }
    }

    private async Task SaveDeviceMetadataAsync()
    {
        DeviceRowViewModel? selected = SelectedDevice;
        NetworkScanResult? result = _lastResult;
        if (selected is null || result is null)
            return;

        try
        {
            await _deviceMetadata.SaveAsync(selected.Device, result.NetworkInterface.NetworkCidr);
            selected.Update(selected.Device);
            RefreshFilter();
            StatusMessage = $"Preferências de {selected.Hostname} guardadas.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _dialogs.ShowError("Falha ao guardar o dispositivo", exception.Message);
        }
    }

    private async Task WakeOnLanAsync()
    {
        DeviceRowViewModel? selected = SelectedDevice;
        LocalNetworkInterface? networkInterface = SelectedNetworkInterface;
        if (selected is null || networkInterface is null || !selected.HasMacAddress)
            return;

        if (!_dialogs.Confirm(
                "Wake-on-LAN",
                $"Enviar um magic packet para {selected.Hostname} ({selected.MacAddress})?"))
        {
            return;
        }

        try
        {
            IPAddress broadcast = IpAddressHelper.GetBroadcastAddress(
                networkInterface.IpAddress,
                networkInterface.SubnetMask);
            await _wakeOnLan.SendAsync(selected.MacAddress, broadcast);
            StatusMessage = $"Magic packet enviado para {selected.Hostname}.";
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or FormatException or System.Net.Sockets.SocketException)
        {
            _dialogs.ShowError("Falha no Wake-on-LAN", exception.Message);
        }
    }

    private async Task UpdateOuiDatabaseAsync()
    {
        if (!_dialogs.Confirm(
                "Atualizar fabricantes",
                "Transferir a base pública OUI diretamente da IEEE? O ficheiro fica guardado apenas neste computador."))
        {
            return;
        }

        StatusMessage = "A transferir a base de fabricantes da IEEE...";
        try
        {
            await _ouiDatabase.UpdateAsync();
            _scanner = new NetworkScannerService();
            StatusMessage = "Base de fabricantes atualizada. Será usada no próximo scan.";
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            _dialogs.ShowError("Não foi possível atualizar fabricantes", exception.Message);
            StatusMessage = "A base integrada de fabricantes continua disponível.";
        }
    }

    private void CopyIp()
    {
        if (SelectedDevice is null)
            return;

        StatusMessage = _dialogs.TryCopyText(SelectedDevice.IpAddress)
            ? $"IP {SelectedDevice.IpAddress} copiado."
            : "O Windows não permitiu aceder à área de transferência.";
    }

    private void CopyMac()
    {
        if (SelectedDevice is null || !SelectedDevice.HasMacAddress)
            return;

        StatusMessage = _dialogs.TryCopyText(SelectedDevice.MacAddress)
            ? $"MAC {SelectedDevice.MacAddress} copiado."
            : "O Windows não permitiu aceder à área de transferência.";
    }

    private void RunDesktopAction(Action<NetworkDevice> action, string successMessage)
    {
        if (SelectedDevice is null)
            return;

        try
        {
            action(SelectedDevice.Device);
            StatusMessage = successMessage;
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or Win32Exception or UriFormatException)
        {
            _dialogs.ShowError("Não foi possível abrir a ação", exception.Message);
        }
    }

    private bool FilterDevice(object item)
    {
        if (item is not DeviceRowViewModel device)
            return false;

        bool categoryMatches = SelectedFilter.Key switch
        {
            "high" => device.RiskLevel == "Alto",
            "medium" => device.RiskLevel == "Médio",
            "low" => device.RiskLevel == "Baixo",
            "new" => device.IsNew,
            "favorite" => device.IsFavorite,
            "changed" => device.HasChanges,
            _ => true
        };
        if (!categoryMatches)
            return false;

        string search = SearchText.Trim();
        if (search.Length == 0)
            return true;

        string searchable = string.Join(
            ' ',
            device.Hostname,
            device.IpAddress,
            device.MacAddress,
            device.Manufacturer,
            device.DeviceType,
            device.OpenPorts,
            device.Protocols,
            device.RiskLevel,
            device.Notes,
            device.NetBiosName,
            device.Workgroup);
        return search.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .All(token => searchable.Contains(token, StringComparison.CurrentCultureIgnoreCase));
    }

    private void RefreshFilter()
    {
        DevicesView.Refresh();
        UpdateVisibleDeviceCount();
    }

    private void UpdateVisibleDeviceCount() =>
        VisibleDeviceCount = DevicesView.Cast<object>().Count();

    private bool CanStartScan() =>
        !IsScanning &&
        !IsLoadingInterfaces &&
        SelectedNetworkInterface is not null &&
        !string.IsNullOrWhiteSpace(NetworkCidr);

    private bool CanExport() => _lastResult is not null && !IsScanning;

    private string BuildExportFileName(string extension)
    {
        string partial = _lastResult?.IsPartial == true ? "-parcial" : string.Empty;
        return $"scan-rede{partial}-{DateTime.Now:yyyyMMdd-HHmm}.{extension}";
    }

    private void RaiseScanCanExecuteChanged() => ScanCommand.RaiseCanExecuteChanged();

    private void RaiseSelectionCanExecuteChanged()
    {
        CopyIpCommand.RaiseCanExecuteChanged();
        CopyMacCommand.RaiseCanExecuteChanged();
        OpenWebCommand.RaiseCanExecuteChanged();
        OpenExplorerCommand.RaiseCanExecuteChanged();
        PingCommand.RaiseCanExecuteChanged();
        TracerouteCommand.RaiseCanExecuteChanged();
        RemoteDesktopCommand.RaiseCanExecuteChanged();
        SaveDeviceMetadataCommand.RaiseCanExecuteChanged();
        WakeOnLanCommand.RaiseCanExecuteChanged();
    }

    private void RaiseAllCanExecuteChanged()
    {
        ScanCommand.RaiseCanExecuteChanged();
        RefreshInterfacesCommand.RaiseCanExecuteChanged();
        CancelCommand.RaiseCanExecuteChanged();
        ClearResultsCommand.RaiseCanExecuteChanged();
        ExportCsvCommand.RaiseCanExecuteChanged();
        ExportJsonCommand.RaiseCanExecuteChanged();
        ExportHtmlCommand.RaiseCanExecuteChanged();
        ExportGraphMlCommand.RaiseCanExecuteChanged();
        UpdateOuiDatabaseCommand.RaiseCanExecuteChanged();
        SaveDeviceMetadataCommand.RaiseCanExecuteChanged();
        WakeOnLanCommand.RaiseCanExecuteChanged();
        RaiseSelectionCanExecuteChanged();
    }

    private void HandleUnexpectedException(Exception exception)
    {
        StatusMessage = "Ocorreu um erro inesperado.";
        _dialogs.ShowError("Erro inesperado", exception.Message);
    }

    private static string ConfidenceToText(ConfidenceLevel confidence) => confidence switch
    {
        ConfidenceLevel.High => "alta",
        ConfidenceLevel.Medium => "média",
        ConfidenceLevel.Low => "baixa",
        _ => "desconhecida"
    };

    private sealed record PreparedScan(
        LocalNetworkInterface NetworkInterface,
        IReadOnlyList<IPAddress> Addresses,
        ScanOptions Options);
}
