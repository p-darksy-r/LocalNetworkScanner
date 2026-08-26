// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
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
    private ThemeModeOption _selectedTheme;
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
    private string _vendorDatabaseStatus = BuildVendorDatabaseStatus();
    private string _progressPhase = "Pronto";
    private string _elapsedText = "00:00";
    private double _progressPercentage;
    private bool _useCustomScanSettings;
    private bool _isCustomScanSettingsExpanded;
    private bool _isScanConfigurationExpanded = true;
    private bool _isLoadingInterfaces;
    private bool _isScanning;
    private bool _isCancelling;
    private bool _isSavingDeviceMetadata;
    private bool _isOnboardingVisible = true;
    private bool _suppressAutomaticCidr;
    private bool _hasInitialized;
    private bool _isSynchronizingTopologySelection;
    private long _progressGeneration;
    private long _activeProgressGeneration;
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
    private bool _enableUpnpDescription = true;
    private bool _enableNetBiosDiscovery = true;
    private bool _enableHistory = true;
    private bool _enableSnmpDeviceDiscovery;
    private bool _enableSnmpTopology;
    private string _snmpSwitchAddress = string.Empty;
    private string _snmpCommunity = string.Empty;
    private int _snmpTimeoutMs = 900;
    private bool _enableNmapDiscovery;
    private string _nmapExecutablePath = string.Empty;
    private int _nmapTimeoutMs = 120_000;
    private bool _enableServiceProbes = true;
    private int _scannedCount;
    private int _onlineCount;
    private int _newCount;
    private int _riskCount;
    private int _visibleDeviceCount;
    private int _inputValidationErrorCount;

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
        LocalizationService.SetLanguage(_loadedSettings.Language, notify: false);
        BuildLocalizedOptions();

        _selectedProfile = Profiles.FirstOrDefault(item => item.Value == _loadedSettings.Profile) ?? Profiles[1];
        AppThemeMode savedTheme = Enum.IsDefined(_loadedSettings.Theme)
            ? _loadedSettings.Theme
            : AppThemeMode.Light;
        _selectedTheme = ThemeModes.First(item => item.Value == savedTheme);
        _selectedFilter = Filters[0];
        ApplyLoadedSettings();
        LocalizationService.LanguageChanged += OnLanguageChanged;

        DevicesView = CollectionViewSource.GetDefaultView(Devices);
        DevicesView.Filter = FilterDevice;

        ScanCommand = new AsyncRelayCommand(ScanAsync, CanStartScan, HandleUnexpectedScanException);
        RefreshInterfacesCommand = new AsyncRelayCommand(
            RefreshInterfacesAsync,
            () => !IsScanning && !IsLoadingInterfaces,
            HandleUnexpectedException);
        CancelCommand = new RelayCommand(CancelScan, () => IsScanning && !IsCancelling);
        ClearResultsCommand = new RelayCommand(
            ClearResults,
            () => !IsScanning && !IsSavingDeviceMetadata && Devices.Count > 0);
        ClearSearchCommand = new RelayCommand(() => SearchText = string.Empty, () => SearchText.Length > 0);
        ResetFiltersCommand = new RelayCommand(
            ResetFilters,
            () => SearchText.Length > 0 || !SelectedFilter.Key.Equals("all", StringComparison.Ordinal));
        DismissOnboardingCommand = new RelayCommand(
            DismissOnboarding,
            () => IsOnboardingVisible);
        ResetProfileOverridesCommand = new RelayCommand(ResetProfileOverrides);
        ExportCsvCommand = new AsyncRelayCommand(ExportCsvAsync, CanExport, HandleUnexpectedException);
        ExportJsonCommand = new AsyncRelayCommand(ExportJsonAsync, CanExport, HandleUnexpectedException);
        ExportHtmlCommand = new AsyncRelayCommand(ExportHtmlAsync, CanExport, HandleUnexpectedException);
        ExportSupportJsonCommand = new AsyncRelayCommand(
            ExportSupportJsonAsync,
            CanExport,
            HandleUnexpectedException);
        ExportGraphMlCommand = new AsyncRelayCommand(ExportGraphMlAsync, CanExport, HandleUnexpectedException);
        DeleteHistoryCommand = new AsyncRelayCommand(
            DeleteHistoryAsync,
            () => !IsScanning && !IsLoadingInterfaces,
            HandleUnexpectedException);
        SaveDeviceMetadataCommand = new AsyncRelayCommand(
            SaveDeviceMetadataAsync,
            () => CanEditSelectedDeviceMetadata,
            HandleUnexpectedException);
        WakeOnLanCommand = new AsyncRelayCommand(
            WakeOnLanAsync,
            () => SelectedDevice?.HasMacAddress == true && SelectedNetworkInterface is not null && !IsScanning,
            HandleUnexpectedException);
        UpdateOuiDatabaseCommand = new AsyncRelayCommand(
            UpdateOuiDatabaseAsync,
            () => !IsScanning && !IsLoadingInterfaces,
            HandleUnexpectedException);
        ResetOuiDatabaseCommand = new RelayCommand(
            ResetOuiDatabase,
            () => !IsScanning &&
                !IsLoadingInterfaces &&
                File.Exists(OuiDatabaseService.DatabasePath));
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
        ToggleThemeCommand = new RelayCommand(ToggleTheme);

        _uiTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(150)
        };
        _uiTimer.Tick += OnUiTimerTick;
    }

    public ObservableCollection<LocalNetworkInterface> NetworkInterfaces { get; } = [];
    public ObservableCollection<DeviceRowViewModel> Devices { get; } = [];
    public ObservableCollection<DiagnosticRowViewModel> Diagnostics { get; } = [];
    public ObservableCollection<string> Warnings { get; } = [];
    public IReadOnlyList<ScanProfileOption> Profiles { get; private set; } = [];
    public IReadOnlyList<ThemeModeOption> ThemeModes { get; private set; } = [];
    public IReadOnlyList<DeviceFilterOption> Filters { get; private set; } = [];
    public ICollectionView DevicesView { get; }

    public AsyncRelayCommand ScanCommand { get; }
    public AsyncRelayCommand RefreshInterfacesCommand { get; }
    public RelayCommand CancelCommand { get; }
    public RelayCommand ClearResultsCommand { get; }
    public RelayCommand ClearSearchCommand { get; }
    public RelayCommand ResetFiltersCommand { get; }
    public RelayCommand DismissOnboardingCommand { get; }
    public RelayCommand ResetProfileOverridesCommand { get; }
    public AsyncRelayCommand ExportCsvCommand { get; }
    public AsyncRelayCommand ExportJsonCommand { get; }
    public AsyncRelayCommand ExportHtmlCommand { get; }
    public AsyncRelayCommand ExportSupportJsonCommand { get; }
    public AsyncRelayCommand ExportGraphMlCommand { get; }
    public AsyncRelayCommand DeleteHistoryCommand { get; }
    public AsyncRelayCommand SaveDeviceMetadataCommand { get; }
    public AsyncRelayCommand WakeOnLanCommand { get; }
    public AsyncRelayCommand UpdateOuiDatabaseCommand { get; }
    public RelayCommand ResetOuiDatabaseCommand { get; }
    public RelayCommand CopyIpCommand { get; }
    public RelayCommand CopyMacCommand { get; }
    public RelayCommand OpenWebCommand { get; }
    public RelayCommand OpenExplorerCommand { get; }
    public RelayCommand PingCommand { get; }
    public RelayCommand TracerouteCommand { get; }
    public RelayCommand RemoteDesktopCommand { get; }
    public RelayCommand ToggleThemeCommand { get; }

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
            if (value is null || !SetProperty(ref _selectedProfile, value))
                return;

            if (!IsNmapProfileEligible)
                EnableNmapDiscovery = false;

            OnPropertyChanged(nameof(SelectedProfileDescription));
            OnPropertyChanged(nameof(IsNmapProfileEligible));
            OnPropertyChanged(nameof(HasNmapPathValidationError));
            OnPropertyChanged(nameof(HasBlockingInputValidationErrors));
            OnPropertyChanged(nameof(InputValidationMessage));
            NotifyCustomOverridesChanged();
            RaiseScanCanExecuteChanged();
        }
    }

    public ThemeModeOption SelectedTheme
    {
        get => _selectedTheme;
        set
        {
            if (value is null || !SetProperty(ref _selectedTheme, value))
                return;

            OnPropertyChanged(nameof(SelectedThemeDescription));
            OnPropertyChanged(nameof(ThemeGlyph));
            OnPropertyChanged(nameof(ThemeButtonToolTip));
            OnPropertyChanged(nameof(ThemeButtonAutomationName));
            OnPropertyChanged(nameof(ThemeButtonHelpText));
        }
    }

    public DeviceFilterOption SelectedFilter
    {
        get => _selectedFilter;
        set
        {
            if (value is not null && SetProperty(ref _selectedFilter, value))
            {
                RefreshFilter();
                ResetFiltersCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public DeviceRowViewModel? SelectedDevice
    {
        get => _selectedDevice;
        set
        {
            if (SetProperty(ref _selectedDevice, value))
            {
                OnPropertyChanged(nameof(CanEditSelectedDeviceMetadata));
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
            ResetFiltersCommand.RaiseCanExecuteChanged();
        }
    }

    public string CustomPorts
    {
        get => _customPorts;
        set => SetCustomScanProperty(ref _customPorts, value ?? string.Empty);
    }

    public string StatusMessage
    {
        get => L(_statusMessage);
        private set => SetProperty(ref _statusMessage, value);
    }

    public string VendorDatabaseStatus
    {
        get => L(_vendorDatabaseStatus);
        private set => SetProperty(ref _vendorDatabaseStatus, value);
    }

    public string ProgressPhase
    {
        get => L(_progressPhase);
        private set
        {
            if (SetProperty(ref _progressPhase, value))
                NotifyEmptyStateChanged();
        }
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

    public bool UseCustomScanSettings
    {
        get => _useCustomScanSettings;
        set
        {
            if (!SetProperty(ref _useCustomScanSettings, value))
                return;

            OnPropertyChanged(nameof(IsAdvancedMode));
            OnPropertyChanged(nameof(SelectedProfileDescription));
            OnPropertyChanged(nameof(HasNmapPathValidationError));
            OnPropertyChanged(nameof(HasBlockingInputValidationErrors));
            OnPropertyChanged(nameof(InputValidationMessage));
            NotifyCustomOverridesChanged();
            RaiseScanCanExecuteChanged();
        }
    }

    // Alias mantido para bindings e preferências de versões anteriores à separação
    // entre expandir o painel e ativar substituições ao perfil.
    public bool IsAdvancedMode
    {
        get => UseCustomScanSettings;
        set => UseCustomScanSettings = value;
    }

    public bool IsCustomScanSettingsExpanded
    {
        get => _isCustomScanSettingsExpanded;
        set => SetProperty(ref _isCustomScanSettingsExpanded, value);
    }

    public bool IsScanConfigurationExpanded
    {
        get => _isScanConfigurationExpanded;
        set
        {
            if (!SetProperty(ref _isScanConfigurationExpanded, value))
                return;

            OnPropertyChanged(nameof(ScanConfigurationToggleLabel));
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
            DeleteHistoryCommand.RaiseCanExecuteChanged();
            UpdateOuiDatabaseCommand.RaiseCanExecuteChanged();
            ResetOuiDatabaseCommand.RaiseCanExecuteChanged();
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
            OnPropertyChanged(nameof(CanEditSelectedDeviceMetadata));
            OnPropertyChanged(nameof(IsNotScanning));
            NotifyEmptyStateChanged();
            RaiseAllCanExecuteChanged();
        }
    }

    public bool IsCancelling
    {
        get => _isCancelling;
        private set
        {
            if (!SetProperty(ref _isCancelling, value))
                return;

            NotifyEmptyStateChanged();
            CancelCommand.RaiseCanExecuteChanged();
        }
    }

    public bool IsSavingDeviceMetadata
    {
        get => _isSavingDeviceMetadata;
        private set
        {
            if (!SetProperty(ref _isSavingDeviceMetadata, value))
                return;

            OnPropertyChanged(nameof(CanEditSelectedDeviceMetadata));
            SaveDeviceMetadataCommand.RaiseCanExecuteChanged();
            ClearResultsCommand.RaiseCanExecuteChanged();
            RaiseScanCanExecuteChanged();
        }
    }

    public int MaximumHosts
    {
        get => _maximumHosts;
        set => SetCustomScanProperty(ref _maximumHosts, value);
    }

    public int MaximumHostConcurrency
    {
        get => _maximumHostConcurrency;
        set => SetCustomScanProperty(ref _maximumHostConcurrency, value);
    }

    public int MaximumPortConcurrency
    {
        get => _maximumPortConcurrency;
        set => SetCustomScanProperty(ref _maximumPortConcurrency, value);
    }

    public int PingTimeoutMs
    {
        get => _pingTimeoutMs;
        set => SetCustomScanProperty(ref _pingTimeoutMs, value);
    }

    public int ConnectTimeoutMs
    {
        get => _connectTimeoutMs;
        set => SetCustomScanProperty(ref _connectTimeoutMs, value);
    }

    public int DiscoveryTimeoutMs
    {
        get => _discoveryTimeoutMs;
        set => SetCustomScanProperty(ref _discoveryTimeoutMs, value);
    }

    public bool EnableIcmp
    {
        get => _enableIcmp;
        set => SetCustomScanProperty(ref _enableIcmp, value);
    }

    public bool EnableTcpDiscovery
    {
        get => _enableTcpDiscovery;
        set => SetCustomScanProperty(ref _enableTcpDiscovery, value);
    }

    public bool EnableArp
    {
        get => _enableArp;
        set => SetCustomScanProperty(ref _enableArp, value);
    }

    public bool EnableMulticastDiscovery
    {
        get => _enableMulticastDiscovery;
        set
        {
            if (!SetCustomScanProperty(ref _enableMulticastDiscovery, value))
                return;

            if (!value)
                EnableUpnpDescription = false;
        }
    }

    public bool EnableUpnpDescription
    {
        get => _enableUpnpDescription;
        set => SetCustomScanProperty(ref _enableUpnpDescription, value);
    }

    public bool EnableNetBiosDiscovery
    {
        get => _enableNetBiosDiscovery;
        set => SetCustomScanProperty(ref _enableNetBiosDiscovery, value);
    }

    public bool EnableHistory
    {
        get => _enableHistory;
        set => SetProperty(ref _enableHistory, value);
    }

    public bool EnableSnmpDeviceDiscovery
    {
        get => _enableSnmpDeviceDiscovery;
        set
        {
            if (SetCustomScanProperty(ref _enableSnmpDeviceDiscovery, value))
                OnPropertyChanged(nameof(IsSnmpEnabled));
        }
    }

    public bool EnableSnmpTopology
    {
        get => _enableSnmpTopology;
        set
        {
            if (SetCustomScanProperty(ref _enableSnmpTopology, value))
                OnPropertyChanged(nameof(IsSnmpEnabled));
        }
    }

    public string SnmpSwitchAddress
    {
        get => _snmpSwitchAddress;
        set => SetCustomScanProperty(ref _snmpSwitchAddress, value ?? string.Empty);
    }

    public string SnmpCommunity
    {
        get => _snmpCommunity;
        set => SetProperty(ref _snmpCommunity, value ?? string.Empty);
    }

    public int SnmpTimeoutMs
    {
        get => _snmpTimeoutMs;
        set => SetCustomScanProperty(ref _snmpTimeoutMs, value);
    }

    public bool EnableNmapDiscovery
    {
        get => _enableNmapDiscovery;
        set
        {
            if (!SetCustomScanProperty(ref _enableNmapDiscovery, value && IsNmapProfileEligible))
                return;

            NotifyNmapValidationChanged();
        }
    }

    public string NmapExecutablePath
    {
        get => _nmapExecutablePath;
        set
        {
            if (SetCustomScanProperty(ref _nmapExecutablePath, value ?? string.Empty))
                NotifyNmapValidationChanged();
        }
    }

    public int NmapTimeoutMs
    {
        get => _nmapTimeoutMs;
        set => SetCustomScanProperty(ref _nmapTimeoutMs, value);
    }

    public bool EnableServiceProbes
    {
        get => _enableServiceProbes;
        set => SetCustomScanProperty(ref _enableServiceProbes, value);
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
    public bool CanEditSelectedDeviceMetadata =>
        SelectedDevice is not null && _lastResult is not null && !IsScanning && !IsSavingDeviceMetadata;
    public bool IsNotScanning => !IsScanning;
    public bool HasNoVisibleDevices => Devices.Count > 0 && VisibleDeviceCount == 0;
    public bool IsOnboardingVisible
    {
        get => _isOnboardingVisible;
        private set
        {
            if (!SetProperty(ref _isOnboardingVisible, value))
                return;

            DismissOnboardingCommand.RaiseCanExecuteChanged();
        }
    }

    public bool HasUnsavedDeviceMetadata => Devices.Any(device => device.IsMetadataDirty);
    public string ScanConfigurationToggleLabel => IsScanConfigurationExpanded
        ? L("Ocultar configuração")
        : L("Configuração do scan");
    public string EmptyStateTitle => IsCancelling
        ? L("A cancelar o scan")
        : IsScanning
            ? L("A procurar dispositivos")
        : _lastResult?.IsPartial == true
            ? L("Scan cancelado sem resultados completos")
            : _progressPhase.Equals("Erro", StringComparison.Ordinal)
                ? L("O scan não pôde ser concluído")
                : _lastResult is not null
                    ? L("Scan concluído sem dispositivos")
                    : L("Ainda não existem resultados");
    public string EmptyStateDescription => IsCancelling
        ? L("A terminar as operações de rede em curso e a preservar todos os resultados parciais já confirmados.")
        : IsScanning
            ? L("Os dispositivos aparecem aqui à medida que forem confirmados. Podes cancelar sem perder resultados já encontrados.")
        : _lastResult?.IsPartial == true
            ? L("Não foi concluído qualquer dispositivo antes do cancelamento. Consulta os diagnósticos e repete o scan quando estiveres pronto.")
            : _progressPhase.Equals("Erro", StringComparison.Ordinal)
                ? L("Consulta o diagnóstico apresentado abaixo e revê a interface, a rede e os parâmetros antes de tentar novamente.")
                : _lastResult is not null
                    ? L("O scan terminou, mas nenhum dispositivo foi confirmado online. Confirma o CIDR, a interface e eventuais regras de firewall.")
                    : L("Seleciona uma interface e inicia um scan. Os dispositivos aparecem aqui à medida que forem encontrados.");
    public string EmptyStateGlyph => IsCancelling
        ? "\uE711"
        : IsScanning
            ? "\uE895"
        : _progressPhase.Equals("Erro", StringComparison.Ordinal)
            ? "\uEA39"
            : _lastResult?.IsPartial == true
                ? "\uE7BA"
                : _lastResult is not null
                    ? "\uE711"
                    : "\uE950";
    public bool HasInputValidationErrors => _inputValidationErrorCount > 0;
    public bool HasNmapPathValidationError => UseCustomScanSettings &&
        EnableNmapDiscovery &&
        !string.IsNullOrWhiteSpace(NmapExecutablePath) &&
        !IsNmapExecutablePathValid(NmapExecutablePath);
    public bool HasBlockingInputValidationErrors =>
        (UseCustomScanSettings && HasInputValidationErrors) || HasNmapPathValidationError;
    public string InputValidationMessage => HasBlockingInputValidationErrors
        ? HasNmapPathValidationError && _inputValidationErrorCount == 0
            ? L("O caminho explícito do Nmap é inválido. Corrige-o ou deixa-o vazio para autodeteção.")
            : HasNmapPathValidationError
                ? L("Existem valores técnicos inválidos, incluindo o caminho do Nmap. Corrige os campos assinalados.")
                : _inputValidationErrorCount == 1
                    ? L("Existe 1 valor técnico inválido. Corrige o campo assinalado antes de iniciar o scan.")
                    : L($"Existem {_inputValidationErrorCount:N0} valores técnicos inválidos. Corrige os campos assinalados antes de iniciar o scan.")
        : string.Empty;
    public bool HasDiagnostics => Diagnostics.Count > 0;
    public string DiagnosticSummary => Diagnostics.Count == 1
        ? L("1 diagnóstico do scan")
        : L($"{Diagnostics.Count:N0} diagnósticos do scan");
    public bool HasWarnings => Warnings.Count > 0;
    public bool IsSnmpEnabled => EnableSnmpDeviceDiscovery || EnableSnmpTopology;
    public bool IsNmapProfileEligible => SelectedProfile.Value == ScanProfile.Deep;
    public int CustomOverrideCount => CountCustomOverrides();
    public int ActiveCustomOverrideCount => UseCustomScanSettings ? CustomOverrideCount : 0;
    public string CustomOverridesStatus => UseCustomScanSettings
        ? ActiveCustomOverrideCount == 1
            ? L("1 substituição ativa")
            : L($"{ActiveCustomOverrideCount:N0} substituições ativas")
        : L("0 substituições ativas · perfil em controlo");
    public string CustomSettingsExplanation => UseCustomScanSettings
        ? CustomOverrideCount == 0
            ? L($"As definições correspondem ao perfil {SelectedProfile.DisplayName}.")
            : L($"Os valores alterados abaixo substituem o perfil {SelectedProfile.DisplayName}.")
        : L($"O perfil {SelectedProfile.DisplayName} comanda o scan; os valores guardados abaixo estão inativos.");
    public string SelectedProfileDescription => UseCustomScanSettings
        ? L($"{SelectedProfile.Description}. As definições personalizadas ativas podem substituir este perfil.")
        : L($"{SelectedProfile.Description}. Este perfil comanda o scan.");
    public string SelectedThemeDescription => L(SelectedTheme.Description);
    public string ThemeGlyph => SelectedTheme.Value == AppThemeMode.Dark ? "\uE706" : "\uE708";
    public string ThemeButtonToolTip => SelectedTheme.Value == AppThemeMode.Dark
        ? L("Mudar para o tema claro")
        : L("Mudar para o tema escuro");
    public string ThemeButtonAutomationName => SelectedTheme.Value == AppThemeMode.Dark
        ? L("Mudar para o tema claro")
        : L("Mudar para o tema escuro");
    public string ThemeButtonHelpText => L("Alterna entre o tema claro e o tema escuro. A escolha é guardada localmente.");
    public string SelectedInterfaceSummary => SelectedNetworkInterface is null
        ? L("Nenhuma interface selecionada")
        : $"{SelectedNetworkInterface.IpAddress}/{SelectedNetworkInterface.PrefixLength}  ·  " +
          $"Gateway {SelectedNetworkInterface.GatewayAddress?.ToString() ?? "—"}  ·  " +
          $"{SelectedNetworkInterface.SpeedMbps:N0} Mbps";
    public string SelectedInterfaceWifi => SelectedNetworkInterface?.WifiSummary ?? "—";
    public string SelectedInterfaceVlan => SelectedNetworkInterface?.VlanId is int vlan
        ? L($"VLAN {vlan} · confiança {ConfidenceToText(SelectedNetworkInterface.VlanConfidence)}")
        : L("VLAN não exposta pelo Windows");

    public void SetInputValidationErrorCount(int count)
    {
        int normalized = Math.Max(0, count);
        if (_inputValidationErrorCount == normalized)
            return;

        _inputValidationErrorCount = normalized;
        OnPropertyChanged(nameof(HasInputValidationErrors));
        OnPropertyChanged(nameof(HasBlockingInputValidationErrors));
        OnPropertyChanged(nameof(InputValidationMessage));
        RaiseScanCanExecuteChanged();
    }

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
            Theme = SelectedTheme.Value,
            Language = LocalizationService.CurrentTag,
            LastInterfaceId = SelectedNetworkInterface?.Id,
            LastInterfaceAddress = SelectedNetworkInterface?.IpAddress.ToString(),
            LastCidr = NetworkCidr,
            Profile = SelectedProfile.Value,
            HasCompletedOnboarding = !IsOnboardingVisible,
            IsAdvancedMode = UseCustomScanSettings,
            UseCustomScanSettings = UseCustomScanSettings,
            IsCustomScanSettingsExpanded = IsCustomScanSettingsExpanded,
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
            EnableUpnpDescription = EnableUpnpDescription,
            EnableNetBiosDiscovery = EnableNetBiosDiscovery,
            EnableHistory = EnableHistory,
            EnableSnmpDeviceDiscovery = EnableSnmpDeviceDiscovery,
            EnableSnmpTopology = EnableSnmpTopology,
            SnmpSwitchAddress = SnmpSwitchAddress,
            SnmpTimeoutMs = SnmpTimeoutMs,
            EnableNmapDiscovery = EnableNmapDiscovery,
            NmapExecutablePath = NmapExecutablePath,
            NmapTimeoutMs = NmapTimeoutMs,
            EnableServiceProbes = EnableServiceProbes
        });
    }

    public void RequestCancellation() => CancelScan();

    public void Dispose()
    {
        LocalizationService.LanguageChanged -= OnLanguageChanged;
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
        _isOnboardingVisible = !_loadedSettings.HasCompletedOnboarding;
        _useCustomScanSettings = _loadedSettings.UseCustomScanSettings ?? _loadedSettings.IsAdvancedMode;
        _isCustomScanSettingsExpanded = _loadedSettings.IsCustomScanSettingsExpanded ??
            _loadedSettings.IsAdvancedMode;
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
        _enableUpnpDescription = _loadedSettings.EnableUpnpDescription;
        _enableNetBiosDiscovery = _loadedSettings.EnableNetBiosDiscovery;
        _enableHistory = _loadedSettings.EnableHistory;
        _enableSnmpDeviceDiscovery = _loadedSettings.EnableSnmpDeviceDiscovery;
        _enableSnmpTopology = _loadedSettings.EnableSnmpTopology;
        _snmpSwitchAddress = _loadedSettings.SnmpSwitchAddress;
        _snmpTimeoutMs = _loadedSettings.SnmpTimeoutMs;
        _enableNmapDiscovery = _loadedSettings.EnableNmapDiscovery &&
            _selectedProfile.Value == ScanProfile.Deep;
        _nmapExecutablePath = _loadedSettings.NmapExecutablePath;
        _nmapTimeoutMs = _loadedSettings.NmapTimeoutMs;
        _enableServiceProbes = _loadedSettings.EnableServiceProbes;
    }

    private static string L(string text) => LocalizationService.Translate(text);

    private void BuildLocalizedOptions()
    {
        Profiles =
        [
            new ScanProfileOption(
                ScanProfile.Quick,
                L("Rápido"),
                L("Primeira passagem pelos mesmos alvos, com menos detalhe e tempos mais curtos."),
                L("Ping, ARP e portas essenciais"),
                L("Mais rápido"),
                L("VISÃO RÁPIDA")),
            new ScanProfileOption(
                ScanProfile.Standard,
                L("Normal"),
                L("Os mesmos alvos, com tempo equilibrado e mais identidade e serviços."),
                L("mDNS, SSDP/UPnP, serviços e identidade"),
                L("Equilibrado"),
                L("RECOMENDADO")),
            new ScanProfileOption(
                ScanProfile.Deep,
                L("Avançado"),
                L("Os mesmos alvos, com mais portas, tempo e enriquecimento opcional."),
                L("Mais portas; SNMP e Nmap opcionais"),
                L("Mais demorado"),
                L("ANÁLISE PROFUNDA"))
        ];
        ThemeModes =
        [
            new ThemeModeOption(AppThemeMode.Light, L("Claro"), L("Usa a paleta clara da aplicação."), "\uE793"),
            new ThemeModeOption(AppThemeMode.Dark, L("Escuro"), L("Usa uma paleta escura com contraste adaptado."), "\uE708")
        ];
        Filters =
        [
            new DeviceFilterOption("all", L("Todos os dispositivos")),
            new DeviceFilterOption("high", L("Risco alto")),
            new DeviceFilterOption("medium", L("Risco médio")),
            new DeviceFilterOption("low", L("Risco baixo")),
            new DeviceFilterOption("new", L("Novos")),
            new DeviceFilterOption("favorite", L("Favoritos")),
            new DeviceFilterOption("changed", L("Alterados"))
        ];
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        ScanProfile selectedProfile = SelectedProfile.Value;
        AppThemeMode selectedTheme = SelectedTheme.Value;
        string selectedFilter = SelectedFilter.Key;
        BuildLocalizedOptions();
        _selectedProfile = Profiles.First(item => item.Value == selectedProfile);
        _selectedTheme = ThemeModes.First(item => item.Value == selectedTheme);
        _selectedFilter = Filters.First(item => item.Key.Equals(selectedFilter, StringComparison.Ordinal));
        foreach (DeviceRowViewModel device in Devices)
            device.RefreshLocalized();
        OnPropertyChanged(nameof(Profiles));
        OnPropertyChanged(nameof(ThemeModes));
        OnPropertyChanged(nameof(Filters));
        OnPropertyChanged(nameof(SelectedProfile));
        OnPropertyChanged(nameof(SelectedTheme));
        OnPropertyChanged(nameof(SelectedFilter));
        OnPropertyChanged(nameof(SelectedProfileDescription));
        OnPropertyChanged(nameof(SelectedThemeDescription));
        OnPropertyChanged(nameof(ThemeGlyph));
        OnPropertyChanged(nameof(ThemeButtonToolTip));
        OnPropertyChanged(nameof(ThemeButtonAutomationName));
        OnPropertyChanged(nameof(ThemeButtonHelpText));
        OnPropertyChanged(nameof(ScanConfigurationToggleLabel));
        OnPropertyChanged(nameof(SelectedInterfaceSummary));
        OnPropertyChanged(nameof(SelectedInterfaceVlan));
        OnPropertyChanged(nameof(StatusMessage));
        OnPropertyChanged(nameof(VendorDatabaseStatus));
        OnPropertyChanged(nameof(ProgressPhase));
        OnPropertyChanged(nameof(EmptyStateTitle));
        OnPropertyChanged(nameof(EmptyStateDescription));
        OnPropertyChanged(nameof(InputValidationMessage));
        OnPropertyChanged(nameof(DiagnosticSummary));
        OnPropertyChanged(nameof(CustomOverridesStatus));
        OnPropertyChanged(nameof(CustomSettingsExplanation));
        RefreshFilter();
    }

    private void ToggleTheme()
    {
        AppThemeMode next = SelectedTheme.Value == AppThemeMode.Dark
            ? AppThemeMode.Light
            : AppThemeMode.Dark;
        SelectedTheme = ThemeModes.First(item => item.Value == next);
        SaveSettings();
    }

    private bool SetCustomScanProperty<T>(
        ref T storage,
        T value,
        [CallerMemberName] string? propertyName = null)
    {
        if (!SetProperty(ref storage, value, propertyName))
            return false;

        NotifyCustomOverridesChanged();
        return true;
    }

    private void NotifyCustomOverridesChanged()
    {
        OnPropertyChanged(nameof(CustomOverrideCount));
        OnPropertyChanged(nameof(ActiveCustomOverrideCount));
        OnPropertyChanged(nameof(CustomOverridesStatus));
        OnPropertyChanged(nameof(CustomSettingsExplanation));
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
                PresentDiagnostic("Sem rede ativa", DiagnosticCatalog.NoActiveInterface());
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
            PresentDiagnostic(
                "Não foi possível obter as interfaces de rede",
                DiagnosticMapper.FromException(exception, "interfaces IPv4"));
        }
        finally
        {
            IsLoadingInterfaces = false;
        }
    }

    private async Task ScanAsync()
    {
        if (Devices.Any(device => device.IsMetadataDirty) &&
            !_dialogs.Confirm(
                "Alterações por guardar",
                "Existem alterações por guardar em nomes personalizados, notas ou favoritos. " +
                "Iniciar outro scan remove o resultado atual e essas alterações. Continuar sem guardar?"))
        {
            return;
        }

        PreparedScan? prepared = PrepareScan();
        if (prepared is null)
            return;

        ClearResultsCore();
        SaveSettings();
        long progressGeneration = Interlocked.Increment(ref _progressGeneration);
        Volatile.Write(ref _activeProgressGeneration, progressGeneration);
        IsScanConfigurationExpanded = false;
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
            Progress<ScanProgress> progress = new(
                update => ApplyProgress(progressGeneration, update));
            NetworkScanResult result = await _scanner.ScanAsync(
                prepared.Addresses,
                prepared.NetworkInterface,
                prepared.Options,
                progress,
                _scanCancellation.Token);

            DeactivateProgress(progressGeneration);
            FlushPendingDeviceUpdates();
            if (EnableHistory)
            {
                ProgressPhase = "Histórico";
                StatusMessage = "A comparar com o scan anterior...";
                try
                {
                    await _history.ApplyAndSaveAsync(result, _scanCancellation.Token);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    result = result.WithAdditionalDiagnostic(
                        DiagnosticCatalog.OptionalFileOperationFailed("histórico local", "guardar snapshot"));
                }
            }
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

            LoadDiagnostics(result);
        }
        catch (OperationCanceledException)
        {
            // Progress<T> publica no Dispatcher. Cede a prioridade uma vez para que
            // observações já enfileiradas entrem no snapshot parcial antes da exportação.
            await Dispatcher.Yield(DispatcherPriority.Background);
            DeactivateProgress(progressGeneration);
            FlushPendingDeviceUpdates();
            IReadOnlyList<NetworkDevice> partialDevices = Devices
                .Select(item => item.Device)
                .OrderBy(item => IpAddressHelper.ToUInt32(item.IpAddress))
                .ToList();
            string partialWarning =
                "Resultado parcial: o scan foi cancelado e alguns dispositivos ou detalhes podem estar em falta.";
            ScanDiagnostic cancellationDiagnostic =
                DiagnosticCatalog.OperationCancelled(prepared.NetworkInterface.NetworkCidr);
            _lastResult = new NetworkScanResult
            {
                NetworkInterface = prepared.NetworkInterface,
                StartedAt = _scanStartedAt,
                CompletedAt = DateTimeOffset.UtcNow,
                AddressesScanned = ScannedCount,
                Devices = partialDevices,
                IsPartial = true,
                Diagnostics = [cancellationDiagnostic],
                Warnings = [partialWarning]
            };
            UpdateTopologyMap();
            LoadDiagnostics(_lastResult);
            SelectedDevice ??= Devices.FirstOrDefault();
            ProgressPhase = "Cancelado";
            StatusMessage = partialDevices.Count == 0
                ? "Scan cancelado. O relatório parcial não contém dispositivos concluídos."
                : $"Scan cancelado. {partialDevices.Count:N0} resultados parciais podem ser exportados.";
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException or FormatException or IOException)
        {
            ScanDiagnostic diagnostic = DiagnosticMapper.FromException(exception, NetworkCidr);
            DeactivateProgress(progressGeneration);
            ProgressPhase = "Erro";
            IsScanConfigurationExpanded = true;
            PresentDiagnostic("Não foi possível concluir o scan", diagnostic);
        }
        finally
        {
            DeactivateProgress(progressGeneration);
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
            IsScanConfigurationExpanded = true;
            PresentDiagnostic("Interface necessária", DiagnosticCatalog.InvalidInterface("nenhuma interface selecionada"));
            return null;
        }

        try
        {
            ValidateAdvancedValues();
            IReadOnlyList<IPAddress> addresses = _ipRangeService.GenerateFromCidr(
                NetworkCidr,
                UseCustomScanSettings ? MaximumHosts : IpRangeService.DefaultMaximumAddresses);

            if (addresses.Any(address => !IpAddressHelper.IsPrivate(address)))
            {
                throw new ScanInputException(DiagnosticCatalog.PublicAddressScope(NetworkCidr), nameof(NetworkCidr));
            }

            ScanOptions options = BuildScanOptions();
            ScanWorkloadEstimate workload = ScanWorkloadEstimator.Estimate(addresses.Count, options);
            bool largeAddressRange = addresses.Count > 4_096;
            List<string> consentSections = [];
            if (largeAddressRange || workload.RequiresExplicitConfirmation)
                consentSections.Add(BuildWorkloadConfirmationMessage(workload));

            if (UseCustomScanSettings && IsSnmpEnabled)
            {
                consentSections.Add(
                    "SNMP v2c: a community é enviada sem cifragem aos alvos configurados. " +
                    "A identidade consulta cada dispositivo online; a topologia consulta apenas o switch indicado. " +
                    "Usa uma community dedicada e apenas de leitura numa rede de gestão confiável.");
            }

            if (UseCustomScanSettings && EnableNmapDiscovery)
            {
                string executable = string.IsNullOrWhiteSpace(NmapExecutablePath)
                    ? "A autodeteção está limitada a Program Files; PATH e caminhos de rede não são usados."
                    : $"Executável local: {Path.GetFullPath(Environment.ExpandEnvironmentVariables(NmapExecutablePath.Trim().Trim('\"')))}.";
                consentSections.Add(
                    "Nmap: uma ferramenta externa executará sondas TCP ativas apenas nos dispositivos online. " +
                    $"{executable} Confirma o publisher e a assinatura do ficheiro no Windows.");
            }

            if (consentSections.Count > 0 && !_dialogs.Confirm(
                    GetWorkloadConfirmationTitle(workload, largeAddressRange),
                    string.Join(Environment.NewLine + Environment.NewLine, consentSections) +
                    Environment.NewLine + Environment.NewLine +
                    "Confirma que administras estes dispositivos, autorizas o tráfego descrito e queres continuar?"))
            {
                return null;
            }

            return new PreparedScan(
                SelectedNetworkInterface,
                addresses,
                options);
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException or FormatException)
        {
            IsScanConfigurationExpanded = true;
            PresentDiagnostic(
                "Configuração inválida",
                DiagnosticMapper.FromException(exception, NetworkCidr));
            return null;
        }
    }

    private static string GetWorkloadConfirmationTitle(
        ScanWorkloadEstimate workload,
        bool largeAddressRange) => workload.Level switch
        {
            ScanWorkloadLevel.Extreme => "Confirmar scan muito intensivo",
            ScanWorkloadLevel.High => "Confirmar scan intensivo",
            _ when largeAddressRange => "Confirmar rede de grande dimensão",
            _ => "Confirmar tráfego ativo"
        };

    private static string BuildWorkloadConfirmationMessage(ScanWorkloadEstimate workload)
    {
        string risk = workload.Level switch
        {
            ScanWorkloadLevel.Extreme =>
                "Esta configuração pode produzir uma carga muito elevada e deve ser usada apenas numa janela de manutenção.",
            ScanWorkloadLevel.High =>
                "Esta configuração pode demorar e gerar tráfego significativo.",
            _ =>
                "A rede selecionada é extensa e pode demorar a analisar."
        };
        string nmapNotice = workload.HasAdditionalNmapTraffic
            ? " O Nmap está ativo e executará sondas adicionais com o seu próprio orçamento; esse tráfego não entra nesta contagem."
            : string.Empty;

        return
            $"A configuração abrange {workload.AddressCount:N0} endereços, " +
            $"{workload.DiscoveryPortCount:N0} portas de descoberta e " +
            $"{workload.FullPortCount:N0} portas de inventário. " +
            $"O máximo conservador das sondas TCP incorporadas é " +
            $"{workload.MaximumBuiltInTcpAttempts:N0} tentativas, incluindo até " +
            $"{workload.MaximumServiceProbeAttempts:N0} ligações leves de serviço e " +
            $"{workload.MaximumUpnpDescriptionAttempts:N0} pedidos de descrição UPnP. " +
            "As portas de inventário só são testadas nos dispositivos confirmados online, " +
            $"pelo que a carga real tende a ser inferior.{nmapNotice} {risk}";
    }

    private void ResetProfileOverrides()
    {
        ScanOptions defaults = ScanOptions.ForProfile(SelectedProfile.Value);

        CustomPorts = string.Empty;
        MaximumHosts = IpRangeService.DefaultMaximumAddresses;
        MaximumHostConcurrency = defaults.MaximumHostConcurrency;
        MaximumPortConcurrency = defaults.MaximumPortConcurrency;
        PingTimeoutMs = defaults.PingTimeoutMs;
        ConnectTimeoutMs = defaults.ConnectTimeoutMs;
        DiscoveryTimeoutMs = defaults.DiscoveryTimeoutMs;
        EnableIcmp = defaults.EnableIcmp;
        EnableTcpDiscovery = defaults.EnableTcpDiscovery;
        EnableArp = defaults.EnableArp;
        EnableMulticastDiscovery = defaults.EnableMulticastDiscovery;
        EnableUpnpDescription = defaults.EnableUpnpDescription;
        EnableNetBiosDiscovery = defaults.EnableNetBiosDiscovery;
        EnableSnmpDeviceDiscovery = defaults.EnableSnmpDeviceDiscovery;
        EnableSnmpTopology = defaults.EnableSnmpTopology;
        SnmpSwitchAddress = string.Empty;
        SnmpCommunity = string.Empty;
        SnmpTimeoutMs = defaults.SnmpTimeoutMs;
        EnableNmapDiscovery = defaults.EnableNmapDiscovery;
        NmapExecutablePath = string.Empty;
        NmapTimeoutMs = defaults.NmapTimeoutMs;
        EnableServiceProbes = defaults.EnableServiceProbes;

        RefreshCustomScanEditorValues();
        StatusMessage = $"Definições personalizadas repostas para o perfil {SelectedProfile.DisplayName}.";
    }

    private void RefreshCustomScanEditorValues()
    {
        string[] propertyNames =
        [
            nameof(CustomPorts),
            nameof(MaximumHosts),
            nameof(MaximumHostConcurrency),
            nameof(MaximumPortConcurrency),
            nameof(PingTimeoutMs),
            nameof(ConnectTimeoutMs),
            nameof(DiscoveryTimeoutMs),
            nameof(EnableIcmp),
            nameof(EnableTcpDiscovery),
            nameof(EnableArp),
            nameof(EnableMulticastDiscovery),
            nameof(EnableUpnpDescription),
            nameof(EnableNetBiosDiscovery),
            nameof(EnableSnmpDeviceDiscovery),
            nameof(EnableSnmpTopology),
            nameof(SnmpSwitchAddress),
            nameof(SnmpCommunity),
            nameof(SnmpTimeoutMs),
            nameof(EnableNmapDiscovery),
            nameof(NmapExecutablePath),
            nameof(NmapTimeoutMs),
            nameof(EnableServiceProbes)
        ];

        foreach (string propertyName in propertyNames)
            OnPropertyChanged(propertyName);

        OnPropertyChanged(nameof(IsSnmpEnabled));
        NotifyNmapValidationChanged();
        NotifyCustomOverridesChanged();
    }

    private int CountCustomOverrides()
    {
        ScanOptions defaults = ScanOptions.ForProfile(SelectedProfile.Value);
        int count = 0;

        Count(!string.IsNullOrWhiteSpace(CustomPorts));
        Count(MaximumHosts != IpRangeService.DefaultMaximumAddresses);
        Count(MaximumHostConcurrency != defaults.MaximumHostConcurrency);
        Count(MaximumPortConcurrency != defaults.MaximumPortConcurrency);
        Count(PingTimeoutMs != defaults.PingTimeoutMs);
        Count(ConnectTimeoutMs != defaults.ConnectTimeoutMs);
        Count(DiscoveryTimeoutMs != defaults.DiscoveryTimeoutMs);
        Count(EnableIcmp != defaults.EnableIcmp);
        Count(EnableTcpDiscovery != defaults.EnableTcpDiscovery);
        Count(EnableArp != defaults.EnableArp);
        Count(EnableMulticastDiscovery != defaults.EnableMulticastDiscovery);
        Count(EnableUpnpDescription != defaults.EnableUpnpDescription);
        Count(EnableNetBiosDiscovery != defaults.EnableNetBiosDiscovery);
        Count(EnableSnmpDeviceDiscovery != defaults.EnableSnmpDeviceDiscovery);
        Count(EnableSnmpTopology != defaults.EnableSnmpTopology);
        Count(IsSnmpEnabled && SnmpTimeoutMs != defaults.SnmpTimeoutMs);
        Count(EnableNmapDiscovery != defaults.EnableNmapDiscovery);
        Count(EnableNmapDiscovery && NmapTimeoutMs != defaults.NmapTimeoutMs);
        Count(EnableServiceProbes != defaults.EnableServiceProbes);
        return count;

        void Count(bool isOverride)
        {
            if (isOverride)
                count++;
        }
    }

    private ScanOptions BuildScanOptions()
    {
        ScanOptions defaults = ScanOptions.ForProfile(SelectedProfile.Value);
        if (!UseCustomScanSettings)
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
            EnableUpnpDescription = EnableUpnpDescription,
            EnableNetBiosDiscovery = EnableNetBiosDiscovery,
            EnableSnmpDeviceDiscovery = EnableSnmpDeviceDiscovery,
            EnableSnmpTopology = EnableSnmpTopology,
            SnmpSwitchAddress = EnableSnmpTopology
                ? IPAddress.Parse(SnmpSwitchAddress)
                : null,
            SnmpCommunity = IsSnmpEnabled ? SnmpCommunity : null,
            SnmpTimeoutMs = SnmpTimeoutMs,
            EnableNmapDiscovery = EnableNmapDiscovery && IsNmapProfileEligible,
            NmapExecutablePath = EnableNmapDiscovery &&
                !string.IsNullOrWhiteSpace(NmapExecutablePath)
                    ? NmapExecutablePath.Trim()
                    : null,
            NmapTimeoutMs = NmapTimeoutMs,
            EnableServiceProbes = EnableServiceProbes,
            DiscoveryPorts = defaults.DiscoveryPorts,
            Ports = ports
        };
    }

    private void ValidateAdvancedValues()
    {
        if (!UseCustomScanSettings)
            return;

        ValidateRange(MaximumHosts, 1, IpRangeService.AbsoluteMaximumAddresses, "Máximo de endereços");
        ValidateRange(MaximumHostConcurrency, 1, 512, "Concorrência por host");
        ValidateRange(MaximumPortConcurrency, 1, 512, "Concorrência por porta");
        ValidateRange(PingTimeoutMs, 50, 30_000, "Timeout de ping");
        ValidateRange(ConnectTimeoutMs, 50, 30_000, "Timeout TCP");
        ValidateRange(DiscoveryTimeoutMs, 100, 30_000, "Timeout de descoberta");
        ValidateRange(SnmpTimeoutMs, 100, 30_000, "Timeout SNMP");

        if (EnableNmapDiscovery)
            ValidateRange(NmapTimeoutMs, 5_000, 600_000, "Timeout Nmap");

        if (!EnableIcmp && !EnableTcpDiscovery && !EnableMulticastDiscovery)
        {
            throw new ScanInputException(
                DiagnosticCatalog.InvalidScanConfiguration("métodos de descoberta"));
        }

        if (EnableUpnpDescription && !EnableMulticastDiscovery)
        {
            throw new ScanInputException(
                DiagnosticCatalog.InvalidScanConfiguration(
                    "descrições UPnP requerem a descoberta SSDP/multicast"));
        }

        if (IsSnmpEnabled)
        {
            if (EnableSnmpTopology &&
                (!IPAddress.TryParse(SnmpSwitchAddress, out IPAddress? switchAddress) ||
                 switchAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                 !IpAddressHelper.IsPrivate(switchAddress)))
            {
                throw new ScanInputException(
                    DiagnosticCatalog.InvalidScanConfiguration("endereço do switch SNMP"));
            }

            if (string.IsNullOrWhiteSpace(SnmpCommunity))
            {
                throw new ScanInputException(
                    DiagnosticCatalog.InvalidScanConfiguration("configuração SNMP"));
            }
        }

        if (EnableNmapDiscovery)
        {
            if (!IsNmapProfileEligible)
            {
                throw new ScanInputException(
                    DiagnosticCatalog.InvalidScanConfiguration(
                        "Nmap requer o perfil Avançado"));
            }

            ValidateNmapExecutablePath(NmapExecutablePath);
        }
    }

    private static void ValidateNmapExecutablePath(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
            return;

        if (!IsNmapExecutablePathValid(executablePath))
        {
            throw new ScanInputException(
                DiagnosticCatalog.InvalidScanConfiguration("caminho do executável Nmap"));
        }
    }

    private static bool IsNmapExecutablePathValid(string executablePath)
    {
        return NmapDiscoveryService.IsSafeExplicitExecutablePath(executablePath);
    }

    private void NotifyNmapValidationChanged()
    {
        OnPropertyChanged(nameof(HasNmapPathValidationError));
        OnPropertyChanged(nameof(HasBlockingInputValidationErrors));
        OnPropertyChanged(nameof(InputValidationMessage));
        RaiseScanCanExecuteChanged();
    }

    private static void ValidateRange(int value, int minimum, int maximum, string label)
    {
        if (value < minimum || value > maximum)
            throw new ScanInputException(
                DiagnosticCatalog.InvalidScanConfiguration(label),
                label);
    }

    private void ApplyProgress(long progressGeneration, ScanProgress update)
    {
        if (progressGeneration != Volatile.Read(ref _activeProgressGeneration))
            return;

        ProgressPercentage = update.Percentage;
        OnlineCount = update.Online;

        if (!IsCancelling)
        {
            ProgressPhase = update.Phase;
            StatusMessage = update.Message;
        }

        if (update.Phase.Equals("Descoberta", StringComparison.OrdinalIgnoreCase))
            ScannedCount = update.Completed;

        if (update.Device is not null)
            _pendingDeviceUpdates[update.Device.IpAddressText] = update.Device;
    }

    private void DeactivateProgress(long progressGeneration)
    {
        Interlocked.CompareExchange(
            ref _activeProgressGeneration,
            0,
            progressGeneration);
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

        bool hasUnsavedMetadata = Devices.Any(device => device.IsMetadataDirty);
        string message = hasUnsavedMetadata
            ? "Existem alterações por guardar em nomes personalizados, notas ou favoritos. " +
              "Limpar agora remove os resultados e essas alterações. Continuar sem guardar?"
            : "Queres remover os resultados, diagnósticos e o mapa do scan atual?";
        if (!_dialogs.Confirm("Limpar resultados", message))
            return;

        ClearResultsCore();
        IsScanConfigurationExpanded = true;
        ProgressPhase = "Pronto";
        StatusMessage = "Resultados limpos. Pronto para um novo scan.";
        ElapsedText = "00:00";
    }

    private void ResetFilters()
    {
        SearchText = string.Empty;
        SelectedFilter = Filters[0];
        StatusMessage = $"Filtros repostos. {Devices.Count:N0} dispositivos disponíveis.";
    }

    private void DismissOnboarding()
    {
        IsOnboardingVisible = false;
        SaveSettings();
    }

    private async Task DeleteHistoryAsync()
    {
        if (!_dialogs.Confirm(
                "Apagar histórico local",
                "Queres apagar todos os snapshots usados para comparar scans? " +
                "Esta ação é irreversível, mas não apaga nomes personalizados nem notas dos dispositivos."))
        {
            return;
        }

        try
        {
            int deleted = await _history.ClearAsync();
            StatusMessage = deleted == 0
                ? "Não existiam snapshots de histórico para apagar."
                : $"{deleted:N0} snapshots de histórico apagados. O resultado atual não foi alterado.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            ReportException("Não foi possível apagar o histórico", exception, "histórico local");
        }
    }

    private void ClearResultsCore()
    {
        Devices.Clear();
        _devicesByIp.Clear();
        _pendingDeviceUpdates.Clear();
        Diagnostics.Clear();
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
        OnPropertyChanged(nameof(HasNoVisibleDevices));
        OnPropertyChanged(nameof(HasDiagnostics));
        OnPropertyChanged(nameof(DiagnosticSummary));
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
            ReportException("Falha ao exportar CSV", exception, path);
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
            ReportException("Falha ao exportar JSON", exception, path);
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
            ReportException("Falha ao exportar HTML", exception, path);
        }
    }

    private async Task ExportSupportJsonAsync()
    {
        NetworkScanResult? result = _lastResult;
        if (result is null)
            return;

        string? path = _dialogs.ChooseExportPath(
            "Guardar relatório de suporte",
            $"relatorio-suporte-{DateTime.Now:yyyyMMdd-HHmm}.json",
            "Relatório de suporte JSON (*.json)|*.json|Todos os ficheiros (*.*)|*.*");
        if (path is null)
            return;

        try
        {
            await _export.ExportSupportJsonAsync(result, path);
            StatusMessage =
                $"Relatório de suporte guardado em {path}. Revê o conteúdo antes de o partilhar.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            ReportException("Falha ao guardar o relatório de suporte", exception, path);
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
            ReportException("Falha ao guardar GraphML", exception, path);
        }
    }

    private async Task SaveDeviceMetadataAsync()
    {
        DeviceRowViewModel? selected = SelectedDevice;
        NetworkScanResult? result = _lastResult;
        if (selected is null || result is null)
            return;

        IsSavingDeviceMetadata = true;
        StatusMessage = $"A guardar preferências de {selected.Hostname}...";
        try
        {
            await _deviceMetadata.SaveAsync(selected.Device, result.NetworkInterface.NetworkCidr);
            selected.MarkMetadataSaved();
            selected.Update(selected.Device);
            RefreshFilter();
            StatusMessage = $"Preferências de {selected.Hostname} guardadas.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            ReportException("Falha ao guardar o dispositivo", exception, selected.IpAddress);
        }
        finally
        {
            IsSavingDeviceMetadata = false;
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
            ReportException("Falha no Wake-on-LAN", exception, selected.IpAddress);
        }
    }

    private async Task UpdateOuiDatabaseAsync()
    {
        if (!_dialogs.Confirm(
                "Atualização IEEE opcional",
                "A aplicação já inclui a base completa da release e funciona offline. Procurar agora atribuições MA-L, MA-M, MA-S e IAB mais recentes diretamente na IEEE? A cópia atualizada fica apenas neste computador."))
        {
            return;
        }

        StatusMessage = "A verificar as listagens públicas da IEEE...";
        try
        {
            Progress<double> progress = new(value =>
                StatusMessage = $"A atualizar a base IEEE... {value:P0}");
            await _ouiDatabase.UpdateAsync(progress);
            _scanner = new NetworkScannerService();
            VendorDatabaseStatus = BuildVendorDatabaseStatus();
            ResetOuiDatabaseCommand.RaiseCanExecuteChanged();
            StatusMessage = "Base IEEE atualizada e validada. Será usada no próximo scan.";
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            ReportException("Não foi possível atualizar a base IEEE", exception, OuiDatabaseService.OfficialDatabaseUrl);
            StatusMessage = "A atualização falhou; a base incorporada continua disponível e intacta.";
        }
    }

    private void ResetOuiDatabase()
    {
        if (!_dialogs.Confirm(
                "Repor base IEEE incorporada",
                "Remover a atualização local e voltar a usar apenas a snapshot incorporada nesta versão?"))
        {
            return;
        }

        try
        {
            bool removed = _ouiDatabase.ResetLocalDatabase();
            _scanner = new NetworkScannerService();
            VendorDatabaseStatus = BuildVendorDatabaseStatus();
            ResetOuiDatabaseCommand.RaiseCanExecuteChanged();
            StatusMessage = removed
                ? "Atualização local removida. A base incorporada está ativa."
                : "A base incorporada já estava ativa.";
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ReportException(
                "Não foi possível repor a base IEEE incorporada",
                exception,
                OuiDatabaseService.DatabasePath);
        }
    }

    private static string BuildVendorDatabaseStatus()
    {
        MacVendorService service = new();
        VendorDatabaseInfo info = service.DatabaseInfo;
        if (info.IsDegraded)
            return "Base IEEE degradada · recurso incorporado indisponível; reinstala ou verifica uma atualização";

        string status =
            $"{info.DisplayText} · MA-L / MA-M / MA-S / IAB · funciona offline";
        return string.IsNullOrWhiteSpace(service.ExternalDatabaseError)
            ? status
            : status + " · uma atualização local inválida foi ignorada";
    }

    private void CopyIp()
    {
        if (SelectedDevice is null)
            return;

        if (_dialogs.TryCopyText(SelectedDevice.IpAddress))
        {
            StatusMessage = $"IP {SelectedDevice.IpAddress} copiado.";
            return;
        }

        PresentDiagnostic(
            "Não foi possível copiar o IP",
            DiagnosticCatalog.AccessDenied("área de transferência do Windows"));
    }

    private void CopyMac()
    {
        if (SelectedDevice is null || !SelectedDevice.HasMacAddress)
            return;

        if (_dialogs.TryCopyText(SelectedDevice.MacAddress))
        {
            StatusMessage = $"MAC {SelectedDevice.MacAddress} copiado.";
            return;
        }

        PresentDiagnostic(
            "Não foi possível copiar o MAC",
            DiagnosticCatalog.AccessDenied("área de transferência do Windows"));
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
            ReportException("Não foi possível abrir a ação", exception, SelectedDevice?.IpAddress);
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
            device.MacAssignee,
            device.MacAssignment,
            device.Model,
            device.FriendlyName,
            device.SerialNumber,
            device.Firmware,
            device.HardwareRevision,
            device.IdentityDescription,
            device.SsdpServiceType,
            device.SsdpUniqueServiceName,
            device.SnmpIdentity,
            device.NmapIdentity,
            device.IdentitySearchText,
            string.Join(' ', device.MdnsNames),
            device.MdnsServiceSearchText,
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

    private void UpdateVisibleDeviceCount()
    {
        VisibleDeviceCount = DevicesView.Cast<object>().Count();
        OnPropertyChanged(nameof(HasNoVisibleDevices));
    }

    private void NotifyEmptyStateChanged()
    {
        OnPropertyChanged(nameof(EmptyStateTitle));
        OnPropertyChanged(nameof(EmptyStateDescription));
        OnPropertyChanged(nameof(EmptyStateGlyph));
    }

    private bool CanStartScan() =>
        !IsScanning &&
        !IsSavingDeviceMetadata &&
        !IsLoadingInterfaces &&
        !HasBlockingInputValidationErrors &&
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
        ExportSupportJsonCommand.RaiseCanExecuteChanged();
        ExportGraphMlCommand.RaiseCanExecuteChanged();
        DeleteHistoryCommand.RaiseCanExecuteChanged();
        UpdateOuiDatabaseCommand.RaiseCanExecuteChanged();
        ResetOuiDatabaseCommand.RaiseCanExecuteChanged();
        SaveDeviceMetadataCommand.RaiseCanExecuteChanged();
        WakeOnLanCommand.RaiseCanExecuteChanged();
        RaiseSelectionCanExecuteChanged();
    }

    public void ReportException(string title, Exception exception, string? target = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentNullException.ThrowIfNull(exception);
        PresentDiagnostic(title, DiagnosticMapper.FromException(exception, target));
    }

    private void LoadDiagnostics(NetworkScanResult result)
    {
        Diagnostics.Clear();
        Warnings.Clear();

        HashSet<string> diagnosticMessages = new(StringComparer.Ordinal);
        foreach (ScanDiagnostic diagnostic in result.Diagnostics)
        {
            Diagnostics.Add(new DiagnosticRowViewModel(diagnostic));
            diagnosticMessages.Add(diagnostic.Message);
        }

        foreach (string warning in result.Warnings.Where(warning => !diagnosticMessages.Contains(warning)))
            Warnings.Add(warning);

        OnPropertyChanged(nameof(HasDiagnostics));
        OnPropertyChanged(nameof(DiagnosticSummary));
        OnPropertyChanged(nameof(HasWarnings));
    }

    private void PresentDiagnostic(string title, ScanDiagnostic diagnostic)
    {
        bool alreadyPresent = Diagnostics.Any(item =>
            item.Code.Equals(diagnostic.Code, StringComparison.Ordinal) &&
            string.Equals(item.Target, diagnostic.Target, StringComparison.OrdinalIgnoreCase));
        if (!alreadyPresent)
            Diagnostics.Add(new DiagnosticRowViewModel(diagnostic));

        OnPropertyChanged(nameof(HasDiagnostics));
        OnPropertyChanged(nameof(DiagnosticSummary));
        StatusMessage = $"[{diagnostic.Code}] {diagnostic.Message}";
        _dialogs.ShowDiagnostic(title, diagnostic);
    }

    private void HandleUnexpectedException(Exception exception)
    {
        PresentDiagnostic(
            "Erro inesperado",
            DiagnosticMapper.FromException(exception, "interface gráfica"));
    }

    private void HandleUnexpectedScanException(Exception exception)
    {
        Volatile.Write(ref _activeProgressGeneration, 0);
        ProgressPhase = "Erro";
        IsScanConfigurationExpanded = true;
        PresentDiagnostic(
            "Erro inesperado durante o scan",
            DiagnosticMapper.FromException(exception, NetworkCidr));
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

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
