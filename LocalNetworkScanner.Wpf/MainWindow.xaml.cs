// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.ComponentModel;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using LocalNetworkScanner.Wpf.Infrastructure;
using LocalNetworkScanner.Wpf.Services;
using LocalNetworkScanner.Wpf.ViewModels;

namespace LocalNetworkScanner.Wpf;

public partial class MainWindow : Window
{
    private bool _hasLoaded;
    private TopologyWindow? _topologyWindow;
    private int _inputValidationErrorCount;
    private bool _statusLiveRegionUpdatePending;
    private bool _isFatalShutdown;
    private bool _shutdownCleanupCompleted;

    public MainWindow()
        : this(new UiSettingsService())
    {
    }

    public MainWindow(UiSettingsService settingsService)
    {
        ArgumentNullException.ThrowIfNull(settingsService);
        InitializeComponent();
        ViewModel = new MainViewModel(
            new UserDialogService(),
            new DesktopActionService(),
            settingsService);
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
        DataContext = ViewModel;
    }

    public MainViewModel ViewModel { get; }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_hasLoaded)
            return;

        _hasLoaded = true;
        FitWindowToWorkArea();
        await ViewModel.InitializeAsync();
    }

    private void FitWindowToWorkArea()
    {
        Rect workArea = SystemParameters.WorkArea;
        if (workArea.Width <= 0 || workArea.Height <= 0)
            return;

        MinWidth = Math.Min(MinWidth, workArea.Width);
        MinHeight = Math.Min(MinHeight, workArea.Height);
        Width = Math.Min(Math.Max(MinWidth, Width), workArea.Width);
        Height = Math.Min(Math.Max(MinHeight, Height), workArea.Height);
        Left = workArea.Left + Math.Max(0, (workArea.Width - Width) / 2);
        Top = workArea.Top + Math.Max(0, (workArea.Height - Height) / 2);
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!_isFatalShutdown && ViewModel.IsSavingDeviceMetadata)
        {
            MessageBox.Show(
                this,
                "As preferências do dispositivo ainda estão a ser guardadas. Aguarda um momento e volta a fechar a aplicação.",
                "A guardar preferências",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            e.Cancel = true;
            return;
        }

        if (!_isFatalShutdown && (ViewModel.IsScanning || ViewModel.HasUnsavedDeviceMetadata))
        {
            string title;
            string message;
            if (ViewModel.IsScanning && ViewModel.HasUnsavedDeviceMetadata)
            {
                title = "Scan e alterações em curso";
                message =
                    "Existe um scan em curso e há alterações por guardar em nomes, notas ou favoritos. " +
                    "Queres cancelar o scan, perder essas alterações e fechar a aplicação?";
            }
            else if (ViewModel.IsScanning)
            {
                title = "Scan em curso";
                message = "Existe um scan em curso. Queres cancelá-lo e fechar a aplicação?";
            }
            else
            {
                title = "Alterações por guardar";
                message =
                    "Existem alterações por guardar em nomes personalizados, notas ou favoritos. " +
                    "Queres perdê-las e fechar a aplicação?";
            }

            MessageBoxResult result = MessageBox.Show(
                this,
                message,
                title,
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);
            if (result != MessageBoxResult.Yes)
            {
                e.Cancel = true;
                return;
            }

            if (ViewModel.IsScanning)
                ViewModel.RequestCancellation();
        }

        CompleteShutdown(saveSettings: !_isFatalShutdown);
    }

    internal void PrepareForFatalShutdown()
    {
        _isFatalShutdown = true;
        ViewModel.RequestCancellation();
    }

    private void CompleteShutdown(bool saveSettings)
    {
        if (_shutdownCleanupCompleted)
            return;

        _shutdownCleanupCompleted = true;
        _topologyWindow?.Close();
        if (saveSettings)
            ViewModel.SaveSettings();
        ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        ViewModel.Dispose();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.SnmpCommunity) &&
            string.IsNullOrEmpty(ViewModel.SnmpCommunity) &&
            SnmpCommunityPasswordBox.Password.Length > 0)
        {
            SnmpCommunityPasswordBox.Clear();
        }

        if (e.PropertyName is nameof(MainViewModel.StatusMessage) or nameof(MainViewModel.ProgressPhase))
            QueueStatusLiveRegionUpdate();
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        ModifierKeys modifiers = Keyboard.Modifiers;
        Key key = e.Key == Key.System ? e.SystemKey : e.Key;
        if (modifiers == ModifierKeys.Control && key == Key.F)
        {
            SearchTextBox.Focus();
            SearchTextBox.SelectAll();
            e.Handled = true;
            return;
        }

        if (modifiers == ModifierKeys.Control && key == Key.E && ViewModel.ExportCsvCommand.CanExecute(null))
        {
            ViewModel.ExportCsvCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (modifiers == ModifierKeys.Alt && key == Key.I && ViewModel.ScanCommand.CanExecute(null))
        {
            ViewModel.ScanCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (modifiers == ModifierKeys.Alt && key == Key.C && ViewModel.CancelCommand.CanExecute(null))
        {
            ViewModel.CancelCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (modifiers == ModifierKeys.None && key == Key.F5 && ViewModel.ScanCommand.CanExecute(null))
        {
            ViewModel.ScanCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (modifiers != ModifierKeys.None || key != Key.Escape)
            return;

        if (SearchTextBox.IsKeyboardFocusWithin)
        {
            if (ViewModel.ClearSearchCommand.CanExecute(null))
                ViewModel.ClearSearchCommand.Execute(null);

            e.Handled = true;
            return;
        }

        if (KeyboardInteractionGuard.ShouldDeferEscape(e))
            return;

        if (ViewModel.CancelCommand.CanExecute(null))
        {
            ViewModel.CancelCommand.Execute(null);
            e.Handled = true;
        }
    }

    private void QueueStatusLiveRegionUpdate()
    {
        if (_statusLiveRegionUpdatePending || !IsLoaded)
            return;

        _statusLiveRegionUpdatePending = true;
        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.ContextIdle,
            new Action(() =>
            {
                _statusLiveRegionUpdatePending = false;
                AutomationPeer? peer = UIElementAutomationPeer.FromElement(StatusLiveRegion) ??
                    UIElementAutomationPeer.CreatePeerForElement(StatusLiveRegion);
                peer?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
            }));
    }

    private void OnSnmpCommunityPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox passwordBox)
            ViewModel.SnmpCommunity = passwordBox.Password;
    }

    private void OnInputValidationError(object sender, ValidationErrorEventArgs e)
    {
        _inputValidationErrorCount = e.Action == ValidationErrorEventAction.Added
            ? _inputValidationErrorCount + 1
            : Math.Max(0, _inputValidationErrorCount - 1);
        ViewModel.SetInputValidationErrorCount(_inputValidationErrorCount);
    }

    private void OnDevicesDataGridPreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject source ||
            ItemsControl.ContainerFromElement(DevicesDataGrid, source) is not DataGridRow row)
        {
            return;
        }

        DevicesDataGrid.SelectedItem = row.Item;
        row.IsSelected = true;
        row.Focus();
    }

    private void OnOpenTopologyClick(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.HasTopologyMap)
        {
            MessageBox.Show(
                this,
                "Inicia e conclui um scan com resultados antes de abrir o mapa.",
                "Topologia ainda vazia",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        if (_topologyWindow is { IsVisible: true })
        {
            if (_topologyWindow.WindowState == WindowState.Minimized)
                _topologyWindow.WindowState = WindowState.Normal;

            _topologyWindow.Activate();
            return;
        }

        _topologyWindow = new TopologyWindow(ViewModel)
        {
            Owner = this
        };
        _topologyWindow.Closed += (_, _) => _topologyWindow = null;
        _topologyWindow.Show();
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
