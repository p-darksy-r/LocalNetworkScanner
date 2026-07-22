// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using LocalNetworkScanner.Wpf.Services;
using LocalNetworkScanner.Wpf.ViewModels;

namespace LocalNetworkScanner.Wpf;

public partial class MainWindow : Window
{
    private bool _hasLoaded;
    private TopologyWindow? _topologyWindow;

    public MainWindow()
    {
        InitializeComponent();
        ViewModel = new MainViewModel(
            new UserDialogService(),
            new DesktopActionService(),
            new UiSettingsService());
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
        if (ViewModel.IsScanning)
        {
            MessageBoxResult result = MessageBox.Show(
                this,
                "Existe um scan em curso. Queres cancelá-lo e fechar a aplicação?",
                "Scan em curso",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);
            if (result != MessageBoxResult.Yes)
            {
                e.Cancel = true;
                return;
            }

            ViewModel.RequestCancellation();
        }

        _topologyWindow?.Close();
        ViewModel.SaveSettings();
        ViewModel.Dispose();
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        ModifierKeys modifiers = Keyboard.Modifiers;
        if (modifiers == ModifierKeys.Control && e.Key == Key.F)
        {
            SearchTextBox.Focus();
            SearchTextBox.SelectAll();
            e.Handled = true;
            return;
        }

        if (modifiers == ModifierKeys.Control && e.Key == Key.E && ViewModel.ExportCsvCommand.CanExecute(null))
        {
            ViewModel.ExportCsvCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (modifiers == ModifierKeys.None && e.Key == Key.F5 && ViewModel.ScanCommand.CanExecute(null))
        {
            ViewModel.ScanCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (modifiers == ModifierKeys.None && e.Key == Key.Escape && ViewModel.CancelCommand.CanExecute(null))
        {
            ViewModel.CancelCommand.Execute(null);
            e.Handled = true;
        }
    }

    private void OnSnmpCommunityPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox passwordBox)
            ViewModel.SnmpCommunity = passwordBox.Password;
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
