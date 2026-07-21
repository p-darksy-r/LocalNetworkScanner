using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using LocalNetworkScanner.Wpf.Services;
using LocalNetworkScanner.Wpf.ViewModels;

namespace LocalNetworkScanner.Wpf;

public partial class MainWindow : Window
{
    private bool _hasLoaded;

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

    private void OnFitTopologyClick(object sender, RoutedEventArgs e) => TopologyGraph.FitToView();

    private void OnResetTopologyClick(object sender, RoutedEventArgs e) => TopologyGraph.ResetView();

    private void OnExportTopologyPngClick(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.HasTopologyMap)
        {
            MessageBox.Show(
                this,
                "Inicia um scan antes de guardar o mapa de topologia.",
                "Topologia ainda vazia",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        SaveFileDialog dialog = new()
        {
            Title = "Guardar mapa de topologia",
            FileName = $"topologia-rede-{DateTime.Now:yyyyMMdd-HHmm}.png",
            DefaultExt = ".png",
            Filter = "Imagem PNG (*.png)|*.png|Todos os ficheiros (*.*)|*.*",
            AddExtension = true,
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) != true)
            return;

        try
        {
            TopologyGraph.ExportVisiblePng(dialog.FileName);
            MessageBox.Show(
                this,
                $"Mapa guardado em:\n{dialog.FileName}",
                "Topologia exportada",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            MessageBox.Show(
                this,
                exception.Message,
                "Não foi possível guardar o mapa",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }
}
