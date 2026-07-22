// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using LocalNetworkScanner.Wpf.ViewModels;

namespace LocalNetworkScanner.Wpf;

public partial class TopologyWindow : Window
{
    public TopologyWindow(MainViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        InitializeComponent();
        DataContext = viewModel;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        TopologyGraph.FitToView();
        TopologyGraph.Focus();
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Home && Keyboard.Modifiers == ModifierKeys.None)
        {
            TopologyGraph.FitToView();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && Keyboard.Modifiers == ModifierKeys.None)
        {
            Close();
            e.Handled = true;
        }
    }

    private void OnFitTopologyClick(object sender, RoutedEventArgs e) => TopologyGraph.FitToView();

    private void OnResetTopologyClick(object sender, RoutedEventArgs e) => TopologyGraph.ResetView();

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    private void OnExportTopologyPngClick(object sender, RoutedEventArgs e)
    {
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
            if (DataContext is MainViewModel viewModel)
                viewModel.ReportException("Não foi possível guardar o mapa", exception, dialog.FileName);
        }
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
