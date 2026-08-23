// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Input;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Wpf.Controls;
using LocalNetworkScanner.Wpf.Infrastructure;
using Microsoft.Win32;
using LocalNetworkScanner.Wpf.ViewModels;

namespace LocalNetworkScanner.Wpf;

public partial class TopologyWindow : Window
{
    private readonly MainViewModel _viewModel;
    private bool _isSynchronizingTableSelection;

    public TopologyWindow(MainViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        _viewModel = viewModel;
        InitializeComponent();
        DataContext = viewModel;
        _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        TopologyGraph.ViewportChanged += OnTopologyViewportChanged;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ApplyTopologyFilter();
        TopologyGraph.FitToView();
        TopologyGraph.Focus();
    }

    protected override void OnClosed(EventArgs e)
    {
        _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        TopologyGraph.ViewportChanged -= OnTopologyViewportChanged;
        base.OnClosed(e);
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Home &&
            Keyboard.Modifiers == ModifierKeys.None &&
            TopologyViews.SelectedIndex == 0)
        {
            TopologyGraph.FitToView();
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key is Key.D1 or Key.NumPad1)
        {
            TopologyViews.SelectedIndex = 0;
            TopologyGraph.Focus();
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key is Key.D2 or Key.NumPad2)
        {
            TopologyViews.SelectedIndex = 1;
            TopologyNodesTable.Focus();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape &&
                 Keyboard.Modifiers == ModifierKeys.None &&
                 !KeyboardInteractionGuard.ShouldDeferEscape(e))
        {
            Close();
            e.Handled = true;
        }
    }

    private void OnFitTopologyClick(object sender, RoutedEventArgs e)
    {
        TopologyViews.SelectedIndex = 0;
        TopologyGraph.FitToView();
    }

    private void OnZoomOutTopologyClick(object sender, RoutedEventArgs e)
    {
        TopologyViews.SelectedIndex = 0;
        TopologyGraph.ZoomOut();
        TopologyGraph.Focus();
    }

    private void OnZoomInTopologyClick(object sender, RoutedEventArgs e)
    {
        TopologyViews.SelectedIndex = 0;
        TopologyGraph.ZoomIn();
        TopologyGraph.Focus();
    }

    private void OnTopologyViewportChanged(object? sender, EventArgs e)
    {
        string zoomText = $"{TopologyGraph.ZoomPercent}%";
        if (string.Equals(TopologyZoomText.Text, zoomText, StringComparison.Ordinal))
            return;

        TopologyZoomText.Text = zoomText;
        AutomationPeer? peer = UIElementAutomationPeer.FromElement(TopologyZoomText) ??
            UIElementAutomationPeer.CreatePeerForElement(TopologyZoomText);
        peer?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
    }

    private void OnResetTopologyClick(object sender, RoutedEventArgs e)
    {
        TopologyViews.SelectedIndex = 0;
        TopologyGraph.ResetView();
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    private void OnTopologyFilterChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || TopologyGraph is null)
            return;

        ApplyTopologyFilter();
    }

    private void OnTopologyViewChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.OriginalSource, TopologyViews) || !IsLoaded)
            return;

        if (TopologyViews.SelectedIndex == 0)
        {
            TopologyGraph.Focus();
        }
        else
        {
            SynchronizeTableSelection();
            TopologyNodesTable.Focus();
        }
    }

    private void OnTopologyNodeTableSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_isSynchronizingTableSelection ||
            TopologyNodesTable.SelectedItem is not TopologyNodeTableRow selected)
        {
            return;
        }

        _viewModel.SelectedTopologyNode = selected.Node;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.SelectedTopologyNode))
        {
            SynchronizeTableSelection();
        }
        else if (e.PropertyName == nameof(MainViewModel.TopologyMap))
        {
            ApplyTopologyFilter();
        }
    }

    private void ApplyTopologyFilter()
    {
        TopologyFilterMode filterMode = GetSelectedFilterMode();
        TopologyGraph.FilterMode = filterMode;

        NetworkMap? map = _viewModel.TopologyMap;
        if (map is null)
        {
            TopologyNodesTable.ItemsSource = Array.Empty<TopologyNodeTableRow>();
            TopologyEdgesTable.ItemsSource = Array.Empty<TopologyEdgeTableRow>();
            TopologySummaryText.Text = "Sem mapa disponível";
            return;
        }

        NetworkMapNode[] visibleNodes = NetworkTopologyControl
            .GetVisibleNodes(map, filterMode, out int matchingCount)
            .OrderBy(NodeLayer)
            .ThenBy(node => node.Label, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
        HashSet<string> visibleIds = visibleNodes
            .Select(node => node.Id)
            .ToHashSet(StringComparer.Ordinal);
        Dictionary<string, string> labels = map.Nodes.ToDictionary(
            node => node.Id,
            node => node.Label,
            StringComparer.Ordinal);
        NetworkMapEdge[] visibleEdges = map.Edges
            .Where(edge => visibleIds.Contains(edge.SourceId) && visibleIds.Contains(edge.TargetId))
            .ToArray();

        TopologyNodesTable.ItemsSource = visibleNodes
            .Select(node => new TopologyNodeTableRow(
                node,
                NodeKindText(node),
                node.IpAddress?.ToString() ?? "—",
                node.Kind == NetworkMapNodeKind.NetworkSegment
                    ? "Rede"
                    : node.IsOnline ? "Online" : "Não confirmado",
                node.RiskLevel,
                node.VlanId is int vlan ? vlan.ToString(CultureInfo.CurrentCulture) : "—"))
            .ToArray();
        TopologyEdgesTable.ItemsSource = visibleEdges
            .Select(edge => new TopologyEdgeTableRow(
                labels.GetValueOrDefault(edge.SourceId, edge.SourceId),
                labels.GetValueOrDefault(edge.TargetId, edge.TargetId),
                EdgeKindText(edge.Kind),
                ConfidenceText(edge.Confidence),
                $"{edge.Label}. {edge.Evidence}"))
            .ToArray();

        int alertCount = visibleNodes.Count(node =>
            node.RiskLevel.Equals("Alto", StringComparison.OrdinalIgnoreCase) ||
            node.RiskLevel.Equals("Médio", StringComparison.OrdinalIgnoreCase));
        int contextCount = visibleNodes.Length - matchingCount;
        TopologySummaryText.Text = filterMode == TopologyFilterMode.All
            ? $"{visibleNodes.Length:N0} nós · {visibleEdges.Length:N0} ligações · {alertCount:N0} com alertas"
            : $"{matchingCount:N0} correspondências · {contextCount:N0} nós de contexto · " +
              $"{visibleEdges.Length:N0} ligações · {alertCount:N0} com alertas";
        SynchronizeTableSelection();
        Dispatcher.BeginInvoke(TopologyGraph.FitToView);
    }

    private TopologyFilterMode GetSelectedFilterMode()
    {
        string? value = (TopologyFilterComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString();
        return Enum.TryParse(value, ignoreCase: true, out TopologyFilterMode result)
            ? result
            : TopologyFilterMode.All;
    }

    private void SynchronizeTableSelection()
    {
        if (_isSynchronizingTableSelection || TopologyNodesTable?.ItemsSource is null)
            return;

        _isSynchronizingTableSelection = true;
        try
        {
            TopologyNodeTableRow? matching = TopologyNodesTable.Items
                .OfType<TopologyNodeTableRow>()
                .FirstOrDefault(row => string.Equals(
                    row.Node.Id,
                    _viewModel.SelectedTopologyNode?.Id,
                    StringComparison.Ordinal));
            TopologyNodesTable.SelectedItem = matching;
            if (matching is not null)
                TopologyNodesTable.ScrollIntoView(matching);
        }
        finally
        {
            _isSynchronizingTableSelection = false;
        }
    }

    private static int NodeLayer(NetworkMapNode node) => node.Kind switch
    {
        NetworkMapNodeKind.NetworkSegment => 0,
        NetworkMapNodeKind.Gateway => 1,
        NetworkMapNodeKind.ManagedSwitch or NetworkMapNodeKind.LldpNeighbor => 2,
        _ when NetworkTopologyControl.IsInfrastructureNode(node) => 2,
        _ => 3
    };

    private static string NodeKindText(NetworkMapNode node) => node.Kind switch
    {
        NetworkMapNodeKind.NetworkSegment => "Rede",
        NetworkMapNodeKind.Gateway => "Gateway / router",
        NetworkMapNodeKind.ManagedSwitch => "Switch gerido",
        NetworkMapNodeKind.LldpNeighbor => "Infraestrutura / LLDP",
        NetworkMapNodeKind.LocalHost => "Este computador",
        _ when NetworkTopologyControl.IsInfrastructureNode(node) => "Infraestrutura",
        _ => "Cliente / dispositivo"
    };

    private static string EdgeKindText(NetworkMapEdgeKind kind) => kind switch
    {
        NetworkMapEdgeKind.Layer2Observed => "ARP / L2 observado",
        NetworkMapEdgeKind.MacLearned => "FDB / SNMP",
        NetworkMapEdgeKind.IpReachability => "Alcance IP inferido",
        NetworkMapEdgeKind.DefaultRoute => "Rota predefinida",
        NetworkMapEdgeKind.LldpNeighbor => "Vizinho LLDP",
        _ => "Pertence à rede"
    };

    private static string ConfidenceText(ConfidenceLevel confidence) => confidence switch
    {
        ConfidenceLevel.High => "Alta",
        ConfidenceLevel.Medium => "Média",
        ConfidenceLevel.Low => "Baixa",
        _ => "Não especificada"
    };

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
            TopologyViews.SelectedIndex = 0;
            UpdateLayout();
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

public sealed class TopologyNodeTableRow
{
    public TopologyNodeTableRow(
        NetworkMapNode node,
        string kind,
        string ipAddress,
        string state,
        string risk,
        string vlan)
    {
        Node = node;
        Kind = kind;
        Label = node.Label;
        IpAddress = ipAddress;
        State = state;
        Risk = risk;
        Vlan = vlan;
    }

    public NetworkMapNode Node { get; }

    public string Kind { get; }

    public string Label { get; }

    public string IpAddress { get; }

    public string State { get; }

    public string Risk { get; }

    public string Vlan { get; }
}

public sealed record TopologyEdgeTableRow(
    string Source,
    string Target,
    string Kind,
    string Confidence,
    string Evidence);

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
