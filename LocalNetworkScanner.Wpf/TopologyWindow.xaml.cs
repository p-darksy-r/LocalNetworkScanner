// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Wpf.Controls;
using LocalNetworkScanner.Wpf.Infrastructure;
using Microsoft.Win32;
using LocalNetworkScanner.Wpf.ViewModels;

namespace LocalNetworkScanner.Wpf;

public partial class TopologyWindow : Window
{
    private const uint MonitorDefaultToNearest = 2;

    private readonly MainViewModel _viewModel;
    private bool _isSynchronizingTableSelection;
    private bool _hasLoaded;
    private string? _lastSearchQuery;

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
        if (!_hasLoaded)
        {
            _hasLoaded = true;
            FitWindowToCurrentWorkArea();
        }

        ApplyTopologyFilter();
        TopologyGraph.FitToView();
        AnnounceSelectedTopologyNode();
        TopologyGraph.Focus();
    }

    protected override void OnClosed(EventArgs e)
    {
        _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        TopologyGraph.ViewportChanged -= OnTopologyViewportChanged;
        base.OnClosed(e);
    }

    private void FitWindowToCurrentWorkArea()
    {
        Rect workArea = GetCurrentMonitorWorkArea();
        if (workArea.Width <= 0 || workArea.Height <= 0)
            return;

        double currentWidth = ActualWidth > 0 ? ActualWidth : Width;
        double currentHeight = ActualHeight > 0 ? ActualHeight : Height;
        double centerX = double.IsFinite(Left)
            ? Left + (currentWidth / 2)
            : workArea.Left + (workArea.Width / 2);
        double centerY = double.IsFinite(Top)
            ? Top + (currentHeight / 2)
            : workArea.Top + (workArea.Height / 2);

        MinWidth = Math.Min(MinWidth, workArea.Width);
        MinHeight = Math.Min(MinHeight, workArea.Height);
        Width = Math.Min(Math.Max(MinWidth, Width), workArea.Width);
        Height = Math.Min(Math.Max(MinHeight, Height), workArea.Height);

        double maximumLeft = workArea.Right - Width;
        double maximumTop = workArea.Bottom - Height;
        Left = maximumLeft <= workArea.Left
            ? workArea.Left
            : Math.Clamp(centerX - (Width / 2), workArea.Left, maximumLeft);
        Top = maximumTop <= workArea.Top
            ? workArea.Top
            : Math.Clamp(centerY - (Height / 2), workArea.Top, maximumTop);
    }

    private Rect GetCurrentMonitorWorkArea()
    {
        nint windowHandle = new WindowInteropHelper(this).Handle;
        nint monitorHandle = windowHandle == 0
            ? 0
            : MonitorFromWindow(windowHandle, MonitorDefaultToNearest);
        MonitorInfo monitorInfo = new()
        {
            Size = (uint)Marshal.SizeOf<MonitorInfo>()
        };
        if (monitorHandle == 0 || !GetMonitorInfo(monitorHandle, ref monitorInfo))
            return SystemParameters.WorkArea;

        Matrix fromDevice = PresentationSource.FromVisual(this)?.CompositionTarget?.TransformFromDevice ??
            Matrix.Identity;
        Point topLeft = fromDevice.Transform(new Point(monitorInfo.WorkArea.Left, monitorInfo.WorkArea.Top));
        Point bottomRight = fromDevice.Transform(new Point(monitorInfo.WorkArea.Right, monitorInfo.WorkArea.Bottom));
        return new Rect(topLeft, bottomRight);
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.F)
        {
            TopologySearchTextBox.Focus();
            TopologySearchTextBox.SelectAll();
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == ModifierKeys.None && e.Key == Key.F3)
        {
            LocateTopologyNode();
            e.Handled = true;
        }
        else if (e.Key == Key.Home &&
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
        RaiseLiveRegionChanged(TopologyZoomText);
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

        _lastSearchQuery = null;
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
            AnnounceSelectedTopologyNode();
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
            SetTopologySummary("Sem mapa disponível");
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
        SetTopologySummary(filterMode == TopologyFilterMode.All
            ? $"{visibleNodes.Length:N0} nós · {visibleEdges.Length:N0} ligações · {alertCount:N0} com alertas"
            : $"{matchingCount:N0} correspondências · {contextCount:N0} nós de contexto · " +
              $"{visibleEdges.Length:N0} ligações · {alertCount:N0} com alertas");
        SynchronizeTableSelection();
        Dispatcher.BeginInvoke(TopologyGraph.FitToView);
    }

    private void OnTopologySearchKeyDown(object sender, KeyEventArgs e)
    {
        if (Keyboard.Modifiers != ModifierKeys.None)
            return;

        if (e.Key == Key.Enter)
        {
            LocateTopologyNode();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape)
        {
            if (!string.IsNullOrWhiteSpace(TopologySearchTextBox.Text))
            {
                ClearTopologySearch();
                TopologySearchTextBox.Focus();
            }
            else
            {
                Close();
            }

            e.Handled = true;
        }
    }

    private void OnFindTopologyNodeClick(object sender, RoutedEventArgs e) => LocateTopologyNode();

    private void OnClearTopologySearchClick(object sender, RoutedEventArgs e)
    {
        ClearTopologySearch();
        TopologySearchTextBox.Focus();
    }

    private void LocateTopologyNode()
    {
        string query = TopologySearchTextBox.Text.Trim();
        if (query.Length == 0)
        {
            SetTopologySearchStatus("Introduz parte do nome, IP, MAC, tipo ou fabricante do nó.");
            TopologySearchTextBox.Focus();
            return;
        }

        NetworkMap? map = _viewModel.TopologyMap;
        if (map is null)
        {
            SetTopologySearchStatus("Ainda não existe um mapa onde procurar.");
            return;
        }

        TopologyFilterMode filterMode = GetSelectedFilterMode();
        NetworkMapNode[] matches = NetworkTopologyControl
            .GetVisibleNodes(map, filterMode, out _)
            .Where(node => NodeMatchesSearch(node, query))
            .OrderBy(node => NodeLayer(node))
            .ThenBy(node => node.Label, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
        if (matches.Length == 0)
        {
            _lastSearchQuery = query;
            SetTopologySearchStatus($"Nenhum nó visível corresponde a “{query}”. Revê também o filtro Mostrar.");
            return;
        }

        int matchIndex = 0;
        if (string.Equals(_lastSearchQuery, query, StringComparison.OrdinalIgnoreCase))
        {
            int selectedIndex = Array.FindIndex(matches, node =>
                string.Equals(node.Id, _viewModel.SelectedTopologyNode?.Id, StringComparison.Ordinal));
            if (selectedIndex >= 0)
                matchIndex = (selectedIndex + 1) % matches.Length;
        }

        NetworkMapNode match = matches[matchIndex];
        _lastSearchQuery = query;
        _viewModel.SelectedTopologyNode = match;
        TopologyViews.SelectedIndex = 0;
        TopologyGraph.CenterOnNode(match.Id, focusKeyboard: true);

        string address = match.IpAddress is null ? string.Empty : $" · {match.IpAddress}";
        SetTopologySearchStatus(
            $"Correspondência {matchIndex + 1:N0} de {matches.Length:N0}: {match.Label}{address}. " +
            "Enter ou F3 mostra a próxima.");
    }

    private void ClearTopologySearch()
    {
        TopologySearchTextBox.Clear();
        _lastSearchQuery = null;
        TopologySearchStatusText.Text = string.Empty;
        AutomationProperties.SetName(TopologySearchStatusText, "Estado da pesquisa na topologia");
        TopologySearchStatusText.Visibility = Visibility.Collapsed;
    }

    private static bool NodeMatchesSearch(NetworkMapNode node, string query)
    {
        string searchable = string.Join(
            ' ',
            node.Label,
            node.Subtitle,
            node.IpAddress?.ToString(),
            node.MacAddress,
            node.DeviceType,
            node.VlanId?.ToString(CultureInfo.InvariantCulture),
            node.RiskLevel,
            NodeKindText(node));
        return query.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .All(token => searchable.Contains(token, StringComparison.CurrentCultureIgnoreCase));
    }

    private void SetTopologySummary(string message)
    {
        if (string.Equals(TopologySummaryText.Text, message, StringComparison.Ordinal))
            return;

        TopologySummaryText.Text = message;
        AutomationProperties.SetName(TopologySummaryText, $"Resumo da topologia: {message}");
        RaiseLiveRegionChanged(TopologySummaryText);
    }

    private void SetTopologySearchStatus(string message)
    {
        TopologySearchStatusText.Text = message;
        TopologySearchStatusText.Visibility = Visibility.Visible;
        AutomationProperties.SetName(TopologySearchStatusText, message);
        RaiseLiveRegionChanged(TopologySearchStatusText);
    }

    private void AnnounceSelectedTopologyNode()
    {
        NetworkMapNode? node = _viewModel.SelectedTopologyNode;
        string message = node is null
            ? "Nenhum nó selecionado"
            : $"Nó selecionado: {node.Label}. " +
              $"{(node.IpAddress is null ? "Sem endereço IP." : $"IP {node.IpAddress}.")} " +
              $"Risco {node.RiskLevel}. " +
              $"{(node.VlanId is int vlan ? $"VLAN {vlan}." : "VLAN não confirmada.")}";
        AutomationProperties.SetName(TopologySelectionRegion, message);
        RaiseLiveRegionChanged(TopologySelectionRegion);
    }

    private static void RaiseLiveRegionChanged(UIElement element)
    {
        AutomationPeer? peer = UIElementAutomationPeer.FromElement(element) ??
            UIElementAutomationPeer.CreatePeerForElement(element);
        peer?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
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

    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint MonitorFromWindow(nint windowHandle, uint flags);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(nint monitorHandle, ref MonitorInfo monitorInfo);

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public uint Size;
        public NativeRectangle MonitorArea;
        public NativeRectangle WorkArea;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRectangle
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
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
