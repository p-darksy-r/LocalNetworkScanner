using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Wpf.Controls;

/// <summary>
/// Native WPF network map renderer. Nodes remain real focusable buttons so the
/// graph can be explored with the keyboard and accessibility technologies.
/// </summary>
public sealed class NetworkTopologyControl : Grid
{
    private const double WorldWidth = 1_420;
    private const double WorldHeight = 820;
    private const double NodeWidth = 190;
    private const double NodeHeight = 72;

    public static readonly DependencyProperty MapProperty = DependencyProperty.Register(
        nameof(Map),
        typeof(NetworkMap),
        typeof(NetworkTopologyControl),
        new FrameworkPropertyMetadata(null, OnMapChanged));

    public static readonly DependencyProperty SelectedNodeProperty = DependencyProperty.Register(
        nameof(SelectedNode),
        typeof(NetworkMapNode),
        typeof(NetworkTopologyControl),
        new FrameworkPropertyMetadata(
            null,
            FrameworkPropertyMetadataOptions.BindsTwoWayByDefault,
            OnSelectedNodeChanged));

    private readonly Canvas _canvas = new()
    {
        Width = WorldWidth,
        Height = WorldHeight,
        Background = Brushes.Transparent
    };
    private readonly ScaleTransform _scale = new(1, 1);
    private readonly TranslateTransform _translate = new();
    private readonly TextBlock _emptyMessage;
    private readonly Dictionary<string, Button> _nodeButtons = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Point> _nodeCenters = new(StringComparer.Ordinal);
    private Point _panStart;
    private Vector _translateStart;
    private bool _isPanning;

    public NetworkTopologyControl()
    {
        ClipToBounds = true;
        Background = Brushes.Transparent;
        Focusable = true;

        TransformGroup transforms = new();
        transforms.Children.Add(_scale);
        transforms.Children.Add(_translate);
        _canvas.RenderTransform = transforms;
        Children.Add(_canvas);

        _emptyMessage = new TextBlock
        {
            MaxWidth = 480,
            Margin = new Thickness(32),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            TextAlignment = TextAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            IsHitTestVisible = false
        };
        _emptyMessage.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
        Children.Add(_emptyMessage);

        PreviewMouseWheel += OnPreviewMouseWheel;
        PreviewMouseLeftButtonDown += OnPreviewMouseLeftButtonDown;
        PreviewMouseLeftButtonUp += OnPreviewMouseLeftButtonUp;
        PreviewMouseMove += OnPreviewMouseMove;
        PreviewMouseRightButtonDown += OnPreviewMouseRightButtonDown;
        PreviewMouseRightButtonUp += OnPreviewMouseRightButtonUp;
        KeyDown += OnKeyDown;
        SizeChanged += OnSizeChanged;

        AutomationProperties.SetName(this, "Mapa de topologia da rede");
        AutomationProperties.SetHelpText(
            this,
            "Usa a roda do rato para ampliar, arrasta o fundo para mover e usa Tab para percorrer os nós.");
        RebuildVisuals();
    }

    public NetworkMap? Map
    {
        get => (NetworkMap?)GetValue(MapProperty);
        set => SetValue(MapProperty, value);
    }

    public NetworkMapNode? SelectedNode
    {
        get => (NetworkMapNode?)GetValue(SelectedNodeProperty);
        set => SetValue(SelectedNodeProperty, value);
    }

    public void FitToView()
    {
        if (ActualWidth <= 0 || ActualHeight <= 0 || _nodeCenters.Count == 0)
            return;

        const double margin = 42;
        double minX = _nodeCenters.Values.Min(point => point.X) - (NodeWidth / 2);
        double maxX = _nodeCenters.Values.Max(point => point.X) + (NodeWidth / 2);
        double minY = _nodeCenters.Values.Min(point => point.Y) - (NodeHeight / 2);
        double maxY = _nodeCenters.Values.Max(point => point.Y) + (NodeHeight / 2);
        double contentWidth = Math.Max(1, maxX - minX);
        double contentHeight = Math.Max(1, maxY - minY);
        double scale = Math.Clamp(
            Math.Min((ActualWidth - margin) / contentWidth, (ActualHeight - margin) / contentHeight),
            0.025,
            1.35);

        _scale.ScaleX = scale;
        _scale.ScaleY = scale;
        _translate.X = ((ActualWidth - (contentWidth * scale)) / 2) - (minX * scale);
        _translate.Y = ((ActualHeight - (contentHeight * scale)) / 2) - (minY * scale);
    }

    public void ResetView()
    {
        _scale.ScaleX = 1;
        _scale.ScaleY = 1;
        _translate.X = Math.Max(18, (ActualWidth - _canvas.Width) / 2);
        _translate.Y = 18;
    }

    public void ExportVisiblePng(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (ActualWidth <= 0 || ActualHeight <= 0)
            throw new InvalidOperationException("O mapa ainda não tem uma área visível para exportar.");

        DpiScale dpi = VisualTreeHelper.GetDpi(this);
        int pixelWidth = Math.Max(1, (int)Math.Ceiling(ActualWidth * dpi.DpiScaleX));
        int pixelHeight = Math.Max(1, (int)Math.Ceiling(ActualHeight * dpi.DpiScaleY));
        RenderTargetBitmap bitmap = new(pixelWidth, pixelHeight, dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        DrawingVisual composedVisual = new();
        using (DrawingContext drawing = composedVisual.RenderOpen())
        {
            Rect bounds = new(0, 0, ActualWidth, ActualHeight);
            drawing.DrawRectangle(ResourceBrush("SurfaceMutedBrush", Brushes.White), null, bounds);
            drawing.DrawRectangle(new VisualBrush(this), null, bounds);
        }
        bitmap.Render(composedVisual);

        PngBitmapEncoder encoder = new();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using FileStream stream = File.Create(path);
        encoder.Save(stream);
    }

    private static void OnMapChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e) =>
        ((NetworkTopologyControl)sender).RebuildVisuals();

    private static void OnSelectedNodeChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e) =>
        ((NetworkTopologyControl)sender).RefreshNodeSelection();

    private void RebuildVisuals()
    {
        _canvas.Children.Clear();
        _nodeButtons.Clear();
        _nodeCenters.Clear();

        NetworkMap? map = Map;
        if (map is null || map.Nodes.Count == 0)
        {
            _emptyMessage.Text =
                "A topologia aparecerá depois de um scan. Resultados parciais continuam visíveis quando existirem dados suficientes.";
            _emptyMessage.Visibility = Visibility.Visible;
            return;
        }

        _emptyMessage.Visibility = Visibility.Collapsed;
        BuildLayout(map.Nodes);

        bool showEdgeLabels = map.Edges.Count <= 60;
        foreach (NetworkMapEdge edge in map.Edges)
            AddEdge(edge, showEdgeLabels);

        foreach (NetworkMapNode node in map.Nodes)
            AddNode(node);

        RefreshNodeSelection();
        Dispatcher.BeginInvoke(FitToView, DispatcherPriority.Loaded);
    }

    private void BuildLayout(IReadOnlyList<NetworkMapNode> nodes)
    {
        NetworkMapNode[] segments = nodes.Where(node => node.Kind == NetworkMapNodeKind.NetworkSegment).ToArray();
        NetworkMapNode[] infrastructure = nodes.Where(node =>
            node.Kind is NetworkMapNodeKind.LocalHost or NetworkMapNodeKind.Gateway).ToArray();
        NetworkMapNode[] switches = nodes.Where(node =>
            node.Kind is NetworkMapNodeKind.ManagedSwitch or NetworkMapNodeKind.LldpNeighbor).ToArray();
        NetworkMapNode[] devices = nodes.Where(node => node.Kind == NetworkMapNodeKind.Device).ToArray();

        int columns = Math.Clamp((int)Math.Ceiling(Math.Sqrt(Math.Max(1, devices.Length) * 1.8)), 3, 18);
        double horizontalGap = 210;
        _canvas.Width = Math.Max(WorldWidth, (columns * horizontalGap) + 100);

        PlaceRow(segments, 95, 500);
        PlaceRow(infrastructure, 230, 320);
        PlaceRow(switches, 390, 245);

        for (int index = 0; index < devices.Length; index++)
        {
            int row = index / columns;
            int column = index % columns;
            int rowCount = Math.Min(columns, devices.Length - (row * columns));
            double rowWidth = (rowCount - 1) * horizontalGap;
            _nodeCenters[devices[index].Id] = new Point(
                (_canvas.Width / 2) - (rowWidth / 2) + (column * horizontalGap),
                545 + (row * 120));
        }

        int deviceRows = (int)Math.Ceiling(devices.Length / (double)columns);
        _canvas.Height = Math.Max(WorldHeight, 655 + (Math.Max(1, deviceRows) * 120));

        NetworkMapNode[] unplaced = nodes.Where(node => !_nodeCenters.ContainsKey(node.Id)).ToArray();
        PlaceRow(unplaced, 710, 205);
    }

    private void PlaceRow(IReadOnlyList<NetworkMapNode> nodes, double y, double maximumGap)
    {
        if (nodes.Count == 0)
            return;

        double gap = Math.Min(maximumGap, (_canvas.Width - 160) / nodes.Count);
        double rowWidth = (nodes.Count - 1) * gap;
        for (int index = 0; index < nodes.Count; index++)
            _nodeCenters[nodes[index].Id] = new Point((_canvas.Width / 2) - (rowWidth / 2) + (index * gap), y);
    }

    private void AddEdge(NetworkMapEdge edge, bool showLabel)
    {
        if (!_nodeCenters.TryGetValue(edge.SourceId, out Point source) ||
            !_nodeCenters.TryGetValue(edge.TargetId, out Point target))
        {
            return;
        }

        (Brush brush, DoubleCollection? dash, double thickness, string category) = GetEdgeStyle(edge.Kind);
        Line line = new()
        {
            X1 = source.X,
            Y1 = source.Y,
            X2 = target.X,
            Y2 = target.Y,
            Stroke = brush,
            StrokeThickness = thickness,
            StrokeDashArray = dash,
            SnapsToDevicePixels = true,
            ToolTip = $"{category}: {edge.Label}\n{edge.Evidence}\nConfiança: {ConfidenceText(edge.Confidence)}",
            IsHitTestVisible = true
        };
        AutomationProperties.SetName(line, $"Ligação {category}: {edge.Label}");
        _canvas.Children.Add(line);

        if ((showLabel || edge.Kind == NetworkMapEdgeKind.LldpNeighbor) &&
            edge.Kind is NetworkMapEdgeKind.MacLearned or NetworkMapEdgeKind.Layer2Observed or
            NetworkMapEdgeKind.IpReachability or NetworkMapEdgeKind.LldpNeighbor)
        {
            Border label = new()
            {
                Background = ResourceBrush("SurfaceBrush", Brushes.White),
                BorderBrush = brush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(5, 2, 5, 2),
                Child = new TextBlock
                {
                    Text = category,
                    FontSize = 10,
                    Foreground = ResourceBrush("TextSecondaryBrush", Brushes.DimGray)
                },
                IsHitTestVisible = false
            };
            Canvas.SetLeft(label, ((source.X + target.X) / 2) - 35);
            Canvas.SetTop(label, ((source.Y + target.Y) / 2) - 11);
            _canvas.Children.Add(label);
        }
    }

    private void AddNode(NetworkMapNode node)
    {
        if (!_nodeCenters.TryGetValue(node.Id, out Point center))
            return;

        string kindLabel = NodeKindText(node.Kind);
        TextBlock type = new()
        {
            Text = kindLabel.ToUpperInvariant(),
            FontSize = 9,
            FontWeight = FontWeights.Bold,
            Foreground = ResourceBrush("TextSecondaryBrush", Brushes.DimGray),
            TextTrimming = TextTrimming.CharacterEllipsis
        };
        TextBlock label = new()
        {
            Text = node.Label,
            Margin = new Thickness(0, 3, 0, 0),
            FontWeight = FontWeights.SemiBold,
            Foreground = ResourceBrush("TextPrimaryBrush", Brushes.Black),
            TextTrimming = TextTrimming.CharacterEllipsis
        };
        TextBlock subtitle = new()
        {
            Text = node.Subtitle,
            Margin = new Thickness(0, 2, 0, 0),
            FontSize = 10,
            Foreground = ResourceBrush("TextSecondaryBrush", Brushes.DimGray),
            TextTrimming = TextTrimming.CharacterEllipsis
        };
        StackPanel content = new();
        content.Children.Add(type);
        content.Children.Add(label);
        content.Children.Add(subtitle);

        Button button = new()
        {
            Width = NodeWidth,
            Height = NodeHeight,
            Padding = new Thickness(12, 7, 12, 7),
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            VerticalContentAlignment = VerticalAlignment.Center,
            Background = NodeBackground(node),
            BorderBrush = NodeBorder(node.Kind),
            BorderThickness = NodeBorderThickness(node.Kind),
            Content = content,
            Tag = node,
            ToolTip = BuildNodeToolTip(node),
            Focusable = true
        };
        button.Click += OnNodeClick;
        AutomationProperties.SetName(
            button,
            $"{kindLabel}: {node.Label}. {node.Subtitle}. Estado: {(node.IsOnline ? "online" : "não confirmado online")}.");
        AutomationProperties.SetHelpText(button, "Seleciona o dispositivo e abre os respetivos detalhes.");

        Canvas.SetLeft(button, center.X - (NodeWidth / 2));
        Canvas.SetTop(button, center.Y - (NodeHeight / 2));
        _canvas.Children.Add(button);
        _nodeButtons[node.Id] = button;
    }

    private void OnNodeClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NetworkMapNode node })
            SetCurrentValue(SelectedNodeProperty, node);
    }

    private void RefreshNodeSelection()
    {
        string? selectedId = SelectedNode?.Id;
        foreach ((string id, Button button) in _nodeButtons)
        {
            bool selected = string.Equals(id, selectedId, StringComparison.Ordinal);
            button.BorderThickness = selected
                ? new Thickness(4)
                : NodeBorderThickness(((NetworkMapNode)button.Tag).Kind);
            button.BorderBrush = selected
                ? ResourceBrush("AccentBrush", Brushes.DodgerBlue)
                : NodeBorder(((NetworkMapNode)button.Tag).Kind);
        }
    }

    private void OnPreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        Point pointer = e.GetPosition(this);
        double oldScale = _scale.ScaleX;
        double newScale = Math.Clamp(oldScale * (e.Delta > 0 ? 1.12 : 1 / 1.12), 0.025, 2.8);
        double worldX = (pointer.X - _translate.X) / oldScale;
        double worldY = (pointer.Y - _translate.Y) / oldScale;
        _scale.ScaleX = newScale;
        _scale.ScaleY = newScale;
        _translate.X = pointer.X - (worldX * newScale);
        _translate.Y = pointer.Y - (worldY * newScale);
        e.Handled = true;
    }

    private void OnPreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (FindAncestor<Button>(e.OriginalSource as DependencyObject) is not null)
            return;

        StartPan(e);
    }

    private void OnPreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e) => StartPan(e);

    private void StartPan(MouseButtonEventArgs e)
    {
        _panStart = e.GetPosition(this);
        _translateStart = new Vector(_translate.X, _translate.Y);
        _isPanning = true;
        Cursor = Cursors.Hand;
        CaptureMouse();
        e.Handled = true;
    }

    private void OnPreviewMouseMove(object sender, MouseEventArgs e)
    {
        if (!_isPanning)
            return;

        Vector delta = e.GetPosition(this) - _panStart;
        _translate.X = _translateStart.X + delta.X;
        _translate.Y = _translateStart.Y + delta.Y;
        e.Handled = true;
    }

    private void OnPreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e) => EndPan(e);

    private void OnPreviewMouseRightButtonUp(object sender, MouseButtonEventArgs e) => EndPan(e);

    private void EndPan(MouseButtonEventArgs e)
    {
        if (!_isPanning)
            return;

        _isPanning = false;
        Cursor = null;
        ReleaseMouseCapture();
        e.Handled = true;
    }

    private void OnKeyDown(object sender, KeyEventArgs e)
    {
        const double panStep = 35;
        switch (e.Key)
        {
            case Key.Add:
            case Key.OemPlus:
                ZoomAtCenter(1.15);
                break;
            case Key.Subtract:
            case Key.OemMinus:
                ZoomAtCenter(1 / 1.15);
                break;
            case Key.Left:
                _translate.X += panStep;
                break;
            case Key.Right:
                _translate.X -= panStep;
                break;
            case Key.Up:
                _translate.Y += panStep;
                break;
            case Key.Down:
                _translate.Y -= panStep;
                break;
            case Key.Home:
                FitToView();
                break;
            default:
                return;
        }

        e.Handled = true;
    }

    private void ZoomAtCenter(double factor)
    {
        Point center = new(ActualWidth / 2, ActualHeight / 2);
        double oldScale = _scale.ScaleX;
        double newScale = Math.Clamp(oldScale * factor, 0.025, 2.8);
        double worldX = (center.X - _translate.X) / oldScale;
        double worldY = (center.Y - _translate.Y) / oldScale;
        _scale.ScaleX = newScale;
        _scale.ScaleY = newScale;
        _translate.X = center.X - (worldX * newScale);
        _translate.Y = center.Y - (worldY * newScale);
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (_nodeCenters.Count > 0)
            Dispatcher.BeginInvoke(FitToView, DispatcherPriority.Loaded);
    }

    private (Brush Brush, DoubleCollection? Dash, double Thickness, string Category) GetEdgeStyle(
        NetworkMapEdgeKind kind) => kind switch
        {
            NetworkMapEdgeKind.Layer2Observed =>
                (ResourceBrush("SuccessBrush", Brushes.SeaGreen), null, 3, "ARP / L2 observado"),
            NetworkMapEdgeKind.MacLearned =>
                (ResourceBrush("AccentBrush", Brushes.RoyalBlue), new DoubleCollection([8, 4]), 3, "FDB / SNMP"),
            NetworkMapEdgeKind.IpReachability =>
                (ResourceBrush("TextSecondaryBrush", Brushes.DimGray), new DoubleCollection([2, 4]), 2, "Alcance IP inferido"),
            NetworkMapEdgeKind.DefaultRoute =>
                (ResourceBrush("WarningBrush", Brushes.DarkOrange), new DoubleCollection([12, 3]), 3, "Rota predefinida"),
            NetworkMapEdgeKind.LldpNeighbor =>
                (ResourceBrush("AccentDarkBrush", Brushes.Navy), new DoubleCollection([10, 3, 2, 3]), 3, "Vizinho LLDP"),
            _ =>
                (ResourceBrush("BorderBrush", Brushes.Gray), new DoubleCollection([1, 3]), 2, "Pertence à rede")
        };

    private Brush NodeBackground(NetworkMapNode node)
    {
        if (node.RiskLevel.Equals("Alto", StringComparison.OrdinalIgnoreCase))
            return ResourceBrush("RiskHighBrush", Brushes.MistyRose);
        if (node.RiskLevel.Equals("Médio", StringComparison.OrdinalIgnoreCase))
            return ResourceBrush("RiskMediumBrush", Brushes.LemonChiffon);

        return node.Kind switch
        {
            NetworkMapNodeKind.NetworkSegment => ResourceBrush("SelectionBrush", Brushes.AliceBlue),
            NetworkMapNodeKind.ManagedSwitch => ResourceBrush("SurfaceMutedBrush", Brushes.GhostWhite),
            _ => ResourceBrush("SurfaceBrush", Brushes.White)
        };
    }

    private Brush NodeBorder(NetworkMapNodeKind kind) => kind switch
    {
        NetworkMapNodeKind.NetworkSegment => ResourceBrush("AccentBrush", Brushes.RoyalBlue),
        NetworkMapNodeKind.Gateway => ResourceBrush("WarningBrush", Brushes.DarkOrange),
        NetworkMapNodeKind.ManagedSwitch => ResourceBrush("AccentDarkBrush", Brushes.Navy),
        NetworkMapNodeKind.LocalHost => ResourceBrush("SuccessBrush", Brushes.SeaGreen),
        NetworkMapNodeKind.LldpNeighbor => ResourceBrush("TextSecondaryBrush", Brushes.DimGray),
        _ => ResourceBrush("BorderBrush", Brushes.Gray)
    };

    private static Thickness NodeBorderThickness(NetworkMapNodeKind kind) => kind switch
    {
        NetworkMapNodeKind.NetworkSegment => new Thickness(2, 2, 2, 4),
        NetworkMapNodeKind.ManagedSwitch => new Thickness(4, 2, 4, 2),
        NetworkMapNodeKind.Gateway => new Thickness(2, 4, 2, 2),
        _ => new Thickness(2)
    };

    private static string NodeKindText(NetworkMapNodeKind kind) => kind switch
    {
        NetworkMapNodeKind.NetworkSegment => "Segmento de rede",
        NetworkMapNodeKind.LocalHost => "Este computador",
        NetworkMapNodeKind.Gateway => "Gateway / router",
        NetworkMapNodeKind.ManagedSwitch => "Switch gerido",
        NetworkMapNodeKind.LldpNeighbor => "Vizinho LLDP",
        _ => "Dispositivo"
    };

    private static string BuildNodeToolTip(NetworkMapNode node)
    {
        List<string> details = [NodeKindText(node.Kind), node.Label, node.Subtitle];
        if (node.IpAddress is not null)
            details.Add($"IP: {node.IpAddress}");
        if (!string.IsNullOrWhiteSpace(node.MacAddress))
            details.Add($"MAC: {node.MacAddress}");
        if (node.VlanId.HasValue)
            details.Add($"VLAN confirmada: {node.VlanId}");
        if (!string.IsNullOrWhiteSpace(node.DeviceType))
            details.Add($"Tipo: {node.DeviceType}");
        details.Add($"Risco: {node.RiskLevel}");
        return string.Join(Environment.NewLine, details);
    }

    private Brush ResourceBrush(string key, Brush fallback) => TryFindResource(key) as Brush ?? fallback;

    private static string ConfidenceText(ConfidenceLevel confidence) => confidence switch
    {
        ConfidenceLevel.High => "alta",
        ConfidenceLevel.Medium => "média",
        ConfidenceLevel.Low => "baixa",
        _ => "não especificada"
    };

    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T result)
                return result;
            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }
}
