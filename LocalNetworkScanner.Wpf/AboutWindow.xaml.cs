// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Wpf.Services;

namespace LocalNetworkScanner.Wpf;

public partial class AboutWindow : Window, INotifyPropertyChanged
{
    private static readonly Uri RepositoryUri =
        new("https://github.com/p-darksy-r/LocalNetworkScanner", UriKind.Absolute);
    private static readonly Uri LicenseUri =
        new("https://github.com/p-darksy-r/LocalNetworkScanner/blob/main/LICENSE", UriKind.Absolute);
    private static readonly Uri PrivacyPolicyUri =
        new("https://github.com/p-darksy-r/LocalNetworkScanner/blob/main/PRIVACY.md", UriKind.Absolute);
    private static readonly Uri CodeSigningPolicyUri =
        new("https://github.com/p-darksy-r/LocalNetworkScanner/blob/main/CODE_SIGNING_POLICY.md", UriKind.Absolute);
    private static readonly Uri ThirdPartyNoticesUri =
        new("https://github.com/p-darksy-r/LocalNetworkScanner/blob/main/THIRD_PARTY_NOTICES.md", UriKind.Absolute);

    private readonly DesktopActionService _desktopActions = new();
    private readonly UserDialogService _dialogs = new();
    private readonly string _version;
    private readonly string _summarySource;
    private bool _hasLoaded;

    public AboutWindow()
    {
        Assembly assembly = typeof(AboutWindow).Assembly;
        ProductName = assembly.GetCustomAttribute<AssemblyProductAttribute>()?.Product ??
            "Local Network Scanner";
        string? informationalVersion =
            assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        string version = informationalVersion?.Split('+', 2)[0] ??
            assembly.GetName().Version?.ToString(3) ??
            "0.0.0";
        _version = version;
        _summarySource = assembly.GetCustomAttribute<AssemblyDescriptionAttribute>()?.Description ??
            "Scanner de redes locais para Windows.";
        VersionLabel = BuildVersionLabel();
        Summary = LocalizationService.Translate(_summarySource);
        Creator = assembly.GetCustomAttribute<AssemblyCompanyAttribute>()?.Company ?? "p-darksy-r";
        CopyrightText = assembly.GetCustomAttribute<AssemblyCopyrightAttribute>()?.Copyright ??
            "Copyright (c) 2026 p-darksy-r and Local Network Scanner.";
        RuntimeLabel = $"{RuntimeInformation.ProcessArchitecture} · .NET {Environment.Version.ToString(3)}";

        InitializeComponent();
        DataContext = this;
        LanguageSelector.DisplayMemberPath = nameof(LanguageOption.DisplayName);
        LanguageSelector.SelectedValuePath = nameof(LanguageOption.Tag);
        LanguageSelector.ItemsSource = LocalizationService.LanguageOptions;
        LanguageSelector.SelectedValue = LocalizationService.CurrentTag;
        LocalizationService.LanguageChanged += OnLanguageChanged;
        Closed += OnClosed;
    }

    public string ProductName { get; }

    public string VersionLabel { get; private set; }

    public string Summary { get; private set; }

    public string Creator { get; }

    public string CopyrightText { get; }

    public string RuntimeLabel { get; }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_hasLoaded)
            return;

        _hasLoaded = true;
        FitWindowToWorkArea();
        CloseAboutButton.Focus();
    }

    private void OnLanguageSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (LanguageSelector.SelectedValue is string tag)
            LocalizationService.SetLanguage(tag);
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        VersionLabel = BuildVersionLabel();
        Summary = LocalizationService.Translate(_summarySource);
        LanguageSelector.ItemsSource = LocalizationService.LanguageOptions;
        LanguageSelector.SelectedValue = LocalizationService.CurrentTag;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(VersionLabel)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Summary)));
    }

    private string BuildVersionLabel() => $"{LocalizationService.Translate("Versão")} {_version}";

    private void OnClosed(object? sender, EventArgs e)
    {
        LocalizationService.LanguageChanged -= OnLanguageChanged;
        Closed -= OnClosed;
    }

    private void FitWindowToWorkArea()
    {
        Rect workArea = SystemParameters.WorkArea;
        if (workArea.Width <= 0 || workArea.Height <= 0)
            return;

        double currentWidth = ActualWidth > 0 ? ActualWidth : Width;
        double currentHeight = ActualHeight > 0 ? ActualHeight : Height;
        double centerX = Left + (currentWidth / 2);
        double centerY = Top + (currentHeight / 2);
        MinWidth = Math.Min(MinWidth, workArea.Width);
        MinHeight = Math.Min(MinHeight, workArea.Height);
        double fittedWidth = Math.Min(Math.Max(MinWidth, Width), workArea.Width);
        double fittedHeight = Math.Min(Math.Max(MinHeight, Height), workArea.Height);
        bool sizeChanged = !fittedWidth.Equals(Width) || !fittedHeight.Equals(Height);
        Width = fittedWidth;
        Height = fittedHeight;

        // CenterOwner já escolheu o monitor e a posição corretos. Não substituímos
        // essa decisão pelo centro do monitor principal; se for mesmo necessário
        // reduzir a janela, preservamos apenas o centro que o WPF já calculou.
        if (sizeChanged &&
            double.IsFinite(centerX) &&
            double.IsFinite(centerY))
        {
            Left = centerX - (Width / 2);
            Top = centerY - (Height / 2);
        }
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (Keyboard.Modifiers == ModifierKeys.None && e.Key == Key.Escape)
        {
            Close();
            e.Handled = true;
        }
    }

    private void OnRepositoryClick(object sender, RoutedEventArgs e) => OpenExternal(RepositoryUri);

    private void OnLicenseClick(object sender, RoutedEventArgs e) => OpenExternal(LicenseUri);

    private void OnPrivacyPolicyClick(object sender, RoutedEventArgs e) => OpenExternal(PrivacyPolicyUri);

    private void OnCodeSigningPolicyClick(object sender, RoutedEventArgs e) => OpenExternal(CodeSigningPolicyUri);

    private void OnThirdPartyNoticesClick(object sender, RoutedEventArgs e) => OpenExternal(ThirdPartyNoticesUri);

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    private void OpenExternal(Uri uri)
    {
        try
        {
            _desktopActions.OpenUri(uri);
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or
                Win32Exception or
                IOException or
                NotSupportedException)
        {
            _dialogs.ShowDiagnostic(
                this,
                "Não foi possível abrir o link",
                DiagnosticMapper.FromException(exception, "browser predefinido"));
        }
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
