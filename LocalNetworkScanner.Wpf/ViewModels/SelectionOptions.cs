using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Wpf.ViewModels;

public sealed record ScanProfileOption(
    ScanProfile Value,
    string DisplayName,
    string Description);

public sealed record DeviceFilterOption(
    string Key,
    string DisplayName);
