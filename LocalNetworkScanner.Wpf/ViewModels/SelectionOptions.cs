// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Wpf.Services;

namespace LocalNetworkScanner.Wpf.ViewModels;

public sealed record ScanProfileOption(
    ScanProfile Value,
    string DisplayName,
    string Description,
    string Scope,
    string Duration,
    string Badge);

public sealed record DeviceFilterOption(
    string Key,
    string DisplayName);

public sealed record ThemeModeOption(
    AppThemeMode Value,
    string DisplayName,
    string Description,
    string Glyph);

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
