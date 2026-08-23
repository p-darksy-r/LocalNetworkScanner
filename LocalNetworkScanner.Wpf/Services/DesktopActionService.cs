// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Diagnostics;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;

namespace LocalNetworkScanner.Wpf.Services;

public sealed class DesktopActionService
{
    public void OpenUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException("A aplicação só abre endereços Web HTTP ou HTTPS explícitos.");
        }

        Start(uri.AbsoluteUri);
    }

    public void OpenWeb(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        PortScanResult? port = device.Ports.FirstOrDefault(item => ServiceCatalog.IsHttpPort(item.Port));
        if (port is null)
            throw new InvalidOperationException("O dispositivo não expõe uma interface Web conhecida.");

        // A convenção da porta ajuda apenas a escolher o URL quando não houve probe.
        // Nunca é convertida em evidência de que o serviço está cifrado.
        string scheme = port.IsEncrypted == true || ServiceCatalog.IsTlsPort(port.Port)
            ? "https"
            : "http";
        Uri uri = new UriBuilder(scheme, device.IpAddressText, port.Port).Uri;
        Start(uri.AbsoluteUri);
    }

    public void OpenExplorer(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        Start("explorer.exe", $"\\\\{device.IpAddressText}");
    }

    public void OpenPing(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        Start("cmd.exe", $"/k title Ping {device.IpAddressText} & ping.exe {device.IpAddressText}");
    }

    public void OpenTraceroute(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        Start("cmd.exe", $"/k title Tracert {device.IpAddressText} & tracert.exe -d {device.IpAddressText}");
    }

    public void OpenRemoteDesktop(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        Start("mstsc.exe", $"/v:{device.IpAddressText}");
    }

    private static void Start(string target)
    {
        Process.Start(new ProcessStartInfo(target)
        {
            UseShellExecute = true
        });
    }

    private static void Start(string executable, string arguments)
    {
        Process.Start(new ProcessStartInfo(executable, arguments)
        {
            UseShellExecute = true
        });
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
