using System.Diagnostics;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;

namespace LocalNetworkScanner.Wpf.Services;

public sealed class DesktopActionService
{
    public void OpenWeb(NetworkDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        PortScanResult? port = device.Ports.FirstOrDefault(item => ServiceCatalog.IsHttpPort(item.Port));
        if (port is null)
            throw new InvalidOperationException("O dispositivo não expõe uma interface Web conhecida.");

        string scheme = port.IsEncrypted || ServiceCatalog.IsTlsPort(port.Port) ? "https" : "http";
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
