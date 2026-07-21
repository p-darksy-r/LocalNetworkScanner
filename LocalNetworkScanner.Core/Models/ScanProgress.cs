namespace LocalNetworkScanner.Core.Models;

public sealed record ScanProgress(
    string Phase,
    int Completed,
    int Total,
    int Online,
    string Message,
    NetworkDevice? Device = null)
{
    public double Percentage => Total <= 0 ? 0 : Math.Clamp(Completed * 100d / Total, 0, 100);
}
