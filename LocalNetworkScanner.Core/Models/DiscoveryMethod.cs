namespace LocalNetworkScanner.Core.Models;

[Flags]
public enum DiscoveryMethod
{
    None = 0,
    Icmp = 1,
    Tcp = 2,
    Arp = 4,
    Mdns = 8,
    Ssdp = 16,
    LocalHost = 32,
    NetBios = 64,
    WsDiscovery = 128
}
