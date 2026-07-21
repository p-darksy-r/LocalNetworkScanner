using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Utilities;

namespace LocalNetworkScanner.Core.Services;

public sealed class TopologyInferenceService
{
    public TopologyAssessment Assess(NetworkDevice device, LocalNetworkInterface networkInterface)
    {
        bool sameSubnet = IpAddressHelper.IsInSameSubnet(
            device.IpAddress,
            networkInterface.IpAddress,
            networkInterface.SubnetMask);
        bool hasDirectArp =
            device.DiscoveryMethods.HasFlag(DiscoveryMethod.Arp) &&
            !string.IsNullOrWhiteSpace(device.MacAddress);

        return new TopologyAssessment
        {
            SameIpSubnet = sameSubnet,
            SameLayer2Segment = sameSubnet && hasDirectArp ? true : null,
            Layer2Confidence = sameSubnet && hasDirectArp
                ? ConfidenceLevel.Medium
                : ConfidenceLevel.Unknown,
            VlanId = sameSubnet && hasDirectArp ? networkInterface.VlanId : null,
            VlanConfidence = sameSubnet && hasDirectArp
                ? networkInterface.VlanConfidence
                : ConfidenceLevel.Unknown,
            SamePhysicalSwitch = null,
            SwitchEvidence = hasDirectArp
                ? "ARP confirma alcance direto na camada 2, mas não identifica o switch físico. Uma FDB SNMP pode localizar a porta aprendida, que também pode ser uplink/trunk; a ligação física exige telemetria adicional da infraestrutura."
                : "Sem uma entrada ARP direta. A localização física exige telemetria da infraestrutura, como porta de acesso e caminho LLDP; uma FDB isolada não é prova suficiente."
        };
    }
}
