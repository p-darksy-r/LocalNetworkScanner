namespace LocalNetworkScanner.Core.Models;

public sealed class TopologyAssessment
{
    public bool SameIpSubnet { get; set; }

    public bool? SameLayer2Segment { get; set; }

    public ConfidenceLevel Layer2Confidence { get; set; }

    public int? VlanId { get; set; }

    public ConfidenceLevel VlanConfidence { get; set; }

    public bool? SamePhysicalSwitch { get; set; }

    public bool ObservedOnManagedBridge { get; set; }

    public string? SwitchAddress { get; set; }

    public string? SwitchName { get; set; }

    public int? SwitchPort { get; set; }

    public string? SwitchInterface { get; set; }

    public int? SwitchPortPvid { get; set; }

    public ConfidenceLevel SwitchConfidence { get; set; }

    public string SwitchEvidence { get; set; } =
        "A FDB/SNMP pode localizar onde o MAC foi aprendido, mas confirmar a ligação física exige telemetria da porta de acesso e/ou caminho LLDP.";

    public string Summary
    {
        get
        {
            string layer2 = SameLayer2Segment switch
            {
                true => "mesmo segmento L2",
                false => "segmento L2 diferente",
                null => "segmento L2 incerto"
            };

            string vlan = VlanId.HasValue ? $"VLAN {VlanId}" : "VLAN desconhecida";
            string physicalSwitch = SamePhysicalSwitch.HasValue
                ? SamePhysicalSwitch.Value ? "mesmo switch" : "switch diferente"
                : ObservedOnManagedBridge
                    ? "observado na FDB do switch"
                    : "switch físico indeterminado";

            if (SamePhysicalSwitch == true && !string.IsNullOrWhiteSpace(SwitchInterface))
                physicalSwitch += $" ({SwitchInterface})";
            else if (SamePhysicalSwitch == true && SwitchPort.HasValue)
                physicalSwitch += $" (porta {SwitchPort})";

            return $"{layer2} · {vlan} · {physicalSwitch}";
        }
    }
}
