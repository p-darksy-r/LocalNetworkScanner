// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

/// <summary>Catálogo central dos códigos públicos e estáveis do produto.</summary>
public static class DiagnosticCatalog
{
    public const string InvalidCommandCode = "LNS-USR-001";
    public const string MissingOptionValueCode = "LNS-USR-002";
    public const string InvalidProfileCode = "LNS-USR-003";
    public const string InvalidInterfaceCode = "LNS-USR-004";
    public const string InvalidCidrCode = "LNS-USR-005";
    public const string PublicAddressScopeCode = "LNS-USR-006";
    public const string RangeLimitExceededCode = "LNS-USR-007";
    public const string InvalidScanConfigurationCode = "LNS-USR-008";
    public const string OperationCancelledCode = "LNS-USR-009";
    public const string InvalidPortSpecificationCode = "LNS-USR-010";

    public const string NoActiveInterfaceCode = "LNS-NET-001";
    public const string NoDevicesFoundCode = "LNS-NET-002";
    public const string SnmpUnavailableCode = "LNS-NET-003";
    public const string VlanUnavailableCode = "LNS-NET-004";
    public const string WifiTelemetryUnavailableCode = "LNS-NET-005";
    public const string Layer2InferenceCode = "LNS-NET-006";
    public const string NetworkOperationFailedCode = "LNS-NET-007";
    public const string SnmpDeviceIdentityUnavailableCode = "LNS-NET-008";
    public const string NmapUnavailableCode = "LNS-NET-009";
    public const string NmapScanFailedCode = "LNS-NET-010";
    public const string ArpBaselineUnavailableCode = "LNS-NET-011";

    public const string InvalidMacAddressCode = "LNS-DEV-001";
    public const string UnknownManufacturerCode = "LNS-DEV-002";
    public const string UnrecognizedDeviceCode = "LNS-DEV-003";
    public const string RandomizedMacAddressCode = "LNS-DEV-004";
    public const string IdentityConflictCode = "LNS-DEV-005";

    public const string UnexpectedApplicationErrorCode = "LNS-APP-001";
    public const string FileOperationFailedCode = "LNS-APP-002";
    public const string AccessDeniedCode = "LNS-APP-003";
    public const string PacketCaptureUnavailableCode = "LNS-APP-004";
    public const string ApplicationControlBlockedCode = "LNS-APP-005";
    public const string ApplicationControlInconclusiveCode = "LNS-APP-006";

    public static ScanDiagnostic InvalidCommand(string? command = null) => new(
        InvalidCommandCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Error,
        "O comando ou a opção indicada não é reconhecida.",
        "Consulta --help e corrige o comando ou a opção.",
        command,
        Context(("inputKind", "command-or-option")));

    public static ScanDiagnostic MissingOptionValue(string option) => new(
        MissingOptionValueCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Error,
        "Falta o valor obrigatório de uma opção.",
        "Indica um valor após a opção e volta a executar o comando.",
        option);

    public static ScanDiagnostic InvalidProfile(string? profile = null) => new(
        InvalidProfileCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Error,
        "O perfil de scan indicado não é válido.",
        "Usa quick/rápido, standard/normal ou advanced/avançado (deep continua aceite).",
        profile);

    public static ScanDiagnostic InvalidInterface(string? selector = null) => new(
        InvalidInterfaceCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Error,
        "A interface de rede selecionada não existe ou já não está disponível.",
        "Executa o comando interfaces e seleciona uma interface IPv4 ativa.",
        selector);

    public static ScanDiagnostic InvalidCidr(string? cidr = null) => new(
        InvalidCidrCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Error,
        "O endereço ou prefixo CIDR IPv4 não é válido.",
        "Usa o formato rede/prefixo, por exemplo 192.168.1.0/24.",
        cidr);

    public static ScanDiagnostic PublicAddressScope(string? target = null) => new(
        PublicAddressScopeCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Error,
        "O scan contém endereços públicos e foi bloqueado por segurança.",
        "Seleciona apenas uma rede IPv4 privada, local ou link-local para a qual tens autorização.",
        target);

    public static ScanDiagnostic RangeLimitExceeded(
        string? target = null,
        int? addressCount = null,
        int? configuredLimit = null) => new(
        RangeLimitExceededCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Error,
        "A rede excede o limite de endereços configurado para um único scan.",
        "Reduz o CIDR ou aumenta --max-hosts conscientemente dentro do limite suportado.",
        target,
        Context(
            ("addressCount", addressCount?.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("configuredLimit", configuredLimit?.ToString(System.Globalization.CultureInfo.InvariantCulture))));

    public static ScanDiagnostic InvalidScanConfiguration(string? target = null) => new(
        InvalidScanConfigurationCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Error,
        "A configuração do scan contém um valor inválido ou incompatível.",
        "Revê os limites, timeouts, portas e opções de topologia antes de repetir.",
        target);

    public static ScanDiagnostic OperationCancelled(string? target = null) => new(
        OperationCancelledCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Information,
        "A operação foi cancelada antes de terminar.",
        "Inicia novamente quando pretenderes concluir o scan.",
        target);

    public static ScanDiagnostic InvalidPortSpecification(string? specification = null) => new(
        InvalidPortSpecificationCode,
        DiagnosticCategory.User,
        DiagnosticSeverity.Error,
        "A lista ou o intervalo de portas não é válido.",
        "Usa portas entre 1 e 65535, por exemplo 22,80,443 ou 1-1024.",
        specification);

    public static ScanDiagnostic NoActiveInterface() => new(
        NoActiveInterfaceCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Error,
        "Não foi encontrada nenhuma interface IPv4 ativa.",
        "Liga o Wi-Fi ou Ethernet, confirma que recebeu um endereço IPv4 e tenta novamente.");

    public static ScanDiagnostic NoDevicesFound(string? networkCidr = null) => new(
        NoDevicesFoundCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Warning,
        "O scan terminou sem encontrar dispositivos online.",
        "Confirma a interface e o CIDR; firewalls ou isolamento Wi-Fi podem bloquear respostas.",
        networkCidr);

    public static ScanDiagnostic SnmpUnavailable(string? switchAddress = null) => new(
        SnmpUnavailableCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Warning,
        "O switch SNMP não respondeu ou rejeitou o pedido; foi mantida a topologia inferida.",
        "Confirma o endereço, a versão SNMP, a ACL e a community no switch sem partilhar a credencial.",
        switchAddress);

    public static ScanDiagnostic VlanUnavailable(string? interfaceName = null) => new(
        VlanUnavailableCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Information,
        "O sistema operativo não expôs a VLAN da interface.",
        "Consulta o switch ou o controlador de rede para confirmar a VLAN; a aplicação não inventa um ID.",
        interfaceName);

    public static ScanDiagnostic WifiTelemetryUnavailable(string? interfaceName = null) => new(
        WifiTelemetryUnavailableCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Information,
        "O sistema operativo não devolveu a intensidade do sinal Wi-Fi.",
        "Atualiza o driver Wi-Fi ou consulta o access point/controlador para RSSI por dispositivo.",
        interfaceName);

    public static ScanDiagnostic Layer2Inference() => new(
        Layer2InferenceCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Information,
        "A relação de camada 2 é uma inferência: ARP e FDB não provam uma ligação física direta ao mesmo switch.",
        "Confirma ligações físicas com LLDP, a configuração do switch e a respetiva tabela de portas.");

    public static ScanDiagnostic NetworkOperationFailed(string? target = null) => new(
        NetworkOperationFailedCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Error,
        "Uma operação de rede necessária ao scan falhou.",
        "Confirma a ligação, a interface, as regras de firewall e volta a tentar.",
        target);

    public static ScanDiagnostic SnmpDeviceIdentityUnavailable(int attemptedDevices) => new(
        SnmpDeviceIdentityUnavailableCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Information,
        "Nenhum dispositivo respondeu à consulta opcional de identidade SNMP v2c.",
        "Confirma autorização, community e ACL; SNMP v2c envia a community sem cifragem e nunca deve ser ativado numa rede não confiável.",
        context: Context(("attemptedDevices", attemptedDevices.ToString(
            System.Globalization.CultureInfo.InvariantCulture))));

    public static ScanDiagnostic NmapUnavailable(string? target = null) => new(
        NmapUnavailableCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Information,
        "A integração opcional Nmap foi pedida, mas não foi encontrado um executável Nmap utilizável.",
        "Instala o Nmap separadamente a partir da origem oficial ou indica o caminho; a aplicação não o redistribui sem licença OEM.",
        target);

    public static ScanDiagnostic NmapScanFailed(string? target = null) => new(
        NmapScanFailedCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Warning,
        "O enriquecimento opcional Nmap não terminou com dados válidos.",
        "Confirma o executável, permissões, firewall e limites; repete apenas numa rede autorizada e num intervalo menor.",
        target);

    public static ScanDiagnostic ArpBaselineUnavailable(string? interfaceName = null) => new(
        ArpBaselineUnavailableCode,
        DiagnosticCategory.Network,
        DiagnosticSeverity.Warning,
        "O Windows não disponibilizou o baseline da tabela ARP; a confirmação ARP ativa foi desativada neste scan.",
        "Os resultados confirmados por ICMP, TCP ou multicast continuam válidos. Atualiza as interfaces ou repete o scan; não desatives controlos de segurança.",
        interfaceName);

    public static ScanDiagnostic InvalidMacAddress(string target, string? observedValue = null) => new(
        InvalidMacAddressCode,
        DiagnosticCategory.Device,
        DiagnosticSeverity.Warning,
        "O dispositivo devolveu um endereço MAC inválido ou não utilizável como identidade unicast.",
        "Confirma a entrada ARP/ND e a configuração do dispositivo; não uses este valor como identidade.",
        target,
        Context(("observedMac", observedValue)));

    public static ScanDiagnostic UnknownManufacturer(string target, string normalizedMac) => new(
        UnknownManufacturerCode,
        DiagnosticCategory.Device,
        DiagnosticSeverity.Warning,
        "Não foi possível associar o MAC a um titular de prefixo IEEE conhecido.",
        "A snapshot offline já foi consultada. Para um MAC global recente, verifica opcionalmente uma atualização IEEE; para entradas Private, locais ou inconclusivas, valida o equipamento no inventário da organização.",
        target,
        Context(("mac", normalizedMac)));

    public static ScanDiagnostic UnrecognizedDevice(string target) => new(
        UnrecognizedDeviceCode,
        DiagnosticCategory.Device,
        DiagnosticSeverity.Warning,
        "Não existem evidências suficientes para reconhecer o tipo deste dispositivo.",
        "Executa o perfil advanced/avançado e confirma hostname, portas, serviços e inventário autorizado.",
        target);

    public static ScanDiagnostic RandomizedMacAddress(string target, string normalizedMac) => new(
        RandomizedMacAddressCode,
        DiagnosticCategory.Device,
        DiagnosticSeverity.Information,
        "O endereço MAC é localmente administrado e pode ser privado ou aleatório.",
        "Correlaciona o dispositivo pelo IP, hostname e histórico; o MAC pode mudar.",
        target,
        Context(("mac", normalizedMac)));

    public static ScanDiagnostic IdentityConflict(string target, int evidenceCount) => new(
        IdentityConflictCode,
        DiagnosticCategory.Device,
        DiagnosticSeverity.Warning,
        "Foram observados valores contraditórios para o fabricante ou modelo deste dispositivo.",
        "Compare as fontes e a confiança; o titular IEEE pode identificar apenas a interface ou um OEM. Confirme a etiqueta ou consola de gestão antes de usar a identificação.",
        target,
        Context(("evidenceCount", evidenceCount.ToString(
            System.Globalization.CultureInfo.InvariantCulture))));

    public static ScanDiagnostic UnexpectedApplicationError(string? target = null, string? exceptionType = null) => new(
        UnexpectedApplicationErrorCode,
        DiagnosticCategory.Application,
        DiagnosticSeverity.Critical,
        "Ocorreu uma falha interna inesperada na aplicação.",
        "Repete a operação; se persistir, reporta o código e a versão da aplicação.",
        target,
        Context(("exceptionType", exceptionType)));

    public static ScanDiagnostic FileOperationFailed(string? target = null) => new(
        FileOperationFailedCode,
        DiagnosticCategory.Application,
        DiagnosticSeverity.Error,
        "Não foi possível ler ou guardar um ficheiro necessário.",
        "Confirma o caminho, o espaço disponível e se o ficheiro está aberto noutra aplicação.",
        target);

    public static ScanDiagnostic OptionalFileOperationFailed(
        string? target = null,
        string? operation = null) => new(
        FileOperationFailedCode,
        DiagnosticCategory.Application,
        DiagnosticSeverity.Warning,
        "Não foi possível concluir uma operação opcional de dados locais; o resultado principal foi preservado.",
        "Confirma o espaço, as permissões e a proteção antimalware antes de repetir.",
        target,
        Context(("operation", operation)));

    public static ScanDiagnostic AccessDenied(string? target = null) => new(
        AccessDeniedCode,
        DiagnosticCategory.Application,
        DiagnosticSeverity.Error,
        "O Windows recusou o acesso ao recurso solicitado.",
        "Escolhe um local permitido ou executa apenas a operação que requer privilégios com autorização adequada.",
        target);

    public static ScanDiagnostic PacketCaptureUnavailable() => new(
        PacketCaptureUnavailableCode,
        DiagnosticCategory.Application,
        DiagnosticSeverity.Information,
        "Esta versão identifica protocolos por descoberta, portas e banners; não inclui captura integral de pacotes.",
        "Interpreta os protocolos como evidência do scan ativo; para analisar tráfego, usa uma ferramenta dedicada numa rede autorizada.");

    public static ScanDiagnostic ApplicationControlBlocked(string? target = null) => new(
        ApplicationControlBlockedCode,
        DiagnosticCategory.Application,
        DiagnosticSeverity.Error,
        "Uma política do Windows Application Control bloqueou a execução do ficheiro.",
        "Usa uma release com assinatura Authenticode confiável ou pede ao administrador que autorize o publisher, hash ou catálogo; não desatives a proteção para contornar o bloqueio.",
        target,
        Context(("nativeErrorCode", "4551")));

    public static ScanDiagnostic ApplicationControlInconclusive(string? target = null) => new(
        ApplicationControlInconclusiveCode,
        DiagnosticCategory.Application,
        DiagnosticSeverity.Warning,
        "O diagnóstico de Windows Application Control não encontrou prova suficiente de um bloqueio de enforcement.",
        "Repete com o caminho completo do ficheiro e confirma um evento 3077 correlacionado antes de atribuir o erro 4551.",
        target);

    private static IReadOnlyDictionary<string, string> Context(
        params (string Key, string? Value)[] values) => values
        .Where(item => !string.IsNullOrWhiteSpace(item.Value))
        .ToDictionary(item => item.Key, item => item.Value!, StringComparer.OrdinalIgnoreCase);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
