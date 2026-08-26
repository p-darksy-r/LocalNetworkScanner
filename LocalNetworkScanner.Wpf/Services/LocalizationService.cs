// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Collections;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Media3D;

namespace LocalNetworkScanner.Wpf.Services;

public sealed record LanguageOption(string Tag, string DisplayName);

/// <summary>
/// Localização da interface. Os textos estáticos são traduzidos sem substituir
/// bindings de dados, para que nomes anunciados e valores do inventário não sejam
/// alterados acidentalmente.
/// </summary>
public static class LocalizationService
{
    private static readonly IReadOnlyDictionary<string, string> English =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Sobre o Local Network Scanner"] = "About Local Network Scanner",
            ["Ícone do Local Network Scanner"] = "Local Network Scanner icon",
            ["Windows x64 · ARM64"] = "Windows x64 · ARM64",
            ["INFORMAÇÃO DA APLICAÇÃO"] = "APPLICATION INFORMATION",
            ["Criador"] = "Creator",
            ["Execução"] = "Runtime",
            ["Licença"] = "License",
            ["MIT para o código-fonte"] = "MIT for source code",
            ["CAPACIDADES PRINCIPAIS"] = "CORE CAPABILITIES",
            ["Descoberta multicamada"] = "Multilayer discovery",
            ["Inventário e identidade"] = "Inventory and identity",
            ["Diagnósticos LNS"] = "LNS diagnostics",
            ["Topologia opcional"] = "Optional topology",
            ["A aplicação não envia telemetria. Executa scans apenas em redes próprias ou explicitamente autorizadas."] =
                "The application sends no telemetry. Run scans only on networks you own or are explicitly authorized to administer.",
            ["GitHub"] = "GitHub",
            ["Licença MIT"] = "MIT License",
            ["Privacidade"] = "Privacy",
            ["Assinatura"] = "Signing",
            ["Avisos de terceiros"] = "Third-party notices",
            ["Fechar informação (Esc)"] = "Close information (Esc)",
            ["Fechar informação sobre a aplicação"] = "Close application information",
            ["Fecha esta janela. Também pode usar Escape."] = "Closes this window. You can also press Escape.",
            ["Local Network Scanner"] = "Local Network Scanner",
            ["Rápido"] = "Quick",
            ["Normal"] = "Standard",
            ["Avançado"] = "Advanced",
            ["Primeira passagem pelos mesmos alvos, com menos detalhe e tempos mais curtos."] =
                "First pass over the same targets, with less detail and shorter timeouts.",
            ["Os mesmos alvos, com tempo equilibrado e mais identidade e serviços."] =
                "The same targets, with balanced timing and more identity and service checks.",
            ["Os mesmos alvos, com mais portas, tempo e enriquecimento opcional."] =
                "The same targets, with more ports, time and optional enrichment.",
            ["Ping, ARP e portas essenciais"] = "Ping, ARP and essential ports",
            ["mDNS, SSDP/UPnP, serviços e identidade"] = "mDNS, SSDP/UPnP, services and identity",
            ["Mais portas; SNMP e Nmap opcionais"] = "More ports; optional SNMP and Nmap",
            ["Mais rápido"] = "Faster",
            ["Equilibrado"] = "Balanced",
            ["Mais demorado"] = "Slower",
            ["VISÃO RÁPIDA"] = "QUICK VIEW",
            ["RECOMENDADO"] = "RECOMMENDED",
            ["ANÁLISE PROFUNDA"] = "DEEP ANALYSIS",
            ["Claro"] = "Light",
            ["Escuro"] = "Dark",
            ["Usa a paleta clara da aplicação."] = "Uses the application's light palette.",
            ["Usa uma paleta escura com contraste adaptado."] = "Uses a dark palette with adapted contrast.",
            ["Mudar para o tema claro"] = "Switch to light theme",
            ["Mudar para o tema escuro"] = "Switch to dark theme",
            ["Alterna entre o tema claro e o tema escuro. A escolha é guardada localmente."] =
                "Switches between light and dark themes. Your choice is saved locally.",
            ["Versão"] = "Version",
            ["Ocultar configuração"] = "Hide configuration",
            ["Configuração do scan"] = "Scan configuration",
            ["A preparar a aplicação..."] = "Preparing the application...",
            ["Pronto"] = "Ready",
            ["Erro"] = "Error",
            ["A cancelar o scan"] = "Cancelling scan",
            ["A procurar dispositivos"] = "Discovering devices",
            ["Scan cancelado sem resultados completos"] = "Scan cancelled before completion",
            ["O scan não pôde ser concluído"] = "The scan could not be completed",
            ["Scan concluído sem dispositivos"] = "Scan completed without devices",
            ["Ainda não existem resultados"] = "No results yet",
            ["A terminar as operações de rede em curso e a preservar todos os resultados parciais já confirmados."] =
                "Finishing active network operations and preserving all confirmed partial results.",
            ["Os dispositivos aparecem aqui à medida que forem confirmados. Podes cancelar sem perder resultados já encontrados."] =
                "Devices appear here as they are confirmed. You can cancel without losing devices already found.",
            ["Não foi concluído qualquer dispositivo antes do cancelamento. Consulta os diagnósticos e repete o scan quando estiveres pronto."] =
                "No device was completed before cancellation. Review diagnostics and run the scan again when ready.",
            ["Consulta o diagnóstico apresentado abaixo e revê a interface, a rede e os parâmetros antes de tentar novamente."] =
                "Review the diagnostic below, then check the interface, network and parameters before trying again.",
            ["O scan terminou, mas nenhum dispositivo foi confirmado online. Confirma o CIDR, a interface e eventuais regras de firewall."] =
                "The scan finished, but no device was confirmed online. Check the CIDR, interface and firewall rules.",
            ["Seleciona uma interface e inicia um scan. Os dispositivos aparecem aqui à medida que forem encontrados."] =
                "Select an interface and start a scan. Devices appear here as they are found.",
            ["O caminho explícito do Nmap é inválido. Corrige-o ou deixa-o vazio para autodeteção."] =
                "The explicit Nmap path is invalid. Correct it or leave it empty for automatic detection.",
            ["Existem valores técnicos inválidos, incluindo o caminho do Nmap. Corrige os campos assinalados."] =
                "Some technical values are invalid, including the Nmap path. Correct the highlighted fields.",
            ["Existe 1 valor técnico inválido. Corrige o campo assinalado antes de iniciar o scan."] =
                "One technical value is invalid. Correct the highlighted field before starting the scan.",
            ["1 diagnóstico do scan"] = "1 scan diagnostic",
            ["diagnósticos do scan"] = "scan diagnostics",
            ["1 substituição ativa"] = "1 active override",
            ["substituições ativas"] = "active overrides",
            ["0 substituições ativas · perfil em controlo"] = "0 active overrides · profile controls scan",
            ["As definições correspondem ao perfil"] = "Settings match profile",
            ["Os valores alterados abaixo substituem o perfil"] = "Changed values below override profile",
            ["comanda o scan; os valores guardados abaixo estão inativos."] = "controls the scan; saved values below are inactive.",
            ["As definições personalizadas ativas podem substituir este perfil."] = "Active custom settings can override this profile.",
            ["Este perfil comanda o scan."] = "This profile controls the scan.",
            ["Nenhuma interface selecionada"] = "No interface selected",
            ["Descoberta multicamada, inventário e segurança da tua rede local"] =
                "Multilayer discovery, inventory and security for your local network",
            ["Mostrar ou ocultar configuração do scan"] = "Show or hide scan configuration",
            ["Recolhe a configuração para dar mais espaço aos resultados. Pode ser reaberta a qualquer momento."] =
                "Collapse configuration to give results more space. It can be reopened at any time.",
            ["Tema da aplicação"] = "Application theme",
            ["Escolhe livremente entre o tema claro e o tema escuro. A escolha é guardada localmente."] =
                "Switch freely between light and dark themes. Your choice is saved locally.",
            ["Sobre o Local Network Scanner (F1)"] = "About Local Network Scanner (F1)",
            ["Abrir informação sobre a aplicação"] = "Open application information",
            ["Mostra versão, resumo, criador, licença e informação técnica da aplicação. Atalho F1."] =
                "Shows the version, summary, creator, license and technical information. F1 shortcut.",
            ["Sair da aplicação (Alt+F4)"] = "Exit application (Alt+F4)",
            ["Sair da aplicação"] = "Exit application",
            ["Fecha a aplicação e pede confirmação se existir um scan ou alterações por guardar."] =
                "Closes the application and asks for confirmation when a scan or unsaved changes exist.",
            ["F5 iniciar · Esc cancelar · Ctrl+F procurar · Ctrl+E exportar"] =
                "F5 start · Esc cancel · Ctrl+F search · Ctrl+E export",
            ["Introdução à utilização responsável"] = "Responsible-use introduction",
            ["Explica o âmbito autorizado do scan, o tráfego de rede e a ausência de telemetria."] =
                "Explains the authorized scan scope, network traffic and absence of telemetry.",
            ["Antes do primeiro scan"] = "Before your first scan",
            ["Analisa apenas redes tuas ou que estás autorizado a administrar. O scan envia pedidos ativos à rede selecionada. A aplicação não envia telemetria nem o inventário; o histórico, quando ativo, permanece neste computador."] =
                "Scan only networks you own or are authorized to administer. The scan sends active requests to the selected network. The application sends neither telemetry nor inventory; when enabled, history stays on this computer.",
            ["Entendi"] = "Got it",
            ["Concluir introdução"] = "Complete introduction",
            ["Oculta esta introdução nos próximos arranques."] = "Hides this introduction on future launches.",
            ["Interface de rede"] = "Network interface",
            ["Rede / CIDR"] = "Network / CIDR",
            ["Interface IPv4 usada como referência para o scan."] = "IPv4 interface used as the scan reference.",
            ["Exemplo: 192.168.1.0/24. Apenas redes privadas são aceites."] =
                "Example: 192.168.1.0/24. Only private networks are accepted.",
            ["Rede em formato CIDR"] = "Network in CIDR format",
            ["Introduz uma rede IPv4 privada, por exemplo 192.168.1.0 barra 24."] =
                "Enter a private IPv4 network, for example 192.168.1.0 slash 24.",
            ["Atualizar interfaces de rede"] = "Refresh network interfaces",
            ["Volta a detetar as interfaces de rede disponíveis."] = "Detects available network interfaces again.",
            ["Iniciar scan (F5 ou Alt+I)"] = "Start scan (F5 or Alt+I)",
            ["Iniciar scan"] = "Start scan",
            ["Inicia o scan da rede selecionada. Atalhos F5 e Alt+I."] =
                "Starts a scan of the selected network. F5 and Alt+I shortcuts.",
            ["Cancelar scan (Escape ou Alt+C)"] = "Cancel scan (Escape or Alt+C)",
            ["Cancelar scan"] = "Cancel scan",
            ["Cancela o scan em curso. Atalhos Escape e Alt+C."] =
                "Cancels the current scan. Escape and Alt+C shortcuts.",
            ["Escolhe o tipo de scan"] = "Choose scan type",
            ["Os três perfis visam os mesmos equipamentos e usam a mesma descoberta base: ICMP, TCP, ARP e multicast. Normal e Avançado dedicam mais tempo a portas e identidade; as contagens durante o scan, ou entre momentos diferentes, são transitórias e podem subir ou descer."] =
                "All three profiles target the same equipment and use the same base discovery: ICMP, TCP, ARP and multicast. Standard and Advanced spend more time on ports and identity; counts during a scan or between moments are transient and may rise or fall.",
            ["Tipo de scan"] = "Scan type",
            ["Escolhe entre scan Rápido, Normal recomendado ou Avançado."] =
                "Choose Quick, recommended Standard or Advanced scan.",
            ["Parâmetros técnicos personalizados"] = "Custom technical parameters",
            ["Usar definições personalizadas"] = "Use custom settings",
            ["Quando está desligado, o perfil selecionado controla integralmente os parâmetros técnicos."] =
                "When disabled, the selected profile fully controls the technical parameters.",
            ["Repor valores do perfil"] = "Reset profile values",
            ["Portas"] = "Ports",
            ["Máx. endereços"] = "Max. addresses",
            ["Hosts paralelos"] = "Parallel hosts",
            ["Portas paralelas"] = "Parallel ports",
            ["Ping (ms)"] = "Ping (ms)",
            ["TCP (ms)"] = "TCP (ms)",
            ["Descoberta (ms)"] = "Discovery (ms)",
            ["ICMP / ping"] = "ICMP / ping",
            ["Descoberta TCP"] = "TCP discovery",
            ["Resolver MAC por ARP"] = "Resolve MAC via ARP",
            ["mDNS, SSDP e WSD"] = "mDNS, SSDP and WSD",
            ["Descrições UPnP"] = "UPnP descriptions",
            ["NetBIOS"] = "NetBIOS",
            ["Banners e TLS"] = "Banners and TLS",
            ["Identidade por SNMP"] = "Identity via SNMP",
            ["Topologia SNMP"] = "SNMP topology",
            ["Nmap local"] = "Local Nmap",
            ["Histórico local"] = "Local history",
            ["Todos os dispositivos"] = "All devices",
            ["Risco alto"] = "High risk",
            ["Risco médio"] = "Medium risk",
            ["Risco baixo"] = "Low risk",
            ["Novos"] = "New",
            ["Favoritos"] = "Favorites",
            ["Alterados"] = "Changed",
            ["Resultados"] = "Results",
            ["Dispositivos"] = "Devices",
            ["IP"] = "IP",
            ["Hostname"] = "Hostname",
            ["MAC"] = "MAC",
            ["Fabricante"] = "Manufacturer",
            ["Modelo"] = "Model",
            ["Ping"] = "Ping",
            ["Portas e serviços"] = "Ports and services",
            ["Risco"] = "Risk",
            ["Topologia"] = "Topology",
            ["Histórico"] = "History",
            ["Segurança"] = "Security",
            ["Rede"] = "Network",
            ["Resumo"] = "Summary",
            ["Identidade"] = "Identity",
            ["Abrir topologia"] = "Open topology",
            ["Exportar"] = "Export",
            ["Guardar"] = "Save",
            ["Copiar IP"] = "Copy IP",
            ["Copiar MAC"] = "Copy MAC",
            ["Abrir Web"] = "Open Web",
            ["Explorador"] = "Explorer",
            ["Tracert"] = "Tracert",
            ["Ambiente de Trabalho Remoto"] = "Remote Desktop",
            ["Wake-on-LAN"] = "Wake-on-LAN",
            ["Marcar como favorito"] = "Mark as favorite",
            ["Nome personalizado"] = "Custom name",
            ["Notas"] = "Notes",
            ["Guardar preferências"] = "Save preferences",
            ["Topologia do scan atual"] = "Topology of current scan",
            ["Topologia do scan"] = "Scan topology",
            ["Mapa visual"] = "Visual map",
            ["Tabela acessível"] = "Accessible table",
            ["Nós visíveis"] = "Visible nodes",
            ["Ligações e respetiva evidência"] = "Links and evidence",
            ["LEGENDA"] = "LEGEND",
            ["Localizar"] = "Find",
            ["Mostrar"] = "Show",
            ["Todos"] = "All",
            ["Infraestrutura"] = "Infrastructure",
            ["Clientes"] = "Clients",
            ["Alertas"] = "Alerts",
            ["A preparar a topologia..."] = "Preparing topology...",
            ["Fechar topologia (Escape ou Alt+F4)"] = "Close topology (Escape or Alt+F4)",
            ["Fechar janela de topologia"] = "Close topology window",
            ["Ferramentas do mapa de topologia"] = "Topology map tools",
            ["Reduzir a topologia (tecla −)"] = "Zoom out topology (− key)",
            ["Ampliar a topologia (tecla +)"] = "Zoom in topology (+ key)",
            ["Ajustar"] = "Fit",
            ["Guardar PNG"] = "Save PNG",
            ["Guardar mapa de topologia em PNG"] = "Save topology map as PNG",
            ["Guardar topologia em GraphML"] = "Save topology as GraphML",
            ["Resumo da topologia"] = "Topology summary",
            ["Localizar nó na topologia"] = "Find node in topology",
            ["Localizar e centrar nó (Enter ou F3)"] = "Find and center node (Enter or F3)",
            ["Limpar pesquisa de nós"] = "Clear node search",
            ["Mapa"] = "Map",
            ["Camada"] = "Layer",
            ["Nome"] = "Name",
            ["Estado"] = "State",
            ["Origem"] = "Source",
            ["Destino"] = "Target",
            ["Tipo"] = "Type",
            ["Confiança"] = "Confidence",
            ["Evidência"] = "Evidence",
            ["Notas e limites do mapa"] = "Map notes and limits",
            ["NÓ SELECIONADO"] = "SELECTED NODE",
            ["Nenhum nó selecionado"] = "No node selected",
            ["Idioma"] = "Language",
            ["Português (Portugal)"] = "Portuguese (Portugal)",
            ["Escolher idioma"] = "Choose language",
            ["Escolhe o idioma da interface entre Português (Portugal) e English (United States)."] =
                "Choose the interface language between Portuguese (Portugal) and English (United States).",
            ["English (United States)"] = "English (United States)",
            ["Fechar"] = "Close",
            ["Desconhecido"] = "Unknown",
            ["Desconhecida"] = "Unknown",
            ["Sem evidência"] = "No evidence",
            ["Não comparado"] = "Not compared",
            ["Novo"] = "New",
            ["Alterado"] = "Changed",
            ["Conhecido"] = "Known",
            ["Baixo"] = "Low",
            ["Médio"] = "Medium",
            ["Alto"] = "High",
            ["Dispositivo de rede"] = "Network device",
            ["Sem telemetria de infraestrutura"] = "No infrastructure telemetry",
            ["VLAN desconhecida"] = "Unknown VLAN",
            ["VLAN não confirmada"] = "VLAN not confirmed",
            ["VLAN não exposta pelo Windows"] = "VLAN not exposed by Windows",
            ["Mesmo segmento L2"] = "Same L2 segment",
            ["Segmento L2 diferente"] = "Different L2 segment",
            ["Segmento L2 indeterminado"] = "L2 segment undetermined",
            ["Switch físico indeterminado"] = "Physical switch undetermined",
            ["Confiança alta"] = "High confidence",
            ["Confiança média"] = "Medium confidence",
            ["Confiança baixa"] = "Low confidence",
            ["Sem evidência suficiente"] = "Insufficient evidence",
            ["Interface local"] = "Local interface",
            ["Cache ARP passiva"] = "Passive ARP cache",
            ["ARP ativo deste scan"] = "Active ARP for this scan",
            ["Vizinho Reachable atual/revalidado"] = "Current/revalidated Reachable neighbor",
            ["Outro protocolo / origem não classificada"] = "Other protocol / unclassified source"
            ,
            ["Sobre — Local Network Scanner"] = "About — Local Network Scanner"
            ,
            ["Topologia da rede — Local Network Scanner"] = "Network topology — Local Network Scanner"
            ,
            ["Abrir repositório no GitHub"] = "Open GitHub repository"
            ,
            ["Abrir licença MIT"] = "Open MIT license"
            ,
            ["Abrir política de privacidade"] = "Open privacy policy"
            ,
            ["Abrir política de assinatura de código"] = "Open code-signing policy"
            ,
            ["Abrir avisos de terceiros"] = "Open third-party notices"
            ,
            ["Os dados IEEE incorporados mantêm os termos dos respetivos titulares. O estado de assinatura e validação encontra-se no SIGNING-STATE.txt de cada release."] = "Bundled IEEE data remains subject to its respective owners' terms. Signing and validation status is documented in SIGNING-STATE.txt for each release."
            ,
            ["Rápido, Normal e Avançado procuram os mesmos equipamentos. Diferem sobretudo no tempo e no detalhe recolhido; as contagens temporárias podem variar."] = "Quick, Standard and Advanced target the same equipment. They mainly differ in timing and collected detail; temporary counts may vary."
            ,
            ["Parâmetros técnicos personalizados do scan"] = "Custom scan technical parameters"
            ,
            ["Usar definições personalizadas do scan"] = "Use custom scan settings"
            ,
            ["Repõe os parâmetros técnicos nos valores do perfil selecionado sem alterar o histórico local."] = "Resets technical parameters to the selected profile without changing local history."
            ,
            ["Portas personalizadas"] = "Custom ports"
            ,
            ["Máximo de endereços"] = "Maximum addresses"
            ,
            ["Concorrência máxima por host"] = "Maximum host concurrency"
            ,
            ["Concorrência máxima por porta"] = "Maximum port concurrency"
            ,
            ["Timeout ICMP em milissegundos"] = "ICMP timeout in milliseconds"
            ,
            ["Timeout TCP em milissegundos"] = "TCP timeout in milliseconds"
            ,
            ["Timeout multicast em milissegundos"] = "Multicast timeout in milliseconds"
            ,
            ["Ativar descoberta ICMP"] = "Enable ICMP discovery"
            ,
            ["Ativar descoberta TCP"] = "Enable TCP discovery"
            ,
            ["Ativar resolução ARP"] = "Enable ARP resolution"
            ,
            ["Ativar descoberta multicast"] = "Enable multicast discovery"
            ,
            ["Obter descrições de dispositivos UPnP"] = "Get UPnP device descriptions"
            ,
            ["Ativar descoberta NetBIOS"] = "Enable NetBIOS discovery"
            ,
            ["Ativar análise de serviços e TLS"] = "Enable service and TLS analysis"
            ,
            ["Ativar descoberta de identidade por SNMP"] = "Enable SNMP identity discovery"
            ,
            ["Ativar consulta SNMP ao switch"] = "Enable SNMP switch query"
            ,
            ["Enriquecer com Nmap"] = "Enrich with Nmap"
            ,
            ["Ativar enriquecimento opcional com Nmap"] = "Enable optional Nmap enrichment"
            ,
            ["Guardar e comparar histórico local"] = "Save and compare local history"
            ,
            ["IP do switch SNMP"] = "SNMP switch IP"
            ,
            ["Endereço IP do switch SNMP"] = "SNMP switch IP address"
            ,
            ["Comunidade SNMP"] = "SNMP community"
            ,
            ["Timeout SNMP em milissegundos"] = "SNMP timeout in milliseconds"
            ,
            ["Caminho do nmap.exe (opcional)"] = "nmap.exe path (optional)"
            ,
            ["Caminho opcional do executável Nmap"] = "Optional Nmap executable path"
            ,
            ["Timeout global do Nmap em milissegundos"] = "Global Nmap timeout in milliseconds"
            ,
            ["Verificar atualização opcional da base IEEE"] = "Check for optional IEEE database update"
            ,
            ["Repor a base IEEE incorporada"] = "Reset bundled IEEE database"
            ,
            ["Apagar histórico"] = "Delete history"
            ,
            ["Apagar todo o histórico local de scans"] = "Delete all local scan history"
            ,
            ["Aumentar a concorrência ou analisar todas as portas gera mais tráfego. Usa estas opções apenas em redes que administras."] = "Increasing concurrency or scanning all ports creates more traffic. Use these options only on networks you administer."
            ,
            ["ENDEREÇOS ANALISADOS"] = "ADDRESSES SCANNED"
            ,
            ["DISPOSITIVOS ONLINE"] = "ONLINE DEVICES"
            ,
            ["COM ALERTAS"] = "WITH ALERTS"
            ,
            ["TEMPO DECORRIDO"] = "ELAPSED TIME"
            ,
            ["Pesquisar dispositivos"] = "Search devices"
            ,
            ["Filtra por nome, IP, MAC, entidade IEEE, tipo, porta ou protocolo."] = "Filter by name, IP, MAC, IEEE entity, type, port or protocol."
            ,
            ["Limpar pesquisa"] = "Clear search"
            ,
            ["Remove o texto usado para filtrar os dispositivos."] = "Removes the text used to filter devices."
            ,
            ["Filtrar dispositivos por estado"] = "Filter devices by state"
            ,
            ["visíveis"] = "visible"
            ,
            ["Abre o mapa deste scan numa janela independente. Disponível após existirem resultados."] = "Opens this scan's map in a separate window. Available after results exist."
            ,
            ["Abrir topologia do scan"] = "Open scan topology"
            ,
            ["Exportar resultados em CSV"] = "Export results as CSV"
            ,
            ["Exportar resultados em JSON"] = "Export results as JSON"
            ,
            ["Exportar relatório em HTML"] = "Export HTML report"
            ,
            ["Guardar preferências do dispositivo"] = "Save device preferences"
            ,
            ["Detalhes do dispositivo"] = "Device details"
            ,
            ["AÇÕES SEGURAS"] = "SAFE ACTIONS"
            ,
            ["PREFERÊNCIAS DO DISPOSITIVO"] = "DEVICE PREFERENCES"
            ,
            ["Nome personalizado do dispositivo"] = "Custom device name"
            ,
            ["Notas adicionais do resultado"] = "Additional result notes"
            ,
            ["Marcar dispositivo como favorito"] = "Mark device as favorite"
            ,
            ["Não foram detetadas portas TCP abertas."] = "No open TCP ports were detected."
            ,
            ["Não foram gerados alertas para este dispositivo."] = "No alerts were generated for this device."
            ,
            ["Ainda não existem evidências de identidade para este dispositivo."] = "There is not yet identity evidence for this device."
            ,
            ["A pesquisa ou o filtro atual ocultou todos os resultados deste scan."] = "The current search or filter hides all results from this scan."
            ,
            ["Uso autorizado em redes próprias ou administradas"] = "Authorized use on owned or administered networks"
            ,
            ["Preparação"] = "Preparation"
            ,
            ["Concluído"] = "Completed"
            ,
            ["Cancelado"] = "Cancelled"
            ,
            ["A cancelar"] = "Cancelling"
            ,
            ["A detetar interfaces de rede..."] = "Detecting network interfaces..."
            ,
            ["Interface pronta: "] = "Interface ready: "
            ,
            ["A iniciar scan de "] = "Starting scan of "
            ,
            [" endereços..."] = " addresses..."
            ,
            ["A comparar com o scan anterior..."] = "Comparing with the previous scan..."
            ,
            ["Scan concluído. Não foram encontrados dispositivos online."] = "Scan completed. No online devices were found."
            ,
            ["Scan cancelado. O relatório parcial não contém dispositivos concluídos."] = "Scan cancelled. The partial report contains no completed devices."
            ,
            ["A cancelar o scan com segurança..."] = "Safely cancelling the scan..."
            ,
            ["Resultados limpos. Pronto para um novo scan."] = "Results cleared. Ready for a new scan."
            ,
            ["Filtros repostos. "] = "Filters reset. "
            ,
            [" dispositivos disponíveis."] = " devices available."
            ,
            ["Não existiam snapshots de histórico para apagar."] = "There were no history snapshots to delete."
            ,
            ["Relatório CSV guardado em "] = "CSV report saved to "
            ,
            ["Relatório JSON guardado em "] = "JSON report saved to "
            ,
            ["Relatório HTML guardado em "] = "HTML report saved to "
            ,
            ["Topologia GraphML guardada em "] = "GraphML topology saved to "
            ,
            ["A guardar preferências de "] = "Saving preferences for "
            ,
            ["Preferências de "] = "Preferences for "
            ,
            [" guardadas."] = " saved."
            ,
            ["Magic packet enviado para "] = "Magic packet sent to "
            ,
            ["A verificar as listagens públicas da IEEE..."] = "Checking public IEEE listings..."
            ,
            ["Base IEEE atualizada e validada. Será usada no próximo scan."] = "IEEE database updated and validated. It will be used on the next scan."
            ,
            ["A atualização falhou; a base incorporada continua disponível e intacta."] = "The update failed; the bundled database remains available and unchanged."
            ,
            ["Atualização local removida. A base incorporada está ativa."] = "Local update removed. The bundled database is active."
            ,
            ["A base incorporada já estava ativa."] = "The bundled database was already active."
            ,
            ["Base IEEE degradada · recurso incorporado indisponível; reinstala ou verifica uma atualização"] = "Degraded IEEE database · bundled resource unavailable; reinstall or check for an update"
            ,
            ["funciona offline"] = "works offline"
            ,
            ["uma atualização local inválida foi ignorada"] = "an invalid local update was ignored"
            ,
            ["Mapa opcional da rede"] = "Optional map of network"

            ,
            ["Reduzir topologia"] = "Zoom out topology"
            ,
            ["Ampliar topologia"] = "Zoom in topology"
            ,
            ["Enquadrar todos os nós (Home)"] = "Fit all nodes (Home)"
            ,
            ["Repor ampliação a 100 por cento"] = "Reset zoom to 100 percent"
            ,
            ["Guardar exatamente o mapa visível como imagem PNG"] = "Save exactly the visible map as a PNG image"
            ,
            ["Guardar topologia estruturada para Gephi, yEd ou ferramentas compatíveis"] = "Save structured topology for Gephi, yEd or compatible tools"
            ,
            ["Filtrar nós da topologia"] = "Filter topology nodes"
            ,
            ["Vistas da topologia"] = "Topology views"
            ,
            ["Nós visíveis na topologia"] = "Visible topology nodes"
            ,
            ["Ligações e evidência da topologia"] = "Topology links and evidence"
            ,
            ["Notas e limites técnicos da topologia"] = "Topology technical notes and limits"
            ,
            ["Roda: zoom · arrastar o fundo: mover · Tab: percorrer nós · +/−: zoom · setas: mover · Home: ajustar · Ctrl+F/F3: localizar · Ctrl+1/Ctrl+2: mapa/tabela. A FDB mostra onde o MAC foi aprendido, não prova a ligação física."] = "Wheel: zoom · drag background: pan · Tab: cycle nodes · +/−: zoom · arrows: pan · Home: fit · Ctrl+F/F3: find · Ctrl+1/Ctrl+2: map/table. FDB shows where a MAC was learned; it does not prove a physical link."
            ,
            ["Ações"] = "Actions"
            ,
            ["Abrir interface Web"] = "Open Web interface"
            ,
            ["Abrir no Explorador"] = "Open in Explorer"

            ,
            ["PRESENÇA NA REDE"] = "NETWORK PRESENCE"
            ,
            ["Primeira vez"] = "First seen"
            ,
            ["Última vez"] = "Last seen"
            ,
            ["ALTERAÇÕES DESDE O SCAN ANTERIOR"] = "CHANGES SINCE PREVIOUS SCAN"
            ,
            ["Sem alterações registadas."] = "No changes recorded."
            ,
            ["ORIGEM E EVIDÊNCIAS"] = "ORIGIN AND EVIDENCE"
            ,
            ["IDENTIDADE CONSOLIDADA"] = "CONSOLIDATED IDENTITY"
            ,
            ["IDENTIFICADORES E FONTES TÉCNICAS"] = "IDENTIFIERS AND TECHNICAL SOURCES"
            ,
            ["Evidências de identidade do dispositivo"] = "Device identity evidence"
            ,
            ["PROTOCOLOS OBSERVADOS OU INFERIDOS"] = "OBSERVED OR INFERRED PROTOCOLS"
            ,
            ["Os dados são conciliados a partir de IEEE/OUI, DNS-SD, SSDP/UPnP, SNMP, Nmap e outras respostas observadas."] = "Data is reconciled from IEEE/OUI, DNS-SD, SSDP/UPnP, SNMP, Nmap and other observed responses."
            ,
            ["Os detalhes, serviços, segurança e ações aparecem neste painel."] = "Details, services, security and actions appear in this panel."
            ,
            ["Atribuição IEEE"] = "IEEE assignment"
            ,
            ["Titular do prefixo IEEE"] = "IEEE prefix assignee"
            ,
            ["MAC / titular IEEE"] = "MAC / IEEE assignee"
            ,
            ["Fabricante / candidato"] = "Manufacturer / candidate"
            ,
            ["Nome anunciado"] = "Advertised name"
            ,
            ["Número de série"] = "Serial number"
            ,
            ["Revisão de hardware"] = "Hardware revision"
            ,
            ["SO provável"] = "Likely OS"
            ,
            ["Wi-Fi do dispositivo"] = "Device Wi-Fi"
            ,
            ["Wi-Fi local"] = "Local Wi-Fi"
            ,
            ["Confiança L2"] = "L2 confidence"
            ,
            ["Confiança VLAN"] = "VLAN confidence"
            ,
            ["Switch físico"] = "Physical switch"
            ,
            ["Rede / topologia"] = "Network / topology"
            ,
            ["···· Alcance IP inferido"] = "···· Inferred IP reach"
            ,
            ["↻  Verificar atualização IEEE"] = "↻  Check IEEE update"
            ,
            ["━ ━ FDB / SNMP"] = "━ ━ FDB / SNMP"
            ,
            ["━━ Rota / LLDP"] = "━━ Route / LLDP"
            ,
            ["━━━━ ARP / L2 observado"] = "━━━━ Observed ARP / L2"
            ,
            ["A base completa da release já está incorporada. Esta ação procura apenas atribuições publicadas posteriormente."] = "The complete release database is already bundled. This action only checks assignments published later."
            ,
            ["A community não é guardada, mas é transmitida sem cifragem pelo SNMP v2c."] = "The community is not stored, but is transmitted unencrypted by SNMP v2c."
            ,
            ["A identidade SNMP consulta fabricante, modelo, série, firmware e hardware em cada dispositivo online. A topologia consulta FDB, porta e VLAN no switch indicado. SNMP v2c envia a community sem cifragem: use uma credencial dedicada, apenas de leitura e numa rede de gestão confiável; nunca é persistida pela app."] = "SNMP identity queries manufacturer, model, serial, firmware and hardware on each online device. Topology queries FDB, port and VLAN on the selected switch. SNMP v2c sends the community unencrypted: use a dedicated read-only credential on a trusted management network; it is never persisted by the app."
            ,
            ["Abre opcionalmente a topologia do scan atual numa janela separada. O botão fica disponível depois do scan."] = "Optionally opens the current scan topology in a separate window. The button becomes available after the scan."
            ,
            ["Ajustar topologia à área visível"] = "Fit topology to visible area"
            ,
            ["Alterações por guardar"] = "Unsaved changes"
            ,
            ["Apaga os snapshots locais usados para comparar scans"] = "Deletes local snapshots used to compare scans"
            ,
            ["As ações só são ativadas quando o serviço correspondente foi detetado."] = "Actions are enabled only when the corresponding service was detected."
            ,
            ["Avaliação heurística baseada nos serviços observados."] = "Heuristic assessment based on observed services."
            ,
            ["Cada diagnóstico identifica se a origem provável é o utilizador, a rede, o dispositivo ou a aplicação."] = "Each diagnostic identifies whether the likely source is the user, network, device or application."
            ,
            ["Cancela o scan e preserva os resultados parciais já encontrados. Atalhos Escape e Alt+C."] = "Cancels the scan and preserves partial results already found. Escape and Alt+C shortcuts."
            ,
            ["Cancelar scan em curso"] = "Cancel current scan"
            ,
            ["Consulta identidade nos dispositivos que respondem a SNMP v2c; a community segue sem cifragem para cada alvo."] = "Queries identity on devices responding to SNMP v2c; the community is sent unencrypted to each target."
            ,
            ["Criar relatório de suporte em JSON"] = "Create JSON support report"
            ,
            ["Criar um relatório JSON minimizado para diagnóstico. Revê-o antes de partilhar."] = "Creates a minimized JSON report for diagnostics. Review it before sharing."
            ,
            ["Deixa vazio para procurar apenas nas instalações locais comuns em Program Files. Caminhos UNC, de dispositivo e PATH não são executados automaticamente."] = "Leave empty to search only common local Program Files installations. UNC, device and PATH locations are not executed automatically."
            ,
            ["Descoberta"] = "Discovery"
            ,
            ["Descrição"] = "Description"
            ,
            ["Diagnósticos estruturados do scan"] = "Structured scan diagnostics"
            ,
            ["Disponível apenas no perfil Avançado; o Nmap é externo e não é incluído pela aplicação."] = "Available only in the Advanced profile; Nmap is external and is not included by the application."
            ,
            ["Disponível apenas no perfil Avançado. Requer uma instalação externa do Nmap e gera sondas TCP ativas."] = "Available only in the Advanced profile. Requires an external Nmap installation and generates active TCP probes."
            ,
            ["Dispositivo"] = "Device"
            ,
            ["Dispositivos encontrados"] = "Devices found"
            ,
            ["Escreve parte do nome, IP, MAC, tipo ou fabricante e prime Enter. Repete Enter ou usa F3 para percorrer as correspondências."] = "Type part of a name, IP, MAC, type or manufacturer and press Enter. Press Enter again or use F3 to cycle matches."
            ,
            ["Esta lista resulta de descoberta, portas e banners; não equivale a captura integral de pacotes."] = "This list combines discovery, ports and banners; it is not a full packet capture."
            ,
            ["Estado da pesquisa na topologia"] = "Topology search status"
            ,
            ["Existem alterações de dispositivo por guardar"] = "There are unsaved device changes"
            ,
            ["Exportar CSV"] = "Export CSV"
            ,
            ["Exportar JSON"] = "Export JSON"
            ,
            ["Exportar relatório HTML pronto a imprimir"] = "Export print-ready HTML report"
            ,
            ["Fecha apenas a janela de topologia. Atalhos Escape e Alt+F4."] = "Closes only the topology window. Escape and Alt+F4 shortcuts."
            ,
            ["Guarda localmente o último snapshot desta rede para detetar alterações no scan seguinte."] = "Saves the last snapshot of this network locally to detect changes in the next scan."
            ,
            ["Limpar resultados"] = "Clear results"
            ,
            ["Localizar e centrar nó na topologia"] = "Find and center topology node"
            ,
            ["mDNS / DNS-SD"] = "mDNS / DNS-SD"
            ,
            ["Nível de ampliação da topologia"] = "Topology zoom level"
            ,
            ["Nmap"] = "Nmap"
            ,
            ["Notas do dispositivo"] = "Device notes"
            ,
            ["O caminho tem de ser absoluto, local, existir e terminar em nmap.exe; UNC e device paths são recusados."] = "The path must be absolute, local, existing and end in nmap.exe; UNC and device paths are rejected."
            ,
            ["O histórico fica apenas neste computador e pode ser apagado a qualquer momento."] = "History remains on this computer and can be deleted at any time."
            ,
            ["O Nmap é instalado e licenciado separadamente; não é descarregado nem redistribuído pela app. A app recusa caminhos de rede/dispositivo, não pesquisa no PATH e mostra o executável local antes do scan TCP ativo."] = "Nmap is installed and licensed separately; it is not downloaded or redistributed by the app. The app rejects network/device paths, does not search PATH and shows the local executable before an active TCP scan."
            ,
            ["Obtém fabricante, modelo, nome, série, descrição e tipo anunciados por dispositivos SSDP/UPnP."] = "Gets manufacturer, model, name, serial, description and type advertised by SSDP/UPnP devices."
            ,
            ["Pede confirmação antes de remover os resultados do scan atual."] = "Asks for confirmation before removing current scan results."
            ,
            ["Ping / TTL"] = "Ping / TTL"
            ,
            ["Porta"] = "Port"
            ,
            ["Portas / serviços"] = "Ports / services"
            ,
            ["Portas e serviços abertos"] = "Open ports and services"
            ,
            ["Progresso do scan"] = "Scan progress"
            ,
            ["Proto."] = "Proto."
            ,
            ["Protocolos"] = "Protocols"
            ,
            ["RDP"] = "RDP"
            ,
            ["Redimensionar painel de detalhes"] = "Resize details panel"
            ,
            ["Remove as substituições técnicas e mantém a utilização de definições personalizadas no estado atual."] = "Removes technical overrides and keeps custom settings in their current state."
            ,
            ["Remove uma atualização local e volta à snapshot incluída nesta versão"] = "Removes a local update and returns to the snapshot bundled with this version"
            ,
            ["Repor ampliação da topologia"] = "Reset topology zoom"
            ,
            ["Repor base incorporada"] = "Reset bundled database"
            ,
            ["Repor definições personalizadas para os valores do perfil"] = "Reset custom settings to profile values"
            ,
            ["Repor pesquisa e filtro"] = "Reset search and filter"
            ,
            ["Repor pesquisa e filtro de dispositivos"] = "Reset device search and filter"
            ,
            ["Requer a descoberta SSDP e está desligado por omissão no perfil Rápido."] = "Requires SSDP discovery and is off by default in the Quick profile."
            ,
            ["Segmento L2"] = "L2 segment"
            ,
            ["Seleciona um dispositivo"] = "Select a device"
            ,
            ["Seleciona um dispositivo para consultar detalhes e ações."] = "Select a device to view details and actions."
            ,
            ["Sem dispositivos correspondentes"] = "No matching devices"
            ,
            ["Serviço"] = "Service"
            ,
            ["Serviços"] = "Services"
            ,
            ["SNMP"] = "SNMP"
            ,
            ["Só é necessário para a topologia. A descoberta de identidade SNMP consulta diretamente cada dispositivo."] = "Only required for topology. SNMP identity discovery queries each device directly."
            ,
            ["SSDP / UPnP"] = "SSDP / UPnP"
            ,
            ["SSDP ST"] = "SSDP ST"
            ,
            ["SSDP USN"] = "SSDP USN"
            ,
            ["Suporte"] = "Support"
            ,
            ["Timeout (ms)"] = "Timeout (ms)"
            ,
            ["Titular IEEE"] = "IEEE assignee"
            ,
            ["TLS"] = "TLS"
            ,
            ["TOPOLOGIA E EVIDÊNCIA"] = "TOPOLOGY AND EVIDENCE"
            ,
            ["Topologia por SNMP"] = "SNMP topology"
            ,
            ["Usa a community apenas nesta sessão, mas o protocolo SNMP v2c transmite-a sem cifragem."] = "Uses the community only for this session, but SNMP v2c transmits it unencrypted."
            ,
            ["Vazio procura em Program Files; um caminho explícito tem de ser local e apontar para nmap.exe."] = "Empty searches Program Files; an explicit path must be local and point to nmap.exe."
            ,
            ["Vazio usa o perfil. Exemplos: 22,80,443; 1-1024; quick; all."] = "Empty uses the profile. Examples: 22,80,443; 1-1024; quick; all."
            ,
            ["VLAN"] = "VLAN"
            ,
            ["WS-Discovery"] = "WS-Discovery"
            ,
            ["Sim"] = "Yes"
            ,
            ["Não"] = "No"
            ,
            ["prefixo"] = "prefix"
            ,
            ["série"] = "serial"
            ,
            ["firmware"] = "firmware"
            ,
            ["hardware"] = "hardware"
            ,
            ["VLAN não confirmada · PVID da porta "] = "VLAN not confirmed · port PVID "
            ,
            [" (apenas referência)"] = " (reference only)"
            ,
            ["Perfil de scan "] = "Scan profile "
            ,
            ["Tempo: "] = "Time: "
            ,
            ["Ação recomendada: "] = "Recommended action: "
            ,
            ["Alvo: "] = "Target: "
            ,
            ["• "] = "• "
            ,
            ["⚠  "] = "⚠  "
            ,
            ["Risco "] = "Risk "
            ,
            ["Nível de risco: "] = "Risk level: "
            ,
            ["Risco: "] = "Risk: "
            ,
            ["Mapa opcional da rede "] = "Optional network map "
            ,
            ["IP: "] = "IP: "
            ,
            ["VLAN: "] = "VLAN: "
            ,
            [" visíveis"] = " visible"
            ,
            ["Não confirmado"] = "Unconfirmed"
            ,
            ["Gateway / router"] = "Gateway / router"
            ,
            ["Switch gerido"] = "Managed switch"
            ,
            ["Infraestrutura / LLDP"] = "Infrastructure / LLDP"
            ,
            ["Este computador"] = "This computer"
            ,
            ["Cliente / dispositivo"] = "Client / device"
            ,
            ["Rota predefinida"] = "Default route"
            ,
            ["Vizinho LLDP"] = "LLDP neighbor"
            ,
            ["Pertence à rede"] = "Belongs to network"
            ,
            ["Alta"] = "High"
            ,
            ["Média"] = "Medium"
            ,
            ["Baixa"] = "Low"
            ,
            ["Não especificada"] = "Not specified"
            ,
            ["Nó selecionado: "] = "Selected node: "
            ,
            ["Sem endereço IP."] = "No IP address."
            ,
            ["IP "] = "IP "
            ,
            ["VLAN não confirmada."] = "VLAN not confirmed."
            ,
            ["Resumo da topologia: "] = "Topology summary: "
            ,
            ["O que fazer: "] = "What to do: "
            ,
            ["Utilizador"] = "User"
            ,
            ["Dispositivo/dados"] = "Device/data"
            ,
            ["Aplicação"] = "Application"
            ,
            ["Informação"] = "Information"
            ,
            ["Aviso"] = "Warning"
            ,
            ["Erro crítico"] = "Critical error"
            ,
            ["Correspondência "] = "Match "
            ,
            [" de "] = " of "
            ,
            [". Enter ou F3 mostra a próxima."] = ". Enter or F3 shows the next match."
            ,
            ["Ainda não existe um mapa onde procurar."] = "There is no map to search yet."
            ,
            ["Introduz parte do nome, IP, MAC, tipo ou fabricante do nó."] = "Enter part of the node name, IP, MAC, type or manufacturer."
            ,
            ["Nenhum nó visível corresponde a “"] = "No visible node matches “"
            ,
            ["”. Revê também o filtro Mostrar."] = "”. Also review the Show filter."
            ,
            ["Sem mapa disponível"] = "No map available"
            ,
            ["Guardar mapa de topologia"] = "Save topology map"
            ,
            ["Imagem PNG (*.png)|*.png|Todos os ficheiros (*.*)|*.*"] = "PNG image (*.png)|*.png|All files (*.*)|*.*"
            ,
            ["Mapa guardado em:\n"] = "Map saved to:\n"
            ,
            ["Topologia exportada"] = "Topology exported"
            ,
            ["Não foi possível guardar o mapa"] = "Could not save the map"
            ,
            ["Scanner de redes locais para Windows."] = "Local network scanner for Windows."
            ,
            ["Scanner de redes locais para Windows com descoberta multicamada, inventário, diagnósticos acionáveis e topologia opcional."] = "Windows local network scanner with multilayer discovery, inventory, actionable diagnostics and optional topology."
            ,
            ["As preferências do dispositivo ainda estão a ser guardadas. Aguarda um momento e volta a fechar a aplicação."] = "Device preferences are still being saved. Wait a moment and try closing the application again."
            ,
            ["A guardar preferências"] = "Saving preferences"
            ,
            ["Scan e alterações em curso"] = "Scan and changes in progress"
            ,
            ["Existe um scan em curso e há alterações por guardar em nomes, notas ou favoritos. Queres cancelar o scan, perder essas alterações e fechar a aplicação?"] = "A scan is in progress and names, notes or favorites have unsaved changes. Cancel the scan, discard those changes and close the application?"
            ,
            ["Scan em curso"] = "Scan in progress"
            ,
            ["Existe um scan em curso. Queres cancelá-lo e fechar a aplicação?"] = "A scan is in progress. Cancel it and close the application?"
            ,
            ["Existem alterações por guardar em nomes personalizados, notas ou favoritos. Queres perdê-las e fechar a aplicação?"] = "Custom names, notes or favorites have unsaved changes. Discard them and close the application?"
            ,
            ["Inicia e conclui um scan com resultados antes de abrir o mapa."] = "Complete a scan with results before opening the map."
            ,
            ["Topologia ainda vazia"] = "Topology is empty"
            ,
            [" nós "] = " nodes "
            ,
            [" ligações "] = " links "
            ,
            [" com alertas"] = " with alerts"
            ,
            [" correspondências "] = " matches "
            ,
            [" nós de contexto "] = " context nodes "
        };

    private static readonly ConditionalWeakTable<DependencyObject, OriginalValues> OriginalValuesByElement = new();
    private static readonly List<WeakReference<FrameworkElement>> Roots = [];
    private static AppLanguage _current = AppLanguage.PtPt;

    public static IReadOnlyList<LanguageOption> LanguageOptions =>
    [
        new("pt-PT", Translate("Português (Portugal)")),
        new("en-US", Translate("English (United States)"))
    ];

    public static AppLanguage CurrentLanguage => _current;

    public static string CurrentTag => _current == AppLanguage.EnUs ? "en-US" : "pt-PT";

    public static CultureInfo CurrentCulture =>
        _current == AppLanguage.EnUs
            ? CultureInfo.GetCultureInfo("en-US")
            : CultureInfo.GetCultureInfo("pt-PT");

    public static event EventHandler? LanguageChanged;

    public static void SetLanguage(string? tag, bool notify = true)
    {
        AppLanguage next = tag?.Trim().ToLowerInvariant() switch
        {
            "en" or "en-us" or "english" => AppLanguage.EnUs,
            _ => AppLanguage.PtPt
        };
        if (_current == next)
            return;

        _current = next;
        if (notify)
        {
            LanguageChanged?.Invoke(null, EventArgs.Empty);
            RefreshRegisteredRoots();
        }
    }

    public static string Translate(string? value)
    {
        if (string.IsNullOrEmpty(value) || _current != AppLanguage.EnUs)
            return value ?? string.Empty;
        if (English.TryGetValue(value, out string? translated))
            return translated;

        // Dynamic status lines contain counters, addresses or device names. Apply
        // only longer phrases so identifiers such as IP/MAC are never rewritten.
        string result = value;
        foreach ((string source, string target) in English
                     .Where(pair => pair.Key.Length >= 5 && pair.Key.Any(char.IsWhiteSpace))
                     .OrderByDescending(pair => pair.Key.Length))
        {
            if (result.Contains(source, StringComparison.Ordinal))
                result = result.Replace(source, target, StringComparison.Ordinal);
        }

        return result;
    }

    /// <summary>
    /// Translates one complete, known UI value without applying phrase replacement
    /// to user- or network-provided text.
    /// </summary>
    public static string TranslateExact(string? value)
    {
        if (string.IsNullOrEmpty(value) || _current != AppLanguage.EnUs)
            return value ?? string.Empty;
        return English.TryGetValue(value, out string? translated) ? translated : value;
    }

    public static readonly DependencyProperty IsEnabledProperty =
        DependencyProperty.RegisterAttached(
            "IsEnabled",
            typeof(bool),
            typeof(LocalizationService),
            new PropertyMetadata(false, OnIsEnabledChanged));

    public static void SetIsEnabled(DependencyObject element, bool value) =>
        element.SetValue(IsEnabledProperty, value);

    public static bool GetIsEnabled(DependencyObject element) =>
        (bool)element.GetValue(IsEnabledProperty);

    private static void OnIsEnabledChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
    {
        if (dependencyObject is not FrameworkElement root || args.NewValue is not true)
            return;

        lock (Roots)
            Roots.Add(new WeakReference<FrameworkElement>(root));
        root.Loaded += OnRootLoaded;
        if (root.IsLoaded)
            TranslateTree(root);
    }

    private static void OnRootLoaded(object sender, RoutedEventArgs args)
    {
        if (sender is FrameworkElement root)
            TranslateTree(root);
    }

    private static void RefreshRegisteredRoots()
    {
        List<FrameworkElement> liveRoots = [];
        lock (Roots)
        {
            for (int index = Roots.Count - 1; index >= 0; index--)
            {
                if (Roots[index].TryGetTarget(out FrameworkElement? root))
                    liveRoots.Add(root);
                else
                    Roots.RemoveAt(index);
            }
        }

        foreach (FrameworkElement root in liveRoots)
        {
            if (root.Dispatcher.CheckAccess())
                TranslateTree(root);
            else
                _ = root.Dispatcher.InvokeAsync(() => TranslateTree(root));
        }
    }

    private static void TranslateTree(DependencyObject root)
    {
        TranslateElement(root);
        foreach (DependencyObject child in EnumerateChildren(root))
            TranslateElement(child);
    }

    private static IEnumerable<DependencyObject> EnumerateChildren(DependencyObject parent)
    {
        int visualCount = VisualTreeHelper.GetChildrenCount(parent);
        for (int index = 0; index < visualCount; index++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(parent, index);
            yield return child;
            foreach (DependencyObject descendant in EnumerateChildren(child))
                yield return descendant;
        }

        if (parent is not FrameworkElement)
            yield break;

        foreach (object child in LogicalTreeHelper.GetChildren(parent).OfType<object>())
        {
            if (child is DependencyObject dependencyChild &&
                !ReferenceEquals(child, parent) &&
                !IsVisualDescendant(parent, dependencyChild))
            {
                yield return dependencyChild;
                foreach (DependencyObject descendant in EnumerateChildren(dependencyChild))
                    yield return descendant;
            }
        }
    }

    private static bool IsVisualDescendant(DependencyObject parent, DependencyObject child)
    {
        if (child is not Visual && child is not Visual3D)
            return false;

        DependencyObject? current = child;
        while (current is not null)
        {
            current = current is Visual visual
                ? VisualTreeHelper.GetParent(visual)
                : current is Visual3D visual3D
                    ? VisualTreeHelper.GetParent(visual3D)
                    : null;
            if (ReferenceEquals(current, parent))
                return true;
        }
        return false;
    }

    private static void TranslateElement(DependencyObject element)
    {
        if (element is TextBlock textBlock)
            TranslateProperty(textBlock, TextBlock.TextProperty);
        if (element is Run run)
            TranslateProperty(run, Run.TextProperty);
        if (element is ContentControl contentControl)
            TranslateProperty(contentControl, ContentControl.ContentProperty);
        if (element is HeaderedContentControl headered)
            TranslateProperty(headered, HeaderedContentControl.HeaderProperty);
        if (element is Window window)
            TranslateProperty(window, Window.TitleProperty);

        TranslateProperty(element, FrameworkElement.ToolTipProperty);
        TranslateProperty(element, AutomationProperties.NameProperty);
        TranslateProperty(element, AutomationProperties.HelpTextProperty);
    }

    private static void TranslateProperty(DependencyObject element, DependencyProperty property)
    {
        if (BindingOperations.IsDataBound(element, property))
        {
            BindingOperations.GetBindingExpressionBase(element, property)?.UpdateTarget();
            return;
        }

        object localValue = element.ReadLocalValue(property);
        if (localValue == DependencyProperty.UnsetValue || localValue is not string current)
            return;

        OriginalValues originals = OriginalValuesByElement.GetOrCreateValue(element);
        if (!originals.Values.ContainsKey(property))
            originals.Values[property] = current;

        string original = originals.Values[property];
        string translated = Translate(original);
        if (!string.Equals(current, translated, StringComparison.Ordinal))
            element.SetValue(property, translated);
    }

    private sealed class OriginalValues
    {
        public Dictionary<DependencyProperty, string> Values { get; } = [];
    }
}

public enum AppLanguage
{
    PtPt,
    EnUs
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
