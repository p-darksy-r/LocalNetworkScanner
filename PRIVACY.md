<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Política de privacidade

Última atualização: 23 de agosto de 2026.

## Resumo

O Local Network Scanner não tem contas, publicidade, telemetria, analytics, sincronização cloud, atualização automática nem um serviço próprio que receba inventários ou relatórios de falha.

> This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

Um scan é, por natureza, uma comunicação de rede. A aplicação só inicia essas comunicações depois de o utilizador escolher ou confirmar o âmbito e executar a operação. Os resultados permanecem no computador, exceto quando o utilizador os exporta, abre um destino externo ou os partilha por outro meio.

## Comunicações de rede iniciadas pelo utilizador

Consoante o perfil e as opções escolhidas, um scan pode enviar pedidos ICMP, ARP, TCP, mDNS/DNS-SD, SSDP/UPnP, WS-Discovery, NetBIOS e, quando ativado, SNMP para a rede local selecionada. A resolução de hostnames usa a configuração DNS do Windows; por isso, as consultas podem chegar ao resolver definido pelo utilizador, pela rede, por uma VPN ou pela organização. O Nmap é opcional, usa uma instalação local fornecida separadamente pelo utilizador e pode gerar tráfego adicional. Estes pedidos destinam-se aos endereços selecionados, a grupos multicast locais, ao resolver DNS configurado ou ao equipamento de gestão indicado pelo utilizador; não são enviados para servidores do projeto.

Outras comunicações só acontecem através de ações explícitas:

- **Verificar atualização IEEE** obtém as listagens públicas MA-L, MA-M, MA-S e IAB diretamente dos endpoints da IEEE Registration Authority. O pedido não anexa MACs, IPs, SSID, topologia nem o inventário do scan.
- **Abrir interface Web** abre no browser o endereço local escolhido pelo utilizador.
- **Wake-on-LAN** envia um magic packet para o destino local escolhido pelo utilizador.
- As ligações em **Sobre** e na documentação abrem no browser páginas externas, como GitHub, Microsoft, IEEE, Nmap, SignPath ou os textos das respetivas licenças.

Esses destinos aplicam as suas próprias políticas de privacidade aos pedidos que recebem. O projeto não controla o browser, o Nmap, o equipamento consultado nem os serviços externos.

## Dados guardados localmente

A aplicação pode guardar sob `%LOCALAPPDATA%\LocalNetworkScanner`:

- `settings.json`, com preferências da UI, último âmbito e opções técnicas, sem guardar a community SNMP;
- `snapshots\`, com o histórico de inventários quando essa opção está ativa;
- `devices.json`, com aliases, notas e favoritos introduzidos pelo utilizador;
- `logs\app.log` e `logs\app.previous.log`, com metadados técnicos limitados de falhas fatais;
- `vendor-database.tsv.gz`, quando o utilizador atualiza explicitamente a base de entidades MAC.

O registo fatal é limitado e exclui deliberadamente mensagens e argumentos da exceção, alvo e contexto do diagnóstico, credenciais e identificadores de rede. Pode conservar versão da aplicação, sistema, arquitetura, tipo de exceção, `HResult` e stack sanitizada.

A versão portátil usa a mesma pasta de dados. “Portátil” significa que o programa não necessita de instalação; não significa que funcione sem dados locais.

## Inventário e exportações

Snapshots e exportações JSON, CSV, HTML, GraphML ou PNG podem conter informação sensível, incluindo IPs, MACs, hostnames, SSIDs, BSSIDs, fabricantes, modelos, firmware, números de série, portas, serviços e relações de topologia. As exportações só são criadas no caminho escolhido pelo utilizador e não são carregadas automaticamente para nenhum serviço.

O relatório de suporte agregado foi desenhado para excluir identificadores de rede, mas deve ser revisto antes de ser partilhado. Não publique inventários, communities SNMP, credenciais ou logs não revistos numa issue pública.

## Retenção e eliminação

- **Apagar histórico** na aplicação elimina os snapshots usados para comparação; não elimina preferências, aliases, notas, favoritos, logs, exports ou a base IEEE atualizada.
- A desinstalação preserva `%LOCALAPPDATA%\LocalNetworkScanner` para evitar perda silenciosa de dados.
- Para eliminar todos os dados locais da aplicação, feche-a, reveja o que pretende conservar e apague manualmente `%LOCALAPPDATA%\LocalNetworkScanner`.
- Exports guardados noutros caminhos devem ser eliminados pelo utilizador.

O projeto não consegue apagar cópias que o utilizador tenha partilhado com terceiros.

## Assinatura e distribuição

A avaliação de elegibilidade para o programa gratuito da SignPath Foundation está pendente. Nenhum artefacto publicado atualmente transfere dados para a SignPath durante a execução e nenhuma release atual deve ser tratada como assinada pela SignPath Foundation. Consulte a [Code signing policy](CODE_SIGNING_POLICY.md) para o estado exato.

## Contacto e alterações

Questões gerais sobre esta política podem ser abertas nas [GitHub Issues](https://github.com/p-darksy-r/LocalNetworkScanner/issues) sem incluir dados de uma rede real. Uma vulnerabilidade ou exposição sensível deve ser comunicada através de um [GitHub Security Advisory privado](https://github.com/p-darksy-r/LocalNetworkScanner/security/advisories/new), quando disponível; nunca publique o conteúdo sensível numa issue. Consulte o canal alternativo em [SECURITY.md](SECURITY.md).

Alterações materiais de recolha, armazenamento ou comunicação devem atualizar esta política antes de serem distribuídas.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
