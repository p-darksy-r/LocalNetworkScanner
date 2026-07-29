<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Changelog

Todas as alterações relevantes deste projeto são registadas neste ficheiro. O formato segue os princípios de Keep a Changelog e o versionamento segue Semantic Versioning.

## [Unreleased — candidato 1.3.0]

Validado em 2026-07-29; ainda não publicado como tag/release.

### Added

- relatório de suporte JSON agregado e sem identificadores de rede, disponível na UI e através de `--support`;
- snapshot offline comprimida das listagens IEEE MA-L, MA-M, MA-S e IAB, com 58 019 linhas de origem em 2026-07-28 e 58 016 prefixos únicos depois da normalização;
- lookup de titular IEEE pelo prefixo mais específico (`/36 → /28 → /24`) e atualização opcional das quatro listagens oficiais, sem exigir download no primeiro arranque;
- controlo de privacidade para desativar a leitura/escrita do histórico e ação explícita para apagar snapshots locais;
- código `LNS-APP-005` para bloqueios do Windows Application Control, incluindo `CreateProcess` 4551;
- diagnóstico e documentação dedicados a Smart App Control/App Control, sem recomendar que a proteção seja contornada;
- suporte de release opcional e fail-closed para assinatura Authenticode quando forem fornecidas credenciais de assinatura confiáveis;
- descoberta DNS-SD progressiva e dirigida, com parsing limitado e defensivo de registos PTR, SRV, TXT, A e AAAA.

### Changed

- topologia redesenhada com uma hierarquia visual inspirada em controladores de rede modernos, melhor leitura de infraestrutura, clientes, VLAN, risco e evidência;
- README reorganizado como página de produto, com imagens sintéticas da UI, download, instalação, início rápido, compatibilidade, privacidade, funcionalidades e limites antes da informação de desenvolvimento;
- histórico e metadados passam a preservar a identidade durante transições IP→MAC, ausência temporária de MAC e alterações da âncora da rede;
- ordenação da lista usa valores tipados para IP, latência, risco e número de portas;
- filtros sem correspondências apresentam um estado claro e uma ação para repor pesquisa/filtro;
- o clique direito seleciona primeiro a linha alvo antes de executar ações do dispositivo;
- parâmetros numéricos avançados bloqueiam o scan enquanto existirem erros de conversão ou intervalo visíveis;
- descoberta ARP deixa de criar um processo `arp.exe` por endereço e reutiliza informação de vizinhança ao longo do scan;
- pedidos ICMP IPv4 no Windows usam I/O nativo assíncrono ligado à origem da interface escolhida, sem ocupar uma thread por host nem mudar silenciosamente para outra interface ou VPN;
- o estado TLS separa “não verificado”, “handshake confirmado” e “handshake falhou”, sem transformar o número convencional da porta em prova de cifragem;
- exports JSON usam schema v4 para representar o estado TLS triestado sem reutilizar a semântica booleana do schema anterior;
- filtros da topologia preservam os nós de infraestrutura que são ancestrais dos clientes ou alertas encontrados;
- identificação MAC passa a descrever o titular registado do prefixo em vez de prometer o fabricante físico; CID é excluído e casos `Private`, local/aleatório, virtual ou OEM permanecem explicitamente inconclusivos;
- repositório documenta diretamente o candidato atual, e o GitHub passa a ter descrição, tópicos e alertas de dependências sem branches automáticos.

### Fixed

- aliases, notas, favoritos e comparação histórica já não desaparecem quando o mesmo dispositivo ganha/perde temporariamente um MAC válido;
- reutilização do mesmo IP por um MAC diferente deixa de herdar silenciosamente identidade anterior;
- a execução automática no fim do instalador já não transforma um bloqueio da aplicação pela política do Windows num erro aparente de instalação;
- o indicador de estado da lista já não apresenta dispositivos offline com o mesmo ponto verde dos dispositivos online.

### Security

- relatórios de suporte excluem IPs, MACs, nomes de interface/host/switch, SSID/BSSID, aliases, notas, alvos, contexto e avisos brutos;
- atualização da base IEEE é sempre explícita e não envia telemetria, MACs, IPs ou inventário; a snapshot remove endereços postais e conserva apenas os campos necessários ao lookup;
- dados IEEE são documentados separadamente, não são colocados sob MIT e exigem autorização escrita antes de redistribuição pública;
- artefactos privados de QA continuam a identificar honestamente `NotSigned`, mas a publicação de uma GitHub Release exige Authenticode `Signed` e aprovação explícita da redistribuição IEEE;
- a publicação usa um job com permissão de escrita isolada, exige exatamente os dez assets previstos, volta a validar hashes/assinaturas e recusa substituir assets de uma release existente.

## [1.2.0] - 2026-07-22

### Added

- diagnósticos estruturados com códigos estáveis `LNS-USR-*`, `LNS-NET-*`, `LNS-DEV-*` e `LNS-APP-*`, categoria, severidade, ação recomendada e contexto sanitizado;
- códigos específicos para entrada inválida, ausência de interface IPv4, MAC inválido, fabricante desconhecido, tipo de dispositivo não reconhecido e falhas inesperadas;
- catálogo público de códigos de erro e orientação para suporte sem exposição do inventário da rede;
- perfis de scan **Rápido**, **Normal** e **Avançado**, com descrições de impacto e profundidade adequadas a utilizadores iniciantes e avançados;
- scripts idempotentes para aplicar e verificar cabeçalhos e rodapés de copyright em todos os formatos comentáveis do repositório;
- validação explícita da política de copyright nos workflows de CI e release.

### Changed

- a lista de dispositivos volta a ser sempre a vista principal após o scan;
- a topologia do resultado passa a abrir apenas a pedido, numa janela separada através do botão com ícone **Abrir topologia**;
- a janela de topologia mantém zoom, pan, ajuste, seleção sincronizada e exportações PNG/GraphML sem competir com o espaço da lista;
- exports JSON usam schema v3 para incluir os diagnósticos estruturados; HTML e GraphML preservam os códigos relevantes;
- versão do produto e documentação de distribuição atualizadas para `1.2.0`.
- atribuição de copyright uniformizada em todos os ficheiros e metadados para `p-darksy-r and Local Network Scanner`, sob licença MIT.

### Fixed

- mensagens antes genéricas distinguem agora problemas corrigíveis pelo utilizador, limitações ou falhas da rede, respostas inválidas/desconhecidas de dispositivos e defeitos inesperados da aplicação.
- argumentos e alvos de diagnóstico ocultam padrões de credenciais; uma falha ao guardar o histórico local já não elimina um scan concluído.

## [1.1.0] - 2026-07-21

### Added

- visualização interativa da topologia da rede com diferenciação entre observações diretas e ligações inferidas;
- descoberta e apresentação de vizinhos LLDP disponibilizados por switches geridos autorizados;
- exportação GraphML da topologia com tipo, origem, confiança e evidência de cada ligação;
- schema JSON v2 com o grafo de topologia e metadados de compatibilidade explícitos;
- opções CLI `--html` e `--graphml` para relatórios completos não interativos;
- metadados canónicos e ligações para `p-darksy-r/LocalNetworkScanner`;
- CI Windows para restore, verificação de formato, build, testes determinísticos e smoke da CLI;
- releases por tag para Windows x64 e ARM64 com ZIPs portáteis, checksums individuais e manifesto SHA-256 combinado;
- instalador por utilizador opcional baseado em Inno Setup 6, sem elevação, driver ou serviço;
- templates seguros para erros, funcionalidades e comunicação privada de vulnerabilidades;
- documentação separada de instalação, arquitetura, integridade, desinstalação e estado de assinatura.

### Changed

- identidade de ficheiros e assemblies alinhada com o atual responsável e repositório GitHub;
- processo de release bloqueia tags que não coincidam com a versão do projeto;
- distribuição documenta explicitamente quando executáveis e instaladores não têm assinatura Authenticode.

### Fixed

- sincronização incremental da lista WPF durante scans, evitando alterações inválidas enquanto a vista estava em atualização diferida;
- bindings de propriedades de diagnóstico apenas de leitura, evitando tentativas de escrita pelo motor WPF;
- reajuste responsivo do grafo e apresentação compacta dos limites de interpretação da topologia;
- identidade HTTP derivada da versão do assembly, evitando anunciar uma versão antiga em pedidos OUI e probes HTTP;
- passagem segura de nomes de tags e outputs entre GitHub Actions e PowerShell, sem interpolação direta no shell.

## [1.0.0] - 2026-07-21

### Added

- versão base do motor de descoberta e inventário de redes locais;
- interfaces CLI e WPF para Windows;
- descoberta por ICMP, TCP, ARP e mecanismos multicast locais;
- inventário de IP, hostname, MAC, fabricante, portas e serviços observados;
- inferências transparentes de tipo de dispositivo, risco, VLAN local e camada 2;
- informação da ligação Wi-Fi local quando fornecida pelo Windows;
- histórico local e exportação JSON/CSV/HTML;
- resultados parciais claramente identificados e exportáveis após cancelamento, sem alterar o histórico;
- integração de topologia SNMP v2c opt-in para observações Bridge/Q-BRIDGE de switches geridos, sem confundir FDB com ligação física direta;
- camada de release reproduzível para Windows x64 e ARM64;
- documentação de utilização, segurança, privacidade e limites técnicos;
- scripts de validação, publish self-contained single-file, ZIP e SHA-256;
- gates documentados para testes, assinatura e validação num Windows limpo.

### Security

- limitação da CLI a endereços privados/locais;
- documentação explícita de utilização autorizada e tratamento de inventário sensível;
- neutralização de formula injection em campos não confiáveis exportados para CSV;
- parsing estrito das colunas Registry/Assignment/Organization da base IEEE OUI.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
