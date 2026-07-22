<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Changelog

Todas as alterações relevantes deste projeto são registadas neste ficheiro. O formato segue os princípios de Keep a Changelog e o versionamento segue Semantic Versioning.

## [Unreleased]

Ainda sem alterações após `1.2.0`.

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
