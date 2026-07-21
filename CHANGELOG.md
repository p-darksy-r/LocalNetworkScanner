# Changelog

Todas as alterações relevantes deste projeto são registadas neste ficheiro. O formato segue os princípios de Keep a Changelog e o versionamento segue Semantic Versioning.

## [Unreleased]

Ainda sem alterações após `1.1.0`.

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
