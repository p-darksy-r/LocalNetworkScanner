# Local Network Scanner

[![CI](https://github.com/p-darksy-r/LocalNetworkScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/p-darksy-r/LocalNetworkScanner/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/p-darksy-r/LocalNetworkScanner?display_name=tag)](https://github.com/p-darksy-r/LocalNetworkScanner/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Scanner de redes locais para Windows, com uma aplicação gráfica WPF e uma CLI para automação. O objetivo é apresentar uma visão útil da rede sem esconder a qualidade da evidência: o programa distingue aquilo que observou diretamente daquilo que apenas inferiu.

O executável publicado é self-contained e inclui o runtime .NET necessário. O utilizador final não precisa de instalar o .NET. É uma aplicação Windows em WPF; “single-file” não significa NativeAOT e algumas bibliotecas internas podem ser extraídas temporariamente pelo runtime ao arrancar.

As versões oficiais, quando existirem, serão publicadas na página de [Releases do GitHub](https://github.com/p-darksy-r/LocalNetworkScanner/releases) como ZIP portátil e instalador por utilizador para Windows x64 e ARM64. Consulte [Instalação no Windows](docs/INSTALLATION.md), incluindo a nota sobre binários ainda não assinados.

## Funcionalidades

- seleção da interface IPv4 e da rede privada a analisar;
- perfis rápido, normal e profundo, com limites de concorrência e cancelamento seguro;
- descoberta por ICMP, tentativa de ligação TCP, ARP e mecanismos locais multicast;
- endereço IP, latência, hostname, MAC quando disponível e fabricante por heurística OUI;
- pesquisa de portas TCP e identificação leve de serviços por portas e respostas de aplicação;
- observações de mDNS, SSDP/UPnP e WS-Discovery quando a rede permite multicast;
- classificação heurística do tipo de equipamento, sistema operativo provável e risco;
- histórico local, deteção de alterações e exportação JSON schema v2, CSV, HTML e GraphML;
- informação da ligação Wi-Fi local, incluindo SSID, BSSID, canal e percentagem de sinal quando o Windows a fornece;
- VLAN da interface local quando exposta pelo nome ou pelas propriedades avançadas do adaptador;
- indicação prudente de alcance direto em camada 2 quando existe evidência ARP;
- topologia SNMP v2c opcional, desativada por defeito, para switches geridos autorizados: nome/descrição, observações da FDB Bridge/Q-BRIDGE, porta/interface quando não ambígua e VLAN apenas quando o mapeamento do equipamento é inequívoco;
- visualização de topologia em grafo, com origem e confiança da evidência, enriquecida por vizinhos LLDP quando estes são disponibilizados pelo switch autorizado;
- exportação GraphML da topologia para análise em ferramentas externas, preservando o tipo, a origem, a confiança e o resumo da evidência de cada ligação.

## O que os resultados não significam

O programa não captura tráfego, não inspeciona todos os pacotes que atravessam a rede e não faz uma análise exaustiva de protocolos. A lista de protocolos é derivada dos métodos de descoberta, das portas abertas e de respostas leves dos serviços.

Uma entrada ARP pode sustentar a inferência de que um dispositivo está no mesmo segmento de camada 2, mas não identifica o switch físico. A integração opcional com um switch gerido também não afirma ligação física direta: uma FDB pode aprender o MAC através de uma porta de acesso, uplink, trunk, access point ou bridge remota.

Quando SNMP v2c é explicitamente ativado por um administrador, o motor consulta um único switch indicado e pode confirmar que um MAC foi observado na FDB dessa bridge gerida. MACs com várias observações mantêm todas as alternativas e não recebem uma porta única. Em Q-BRIDGE, um FDB-ID só é apresentado como VLAN depois de uma correspondência única na tabela de mapeamento VLAN→FDB; o PVID da porta aparece apenas como referência e nunca é tratado como a VLAN do dispositivo. O mesmo switch pode enriquecer o mapa com os vizinhos que publica através de LLDP. A funcionalidade não suporta SNMPv3, descoberta automática de switches ou switches não geridos.

A intensidade Wi-Fi apresentada pertence à ligação do computador que executa a aplicação. Não é o RSSI de cada dispositivo remoto.

Consulte [Limites técnicos](docs/TECHNICAL_LIMITS.md) antes de interpretar ou partilhar um relatório.

## Utilização responsável

Utilize o scanner apenas numa rede própria ou numa rede para a qual possui autorização explícita. Um scan abre ligações e envia pedidos de descoberta; pode ser registado por firewalls, sistemas de deteção e equipamentos de rede.

Não é necessário executar a aplicação como administrador para o fluxo normal. Algumas informações do adaptador podem não ser expostas pelo Windows, pelo driver ou pela política da organização. A aplicação deve apresentar esses campos como indisponíveis, nunca inventá-los.

A topologia SNMP é uma funcionalidade avançada e opt-in. Deve ser usada apenas num switch gerido autorizado e numa rede de gestão confiável. Dados de acesso nunca devem ser incluídos em relatórios, argumentos partilhados, logs, screenshots ou no repositório.

## Privacidade e dados locais

O histórico é guardado localmente em:

```text
%LOCALAPPDATA%\LocalNetworkScanner\snapshots
```

Os ficheiros de histórico e as exportações podem conter IPs, MACs, hostnames, portas e nomes de redes Wi-Fi. Trate-os como inventário sensível. Reveja-os antes de os anexar a issues ou pedidos de suporte.

O projeto não deve adicionar telemetria ou transmissão de inventário sem consentimento explícito, documentação e uma opção clara para desativar.

## Requisitos de desenvolvimento

- Windows 10 ou Windows 11;
- .NET SDK `10.0.301`, selecionado por `global.json`;
- PowerShell 5.1 ou PowerShell 7 para os scripts;
- uma interface IPv4 ativa para scans reais.

O SDK pode usar uma atualização de patch compatível da mesma feature band através de `rollForward: latestPatch`. Builds de release devem registar a versão efetivamente usada por `dotnet --version`.

## Compilar e verificar

Validação completa dos projetos disponíveis:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1
```

Para omitir o build e a verificação de formato explícitos do projeto gráfico:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -SkipWpf
```

O script restaura e compila cada projeto explícito, executa os projetos de testes que encontrar e faz um smoke test da ajuda da CLI. A suite atual contém também um smoke WPF, pelo que `-SkipWpf` continua a exigir Windows e pode compilar a UI através dessa dependência de testes; não é um gate de release. A inexistência de testes é assinalada; antes de uma release estável, a checklist exige pelo menos uma suite com contagem verificada.

## Executar durante o desenvolvimento

Aplicação gráfica:

```powershell
dotnet run --project .\LocalNetworkScanner.Wpf\LocalNetworkScanner.Wpf.csproj
```

Listar interfaces pela CLI:

```powershell
dotnet run --project .\LocalNetworkScanner.Cli\LocalNetworkScanner.Cli.csproj -- interfaces
```

Scan interativo:

```powershell
dotnet run --project .\LocalNetworkScanner.Cli\LocalNetworkScanner.Cli.csproj
```

Scan não interativo de uma rede privada com exportação:

```powershell
dotnet run --project .\LocalNetworkScanner.Cli\LocalNetworkScanner.Cli.csproj -- scan --cidr 192.168.1.0/24 --profile standard --json .\report.json --csv .\report.csv --html .\report.html --graphml .\topology.graphml
```

Ajuda completa:

```powershell
dotnet run --project .\LocalNetworkScanner.Cli\LocalNetworkScanner.Cli.csproj -- --help
```

## Publicar para Windows

O script publica a UI e a CLI como executáveis self-contained single-file, valida a ajuda da CLI e o ciclo de vida real da janela WPF, cria um ZIP e escreve o respetivo SHA-256.

O smoke do executável publicado só é executado quando a arquitetura é compatível com o host de build. Um pacote ARM64 criado num PC x64 tem de ser aberto e testado posteriormente num Windows ARM64; o script assinala esse gate em vez de simular sucesso.

Windows x64:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish-windows.ps1 -RuntimeIdentifier win-x64
```

Windows ARM64:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish-windows.ps1 -RuntimeIdentifier win-arm64
```

Resultados:

```text
artifacts\publish\<RID>\
artifacts\staging\LocalNetworkScanner-1.1.0-<RID>\
artifacts\release\LocalNetworkScanner-1.1.0-<RID>.zip
artifacts\release\LocalNetworkScanner-1.1.0-<RID>.zip.sha256
```

Instalador opcional com [Inno Setup 6](https://jrsoftware.org/isdl.php):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-installer.ps1 -RuntimeIdentifier win-x64
```

Uma tag `v1.1.0` que coincida com `Directory.Build.props` inicia o workflow de release. O workflow volta a validar formato, build e testes, cria pacotes x64/ARM64, instaladores e checksums, e publica-os na release correspondente. Não inclui nem simula uma assinatura Authenticode.

Estes ficheiros locais não ficam automaticamente prontos para distribuição pública. A release final deve ter ícone e manifesto revistos, teste num Windows limpo, verificação do checksum e indicação inequívoca do estado Authenticode. Uma assinatura válida continua a ser recomendada para identidade e reputação; até existir, a distribuição permanece explicitamente não assinada. Consulte a [Checklist de release](docs/RELEASE_CHECKLIST.md).

## Estrutura

```text
LocalNetworkScanner.Core/   descoberta, modelos, análise e exportação
LocalNetworkScanner.Cli/    interface de linha de comandos
LocalNetworkScanner.Wpf/    aplicação gráfica Windows
.github/                    CI, release, Dependabot e templates de issues
docs/                       limites técnicos e processo de release
installer/                  definição opcional do instalador Inno Setup
scripts/                    validação e publicação reproduzível
```

Consulte [CONTRIBUTING.md](CONTRIBUTING.md) antes de propor alterações.

## Segurança

Leia [SECURITY.md](SECURITY.md) para comunicar uma vulnerabilidade e para conhecer o modelo de segurança do produto.

Issues e pedidos de funcionalidades: [GitHub Issues](https://github.com/p-darksy-r/LocalNetworkScanner/issues). Vulnerabilidades exploráveis devem usar um [Security Advisory privado](https://github.com/p-darksy-r/LocalNetworkScanner/security/advisories/new).

## Licença

Distribuído sob a licença [MIT](LICENSE).
