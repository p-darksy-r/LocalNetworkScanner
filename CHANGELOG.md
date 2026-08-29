<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Changelog

Todas as alterações relevantes deste projeto são registadas neste ficheiro. O formato segue os princípios de Keep a Changelog e o versionamento segue Semantic Versioning.

## [Unreleased]

Sem alterações adicionais depois da tag de código-fonte `v1.4.1`.

## [1.4.1] - 2026-08-29

A `v1.4.1` fixa o estado validado do código-fonte, sem criar uma GitHub Release nem publicar novos binários. Em 27-08-2026, a SignPath informou que o projeto seria provavelmente problemático para o programa gratuito Foundation e recomendou não submeter o estado atual. Isto não é uma rejeição formal nem uma aprovação; não existe integração SignPath e os binários históricos permanecem `NotSigned`, sem apresentação como produção.

### Added

- contrato `IInfrastructureProvider` e snapshot de evidência para integrações de controladores somente leitura; a FDB SNMP existente é exportada como infraestrutura correlacionada por MAC sem afirmar ligação física, com VLAN/porta/AP/RSSI quando disponíveis;
- infraestrutura de dados por dispositivo e no JSON schema v8, incluindo proveniência, confiança e diagnóstico `LNS-NET-012` quando uma integração opcional falha sem invalidar o scan base;
- infraestrutura MSIX separa rigorosamente `PrivateTest` e `Store`, gera pacotes x64/ARM64 e bundle, valida manifesto, payload, arquitetura PE, assinatura, hashes e identidade e nunca toca nos artefactos de release existentes;
- certificado público `crt/LocalNetworkScanner-PrivateTest.crt`, com chave RSA 3072/SHA-256 não exportável mantida apenas em `CurrentUser\My`, mais scripts explícitos para geração, confiança restrita a `LocalMachine\TrustedPeople` e remoção segura;
- manifesto WPF `packagedClassicApp`/`mediumIL`, assets MSIX determinísticos e documentação passo a passo para sideload interno e futura submissão no Partner Center;
- `PRIVACY.md` documenta comunicações iniciadas pelo utilizador, dados locais, terceiros, retenção e eliminação;
- `CODE_SIGNING_POLICY.md` regista a orientação escrita da SignPath Foundation, funções da equipa, âmbito independente do fornecedor e gates que impedem alegações prematuras de assinatura;
- onboarding inicial, não modal e persistente, explica redes autorizadas, tráfego ativo, histórico local e ausência de telemetria;
- pesquisa de nós na topologia por nome, IP, MAC, tipo, VLAN ou identidade visível, com `Ctrl+F`, `Enter`/`F3`, centralização e anúncios acessíveis;
- a janela Sobre liga diretamente às políticas de privacidade e assinatura;
- botão de ícone único para alternar o tema claro/escuro no cabeçalho, com glyph, tooltip e automação atualizados, aplicação imediata, persistência local e atualização coerente da janela de topologia;
- localização pt-PT/en-US aplicada à UI WPF, incluindo opções de scan, diagnósticos, topologia, tooltips e a janela Sobre, com seleção de idioma persistida;
- workflow manual para renderizar, validar e disponibilizar as imagens sintéticas da documentação num runner Windows quando App Control impede a renderização local;
- pasta raiz `app` com lançador relativo e executável local gerado para a arquitetura nativa; versão, fontes, PE, SHA-256 e Authenticode são validados antes de uma substituição transacional, com lock entre processos, modo rápido para abrir, modo completo para QA local e publicação intermédia isolada dos artefactos de release.

### Changed

- a grelha principal deixa de repetir a coluna **Risco**; o nível e a pontuação continuam visíveis no badge do painel lateral e a tab **Segurança** mantém os alertas heurísticos detalhados;
- CI x64 cria e valida o bundle `PrivateTest` x64+ARM64, o runner ARM64 valida adicionalmente o pacote nativo, e ambos removem as chaves efémeras no fim sem publicar estes artefactos;
- os perfis Rápido, Normal e Avançado explicam agora que partilham o mesmo objetivo de descoberta, diferindo sobretudo no tempo e detalhe, e que as contagens são retratos transitórios;
- o cabeçalho de configuração deixa de impor uma largura mínima superior à janela e mantém Iniciar/Cancelar acessíveis a 760 DIPs;
- a topologia ajusta-se à work area do monitor atual, permite scroll horizontal da toolbar, realça apenas o nó selecionado e as suas ligações e preserva o zoom ao atualizar a paleta de Alto Contraste;
- resumo, pesquisa e seleção da topologia passam a emitir eventos live-region para leitores de ecrã;
- README, segurança, instalação, assinatura, App Control, checklist e documentação IEEE distinguem corretamente repositório público, prereleases históricas `Private QA (NotSigned)` e a orientação de não candidatura gratuita da SignPath Foundation;
- todas as páginas de releases existentes ligam agora a **Code signing policy** e à política de privacidade; a `v1.2.0` foi reclassificada como prerelease histórica `NotSigned`, deixando o projeto sem uma falsa release `Latest` enquanto não existir produção assinada;
- metadados do produto e manifesto Windows avançam para `1.4.1`, sem criar uma release;
- o job x64 do CI usa agora o mesmo `scripts/check.ps1 -VerifyFormat` da validação local, incluindo sintaxe PowerShell e os contratos sintéticos de release;
- o workflow de release passa a ser exclusivamente manual, evitando que o simples push de uma tag termine verde sem produzir um candidato ou uma release;
- a política automática de copyright passa a reconhecer também scripts batch `.cmd` e `.bat` com marcadores `@REM`.
- a paleta escura usa cores com contraste dedicado para superfícies, texto, seleção, estados de risco e ações, enquanto o Alto Contraste do Windows continua a ter prioridade;

### Fixed

- os cabeçalhos **Porta**, **Proto.**, **Serviço** e **TLS** deixam de herdar o chrome claro do `GridViewColumnHeader` nativo; fundo, texto, separadores, hover, pressão e redimensionamento seguem agora a paleta dinâmica no tema escuro;
- os diagnósticos e notas do scan passam a ocupar uma área vertical limitada com scroll por rato, teclado, toque ou barra, permitindo consultar todas as mensagens e ações recomendadas sem conteúdo cortado;
- as tabs do painel lateral e o respetivo conteúdo deixam de usar superfícies claras do template nativo WPF no tema escuro; Resumo, Identidade, Serviços, Segurança, Rede e Histórico usam agora a paleta dinâmica em seleção, hover, foco e desativação;
- as células da linha selecionada deixam de assumir a seleção inativa branca do Windows quando o foco passa para o painel lateral, mantendo uma superfície coerente em tema claro, escuro e Alto Contraste;
- os seletores de interface de rede, filtros de dispositivos, idioma e topologia deixam de herdar o botão, seta, popup e realces claros do template nativo do Windows; todos os estados usam agora a paleta dinâmica da aplicação em tema claro, escuro e Alto Contraste, incluindo rato, teclado, seleção, abertura e desativação;
- uma falha numa sonda por host cancela e observa a descoberta multicast paralela antes de propagar o erro original, evitando sockets e tráfego órfãos em background;
- uma configuração personalizada que desativa simultaneamente ICMP, TCP, ARP e multicast é recusada como `LNS-USR-008`, em vez de terminar com um falso problema de rede e zero descobertas possíveis;
- mudar o filtro da topologia limpa uma seleção que deixou de estar visível e anuncia corretamente que nenhum nó está selecionado;
- exportações JSON, relatório de suporte, GraphML, CSV e HTML são escritas num ficheiro temporário da mesma pasta e só substituem o destino depois de concluírem; cancelamento ou falha preservam o relatório anterior.

### Security

- candidatos Store permanecem obrigatoriamente `UnsignedForMicrosoftStore` e exigem a identidade externa exata do Partner Center; os gates fixam `PrivateTest` ao CRT versionado e rejeitam chaves privadas, payloads/ativações adicionais, capabilities além de `runFullTrust`, mistura de identidades e um pacote Store assinado pelo certificado de QA;
- secret scanning, push protection, relatórios privados de vulnerabilidade e fixação obrigatória das GitHub Actions por SHA foram ativados no repositório público;
- nenhuma funcionalidade de enumeração de portas, Nmap ou avaliação heurística de risco foi removida ou escondida para tentar contornar a orientação de elegibilidade da SignPath Foundation;
- a documentação deixa explícito que a exposição pública dos dados IEEE não constitui autorização e bloqueia uma nova release assinada/estável até existir clarificação escrita aplicável.

## [1.4.0] - 2026-08-23

Tag de código e QA privada. Sem uma identidade Authenticode Public Trust configurada e autorização escrita para redistribuir a snapshot IEEE, os executáveis continuam limitados a uma prerelease privada `Private QA (NotSigned)` e não podem ser apresentados como produção ou `Latest`.

### Added

- ícones compactos de informação e saída no cabeçalho, com alvos de 40 px, tooltips, nomes de automação e acesso por `F1`/`Alt+F4`;
- janela **Sobre** responsiva com nome, versão dinâmica, resumo, criador, copyright, licença, arquitetura/runtime, capacidades principais e links explícitos para o repositório e avisos legais;
- fonte de evidência `CurrentReachableNeighbor`, separada de `ActiveArp` e da cache passiva, preservada na UI e nos exports JSON/CSV/HTML;
- testes determinísticos para ARP em paralelo, reconfirmação de vizinhos entre scans, metadados/acessibilidade da janela Sobre e contrato `Latest` da futura publicação assinada.

### Changed

- ARP começa em paralelo com ICMP e TCP, incluindo a revalidação de vizinhos já presentes, evitando que os timeouts maiores dos perfis Normal/Avançado atrasem a tentativa de camada 2;
- uma entrada preexistente `Reachable` representa alcance recente; uma entrada transitória como `Stale` exige `SendARP` e uma segunda leitura nativa `Reachable`, sem `IsUnreachable` e com o mesmo MAC, enquanto uma entrada `Permanent` permanece passiva;
- o export JSON sobe para schema v7 e identifica `devices[].macAddressSource`; CSV e HTML apresentam a mesma proveniência MAC;
- o README explica por que um inventário é temporal, por que os três perfis partilham a mesma passagem de descoberta e por que Normal/Avançado acrescentam detalhe sem garantirem uma contagem superior;
- a publicação de produção passa a pedir explicitamente `make_latest=true` e os dois gates finais confirmam `releases/latest`; a QA privada pede `make_latest=false`;
- versão do produto, manifesto Windows, linha de segurança, template de erros e documentação atualizados para `v1.4.0`.

### Security

- a aplicação não usa `ResolveIpNetEntry2` nem limpa a tabela ARP inteira; a revalidação `SendARP` é dirigida a um alvo e pode atualizar ou invalidar essa entrada no Windows, mas nunca promove o MAC sem uma leitura posterior coerente;
- links da janela Sobre aceitam apenas URIs HTTP/HTTPS fixos e abrir o ícone Sair reutiliza integralmente as confirmações existentes para scans e metadados por guardar;
- uma release estável/`Latest` permanece impossível sem assinatura Authenticode válida, timestamp, validação nativa x64/ARM64 e autorização IEEE; tornar o repositório público não satisfaz estes gates.

## [1.3.8] - 2026-08-23

Tag nova obrigatória; a `v1.3.7` permanece imutável e a sua prerelease privada continua publicada. Os 12 assets foram materializados, validados e publicados corretamente, mas o passo posterior que escrevia o resumo Markdown continha um escape PowerShell inválido; por isso o job Publish e o gate terminal terminaram vermelhos apesar de a publicação já estar concluída.

### Fixed

- os dois digests do resumo são agora formatados com o operador `-f`, preservando os delimitadores Markdown sem permitir que um backtick escape a aspa final;
- o contrato sintético descobre os 36 passos `shell: pwsh` do workflow, inclui explicitamente o resumo pós-publicação e compila cada bloco com o parser PowerShell antes de qualquer tag;
- versão do produto, manifesto Windows, template de erros, README e checklist de release atualizados para `v1.3.8`.

### Security

- a v1.3.7 confirmou que o cleanup nunca elimina uma release já publicada: reconheceu `draft=false` e terminou como no-op;
- o gate terminal continuou fail-closed e recusou o workflow vermelho, mesmo quando a falha ocorreu depois da publicação remota.

## [1.3.7] - 2026-08-23

Tag nova obrigatória; a `v1.3.6` permanece imutável como evidência da tentativa falhada e não é movida nem reutilizada. Os pacotes, as validações x64/ARM64, o atestado e o SBOM passaram, mas o job de publicação não repôs uma segunda cópia local do estado validado na pasta de evidência; o cleanup eliminou a draft owned e nenhuma release `v1.3.6` foi publicada.

### Fixed

- o materializador pode reconhecer explicitamente o `SIGNING-STATE.txt` já validado dentro do contrato final descarregado, sem exigir uma duplicação local que não existe entre jobs;
- o caminho continua estrito por defeito e só o job de publicação ativa esse modo depois de `DownloadFinal` verificar os 12 assets; o estado reutilizado permanece obrigado ao SHA-256 do atestado, às sete linhas ordenadas e ao contrato exato;
- uma regressão sintética reproduz o layout final, confirma que o modo normal recusa a evidência ausente e que o opt-in validado funciona; versão do produto, manifesto Windows, template de erros e documentação atualizados para `v1.3.7`.

### Security

- a tentativa `v1.3.6` confirmou o novo gate terminal: a falha de publicação deixou a execução vermelha, o cleanup removeu apenas a draft owned de 12 assets e não ficaram release, draft ou artefactos de Actions;
- nenhum ficheiro é confiado apenas pela sua localização: o conteúdo materializado continua ligado ao atestado nativo, ao commit/tag e aos digests canónicos do candidato e da release.

## [1.3.6] - 2026-08-23

Tag nova obrigatória; a `v1.3.5` permanece imutável como evidência da tentativa falhada e não é movida nem reutilizada. Embora os pacotes, a validação x64/ARM64 e o SBOM tenham passado, a publicação foi indevidamente ignorada e o cleanup eliminou a draft owned; nenhuma release `v1.3.5` foi publicada.

### Fixed

- a publicação declara agora `!cancelled()` e exige explicitamente sucesso no preflight, seleção do pacote e gate de validação, evitando que o `success()` implícito do GitHub propague o job público intencionalmente ignorado para o caminho privado;
- um gate terminal independente exige que uma execução elegível tenha publicado efetivamente a release, tornando impossível repetir o estado falso-verde da `v1.3.5`;
- o cleanup só é agendado quando a publicação não teve sucesso; versão do produto, manifesto Windows, template de erros e documentação atualizados para `v1.3.6`.

### Security

- uma publicação ignorada ou falhada continua a eliminar apenas a draft owned, mas passa também a falhar visivelmente o workflow; uma publicação verificada nunca agenda a remoção;
- a tentativa `v1.3.5` confirmou novamente o comportamento fail-closed: não deixou release, draft, assets ou artefactos de Actions remanescentes e preservou a tag imutável.

## [1.3.5] - 2026-08-23

Tag nova obrigatória; a `v1.3.4` permanece imutável como evidência da tentativa falhada e não é movida nem reutilizada. A draft owned dessa tentativa foi eliminada automaticamente e nenhuma release `v1.3.4` foi publicada.

### Fixed

- os jobs de validação x64 e ARM64 recuperam o `contents: write` mínimo exigido pela API do GitHub para consultar e descarregar assets de uma draft privada; com `contents: read`, `GET releases/{id}` devolvia HTTP 403 antes de qualquer instalação;
- versão do produto, manifesto Windows, template de erros e documentação atualizados para `v1.3.5`.

### Security

- o checkout dos validadores continua com `persist-credentials: false`, a tag continua obrigada ao HEAD de `main` e esses jobs invocam exclusivamente `DownloadCandidate`; a permissão adicional satisfaz o requisito de push access da API sem introduzir um passo de mutação;
- a falha `v1.3.4` confirmou o fail-closed: ARM64 e publicação foram bloqueados, e o cleanup removeu apenas a draft owned de dez assets, deixando a tag intacta.

## [1.3.4] - 2026-08-23

Tag nova obrigatória; a `v1.3.3` não é movida nem reutilizada. Esta versão corrige o bloqueio de quota do armazenamento de GitHub Actions sem reduzir os gates de confiança da release.

### Changed

- os dez ficheiros candidatos passam diretamente do job de empacotamento para uma GitHub draft release privada associada à tag final existente, sem criar qualquer artefacto pesado de Actions;
- a evidência nativa compacta circula entre ARM64 e o gate como Base64 limitado a 64 KiB, acompanhado por tamanho e SHA-256, e é validado como UTF-8/JSON antes de ser usado;
- depois da validação, `VALIDATION-ATTESTATION.json` e `LocalNetworkScanner-<versão>-sbom.spdx.json` tornam-se assets permanentes, elevando o contrato final verificável de 10 para 12 assets;
- versão do produto, manifesto Windows, template de erros e documentação atualizados para `v1.3.4`.

### Fixed

- uma quota esgotada de artefactos de Actions já não impede o transporte dos ZIPs e instaladores entre os runners Windows x64/ARM64;
- repetições recuperam a draft apenas por listagem paginada e `release_id` validado, sem depender de `GET releases/tags` para drafts, e aceitam uma release publicada apenas após verificar a proveniência histórica e os três digests distintos: candidato Pending, payload Validated e release final;
- uma falha durante o upload ou qualquer gate posterior elimina somente a draft pertencente à execução; uma release já publicada nunca é removida pelo cleanup.

### Security

- ownership da draft liga repository ID, run, tentativa, commit, tag, digest canónico e nonce; tags lightweight/anotadas e visibilidade privada são confirmadas antes e depois das mutações;
- downloads usam o endpoint autenticado por asset ID e verificam `state`, tamanho e SHA-256; o token com escrita nunca é persistido pelo checkout;
- a única substituição permitida é `SIGNING-STATE.txt` Pending exato → Validated exato, depois dos dois testes nativos e da validação semântica do atestado;
- imediatamente antes de `draft=false`, o workflow volta a obter a release por ID e revalida os 12 assets, tag, visibilidade e marker; depois da publicação confirma também o lookup público/autenticado pela tag.

## [1.3.3] - 2026-08-23

Tag de código e QA privado. Sem uma identidade Authenticode Public Trust e autorização escrita para redistribuir a snapshot IEEE, os pacotes só podem ser publicados no repositório privado como prerelease `Private QA (NotSigned)` e não constituem uma distribuição pública de produção.

### Added

- barra de comandos com ícones simples para atualizar interfaces, iniciar/cancelar o scan, limpar a pesquisa, abrir a topologia e remover resultados, mantendo nomes acessíveis, tooltips, alvos de 40 px e atalhos de teclado (`Alt+I`, `Alt+C`, `F5` e `Esc`);
- anúncios de estado e zoom para tecnologias de assistência, paleta dinâmica de alto contraste e alternativa tabular acessível na topologia;
- estimativa conservadora da carga antes do scan, baseada em endereços, portas e probes de serviço, com confirmação única para cargas altas/extremas, SNMP v2c sem cifragem e tráfego adicional do Nmap;
- endpoints DNS-SD obtidos por registos mDNS SRV, preservando serviço, porta, transporte, endpoint e evidência no inventário e no export JSON;
- registo local limitado e rotativo para falhas fatais em `%LOCALAPPDATA%\LocalNetworkScanner\logs\app.log`, sem inventário, mensagens da exceção, alvo ou contexto do diagnóstico;
- testes de acessibilidade estrutural, atalhos, preservação de metadados, estimativa de carga, retries multicast, serviços SRV, promoção mDNS segura, registo fatal, rotação e proteção de downgrade em diretórios personalizados, elevando a suite para 89 testes.

### Changed

- snapshot IEEE incorporada atualizada para 2026-08-12 a partir das listagens MA-L, MA-M e MA-S fornecidas pelo autor e da listagem IAB oficial preservada: 58 166 registos, 58 163 prefixos únicos e hashes SHA-256 das quatro fontes no manifesto interno;
- SSDP, WS-Discovery e a enumeração mDNS/DNS-SD repetem transmissões iniciais dentro de um orçamento comum e limitado, com jitter e cancelamento imediato, sem transformar anúncios indiretos em dispositivos online;
- o instalador por utilizador aceita atualização para a mesma versão ou uma mais recente, mas recusa de forma explícita um downgrade para evitar substituir uma instalação atual por binários mais antigos;
- a versão do produto, identidade do manifesto Windows, documentação de instalação, template de erros e página principal acompanham a `v1.3.3`.

### Fixed

- aliases, notas e favoritos já editados deixam de ser sobrescritos por atualizações do mesmo dispositivo; iniciar outro scan ou limpar resultados pede confirmação quando existem metadados por guardar;
- fechar a aplicação também confirma metadados por guardar; enquanto a gravação decorre, os campos, novo scan, limpeza e fecho ficam temporariamente bloqueados, evitando resultados órfãos ou alterações perdidas durante a escrita;
- o live region de estado passa a expor um `AutomationPeer` real, e a pesquisa encontra nomes mDNS, tipos DNS-SD e endpoints SRV apresentados nos detalhes;
- o export JSON sobe para schema v6 ao acrescentar `devices[].mdnsServices`, e a estimativa de carga inclui o orçamento máximo de descrições HTTP(S) UPnP;
- a geração do instalador usa as opções corretas do preprocessor Inno Setup e o script de código Pascal mantém um comentário de copyright válido depois da secção `[Code]`;
- exceções não tratadas na UI entram num encerramento controlado, cancelam trabalho pendente e não voltam a guardar preferências durante um estado potencialmente corrompido;
- o fluxo de release deixa de duplicar o payload pesado numa segunda cópia integral “validada”: um único `windows-candidate` imutável é ligado ao commit/run por evidência compacta e o contrato final continua limitado aos dez assets esperados;
- testes de integridade fixam o hash do recurso IEEE comprimido, metadados, contagens por registo e hashes das fontes, mantendo cobertura explícita do lookup pelo prefixo mais longo `/36 → /28 → /24`.

### Security

- o registo de falha fatal guarda apenas versão/ambiente, origem controlada, tipo/HResult, severidade/código e stack sanitizada; roda para `app.previous.log`, tem limite de 512 KiB e omite argumentos, credenciais, IPs, MACs, hostnames e caminhos do perfil do utilizador;
- uma tag com gates de produção incompletos só pode criar automaticamente uma prerelease `Private QA (NotSigned)` se a visibilidade atual confirmada pela API continuar privada; num repositório público o workflow também recusa gerar ou carregar um candidato manual `NotSigned`;
- a validação x64 e ARM64 produz um atestado compacto com digest do candidato e SHA-256 dos dez ficheiros, exige o contrato ordenado exato de `SIGNING-STATE.txt`, materializa esse estado de forma repetível e confirma nome, estado, tamanho e hash de todos os assets remotos;
- o Inno Setup 6.7.3 descarregado pelo workflow é validado por SHA-256 fixo, `ProductVersion`, Authenticode e publisher antes de ser executado;
- a publicação volta a resolver tags lightweight ou anotadas para o commit do workflow antes das mutações e no final, recupera com segurança drafts pertencentes ao mesmo run e trata uma release publicada exatamente igual como sucesso idempotente;
- o único candidato pesado só é removido do armazenamento de Actions depois da release final ser novamente validada; o atestado e o SBOM permanecem como evidência pequena durante 30 dias.

## [1.3.2] - 2026-08-16

Tag de código e QA privado. Os pacotes permanecem `NotSigned` até existir uma identidade Authenticode Public Trust e continuam sujeitos à autorização de redistribuição da snapshot IEEE antes de qualquer publicação de produção.

### Added

- ativação explícita das definições personalizadas, contador de substituições e ação para repor os valores do perfil selecionado;
- botões de zoom, percentagem visível e informação de automação na janela de topologia;
- workflow CodeQL C# com consultas `security-extended`, ativável apenas quando o plano do repositório permite code scanning;
- geração e validação de um SBOM SPDX 2.2, com cobertura explícita dos runtimes `win-x64` e `win-arm64`, como artefacto de evidência separado do payload instalável;
- teste determinístico da migração das preferências antigas e novos asserts WPF para ativação explícita, bindings e zoom, elevando a suite para 83 testes.

### Changed

- abrir ou fechar os parâmetros técnicos deixa de alterar a profundidade do scan; enquanto a personalização está desligada, o perfil Rápido, Normal ou Avançado mantém controlo integral;
- definições antigas que usavam `IsAdvancedMode` são migradas sem perder a intenção do utilizador;
- repor um perfil limpa também entradas numéricas inválidas e a community SNMP visível, sem deixar validações antigas a bloquear o scan;
- a tipografia dos nós, chips, legenda e notas da topologia ficou maior e mais legível;
- zoom e pan escolhidos pelo utilizador deixam de ser anulados automaticamente ao redimensionar a janela;
- a identidade do manifesto Windows acompanha a versão 1.3.2 e as imagens atuais do README são geradas apenas com dados e preferências temporários.

### Security

- a release passa a produzir uma lista de materiais de software validada, mantendo os dez ficheiros executáveis sujeitos ao mesmo contrato, hashes e instalação/smoke nativos;
- o smoke WPF e o renderer de documentação ficam isolados das preferências reais do utilizador;
- as verificações CodeQL usam actions fixadas por SHA e permissões explícitas; em repositórios privados sem a capacidade necessária, o job fica explicitamente ignorado e não apresenta uma análise inexistente como concluída.

## [1.3.1] - 2026-08-12

Tag de código e QA privado preparada em 2026-08-12. Os pacotes continuam `NotSigned` enquanto não existir uma identidade Authenticode Public Trust configurada; a tag não é, por si só, uma release pública instalável.

### Added

- origem tipada para resoluções MAC (`LocalInterface`, `NeighborCache` e `ActiveArp`), permitindo distinguir enriquecimento passivo de confirmação ativa;
- treze testes determinísticos adicionais para baseline ARP, interop IP Helper, índice da interface, contrato `SendARP`, cache antiga, falha fechada, diagnóstico de degradação, promoção fresca e enriquecimento sem falsa evidência de camada 2, elevando a suite para 82 testes.

### Changed

- a configuração do scan recolhe automaticamente quando a operação começa e pode ser reaberta a qualquer momento;
- o botão de cancelamento permanece acessível na barra de progresso, mesmo com a configuração recolhida;
- os painéis de inventário e detalhes usam agora uma divisão proporcional responsiva e limites menores para janelas estreitas;
- o estado vazio distingue aplicação pronta, scan em curso, conclusão sem dispositivos, resultado parcial/cancelado e erro.

### Fixed

- a tabela ARP passa a ser capturada antes de ICMP/TCP; entradas preexistentes permanecem passivas e intactas, enquanto apenas uma linha nativa nova em estado `Reachable` (sem `IsUnreachable`) ou uma resposta ARP pedida sem entrada prévia confirma alcance/camada 2;
- uma falha ao obter o baseline ARP degrada de forma fechada, sem apagar entradas do utilizador nem promover cache desconhecida, e fica visível como `LNS-NET-011`;
- callbacks de progresso atrasados deixam de poder sobrescrever o estado final de sucesso, cancelamento ou erro, incluindo durante um diálogo modal;
- o diagnóstico App Control distingue caminho completo confirmado, hash+caminho relativo provável, conteúdo igual e nome igual; apenas o primeiro confirma automaticamente o alvo, evitando confundir cópias idênticas sujeitas a regras por caminho diferentes;
- as validações dos pacotes x64 e ARM64 deixam de ser ignoradas devido ao job de empacotamento mutuamente exclusivo que ficou `skipped`;
- um novo gate terminal exige que preflight, pacote e validações nativas tenham sucesso, volta a verificar o contrato exato de dez ficheiros, os checksums e o estado de assinatura antes de permitir publicação;
- cancelamentos de CI/release deixam de manter jobs de validação ativos através de `always()`.

### Security

- uma cache de vizinhos manipulada ou obsoleta já não é suficiente para provocar a promoção e o enriquecimento ativo de um alvo que falhou ICMP/TCP; entradas estáticas ou dinâmicas preexistentes não são removidas;
- a release deixa de poder terminar com sucesso aparente quando os validadores dos pacotes exatos foram ignorados.

## [1.3.0] - 2026-08-08

Tag de código e QA privado preparada em 2026-08-08. A existência da tag não transforma artefactos `NotSigned` numa release pública confiável; a publicação instalável continua sujeita aos gates de assinatura e redistribuição documentados.

### Added

- relatório de suporte JSON agregado e sem identificadores de rede, disponível na UI e através de `--support`;
- snapshot offline comprimida inicial das listagens IEEE MA-L, MA-M, MA-S e IAB, com manifesto de proveniência e normalização determinística;
- lookup de titular IEEE pelo prefixo mais específico (`/36 → /28 → /24`) e atualização opcional das quatro listagens oficiais, sem exigir download no primeiro arranque;
- controlo de privacidade para desativar a leitura/escrita do histórico e ação explícita para apagar snapshots locais;
- código `LNS-APP-005` para bloqueios do Windows Application Control, incluindo `CreateProcess` 4551;
- diagnóstico e documentação dedicados a Smart App Control/App Control, sem recomendar que a proteção seja contornada;
- suporte de release opcional e fail-closed para assinatura Authenticode quando forem fornecidas credenciais de assinatura confiáveis;
- códigos de release `LNS-REL-001` a `LNS-REL-009`, com ações concretas para gates, OIDC, assinatura, dados IEEE, arquiteturas, assets e proveniência da tag;
- diagnóstico App Control schema v2, que distingue alvo ausente, ficheiro sem assinatura, assinatura inválida, publisher válido mas bloqueado e ausência de evento correlacionado;
- guia de assinatura com configuração segura das credenciais, alternativas cloud/Store e explicação do bloqueio Win32 `4551` antes do arranque da aplicação;
- descoberta DNS-SD progressiva e dirigida, com parsing limitado e defensivo de registos PTR, SRV, TXT, A e AAAA;
- modelo de identidade com fabricante, titular IEEE separado, modelo, nome anunciado, série, firmware, revisão de hardware, fonte e confiança;
- descrição UPnP limitada ao IP privado que respondeu por SSDP, sem redirects/proxy/credenciais e com XML protegido contra DTD/XXE;
- consulta opcional de identidade SNMP v2c através de MIB-II e ENTITY-MIB, sem guessing nem persistência da community;
- integração opcional com um Nmap instalado separadamente, limitada a TCP Connect/version-light sem privilégios, NSE, UDP ou raw sockets;
- códigos `LNS-NET-008` a `LNS-NET-010` para identidade SNMP/Nmap e `LNS-DEV-005` para evidência contraditória;
- limites globais de datagramas, bytes, registos, hosts e enriquecimentos para descoberta multicast hostil ou excessiva.

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
- exports JSON usam schema v5 para representar estado TLS triestado e evidências de identidade sem reutilizar a semântica booleana dos schemas anteriores;
- filtros da topologia preservam os nós de infraestrutura que são ancestrais dos clientes ou alertas encontrados;
- identificação MAC passa a descrever o titular registado do prefixo em vez de prometer o fabricante físico; CID é excluído e casos `Private`, local/aleatório, virtual ou OEM permanecem explicitamente inconclusivos;
- CI e release passam a exigir build, testes e smoke num runner Windows ARM64 nativo, confirmando `OSArchitecture=Arm64` antes de aceitar o resultado;
- assinatura pública passa de PFX exportável para Microsoft Artifact Signing por OIDC, mantendo a chave no serviço e assinando também o diagnóstico PowerShell e o desinstalador Inno;
- release valida os ZIPs e instaladores exatos, incluindo instalação, smoke da UI/CLI e remoção em Windows x64 e ARM64, antes de promover o payload;
- repositório documenta diretamente o candidato atual, e o GitHub passa a ter descrição, tópicos e alertas de dependências sem branches automáticos;
- histórico passa a comparar alterações de fabricante, modelo e firmware;
- a grelha mantém o titular IEEE separado, enquanto o novo separador Identidade expõe fontes/confiança e detalhes técnicos sem colocar o número de série na lista principal;
- a identidade consolidada é resolvida por campo, com desempate determinístico e confiança global conservadora, sem depender da ordem de chegada das respostas.

### Fixed

- aliases, notas, favoritos e comparação histórica já não desaparecem quando o mesmo dispositivo ganha/perde temporariamente um MAC válido;
- reutilização do mesmo IP por um MAC diferente deixa de herdar silenciosamente identidade anterior;
- a execução automática no fim do instalador já não transforma um bloqueio da aplicação pela política do Windows num erro aparente de instalação;
- o indicador de estado da lista já não apresenta dispositivos offline com o mesmo ponto verde dos dispositivos online;
- WS-Discovery já não permite que um `XAddr` anunciado faça outro IP parecer online e passa a usar parsing XML limitado com entidades externas desativadas;
- respostas SSDP inválidas, sem correlação ou excessivas passam a ser rejeitadas antes de alimentar a identidade;
- dispositivos SSDP com vários documentos/serviços preservam até oito descrições distintas por IP, sem perder ST/USN válidos;
- endereços apenas anunciados em registos mDNS A/AAAA já não são promovidos a dispositivos online sem evidência direta do remetente;
- produtos de serviços Nmap deixam de ser apresentados como modelos físicos e o vendor MAC autodeclarado pelo Nmap deixa de substituir o titular IEEE;
- ENTITY-MIB faz fallback limitado para uma entidade filha quando o chassis existe mas não publica fabricante, modelo ou série.

### Security

- relatórios de suporte excluem IPs, MACs, nomes de interface/host/switch, SSID/BSSID, aliases, notas, alvos, contexto e avisos brutos;
- atualização da base IEEE é sempre explícita e não envia telemetria, MACs, IPs ou inventário; a snapshot remove endereços postais e conserva apenas os campos necessários ao lookup;
- dados IEEE são documentados separadamente, não são colocados sob MIT e exigem autorização escrita antes de redistribuição pública;
- artefactos privados de QA continuam a identificar honestamente `NotSigned`, mas a publicação de uma GitHub Release exige Authenticode `Signed` e aprovação explícita da redistribuição IEEE;
- o preflight de release pública falha antes do build quando falta Artifact Signing/OIDC, autorização IEEE, tag correspondente ou proveniência no HEAD atual de `main`;
- a publicação usa um job com permissão de escrita isolada, exige exatamente os dez assets previstos, volta a validar hashes/assinaturas e recusa substituir assets de uma release existente;
- metadados UPnP, DNS-SD, WS-Discovery, SNMP e Nmap são tratados como evidência não autenticada, sanitizados e limitados; conflitos permanecem visíveis em vez de serem ocultados;
- Nmap deixa de ser autodetetado através do `PATH` e recusa caminhos UNC/device; a UI mostra o caminho local e pede confirmação do publisher;
- a UI avisa e pede consentimento específico antes de enviar uma community SNMP v2c sem cifragem a cada dispositivo consultado.

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
