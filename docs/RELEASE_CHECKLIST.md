<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Checklist de release Windows

Uma release só deve ser marcada como concluída quando todos os itens obrigatórios estiverem verificados. Guardar evidência dos comandos, versões, hashes e máquinas usadas.

**Estado atual:** o repositório é público, a avaliação SignPath está pendente e todos os downloads existentes estão `NotSigned`. Esta checklist não autoriza criar outra tag/release sem assinatura. Os itens SignPath só podem ser marcados depois de aceitação e configuração reais; os itens Microsoft Artifact Signing só se aplicam se esse backend for efetivamente escolhido e configurado.

## 1. Identidade e âmbito

- [ ] A versão em `Directory.Build.props` coincide com o changelog, nome do ZIP e tag.
- [ ] `Product`, `Company`, copyright e publisher representam a entidade que vai distribuir a aplicação.
- [ ] `scripts/check-copyright.ps1` confirma cabeçalho e rodapé em todos os ficheiros comentáveis.
- [ ] O nome “Local Network Scanner” e o ícone são consistentes na UI, propriedades do EXE e instalador.
- [ ] A licença MIT continua a ser a licença pretendida para o código e assets originais; dados IEEE e outros materiais de terceiros permanecem explicitamente fora do âmbito MIT.
- [ ] `THIRD_PARTY_NOTICES.md` acompanha a release, inclui `IEEE. All rights reserved.`, ausência de endorsement e as fontes MA-L/MA-M/MA-S/IAB.
- [ ] Nmap/Npcap não estão no instalador/ZIP/repositório; a integração opcional e os termos externos estão descritos em `THIRD_PARTY_NOTICES.md`.
- [ ] Existe autorização escrita da IEEE para redistribuir publicamente a snapshot incorporada e a release cumpre integralmente o texto e as condições recebidas.
- [ ] A licença/condição da snapshot IEEE também foi aceite pelo serviço de assinatura; uma autorização de redistribuição não é confundida automaticamente com uma licença OSI.
- [ ] `PRIVACY.md` e `CODE_SIGNING_POLICY.md` refletem o comportamento e o estado reais e estão ligados a partir da homepage e da página de download/release.
- [ ] Uma resposta escrita da SignPath confirma a elegibilidade do conjunto exato de funcionalidades incluído no artefacto assinado; enumeração de portas, Nmap e avisos heurísticos de risco não são omitidos da avaliação.
- [ ] O `CHANGELOG.md` descreve apenas funcionalidades presentes nessa revisão.
- [ ] Não existem links placeholder, contactos inexistentes ou alegações de capacidades futuras.

## 2. Código e build reproduzível

- [ ] `dotnet --version` resolve para `10.0.301` ou para um patch permitido por `global.json`.
- [ ] A árvore de trabalho está limpa e a revisão/tag a publicar foi registada.
- [ ] `scripts/check.ps1` termina com exit code `0` sem `-SkipWpf`.
- [ ] O build `Release` tem zero warnings e zero errors.
- [ ] A formatação foi validada com `dotnet format --verify-no-changes --no-restore`.
- [ ] Dependências novas foram revistas quanto a licença, manutenção e vulnerabilidades.
- [ ] A snapshot IEEE foi gerada apenas a partir das quatro URLs oficiais; o manifesto regista data, contagens e SHA-256 das fontes.
- [ ] A snapshot de referência de 2026-08-12 documenta 58 166 linhas de origem e 58 163 prefixos únicos normalizados, ou a alteração é explicada e revista.
- [ ] Não existem certificados, chaves, dumps, relatórios reais ou credenciais no repositório.

Comando base:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1
```

## 3. Testes

- [ ] Existe pelo menos um projeto de testes; o pipeline falha quando a contagem total é zero.
- [ ] Testes unitários cobrem intervalos CIDR, parsing de portas, MAC/IEEE, VLAN e classificação.
- [ ] Lookup de titulares testa longest-prefix `/36 → /28 → /24`, MA-S, IAB, MA-M, MA-L, `Private`, MAC local/aleatório, multicast e ausência de correspondência.
- [ ] CID não é carregado nem apresentado como fabricante de um MAC global.
- [ ] Sem rede, uma instalação limpa usa a snapshot incorporada; falha/cancelamento da atualização opcional preserva uma base válida.
- [ ] Testes de integração usam listeners de loopback e dados simulados, sem depender da rede do runner.
- [ ] Testes reais de rede são opt-in, limitados a um laboratório privado e nunca executados por defeito em CI.
- [ ] Cancelamento durante descoberta e scan de portas não bloqueia nem deixa tarefas pendentes.
- [ ] Exportação JSON/CSV e migração/leitura do histórico foram testadas com dados hostis e Unicode.
- [ ] A UI foi verificada com teclado, leitor de ecrã, escala 100/150/200%, tema claro/escuro e janela pequena.
- [ ] Português é apresentado corretamente; ausência de dados usa “indisponível/desconhecido” sem inventar valores.
- [ ] Perfis Rápido, Normal e Avançado aplicam limites distintos e mostram descrições coerentes na UI.
- [ ] Ícones Informação e Sair têm tooltip, nome de automação e alvo de 40 px; `F1` abre Sobre, `Esc` fecha apenas essa janela e Sair reutiliza as confirmações de scan/metadados.
- [ ] Sobre apresenta versão do assembly, resumo, criador, copyright, arquitetura/runtime e links legais sem depender de rede para abrir a janela.
- [ ] A lista de dispositivos permanece a vista principal e **Abrir topologia** só fica disponível quando existe mapa.
- [ ] A janela de topologia abre/fecha sem repetir o scan e mantém zoom, pan, seleção e exportações.
- [ ] Códigos `LNS-USR-*`, `LNS-NET-*`, `LNS-DEV-*` e `LNS-APP-*` têm categoria, severidade, ação recomendada e contexto sanitizado.
- [ ] UPnP, TXT DNS-SD, SSDP, WS-Discovery, SNMP ENTITY-MIB e XML Nmap têm fixtures válidas, hostis, limites e rejeição de DTD/entidades externas.
- [ ] A fusão de identidade preserva fontes, confiança, valores contraditórios e separa titular IEEE de fabricante/modelo.

## 4. Limites, privacidade e utilização segura

- [ ] A UI liga para `docs/TECHNICAL_LIMITS.md` ou apresenta um resumo equivalente.
- [ ] VLAN é descrita como informação da interface local ou inferência, nunca como scan por dispositivo.
- [ ] “Mesmo segmento L2” exige uma linha ARP nova, resposta direta sem entrada prévia ou vizinho atual/revalidado `Reachable` (sem `IsUnreachable`) e mostra a confiança; uma entrada que permaneça passiva/`Stale`, outro estado nativo ou observação SNMP/FDB nunca é apresentada como prova de ligação ao mesmo switch físico.
- [ ] ARP e a revalidação dirigida de entradas transitórias começam sem esperar pelos timeouts ICMP/TCP; dois scans consecutivos não perdem um vizinho apenas porque o primeiro aqueceu a cache, e `CurrentReachableNeighbor`, `ActiveArp` e `NeighborCache` permanecem distintos na UI/export.
- [ ] SNMP permanece opt-in; timeouts, switch sem resposta e tabela incompleta degradam para “desconhecido”, não para uma conclusão falsa.
- [ ] FDB-ID só é convertido em VLAN com mapeamento VLAN→FDB único; PVID é apenas referência, não a VLAN inferida do dispositivo.
- [ ] MACs repetidos preservam múltiplas observações e não são reduzidos arbitrariamente a uma porta.
- [ ] Dados de acesso SNMP não aparecem em logs, exports, screenshots, argumentos partilhados nem artefactos.
- [ ] O sinal Wi-Fi é identificado como sinal da ligação local, não RSSI de equipamentos remotos.
- [ ] Protocolos são identificados por descoberta/portas/respostas leves; não é alegada captura de pacotes.
- [ ] Relatórios e histórico são tratados como inventário sensível.
- [ ] “Titular IEEE” é explicado separadamente de fabricante/modelo, sem prometer a marca física em casos `Private`, local/aleatório, virtual ou OEM.
- [ ] Número de série, firmware e evidências de identidade são tratados como inventário sensível; não entram no relatório de suporte agregado.
- [ ] Descrição UPnP só segue URL HTTP(S) no mesmo IP privado remetente, sem redirect, proxy ou credenciais, e com tamanho/timeout/XML limitados.
- [ ] Nmap permanece opt-in e só usa instalação externa local validada, nunca `PATH`/UNC/device paths, IPv4 RFC1918, TCP Connect/version-light e argumentos sem shell; não executa NSE/raw/UDP/credential guessing nem transforma produtos de serviço em modelos físicos.
- [ ] A atualização IEEE é iniciada explicitamente, não envia telemetria nem inventário e não é necessária para o primeiro lookup.
- [ ] O utilizador é lembrado de analisar apenas redes autorizadas.
- [ ] O fluxo normal foi testado sem privilégios de administrador.
- [ ] O instalador termina sem iniciar automaticamente a UI; um bloqueio App Control no primeiro arranque não é apresentado como falha na cópia/instalação.
- [ ] O diagnóstico do código `4551` foi validado sem desativar ou alterar Smart App Control, App Control for Business/WDAC, AppLocker ou Defender.
- [ ] Os eventos Code Integrity `3077`/`3076` e a saída apenas de leitura de `CiTool.exe -lp -json` identificam a política responsável ou são entregues ao administrador do dispositivo.
- [ ] O relatório `diagnose-app-control.ps1` schema v2 distingue alvo sem assinatura, assinatura inválida, publisher válido mas bloqueado e ausência de evento correlacionado.

## 5. Publish portátil

- [ ] Publish x64 concluído:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish-windows.ps1 -RuntimeIdentifier win-x64
```

- [ ] Build, testes e publish ARM64 de origem concluídos no job `Native Windows ARM64 validation`; um cross-build x64 isolado não satisfaz este item:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish-windows.ps1 -RuntimeIdentifier win-arm64
```

- [ ] Cada pasta de publish contém os executáveis esperados e não contém PDBs, segredos ou ficheiros temporários.
- [ ] O smoke test `LocalNetworkScanner.Cli.exe --help` termina com exit code `0` numa máquina da arquitetura publicada; o workflow confirma `OSArchitecture=Arm64` antes do smoke ARM64.
- [ ] Os jobs de release instalaram, executaram e removeram os ZIPs e instaladores exatos em x64 e ARM64; o binário testado é o mesmo cujo hash será publicado.
- [ ] O job `Require successful native Windows validation` terminou com sucesso; a draft privada recebeu os dez ficheiros candidatos exatos, a evidência ARM64 atravessou apenas outputs limitados/hashados e `SIGNING-STATE.txt` contém exatamente as sete linhas canónicas, sem marcadores duplicados ou contraditórios.
- [ ] O payload final foi materializado substituindo apenas o `SIGNING-STATE.txt` pendente pela versão validada atestada; os quatro binários, quatro checksums e `SHA256SUMS.txt` são byte a byte os mesmos do candidato imutável.
- [ ] O grupo de concorrência global de release impediu dois payloads grandes de serem produzidos em paralelo; criar/fazer push da tag não iniciou um workflow e só o `workflow_dispatch` explícito contra essa tag iniciou o preflight e o candidato assinado.
- [ ] O SBOM SPDX 2.2 foi gerado a partir desse payload exato e dos metadados restaurados para `win-x64` e `win-arm64`; a cobertura dos dois runtimes foi validada e o manifesto faz parte do contrato final de 12 assets sem alterar os dez ficheiros instaláveis.
- [ ] A UI arranca, inicia e cancela um scan de laboratório e fecha sem processo residual.
- [ ] O ZIP inclui UI, CLI, README, licença, changelog, limites técnicos, `docs/VENDOR_DATABASE.md` e `THIRD_PARTY_NOTICES.md`.
- [ ] Exports JSON schema v8 e GraphML abrem sem perda do tipo, origem, confiança e evidência das ligações, identidade, serviços mDNS/DNS-SD, diagnósticos, estado TLS ou infraestrutura documentados; JSON/CSV/HTML preservam `macAddressSource`/evidência MAC e o resumo de infraestrutura.
- [ ] As opções CLI `--html` e `--graphml` foram verificadas com dados sintéticos ou de laboratório.
- [ ] O SHA-256 publicado corresponde exatamente ao ZIP.

Verificação manual do checksum:

```powershell
$version = '<versão>'
$zip = ".\artifacts\release\LocalNetworkScanner-$version-win-x64.zip"
$expected = (Get-Content "$zip.sha256").Split(' ')[0]
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SHA-256 invalido.' }
```

## 6. Assinatura e reputação

- [ ] Artefactos sem assinatura indicam claramente `QA` e `NotSigned`; no estado público atual não é criada nem publicada uma nova prerelease `PrivateQa`.
- [ ] Uma produção assinada envia `make_latest=true` e os gates Publish/terminal confirmam que `releases/latest` aponta para o mesmo ID/tag; uma QA privada envia `make_latest=false`.
- [ ] Num repositório público, nenhum caminho do workflow gera ou carrega um candidato `NotSigned`; `workflow_dispatch` com `publish_release=false` falha no preflight, e a visibilidade live é consultada novamente pela API imediatamente antes do upload e antes/depois de publicar a prerelease.
- [ ] Uma GitHub Release de produção contém apenas artefactos Authenticode `Signed`; as prereleases históricas `Private QA (NotSigned)` não são promovidas, alteradas ou reutilizadas.
- [ ] Checksums não são apresentados como substitutos de Authenticode nem como prova da identidade do publisher.
- [ ] O artefacto foi testado com SmartScreen/Defender numa máquina sem histórico do produto.
- [ ] Com gates incompletos num repositório público, nenhuma tag nova é criada; com gates completos, a tag nova fica reservada ao caminho assinado e a execução com `publish_release=true` não apresenta `LNS-REL-001` a `LNS-REL-010`.
- [ ] A tag corresponde à versão e aponta exatamente para o HEAD atual de `main`; o job de publicação volta a resolver pela API tags lightweight ou anotadas antes das mutações, imediatamente antes de publicar e após a publicação, exigindo sempre `GITHUB_SHA`.
- [ ] Se a tag estiver reservada para publicação assinada, a configuração do backend escolhido e a autorização/licença IEEE já estavam válidas antes de executar manualmente o workflow nessa tag; o push da tag, por si só, não inicia a release.

Para uma release publicada:

- [ ] Se for usada a SignPath, o projeto foi aceite, o GitHub App/trusted build system está ligado, origin verification passou, o input foi previamente guardado como GitHub Actions artifact e o pedido teve aprovação manual.
- [ ] Se for usado Microsoft Artifact Signing, a conta/perfil tem identidade válida, função mínima `Artifact Signing Certificate Profile Signer`, tipo explícito `PublicTrust` e credencial OIDC limitada a `release-signing`.
- [ ] Não existe PFX/chave privada no GitHub; tokens de integração estão limitados ao projeto, policy e environment necessários.
- [ ] O environment `release-signing` restringe deployments a tags autorizadas e exige reviewer apenas quando essa proteção está efetivamente disponível no plano/repositório; a ausência dessa capacidade tem um gate externo documentado.
- [ ] UI, CLI, diagnóstico PowerShell e instaladores são assinados antes de calcular checksums e criar a release.
- [ ] O bootstrap do Inno Setup 6.7.3 corresponde ao SHA-256 fixado no workflow, anuncia `ProductVersion` 6.7.3 e tem Authenticode válido do publisher esperado antes de ser executado.
- [ ] O Inno Setup usa `SignedUninstaller=yes`; depois de uma instalação de QA, o `unins*.exe` extraído foi verificado com o mesmo signer.
- [ ] A assinatura usa SHA-256 e timestamp de uma autoridade confiável.
- [ ] `signtool verify /pa /tw` e `Get-AuthenticodeSignature` devolvem sucesso/`Valid` para todos os executáveis finais.
- [ ] O certificado é RSA, tem EKU Code Signing, cadeia válida para uma CA confiável e não é self-signed.
- [ ] A chave permanece num HSM/serviço ou token compatível; nunca é exportada para PFX no runner hospedado.
- [ ] Jobs de QA sem assinatura não recebem credenciais de assinatura; permissões `id-token`, `actions` e `contents: write` ficam limitadas aos jobs que realmente necessitam delas. No backend atual, os validadores usam `contents: write` apenas para ler a draft com `persist-credentials: false`; numa integração SignPath, `actions: read` permite ao conector validar o artifact indicado.
- [ ] Os rulesets ativos impedem apagar/reescrever `main` e tags `v*`; no modelo atual de branch único com push direto, confirme manualmente o `CI gate` x64/ARM64 após cada push. Antes de abandonar esse modelo e aceitar alterações por PR, torne o check agregado obrigatório no ruleset.

Uma distribuição que alegue identidade de publisher verificada exige estado `Valid`.

## 7. MSIX ou instalador

O instalador Inno Setup opcional pode ser compilado depois do publish portátil:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-installer.ps1 -RuntimeIdentifier win-x64
powershell -ExecutionPolicy Bypass -File .\scripts\build-installer.ps1 -RuntimeIdentifier win-arm64
```

- [ ] O instalador usa `PrivilegesRequired=lowest` e instala por utilizador.
- [ ] Não instala drivers, serviços nem altera o `PATH`.
- [ ] UI, CLI, documentação e desinstalador estão presentes.
- [ ] `tools\diagnose-app-control.ps1` e `docs\APP_CONTROL.md` estão presentes.
- [ ] A desinstalação preserva os dados locais e essa decisão está documentada.
- [ ] Instalador e respetivo `.sha256` correspondem à arquitetura e versão da tag.
- [ ] O estado Authenticode é apresentado honestamente na release.
- [ ] O instalador não tem uma entrada `[Run]` pós-instalação que transforme o bloqueio do EXE (Win32 `4551`) em “erro de instalação”.

Esta checklist não assume que existe um instalador. Se for publicado MSIX:

- [ ] O `Publisher` do manifesto coincide exatamente com o certificado ou identidade da Store.
- [ ] Nome, versão de quatro componentes, arquitetura e assets do manifesto estão corretos.
- [ ] O pacote contém apenas os ficheiros de release e é assinado depois de ser criado.
- [ ] Instalação, atualização, downgrade recusado e desinstalação foram testados.
- [ ] Dados do utilizador após desinstalação são documentados.

Se for usado outro instalador, documentar a ferramenta e versão, privilégios pedidos, atalhos, atualização e remoção. Não introduzir um driver ou serviço sem uma revisão separada de segurança, licença e assinatura.

## 8. Matriz de validação

- [ ] Windows 10 x64 suportado: arranque, scan, exportação e fecho.
- [ ] Windows 11 x64 suportado: arranque, scan, exportação e fecho.
- [ ] Windows 11 ARM64 suportado: execução nativa ou limitação documentada.
- [ ] Ethernet, Wi-Fi e uma interface virtual foram verificadas.
- [ ] Rede sem ICMP, multicast bloqueado e adaptador sem VLAN exposta produzem resultados honestos.
- [ ] Com duas interfaces/VPN, o ICMP IPv4 usa a origem escolhida e não descobre um alvo através de uma rota diferente.
- [ ] Portas TLS testadas distinguem handshake confirmado, não verificado e falha indeterminada; o número da porta não cria evidência.
- [ ] DNS-SD resolve PTR/SRV/TXT/A/AAAA válidos e limita respostas comprimidas, truncadas ou excessivas.
- [ ] SSDP/UPnP preserva ST/USN e só promove XML do mesmo IP; WS-Discovery prende `XAddr` não autenticado ao IP remetente.
- [ ] Identidade SNMP indisponível e Nmap ausente/falhado preservam o scan base e apresentam `LNS-NET-008`/`009`/`010`.
- [ ] Switch SNMP indisponível, credenciais rejeitadas e tabelas FDB incompletas produzem avisos sem interromper o scan base.
- [ ] Os filtros da topologia conservam o caminho de infraestrutura até às correspondências sem contar os nós de contexto como resultados.
- [ ] Modo offline/sem interface ativa mostra uma mensagem acionável.
- [ ] Entrada inválida, interface ausente, MAC inválido, fabricante/tipo desconhecido e falha inesperada apresentam o código correto sem expor dados sensíveis.
- [ ] Nomes, SSIDs e hostnames com Unicode não quebram a UI nem CSV/JSON.

## 9. Publicação e pós-release

- [ ] ZIP, checksum, changelog e instruções de instalação estão anexados à release correta.
- [ ] A autorização escrita aplicável à redistribuição IEEE foi arquivada com a evidência da release e os avisos exigidos estão presentes no pacote.
- [ ] A variável do repositório `IEEE_REDISTRIBUTION_APPROVED` foi definida como `true` apenas depois de arquivar essa autorização.
- [ ] A página da release contém uma secção ou ligação visível chamada **Code signing policy**, sem alegar SignPath antes da aceitação/assinatura efetiva.
- [ ] Os hashes e assinaturas foram novamente verificados depois do upload.
- [ ] O job de publicação recebeu exatamente 12 assets pela draft privada, verificou nomes, estado, tamanhos, SHA-256 e os digests canónicos do candidato Pending, payload Validated e release final; voltou a validar checksums e, numa release pública, timestamps e um único signer antes de retirar o estado draft.
- [ ] O materializador final aceitou o `SIGNING-STATE.txt` já validado do payload apenas através do opt-in do job Publish e confirmou-o contra o atestado; os restantes caminhos continuam a exigir evidência separada.
- [ ] No backend Microsoft atual, o workflow não criou artefactos de Actions; numa integração SignPath, o artifact de entrada obrigatório foi validado e recebeu retenção mínima/cleanup seguro depois da conclusão. `VALIDATION-ATTESTATION.json` e o SBOM SPDX permanecem como assets da release.
- [ ] O gate terminal `Require an actually published release` terminou com sucesso e confirmou pela API `draft=false`, a tag, o modo de confiança, o marker e os 12 assets, recompondo também os digests canónicos do payload e da release; uma publicação elegível `skipped`, falhada ou cancelada não pode deixar o workflow verde.
- [ ] Todos os blocos `shell: pwsh` do workflow passaram validação sintática, incluindo o resumo executado depois de `draft=false`.
- [ ] `SIGNING-STATE.txt` e as notas da release publicada dizem explicitamente `Signed`; releases anteriores conhecidas como não assinadas permanecem documentadas como `NotSigned`.
- [ ] A release explica arquitetura, versão mínima de Windows suportada e known issues.
- [ ] Existe um canal privado para vulnerabilidades e um canal normal para suporte.
- [ ] A GitHub Release verificada é a cópia final dos 12 assets; atestado e SBOM estão ao lado dos dez ficheiros instaláveis sem qualquer segunda cópia pesada no armazenamento de Actions.
- [ ] A GitHub Release pública ainda não existia; a tag imutável aponta para o commit validado e assets já publicados nunca são substituídos com `--clobber`.
- [ ] Foi preparado um plano de rollback ou retirada da release.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
