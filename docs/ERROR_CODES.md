<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Códigos de erro e diagnóstico

O Local Network Scanner apresenta códigos estáveis para que uma mensagem possa ser pesquisada, comunicada e tratada sem depender do texto exato. Cada diagnóstico contém:

- `Code`: identificador `LNS-<categoria>-<número>`;
- `Category`: responsabilidade provável (`User`, `Network`, `Device` ou `Application`);
- `Severity`: `Information`, `Warning`, `Error` ou `Critical`;
- `Message`: explicação legível em pt-PT;
- `RecommendedAction`: próximo passo concreto;
- `Target`: interface, ficheiro ou dispositivo afetado, quando necessário;
- `Context`: detalhes técnicos sanitizados;
- `IsFatal`: indica se a operação não pode continuar.

Entradas de contexto cujas chaves são identificadas como passwords, secrets, tokens, communities SNMP, credenciais, cabeçalhos de autenticação ou API keys são omitidas. Os nomes das chaves são controlados pela aplicação, mas o alvo e outros valores podem conter um IP, MAC ou caminho local: anonimize sempre o relatório antes de o publicar.

## Como interpretar

- **Information** explica uma capacidade indisponível ou uma limitação esperada; não representa falha.
- **Warning** indica um resultado incompleto ou desconhecido, mas preserva os dados válidos.
- **Error** impede a operação pedida ou exige correção antes de repetir.
- **Critical** representa uma falha interna inesperada que deve ser comunicada se for reproduzível.

A categoria indica a origem mais provável, não atribui culpa. Uma firewall, política empresarial, driver ou equipamento remoto pode alterar a classificação observável.

## Utilizador — `LNS-USR-*`

| Código | Severidade | Significado | Ação recomendada |
| --- | --- | --- | --- |
| `LNS-USR-001` | Error | Comando ou opção desconhecida | Reveja `--help` e corrija o nome da opção. |
| `LNS-USR-002` | Error | Falta o valor obrigatório de uma opção | Indique o valor imediatamente depois da opção. |
| `LNS-USR-003` | Error | Perfil de scan inválido | Use `quick`, `standard` ou `advanced`; o alias `deep` continua aceite. Na UI escolha Rápido, Normal ou Avançado. |
| `LNS-USR-004` | Error | Interface selecionada inválida ou já indisponível | Atualize a lista e escolha uma interface IPv4 ativa. |
| `LNS-USR-005` | Error | CIDR inválido | Use notação IPv4 CIDR, por exemplo `192.168.1.0/24`. |
| `LNS-USR-006` | Error | O âmbito inclui IP público ou bloqueado | Limite o scan a endereços privados/locais autorizados. |
| `LNS-USR-007` | Error | A rede excede o limite de segurança | Reduza o intervalo ou divida-o em scans autorizados menores. |
| `LNS-USR-008` | Error | Configuração do scan inconsistente | Reveja perfil, interface, intervalo, portas e opções avançadas. |
| `LNS-USR-009` | Information | Operação cancelada | Nenhuma ação é necessária; resultados parciais confirmados podem continuar visíveis. |
| `LNS-USR-010` | Error | Lista ou intervalo de portas inválido | Use portas entre 1 e 65535, intervalos válidos ou um alias suportado. |

## Rede — `LNS-NET-*`

| Código | Severidade | Significado | Ação recomendada |
| --- | --- | --- | --- |
| `LNS-NET-001` | Error | Não existe interface IPv4 ativa | Ligue Ethernet/Wi-Fi, confirme a configuração IPv4 e atualize as interfaces. |
| `LNS-NET-002` | Warning | Nenhum dispositivo foi encontrado | Confirme CIDR/interface e considere firewall, isolamento de clientes ou o perfil Normal. |
| `LNS-NET-003` | Warning | O switch SNMP não respondeu ou rejeitou o pedido | Confirme autorização, IP, community, ACL, SNMP v2c e conectividade de gestão. |
| `LNS-NET-004` | Information | O Windows/driver não expôs uma VLAN | Consulte a configuração do adaptador ou switch; não assuma VLAN 0. |
| `LNS-NET-005` | Information | Telemetria Wi-Fi local indisponível | Confirme que a interface Wi-Fi está ligada e que driver/política permitem a consulta. |
| `LNS-NET-006` | Information | Limite de uma inferência L2 baseada em ARP/FDB | Trate segmento/switch como inferência e valide na infraestrutura quando necessário. |
| `LNS-NET-007` | Error | Uma operação de rede falhou | Verifique conectividade, firewall, VPN, permissões e repita num intervalo menor. |
| `LNS-NET-008` | Information | Nenhum alvo respondeu à identidade SNMP opcional | Confirme autorização, community, ACL e agente; lembre-se de que SNMP v2c envia a community sem cifragem. |
| `LNS-NET-009` | Information | Nmap opcional não encontrado ou não validado | Instale-o separadamente a partir da origem oficial ou indique um `nmap.exe` local; `PATH`, UNC e device paths não são usados. |
| `LNS-NET-010` | Warning | O enriquecimento Nmap falhou ou excedeu os limites | Confirme executável, permissões, firewall, intervalo e timeout; o inventário nativo continua válido. |

## Dispositivo — `LNS-DEV-*`

| Código | Severidade | Significado | Ação recomendada |
| --- | --- | --- | --- |
| `LNS-DEV-001` | Warning | MAC inválido, incompleto ou não-unicast | Confirme a resposta e o endereço no equipamento; o resto do dispositivo pode continuar utilizável. |
| `LNS-DEV-002` | Warning | Titular IEEE/fabricante não determinado | A snapshot offline já é usada; atualize-a opcionalmente para um MAC global recente ou aceite “desconhecido” quando a atribuição for privada, inexistente ou inconclusiva. |
| `LNS-DEV-003` | Warning | Tipo de dispositivo não reconhecido | Reveja hostname, fabricante, portas e serviços; não force uma classificação sem evidência. |
| `LNS-DEV-004` | Information | MAC administrado localmente ou aleatório | A identidade e o fabricante podem mudar ou permanecer desconhecidos por design. |
| `LNS-DEV-005` | Warning | Fabricante/modelo contraditório entre fontes | Compare origem e confiança; confirme no equipamento ou consola de gestão antes de atualizar o inventário. |

`LNS-DEV-002` não significa que a base incorporada esteja ausente. A aplicação consulta MA-S/IAB `/36`, MA-M `/28` e MA-L `/24`, por esta ordem. Mesmo com a snapshot completa, a IEEE pode publicar `Private`, um OEM pode não coincidir com a marca do dispositivo e um endereço local/aleatório não oferece atribuição global fiável. CID é deliberadamente excluído e não deve ser usado para forçar uma identificação.

## Aplicação — `LNS-APP-*`

| Código | Severidade | Significado | Ação recomendada |
| --- | --- | --- | --- |
| `LNS-APP-001` | Critical | Falha interna inesperada | Guarde o código/versão, reinicie e comunique uma reprodução mínima com dados anonimizados. |
| `LNS-APP-002` | Error / Warning | Falha ao ler ou escrever um ficheiro | Confirme caminho, espaço, bloqueios, permissões e proteção antimalware. É aviso quando apenas o histórico opcional falha e o scan é preservado. |
| `LNS-APP-003` | Error | O Windows recusou o acesso | Escolha um recurso permitido ou peça ao administrador que reveja a política; não contorne controlos. |
| `LNS-APP-004` | Information | Captura integral não suportada nesta versão | Interprete a lista de protocolos como evidência do scan ativo; para analisar tráfego, use uma ferramenta dedicada numa rede autorizada. |
| `LNS-APP-005` | Error | Windows Application Control bloqueou o ficheiro (`CreateProcess` 4551), confirmado por um evento 3077 correlacionado com o caminho completo de um alvo existente | Use uma release com assinatura Authenticode confiável ou peça ao administrador que autorize o publisher, hash ou catálogo; não desative a proteção para contornar a política. |
| `LNS-APP-006` | Warning | O diagnóstico de Application Control é inconclusivo: existe apenas auditoria, não há evento correlacionado ou a correlação coincide apenas com o nome do ficheiro | Repita com o caminho exato do ficheiro bloqueado e uma janela temporal adequada; confirme o caminho completo nos eventos antes de atribuir o erro 4551. |

O relatório de diagnóstico App Control usa o schema v2. `policyBlockConfirmed=true` só é emitido para um alvo que ainda existe e para o qual foi encontrado um evento de enforcement 3077 com correlação `FullPath`. Uma coincidência apenas pelo nome fica preservada em `codeIntegrity.matchingEvents` com `correlation=FileNameOnly`, mas recebe baixa confiança e nunca confirma o bloqueio. Um alvo ausente também nunca é confirmado.

## Build e release — `LNS-REL-*`

Estes códigos pertencem ao workflow e aos scripts de distribuição; não são diagnósticos de um scan. Impedem que uma ausência de identidade, autorização ou validação seja apresentada como release pronta.

| Código | Severidade | Significado | Ação recomendada |
| --- | --- | --- | --- |
| `LNS-REL-001` | Error | Publicação pedida sem Microsoft Artifact Signing ativado | Configure primeiro a identidade cloud/HSM e só depois ative `ARTIFACT_SIGNING_ENABLED`. |
| `LNS-REL-002` | Error | Configuração Artifact Signing/OIDC incompleta | Configure endpoint, conta, perfil e os IDs Azure exigidos sem guardar uma chave privada no GitHub. |
| `LNS-REL-003` | Error | Cliente, endpoint, ferramenta ou autenticação de assinatura inválida | Confirme Azure Login OIDC, módulo ArtifactSigning, endpoint, Inno Setup e Windows SDK/SignTool. |
| `LNS-REL-004` | Error | Certificado incompatível, autoassinado ou sem cadeia confiável no modo local | Use RSA com EKU Code Signing, cadeia pública aceite e chave protegida por token/HSM. |
| `LNS-REL-005` | Error | Assinatura ou timestamp final não validou | Não publique; corrija a assinatura e volte a gerar todos os assets e hashes. |
| `LNS-REL-006` | Error | Redistribuição da snapshot IEEE não foi autorizada | Arquive autorização escrita antes de definir `IEEE_REDISTRIBUTION_APPROVED=true`. |
| `LNS-REL-007` | Error | Build, instalação, smoke ou remoção nativa x64/ARM64 falhou | Corrija o pacote exato; um cross-build x64 não substitui este gate. |
| `LNS-REL-008` | Error | Contrato de assets ou checksums divergente | Gere uma versão nova a partir de uma árvore limpa; não substitua ficheiros já publicados. |
| `LNS-REL-009` | Error | Versão, tag, ref ou commit não corresponde ao HEAD confiável de `main` | Execute a release a partir de uma tag nova, correspondente à versão, criada no commit atual de `main`. |

Consulte [Assinatura e prontidão de release](SIGNING.md) para o procedimento completo.

## CLI e exportações

A CLI mostra código, categoria, severidade, mensagem, ação, alvo e contexto disponível. Os exit codes são:

| Exit code | Resultado |
| --- | --- |
| `0` | sucesso; podem existir diagnósticos `Information` ou `Warning` |
| `1` | falha fatal da aplicação (`LNS-APP-*`) |
| `2` | entrada/configuração inválida (`LNS-USR-*`) |
| `3` | falha fatal de rede (`LNS-NET-*`) |
| `4` | falha fatal associada a dispositivo (`LNS-DEV-*`) |
| `130` | operação cancelada (`LNS-USR-009`) |

O JSON schema v5 inclui os diagnósticos e as evidências de identidade de forma estruturada em `scan.diagnostics` e `devices[].identityEvidence`. HTML apresenta os diagnósticos numa secção própria e GraphML usa o atributo de grafo `g_diagnostics`. Consumidores automáticos devem decidir pelo código/categoria e não fazer parsing do texto em pt-PT.

## Pedir suporte

Abra uma [issue de erro](https://github.com/p-darksy-r/LocalNetworkScanner/issues/new?template=bug_report.yml) com versão, arquitetura, Windows, código e passos mínimos numa rede de laboratório. Não publique um inventário completo. Vulnerabilidades exploráveis devem ser comunicadas através de um [Security Advisory privado](https://github.com/p-darksy-r/LocalNetworkScanner/security/advisories/new).

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
