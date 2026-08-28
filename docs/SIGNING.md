<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Assinatura e prontidão de release

## Estado atual

O repositório é público. Todos os downloads publicados atualmente estão `NotSigned`; a `v1.2.0` é histórica e as prereleases `v1.3.x`/`v1.4.0` conservam o título histórico `Private QA (NotSigned)`, sem constituírem produção. Não existe uma release assinada pela SignPath Foundation nem pelo backend Microsoft descrito abaixo.

A SignPath respondeu em 27-08-2026 que o projeto seria provavelmente problemático para o programa gratuito Foundation devido à sua categoria de scanner de rede e recomendou não submeter o estado atual. Isto não é uma rejeição formal nem uma aprovação: a candidatura gratuita não prosseguirá, não existe integração SignPath e nenhuma release foi assinada pela Foundation. Consulte a [Code signing policy](../CODE_SIGNING_POLICY.md), que prevalece para o estado público e as alegações de assinatura.

## Porque o erro 4551 não pode ser corrigido apenas no código

O código Win32 `4551` (`0x11C7`, `ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION`) é devolvido antes de a aplicação arrancar. O Windows avaliou o instalador, executável ou script através de Smart App Control/App Control for Business e recusou criar o processo. Nesse momento, a UI e o código do Local Network Scanner ainda não estão em execução e não podem autorizar-se a si próprios.

O projeto consegue produzir, assinar, verificar e diagnosticar os ficheiros. Não consegue inventar uma identidade pública para `p-darksy-r`, aprovar-se numa política empresarial nem declarar autorização legal para redistribuir dados de terceiros. Essas decisões pertencem, respetivamente, a um fornecedor de identidade de assinatura, ao administrador do dispositivo e ao titular dos dados.

Uma chave autoassinada só é útil num laboratório onde a raiz foi instalada deliberadamente. Não substitui uma identidade de Code Signing publicamente confiável e não resolve a distribuição geral.

## Canal MSIX da Microsoft Store

O `main` inclui agora um pipeline MSIX independente do pipeline Authenticode/Inno das releases GitHub. No modo `PrivateTest`, uma chave RSA 3072 não exportável permanece em `CurrentUser\My`, apenas o certificado público é versionado em `crt`, e o pacote é assinado com SHA-256. O administrador de cada PC de QA tem de confiar explicitamente esse CRT em `LocalMachine\TrustedPeople`; ele nunca deve ser instalado como uma autoridade em `Trusted Root` nem apresentado como identidade pública.

No modo `Store`, o script recusa o certificado de testes e exige `IdentityName`, `Publisher` e `PublisherDisplayName` copiados exatamente da identidade reservada no Partner Center. O candidato fica `UnsignedForMicrosoftStore`: não é instalável localmente, não é uma release e não pode usar a identidade isolada `PrivateTest`. Depois de aprovar uma submissão MSIX/AppX, a Microsoft Store substitui a assinatura do pacote e gere a sua distribuição. Esta assinatura de pacote não se transfere para o `LocalNetworkScanner.exe`, ZIP, MSI ou instalador Inno distribuído fora da Store.

O manifesto declara somente `rescap:runFullTrust`, necessário para a aplicação WPF `packagedClassicApp`/`mediumIL`. Essa capacidade restrita terá de ser justificada no Partner Center com o comportamento real de ICMP, sockets, ARP/NDP, enumeração autorizada, ferramentas Windows iniciadas no contexto do utilizador e Nmap local opcional; não são pedidos elevação, drivers, serviços ou acesso amplo ao sistema de ficheiros. Consulte [o guia MSIX](MSIX.md).

## Backend Microsoft implementado, mas não configurado

O workflow versionado contém um caminho de produção para **Microsoft Artifact Signing com OIDC**, sem PFX ou chave privada guardada no GitHub. As variáveis e a identidade externas necessárias não estão configuradas neste repositório; por isso este caminho não assinou nenhuma release. Quando integralmente configurado, o desenho é:

1. um preflight confirma versão, tag, commit exato de `main`, configuração de assinatura e autorização IEEE antes dos builds dispendiosos;
2. o modo `PrivateQa` corre num job sem permissão `id-token`, enquanto só o job de produção entra no GitHub Environment `release-signing` e pode obter um token OIDC temporário;
3. a chave e o certificado permanecem no serviço de assinatura; o runner nunca recebe a chave privada;
4. UI, CLI e `diagnose-app-control.ps1` são assinados e timestamped antes dos ZIPs;
5. o runner só executa o Inno Setup 6.7.3 depois de confirmar SHA-256 fixo, `ProductVersion`, Authenticode e publisher; o Inno chama depois o mesmo signer para o instalador e para o desinstalador embebido;
6. hashes e assinaturas são validados de novo depois do empacotamento;
7. o ZIP e instalador **exatos** são instalados, executados e removidos primeiro em Windows x64 e depois num runner Windows ARM64 nativo;
8. o payload grande é carregado uma única vez como dez assets numa draft release ainda não publicada associada à tag final; não é usado armazenamento de artefactos de Actions;
9. depois do ARM64, o atestado segue para o gate como Base64 limitado a 64 KiB com tamanho e SHA-256; o gate valida encoding, JSON e proveniência antes de substituir apenas `SIGNING-STATE.txt` e confirmar que os restantes nove ficheiros continuam byte a byte iguais;
10. o target remoto da tag, incluindo tags anotadas, é resolvido novamente para o commit do workflow antes de criar, carregar ou publicar o draft e depois da publicação;
11. o SBOM SPDX e `VALIDATION-ATTESTATION.json` são anexados permanentemente, formando o contrato final de 12 assets; a release continua draft até esse contrato ser verificado imediatamente antes de `draft=false`. Uma repetição aceita uma release já publicada apenas quando assets, três digests e proveniência histórica continuam exatos; um draft divergente nunca é substituído;
12. no job final, `DownloadFinal` volta a verificar os 12 assets e coloca o estado já validado no payload; o materializador só pode reutilizá-lo com opt-in explícito e continua a exigir o SHA-256 do atestado, as sete linhas exatas e toda a proveniência;
13. o job de publicação substitui explicitamente o `success()` implícito do GitHub, exige os resultados dos gates diretos e termina num gate independente que falha se uma execução elegível não produzir uma release publicada; esse gate consulta ainda a API e confirma `draft=false`, tag, modo, marker e os 12 assets, recompondo os digests canónicos do payload e da release.

O modo `PrivateQa` permanece `NotSigned` e só pode publicar uma prerelease quando a API confirma que o repositório é privado. Num repositório público, como o atual, `workflow_dispatch` com `publish_release=false` falha no preflight e nenhum candidato `NotSigned` novo é gerado ou carregado. Além do snapshot do evento, o job consulta a visibilidade live pela API imediatamente antes do upload do candidato, antes de criar/publicar o draft e depois da publicação. O título, notas e `SIGNING-STATE.txt` desse modo indicam `Private QA (NotSigned)`; envia `make_latest=false` e nunca é produção nem `Latest`. As prereleases com esse título já existentes foram criadas antes da alteração de visibilidade e continuam sem assinatura apesar de estarem agora acessíveis publicamente.

Criar ou fazer push de uma tag `vX.Y.Z` não executa automaticamente o workflow. A release começa apenas por `workflow_dispatch` dirigido explicitamente à ref da tag, por exemplo `gh workflow run release.yml --ref vX.Y.Z -f publish_release=true`. Isto impede que um push de tag produza um run verde sem candidato nem release. O caminho `PrivateQa` só continua quando o repositório é privado; no estado público atual é recusado. A execução assinada exige `publish_release=true`. A produção pede explicitamente `make_latest=true`; o publicador e o gate terminal confirmam por `releases/latest` o mesmo ID/tag antes de considerar a execução concluída. Assets publicados divergentes nunca são substituídos; uma release já publicada com o contrato exatamente igual é reconhecida de forma idempotente e a execução avança apenas para a verificação final e limpeza. A passagem de uma prerelease QA já criada para produção exige sempre uma versão/tag nova.

Este desenho evita qualquer cópia de aproximadamente 390 MB no armazenamento de Actions. O grupo de concorrência é global ao repositório e a draft é identificada por repository ID, run, tentativa, commit, tag, digest e nonce. Se a validação ou publicação falhar, o cleanup volta a obter a release por ID e só elimina uma draft com ownership exato; uma release publicada nunca é apagada nem agenda cleanup. O gate terminal impede que um job de publicação ignorado produza um workflow verde sem release. O atestado e o SBOM deixam de depender da retenção temporária de Actions e permanecem junto dos binários como assets verificáveis da release.

O GitHub restringe a leitura de draft releases a tokens com push access. Assim, os jobs x64 e ARM64 precisam de `contents: write` apesar de apenas descarregarem assets; `contents: read` recebe HTTP 403 em `GET releases/{id}`. O risco é limitado mantendo a tag no HEAD validado de `main`, usando ações fixadas por SHA, desativando `persist-credentials` e chamando nesses jobs apenas a operação `DownloadCandidate`, que não contém mutações remotas.

O suporte local por thumbprint nos scripts continua disponível para laboratórios, PKI privada ou um runner próprio ligado a token/HSM. O workflow público não usa PFX exportável: certificados Code Signing públicos novos exigem normalmente que a chave seja gerada, armazenada e usada num módulo criptográfico adequado.

## Resultado da avaliação SignPath Foundation

A SignPath não é um backend ativo neste repositório. A orientação recebida desaconselha a candidatura gratuita no estado atual, porque a enumeração de rede, portas e serviços é parte central do produto. As funcionalidades permanecem deliberadamente disponíveis para inventário e troubleshooting autorizado. Se no futuro for escolhida uma subscrição regular SignPath, a integração terá de ser implementada e revista antes de qualquer pedido de assinatura:

1. instalar e autorizar a aplicação GitHub da SignPath conforme a configuração fornecida;
2. ligar o projeto a um trusted build system GitHub com origin verification;
3. produzir o candidato em runners alojados pelo GitHub e carregá-lo primeiro como GitHub Actions artifact;
4. submeter esse artifact através da ação oficial da SignPath, fixada por commit, usando um token limitado à signing policy correta;
5. aplicar restrições de metadados a nome do produto, versão, empresa, copyright e nomes originais dos executáveis;
6. exigir aprovação manual de cada pedido de produção e validar o artifact devolvido antes de gerar checksums ou publicar;
7. documentar exatamente quais executáveis, scripts, instaladores e desinstaladores são abrangidos.

Esta possível integração regular difere do transporte por draft release do backend atual. Não basta trocar o nome do serviço ou criar secrets: a ordem de build, assinatura, criação do instalador, testes nativos e hashes terá de preservar a proveniência do mesmo candidato. Uma autorização de redistribuição IEEE e uma licença OSI são questões diferentes. Não esconda capacidades nem apresente uma resposta parcial como aprovação do produto completo.

## Pré-requisitos externos do backend Microsoft

Os passos desta secção aplicam-se apenas se o projeto escolher e puder usar o backend Microsoft atualmente versionado. Não os execute para simular ou substituir uma aprovação SignPath. Antes de ativar uma release pública por esse backend:

1. confirme primeiro a elegibilidade da entidade: a documentação atual da Microsoft admite Public Trust para organizações nos EUA, Canadá, União Europeia e Reino Unido, mas para developers individuais apenas nos EUA e Canadá. Por isso, uma pessoa individual em Portugal pode não ser elegível; uma organização legal portuguesa está na região UE elegível, sujeita à validação de identidade da Microsoft;
2. crie a conta Artifact Signing, conclua a validação da identidade e crie um certificate profile cujo tipo seja exatamente `PublicTrust`, não `PrivateTrust` nem `PublicTrustTest`;
3. atribua à identidade federada **Artifact Signing Certificate Profile Signer** apenas no perfil necessário e acesso de leitura mínimo ao recurso para o workflow conseguir confirmar o `profileType` pela API ARM antes de assinar;
4. para este repositório criado após 15 de julho de 2026, crie no Azure uma credencial federada com issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange` e o subject imutável:

```text
repo:p-darksy-r@<OWNER_ID>/LocalNetworkScanner@<REPO_ID>:environment:release-signing
```

Não invente os IDs. Obtenha-os diretamente da API do GitHub e confirme os nomes antes de configurar o Azure:

```powershell
$repository = 'p-darksy-r/LocalNetworkScanner'
gh api "repos/$repository" --jq '{owner: .owner.login, owner_id: .owner.id, repository: .name, repository_id: .id}'
```

O step `Validate immutable GitHub OIDC claims` pede um token com a audience acima, descodifica apenas o payload e compara `sub` e `aud` com `github.repository_owner_id`, `github.repository_id` e o environment. O token completo nunca é escrito no log. O Azure Login só é executado depois dessa verificação. Se um repositório mais antigo ainda usar o subject baseado apenas em nomes, opte primeiro pelos immutable subject claims no GitHub e confirme novamente os claims; não enfraqueça a credencial Azure para aceitar ambos sem uma migração deliberada.

5. no GitHub, configure o Environment `release-signing` e as regras disponíveis no plano real da conta;
6. proteja `main`, exija o check agregado **CI gate** e restrinja a criação de tags `v*` a responsáveis autorizados;
7. obtenha e arquive autorização escrita para redistribuir a snapshot IEEE incorporada, ou retire essa snapshot dos binários públicos.

Se o Public Trust do Artifact Signing não estiver disponível para a identidade — cenário provável para um developer individual em Portugal enquanto a elegibilidade publicada se mantiver — use um certificado Code Signing de uma CA pública, com a chave num cloud HSM ou token/hardware que cumpra os requisitos atuais do CA/Browser Forum. Essa alternativa exige adaptar explicitamente o signer do workflow; não guarde um PFX exportável nos GitHub Secrets. A integração alternativa tem de assinar UI, CLI, diagnóstico PowerShell, instalador e desinstalador Inno, e preservar a validação de timestamp e signer comum.

## Environment `release-signing`: disponibilidade e garantias

O nome `release-signing` por si só **não garante aprovação humana**. Um workflow que referencia um environment inexistente pode criá-lo sem regras de proteção. A disponibilidade em repositórios privados depende do plano:

| Plano/visibilidade | Capacidade relevante | Consequência para este projeto |
| --- | --- | --- |
| repositório público, planos atuais | environments e deployment protection rules disponíveis | configure reviewer, prevenção de self-review, tags permitidas e sem bypass, conforme disponível |
| repositório privado pessoal com GitHub Pro ou organização com Team | environment, secrets/variables e deployment branches/tags disponíveis; required reviewers e wait timer não são disponibilizados a privados nesses planos segundo a matriz atual do GitHub | não declare que existe aprovação; dependa dos controlos imutáveis Azure, rulesets e revisão de `main`/tags |
| repositório privado em GitHub Enterprise | podem existir regras adicionais, incluindo aprovação, conforme produto e configuração | confirme na página/API do environment e teste uma execução que fique realmente pendente antes de considerar o gate ativo |
| repositório privado num plano sem environments privados | configuração indisponível ou ignorada | não publique; mude de plano/visibilidade ou use outro gate de release administrado |

Confirme o estado efetivo em **Settings → Environments → release-signing** e pela API, em vez de inferir proteção pela existência do nome:

```powershell
gh api "repos/p-darksy-r/LocalNetworkScanner/environments/release-signing"
```

Independentemente do plano, mantenha o subject OIDC imutável, audience Azure exata, privilégios Azure limitados ao perfil, `main` e tags `v*` protegidos, actions fixadas por commit e revisão obrigatória de alterações ao workflow. A separação dos jobs garante que `publish_release=false` não recebe as variáveis de pedido do token OIDC nem uma sessão Azure.

## Configuração Microsoft no GitHub

Os identificadores seguintes não são chaves privadas, mas devem ser alterados apenas por responsáveis pela release. Configure-os como **repository variables**, porque o job de preflight corre antes de entrar no environment protegido:

```powershell
$repository = 'p-darksy-r/LocalNetworkScanner'

gh variable set ARTIFACT_SIGNING_ENDPOINT --body 'https://<regiao>.codesigning.azure.net' --repo $repository
gh variable set ARTIFACT_SIGNING_RESOURCE_GROUP --body '<resource-group>' --repo $repository
gh variable set ARTIFACT_SIGNING_ACCOUNT --body '<conta>' --repo $repository
gh variable set ARTIFACT_SIGNING_PROFILE --body '<perfil>' --repo $repository
gh variable set AZURE_CLIENT_ID --body '<application-client-id>' --repo $repository
gh variable set AZURE_TENANT_ID --body '<tenant-id>' --repo $repository
gh variable set AZURE_SUBSCRIPTION_ID --body '<subscription-id>' --repo $repository
gh variable set ARTIFACT_SIGNING_ENABLED --body true --repo $repository
```

Não configure `AUTHENTICODE_PFX_BASE64` nem `AUTHENTICODE_PFX_PASSWORD`: o workflow já não os lê. Se esses secrets antigos existirem, remova-os depois de confirmar que nenhuma outra automação depende deles.

Só depois da autorização IEEE:

```powershell
gh variable set IEEE_REDISTRIBUTION_APPROVED --body true --repo $repository
```

Definir a variável sem possuir a autorização não cria direitos de redistribuição.

## Sequência segura no estado público atual

1. Execute CI no `main` e confirme **CI gate**, incluindo o job ARM64 nativo.
2. Não crie uma tag nova para publicar QA sem assinatura: no repositório público o modo `PrivateQa` falha antes do build.
3. Teste UI, CLI, scan, topologia, instalação, atualização e remoção num Windows limpo através de builds locais claramente identificadas como `NotSigned`.
4. Arquive a resposta escrita da SignPath Foundation como orientação de não candidatura gratuita; obtenha separadamente a autorização da snapshot IEEE.
5. Escolha um backend realmente elegível. Para uma subscrição regular SignPath, implemente GitHub artifact/origin verification/aprovação; para Microsoft, configure e proteja `release-signing`, OIDC e um perfil `PublicTrust` elegível.
6. Proteja `main`, tags, workflows e credenciais, e confirme MFA para todas as funções de assinatura.
7. Atualize versão/changelog e confirme novamente que o HEAD local e `origin/main` são o mesmo commit.
8. Configure todos os gates externos antes de criar a nova tag de produção. A primeira release assinada não pode reutilizar `v1.4.0` nem substituir assets existentes.
9. Confirme no workflow que os assets exatos passaram instalação/smoke/uninstall em x64 e ARM64.
10. Depois do upload, descarregue os ficheiros e volte a validar SHA-256, signer e timestamp num Windows sem histórico do produto.

O runner `windows-11-arm` valida uma VM Windows ARM64 nativa; não substitui um ensaio adicional em equipamento ARM64 físico usado por um utilizador real.

## Códigos de release

| Código | Significado | Resolução |
| --- | --- | --- |
| `LNS-REL-001` | publicação pedida sem Artifact Signing ativado | configure a identidade e só depois ative o gate |
| `LNS-REL-002` | configuração/claims OIDC incompletos, perfil ilegível ou tipo diferente de `PublicTrust` | configure endpoint, resource group, conta, perfil público, IDs Azure e credencial federada imutável |
| `LNS-REL-003` | cliente, endpoint, ferramenta ou autenticação inválida | valide módulo, Azure login, SignTool e configuração |
| `LNS-REL-004` | certificado incompatível ou não confiável no modo local | use Code Signing RSA com cadeia confiável e chave protegida |
| `LNS-REL-005` | visibilidade privada, assinatura, signer comum ou timestamp final inválido | não publique; restaure a fronteira de confiança ou corrija e gere todos os assets novamente |
| `LNS-REL-006` | autorização IEEE não confirmada | obtenha autorização escrita ou não redistribua a snapshot |
| `LNS-REL-007` | validação nativa x64/ARM64 ou respetiva evidência/atestação falhou | corrija o pacote ou a cadeia de evidência exata; cross-build não substitui este gate |
| `LNS-REL-008` | ownership da draft, contrato de 10/12 assets, conteúdo, digest ou checksums divergente | não altere recursos não owned; gere uma release nova a partir de uma árvore limpa |
| `LNS-REL-009` | versão, tag, ref ou commit não corresponde ao `main` confiável | use uma tag nova no HEAD atual de `main` |
| `LNS-REL-010` | o SBOM não pôde ser gerado/validado ou não cobre `win-x64` e `win-arm64` | preserve o payload, confirme a ferramenta fixada, os metadados dos dois runtimes e os caminhos sob `artifacts`, e repita sem publicar evidência incompleta |

## Referências oficiais

- [Microsoft — visão geral do Smart App Control](https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview)
- [Microsoft — assinar para Smart App Control](https://learn.microsoft.com/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control)
- [Microsoft — testar assinaturas com Smart App Control](https://learn.microsoft.com/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control)
- [Microsoft — integrações do Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/how-to-signing-integrations)
- [Microsoft — FAQ e elegibilidade do Artifact Signing Public Trust](https://learn.microsoft.com/azure/artifact-signing/faq)
- [Microsoft — API ARM do certificate profile e `profileType`](https://learn.microsoft.com/azure/templates/microsoft.codesigning/2025-10-13/codesigningaccounts/certificateprofiles)
- [Microsoft — autenticação OIDC do Azure Login](https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect)
- [Microsoft — timestamp Authenticode](https://learn.microsoft.com/windows/win32/seccrypto/time-stamping-authenticode-signatures)
- [CA/Browser Forum — Code Signing Baseline Requirements](https://cabforum.org/working-groups/code-signing/requirements/)
- [GitHub — runners hospedados, incluindo Windows ARM64](https://docs.github.com/actions/reference/runners/github-hosted-runners)
- [GitHub — OIDC e subjects imutáveis](https://docs.github.com/actions/reference/security/oidc)
- [GitHub — environments, planos e deployment protection rules](https://docs.github.com/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- [SignPath Foundation — condições para projetos open source](https://signpath.org/terms.html)
- [SignPath — GitHub trusted build system](https://docs.signpath.io/trusted-build-systems/github)

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
