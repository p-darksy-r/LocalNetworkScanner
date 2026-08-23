<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Assinatura e prontidão de release

## Porque o erro 4551 não pode ser corrigido apenas no código

O código Win32 `4551` (`0x11C7`, `ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION`) é devolvido antes de a aplicação arrancar. O Windows avaliou o instalador, executável ou script através de Smart App Control/App Control for Business e recusou criar o processo. Nesse momento, a UI e o código do Local Network Scanner ainda não estão em execução e não podem autorizar-se a si próprios.

O projeto consegue produzir, assinar, verificar e diagnosticar os ficheiros. Não consegue inventar uma identidade pública para `p-darksy-r`, aprovar-se numa política empresarial nem declarar autorização legal para redistribuir dados de terceiros. Essas decisões pertencem, respetivamente, a um fornecedor de identidade de assinatura, ao administrador do dispositivo e ao titular dos dados.

Uma chave autoassinada só é útil num laboratório onde a raiz foi instalada deliberadamente. Não substitui uma identidade de Code Signing publicamente confiável e não resolve a distribuição geral.

## Modelo de produção implementado

O workflow usa **Microsoft Artifact Signing com OIDC**, sem PFX ou chave privada guardada no GitHub:

1. um preflight confirma versão, tag, commit exato de `main`, configuração de assinatura e autorização IEEE antes dos builds dispendiosos;
2. o caminho privado de QA corre num job sem permissão `id-token`, enquanto só o job público entra no GitHub Environment `release-signing` e pode obter um token OIDC temporário;
3. a chave e o certificado permanecem no serviço de assinatura; o runner nunca recebe a chave privada;
4. UI, CLI e `diagnose-app-control.ps1` são assinados e timestamped antes dos ZIPs;
5. o runner só executa o Inno Setup 6.7.3 depois de confirmar SHA-256 fixo, `ProductVersion`, Authenticode e publisher; o Inno chama depois o mesmo signer para o instalador e para o desinstalador embebido;
6. hashes e assinaturas são validados de novo depois do empacotamento;
7. o ZIP e instalador **exatos** são instalados, executados e removidos primeiro em Windows x64 e depois num runner Windows ARM64 nativo;
8. o payload grande é carregado uma única vez como dez assets numa draft release privada associada à tag final; não é usado armazenamento de artefactos de Actions;
9. depois do ARM64, o atestado segue para o gate como Base64 limitado a 64 KiB com tamanho e SHA-256; o gate valida encoding, JSON e proveniência antes de substituir apenas `SIGNING-STATE.txt` e confirmar que os restantes nove ficheiros continuam byte a byte iguais;
10. o target remoto da tag, incluindo tags anotadas, é resolvido novamente para o commit do workflow antes de criar, carregar ou publicar o draft e depois da publicação;
11. o SBOM SPDX e `VALIDATION-ATTESTATION.json` são anexados permanentemente, formando o contrato final de 12 assets; a release continua draft até esse contrato ser verificado imediatamente antes de `draft=false`. Uma repetição aceita uma release já publicada apenas quando assets, três digests e proveniência histórica continuam exatos; um draft divergente nunca é substituído;
12. o job de publicação substitui explicitamente o `success()` implícito do GitHub, exige os resultados dos gates diretos e termina num gate independente que falha se uma execução elegível não produzir uma release publicada; esse gate consulta ainda a API e confirma `draft=false`, tag, modo, marker e os 12 assets, recompondo os digests canónicos do payload e da release.

Artefactos privados de QA permanecem `NotSigned`. Enquanto os gates de produção ainda não estão todos configurados, uma tag nova promove-os automaticamente para uma **prerelease privada**, mas só depois de ambos os testes nativos. Num repositório público, `workflow_dispatch` com `publish_release=false` falha no preflight e nenhum candidato `NotSigned` é gerado ou carregado. Além do snapshot do evento, o job consulta a visibilidade atual pela API imediatamente antes do upload do candidato, antes de criar/publicar o draft e depois da publicação. Estas verificações reduzem a janela de mudança, mas a visibilidade do repositório e a publicação da release não formam uma transação atómica; mantenha o repositório privado durante toda a execução e não altere a visibilidade enquanto existir uma prerelease `NotSigned`. O título, notas e `SIGNING-STATE.txt` indicam claramente `Private QA (NotSigned)`; a prerelease não é produção nem `Latest`.

Criar ou fazer push de uma tag `vX.Y.Z` executa o caminho privado de QA e, se o repositório for privado e a configuração de produção ainda estiver incompleta, cria a prerelease `NotSigned` depois da validação completa. Quando Artifact Signing/OIDC e a autorização IEEE já estão integralmente configurados antes do push, a criação automática e o build pesado sem assinatura são suprimidos: o preflight reserva essa tag nova à execução assinada por `workflow_dispatch` com `publish_release=true`. Assets publicados divergentes nunca são substituídos; uma release já publicada com o contrato exatamente igual é reconhecida de forma idempotente e a execução avança apenas para a verificação final e limpeza. A passagem de uma prerelease QA já criada para produção exige uma versão/tag nova.

Este desenho evita qualquer cópia de aproximadamente 390 MB no armazenamento de Actions. O grupo de concorrência é global ao repositório e a draft é identificada por repository ID, run, tentativa, commit, tag, digest e nonce. Se a validação ou publicação falhar, o cleanup volta a obter a release por ID e só elimina uma draft com ownership exato; uma release publicada nunca é apagada nem agenda cleanup. O gate terminal impede que um job de publicação ignorado produza um workflow verde sem release. O atestado e o SBOM deixam de depender da retenção temporária de Actions e permanecem junto dos binários como assets verificáveis da release.

O GitHub restringe a leitura de draft releases a tokens com push access. Assim, os jobs x64 e ARM64 precisam de `contents: write` apesar de apenas descarregarem assets; `contents: read` recebe HTTP 403 em `GET releases/{id}`. O risco é limitado mantendo a tag no HEAD validado de `main`, usando ações fixadas por SHA, desativando `persist-credentials` e chamando nesses jobs apenas a operação `DownloadCandidate`, que não contém mutações remotas.

O suporte local por thumbprint nos scripts continua disponível para laboratórios, PKI privada ou um runner próprio ligado a token/HSM. O workflow público não usa PFX exportável: certificados Code Signing públicos novos exigem normalmente que a chave seja gerada, armazenada e usada num módulo criptográfico adequado.

## Pré-requisitos externos

Antes de ativar uma release pública:

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

## Environment privado: disponibilidade e garantias

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

## Configuração no GitHub

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

## Sequência segura

1. Execute CI no `main` e confirme **CI gate**, incluindo o job ARM64 nativo.
2. Apenas enquanto o repositório estiver privado, selecione a tag nova correspondente e execute manualmente `Release` com `publish_release=false`; pedidos sobre um branch falham antes do build. O resultado permitido é uma prerelease `Private QA (NotSigned)` com atestado e SBOM permanentes. Num repositório público, este pedido também falha antes do build.
3. Teste UI, CLI, scan, topologia, instalação, atualização e remoção num Windows limpo.
4. Configure e proteja `release-signing`, OIDC e o perfil Artifact Signing.
5. Registe a autorização IEEE.
6. Atualize versão/changelog e confirme novamente que o HEAD local e `origin/main` são o mesmo commit.
7. Para QA sem assinatura, crie uma tag nova `vX.Y.Z` nesse commit enquanto os gates de produção ainda estão incompletos. Num repositório privado, o push cria automaticamente a prerelease `Private QA (NotSigned)` depois de x64 e ARM64 passarem; não reutilize tags nem substitua assets existentes.
8. Para produção, configure primeiro todos os gates externos e só depois crie uma nova versão/tag. A execução automática faz apenas o preflight e reserva essa tag sem carregar um candidato `NotSigned`; execute então `Release` a partir dela com `publish_release=true`. O workflow recusa drafts/releases divergentes, mas uma repetição aceita uma release já publicada quando título, modo, 12 assets, digests e proveniência histórica continuam exatamente válidos.
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
| `LNS-REL-007` | instalação/smoke nativo x64 ou ARM64 falhou | corrija o pacote exato; cross-build não substitui este gate |
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

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
