<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Code signing policy

## Estado atual

O projeto está a pedir uma avaliação de elegibilidade para o programa gratuito de assinatura de código open source da SignPath Foundation. A candidatura, configuração técnica e aprovação ainda não estão concluídas.

Nenhum binário publicado atualmente foi assinado pela SignPath Foundation. A `v1.2.0` é uma release histórica sem assinatura e não é recomendada para produção. As versões `v1.3.x` e a `v1.4.0` publicadas como `Private QA (NotSigned)` conservam esse rótulo histórico e continuam a ser candidatos de QA sem Authenticode, apesar de o repositório ser agora público. Não devem ser apresentadas como releases estáveis, assinadas ou aprovadas pela SignPath.

Se o projeto for aceite e a integração for concluída, será usada a atribuição exigida pelo programa:

> Free code signing provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

Esta frase descreve apenas o processo futuro condicionado à aceitação. O estado real de cada release é o que consta da respetiva página, de `SIGNING-STATE.txt` e das assinaturas Authenticode verificadas nos ficheiros.

## Âmbito proposto

Uma release oficial assinada deverá abranger os executáveis Windows produzidos pelo projeto e distribuídos ao utilizador, incluindo a UI, a CLI, o diagnóstico PowerShell, os instaladores e os componentes de desinstalação que o formato permitir assinar. A configuração final de artefactos aprovada pela SignPath determinará o âmbito exato.

Os ZIPs, checksums, SBOM e atestados não são apresentados como executáveis Authenticode. Os hashes devem ser gerados apenas depois da assinatura final dos ficheiros abrangidos.

Uma release só poderá declarar `Signed` quando:

- todos os ficheiros abrangidos tiverem assinatura Authenticode válida, timestamp e uma identidade comum esperada;
- os pacotes exatos tiverem passado a validação nativa x64 e ARM64 aplicável;
- o SBOM, os checksums e a proveniência corresponderem aos assets publicados;
- os gates jurídicos e de política descritos abaixo estiverem resolvidos;
- a página de download indicar claramente o estado de assinatura.

Como as tags e os assets existentes são imutáveis, a primeira eventual release assinada terá de usar uma versão e tag novas; a `v1.4.0` não será convertida retroativamente numa release assinada.

## Origem e aprovação

A integração proposta usará GitHub Actions em runners alojados pelo GitHub, um artefacto unsigned produzido pelo workflow e origin verification da SignPath. Cada pedido de assinatura de produção deverá exigir aprovação manual na SignPath. Estes mecanismos ainda não estão configurados no workflow atual e não devem ser descritos como ativos.

A chave privada e o certificado não serão guardados no repositório nem entregues ao runner. Tokens de integração devem ficar limitados ao ambiente e à política de assinatura necessários.

## Funções da equipa

| Função | Membro | Responsabilidade |
| --- | --- | --- |
| Autor e committer | [p-darksy-r](https://github.com/p-darksy-r) | manter o código e as definições de build que pode alterar sem revisão adicional |
| Reviewer | [p-darksy-r](https://github.com/p-darksy-r) | rever contribuições de pessoas que não sejam committers antes da integração |
| Approver | [p-darksy-r](https://github.com/p-darksy-r) | confirmar proveniência, testes, conteúdo e política antes de aprovar um pedido de assinatura |

Todas as pessoas que venham a ocupar estas funções têm de usar autenticação multifator no GitHub e na SignPath. Alterações futuras à equipa devem atualizar esta tabela e as permissões reais antes de poderem participar numa assinatura.

## Gates ainda pendentes

Não será pedida nem publicada uma assinatura da SignPath enquanto não estiverem resolvidos, por escrito, pelo menos estes pontos:

- a elegibilidade das funcionalidades de enumeração de portas, integração Nmap e avisos heurísticos de risco à luz da condição **No hacking tools** da SignPath Foundation;
- a licença e autorização aplicáveis à snapshot normalizada das listagens IEEE incorporada no produto e a compatibilidade dessa componente com as condições open source da SignPath;
- a configuração do projeto, artifact configuration, trusted build system, origin verification, aprovadores e restrições de metadados na SignPath;
- as proteções adequadas de `main`, tags de release, workflows e segredos do repositório.

Uma aceitação do projeto não substitui a autorização da IEEE. Uma autorização da IEEE também não prova, por si só, que a snapshot satisfaz a condição de licença OSI da SignPath. Se a solução aprovada exigir excluir dados ou funcionalidades do artefacto assinado, essa diferença será documentada de forma visível e verificável.

## Verificação pelo utilizador

Para uma futura release que declare `Signed`, confirme cada executável com:

```powershell
Get-AuthenticodeSignature -LiteralPath .\LocalNetworkScanner.exe |
    Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

O estado deve ser `Valid`, o signer deve corresponder ao publisher documentado na release e deve existir timestamp válido. Confirme também o SHA-256 publicado. Um checksum não substitui Authenticode, e uma assinatura válida não obriga uma política empresarial a autorizar a aplicação.

Até existir uma release que satisfaça estes critérios, mantenha as proteções Windows ativas e trate todos os downloads atuais como `NotSigned`.

## Privacidade

Consulte a [política de privacidade](PRIVACY.md). Em resumo:

> This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

## Referências

- [Condições da SignPath Foundation para projetos open source](https://signpath.org/terms.html)
- [Integração GitHub como trusted build system](https://docs.signpath.io/trusted-build-systems/github)
- [Política de segurança](SECURITY.md)
- [Estado técnico de assinatura](docs/SIGNING.md)
- [Avisos de terceiros e IEEE](THIRD_PARTY_NOTICES.md)

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
