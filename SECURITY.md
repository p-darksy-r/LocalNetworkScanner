<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Política de segurança

## Versões suportadas

A linha de código suportada é `1.4.x`; apenas a revisão mais recente dessa linha recebe correções de segurança. As linhas `1.2.x` e `1.3.x` são históricas e não devem ser usadas como builds de produção. Builds locais, forks e tags não são, por si só, releases instaláveis oficiais. A prerelease pública `v1.4.0` conserva o título histórico `Private QA (NotSigned)`, mas continua a ser apenas evidência de validação sem Authenticode, não uma distribuição de produção. Atualmente não existe uma release assinada e suportada para produção.

## Comunicar uma vulnerabilidade

Utilize um [GitHub Security Advisory privado](https://github.com/p-darksy-r/LocalNetworkScanner/security/advisories/new). Se essa opção ainda não estiver disponível para a sua conta, não publique os detalhes numa issue: contacte o maintainer através do [perfil GitHub](https://github.com/p-darksy-r) e peça primeiro um canal privado. Se recebeu a aplicação por outro canal, contacte em privado o responsável por esse canal e peça um meio seguro para entregar o relatório.

Não publique imediatamente uma vulnerabilidade explorável e não anexe inventários de rede reais a uma issue pública. Um bom relatório inclui:

- versão e SHA-256 do executável;
- versão do Windows e arquitetura;
- componente afetado;
- passos mínimos para reproduzir numa rede de laboratório;
- impacto observado e impacto esperado;
- código de diagnóstico `LNS-*`, quando apresentado;
- logs já revistos e sem IPs, MACs, SSIDs, credenciais ou tokens reais.

O objetivo inicial é confirmar a receção, reproduzir o problema, avaliar gravidade e combinar uma divulgação coordenada. Não se promete um prazo fixo antes de existir um canal de manutenção formal.

## Modelo de segurança

O Local Network Scanner é uma ferramenta de inventário e diagnóstico ativo. Não deve:

- explorar serviços ou tentar autenticação;
- capturar conteúdo de tráfego;
- transmitir o inventário para terceiros sem consentimento explícito;
- pedir elevação administrativa para operações que funcionam com privilégios normais;
- apresentar inferências de VLAN, sistema operativo ou topologia como factos confirmados.

O scan deve permanecer limitado a redes privadas autorizadas. Mesmo numa rede local, pedidos ICMP, multicast e ligações TCP podem ser registados ou bloqueados.

## Proteção dos dados

O histórico local fica, por predefinição, em `%LOCALAPPDATA%\LocalNetworkScanner\snapshots`. Exportações JSON, CSV, HTML e GraphML são gravadas no caminho escolhido pelo utilizador. Estes ficheiros podem conter um mapa sensível da rede e não são cifrados pela aplicação. Códigos de diagnóstico são adequados para pesquisa; o contexto, alvo e relatório completo continuam a precisar de anonimização.

A [política de privacidade](PRIVACY.md) documenta todas as comunicações iniciadas pelo utilizador, ficheiros locais, retenção e eliminação. A desinstalação preserva os dados sob `%LOCALAPPDATA%\LocalNetworkScanner`; para os remover, o utilizador deve fechar a aplicação, rever o conteúdo e apagar manualmente essa pasta.

Não inclua certificados de assinatura, chaves privadas, passwords ou dumps de rede no repositório. A `.gitignore` exclui formatos comuns de chaves, mas essa exclusão não substitui um gestor de segredos.

## Distribuição segura

Uma release pública deve:

- ser produzida pelo script documentado a partir de uma revisão identificável;
- ter versão, ícone e identidade de publisher consistentes;
- publicar o estado Authenticode e, quando existir assinatura, validar identidade, algoritmo e timestamp;
- publicar um ficheiro SHA-256 separado;
- gerar e validar um SBOM sem o apresentar como substituto de assinatura ou análise de vulnerabilidades;
- ser testada numa instalação Windows limpa;
- documentar claramente se é portátil ou instalada.

O workflow recusa uma nova publicação pública de produção enquanto os binários não tiverem assinatura Authenticode confiável e timestamp válido. As prereleases de QA já publicadas identificam explicitamente o estado `NotSigned` e não devem ser redistribuídas como builds de produção. Para uma distribuição com identidade de publisher verificável e reputação de produção é necessária uma assinatura Authenticode Public Trust válida e com timestamp.

A avaliação de elegibilidade para a SignPath Foundation está pendente. Nenhuma release atual foi assinada ou aprovada pela SignPath, e o workflow ainda não possui essa integração. A [Code signing policy](CODE_SIGNING_POLICY.md) define o estado atual, as funções da equipa e os gates pendentes. Entre esses gates estão a clarificação das funcionalidades de enumeração/risco face à condição **No hacking tools** e a licença/autorização aplicável à snapshot IEEE incorporada. A acessibilidade pública do repositório ou dos assets não resolve nenhum desses pontos.

## Proteções do repositório público

O GitHub está configurado para:

- impedir eliminação, force-push e histórico não linear em `main`;
- impedir eliminação ou movimentação não fast-forward de tags `v*`;
- exigir referências de GitHub Actions fixadas por SHA completo;
- executar CodeQL `security-extended` em alterações C#/XAML e semanalmente;
- usar secret scanning, push protection e relatórios privados de vulnerabilidade.

O projeto mantém apenas o branch `main`; por isso atualizações de Actions fixadas por SHA são revistas manualmente em vez de abrir branches automáticos do Dependabot. Uma alteração a workflows, scripts de release, políticas de assinatura ou futuros ficheiros `.signpath` deve receber atenção equivalente a código executável.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
