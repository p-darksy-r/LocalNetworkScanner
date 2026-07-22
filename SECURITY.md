<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Política de segurança

## Versões suportadas

Enquanto existir apenas a linha `1.2.x`, apenas a versão mais recente dessa linha recebe correções de segurança. Builds locais, forks e artefactos que não tenham sido publicados em [GitHub Releases](https://github.com/p-darksy-r/LocalNetworkScanner/releases) não são considerados releases oficiais.

## Comunicar uma vulnerabilidade

Utilize um [GitHub Security Advisory privado](https://github.com/p-darksy-r/LocalNetworkScanner/security/advisories/new). Se recebeu a aplicação por outro canal, contacte em privado o responsável por esse canal e peça um meio seguro para entregar o relatório.

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

Não inclua certificados de assinatura, chaves privadas, passwords ou dumps de rede no repositório. A `.gitignore` exclui formatos comuns de chaves, mas essa exclusão não substitui um gestor de segredos.

## Distribuição segura

Uma release pública deve:

- ser produzida pelo script documentado a partir de uma revisão identificável;
- ter versão, ícone e identidade de publisher consistentes;
- publicar o estado Authenticode e, quando existir assinatura, validar identidade, algoritmo e timestamp;
- publicar um ficheiro SHA-256 separado;
- ser testada numa instalação Windows limpa;
- documentar claramente se é portátil ou instalada.

Enquanto o projeto não dispuser de assinatura de código, uma release pública deve identificar os binários como não assinados, publicar checksums verificáveis e avisar sobre possíveis alertas do SmartScreen. Para uma distribuição com identidade de publisher verificável e reputação de produção é necessária uma assinatura Authenticode válida e com timestamp.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
