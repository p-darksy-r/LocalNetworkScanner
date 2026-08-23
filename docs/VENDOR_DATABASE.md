<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Base de entidades MAC incorporada

O Local Network Scanner inclui no próprio Core uma snapshot comprimida das listagens públicas de atribuições MAC da IEEE Registration Authority. A consulta funciona offline desde o primeiro arranque: o utilizador não precisa de descarregar uma base para obter resultados.

O valor apresentado corresponde ao **titular registado do prefixo IEEE**, não a uma promessa sobre o fabricante físico, a marca comercial ou o modelo do dispositivo.

## Cobertura

| Registo | Prefixo | Linhas na snapshot de 2026-08-12 | SHA-256 da fonte | Fonte oficial |
| --- | ---: | ---: | --- | --- |
| MA-L, anteriormente OUI | 24 bits / 6 hexadecimais | 39 923 | `f4c224a540adc45c0c48233335c6241a420f1b85f3754bc379022c343c3d3e9d` | [IEEE MA-L](https://standards-oui.ieee.org/oui/oui.csv) |
| MA-M | 28 bits / 7 hexadecimais | 6 540 | `29ec2874d7664610e3622aa157e6b81da53ed6e54912dd6de5e51c70b6b5a32c` | [IEEE MA-M](https://standards-oui.ieee.org/oui28/mam.csv) |
| MA-S, anteriormente OUI-36 | 36 bits / 9 hexadecimais | 7 128 | `7b2927f8857c62cf0638a0e4501076c4ad56df4c29b7ad1092d7dfa6ed7940b5` | [IEEE MA-S](https://standards-oui.ieee.org/oui36/oui36.csv) |
| IAB histórico | 36 bits / 9 hexadecimais | 4 575 | `6e71aa3d47f00f19d09cb3b31ce1038de1834703420f0ce4ce111da586f1a533` | [IEEE IAB](https://standards-oui.ieee.org/iab/iab.csv) |

As fontes somam **58 166 linhas**. Depois de normalizar atribuições históricas repetidas, o manifesto interno da snapshot indica **58 163 prefixos únicos**. O cabeçalho interno também regista a data, URLs, contagens e SHA-256 das quatro fontes usadas naquela build; o SHA-256 do recurso comprimido incorporado é `5149df53f544226cf917275233734aa8ad9ae362a9cf1ec1aa3e9753a518927f`.

## Resolução por prefixo

O lookup normaliza o MAC e procura sempre a atribuição mais específica:

1. MA-S ou IAB com 36 bits;
2. MA-M com 28 bits;
3. MA-L com 24 bits.

Esta ordem `/36 → /28 → /24` evita que uma atribuição genérica esconda o titular de um bloco mais específico. O registo CID é deliberadamente excluído: segundo a IEEE, um CID não gera endereços MAC EUI universalmente administrados. Um CID não deve ser apresentado como fabricante de um MAC global. Desde o schema v5, a aplicação apresenta este valor como **titular IEEE** e mantém separado o fabricante/modelo obtido por outras evidências.

## Limites honestos

- Um MAC multicast/grupo não representa uma interface individual e não recebe um titular.
- Um MAC localmente administrado ou aleatório não identifica de forma fiável uma organização e é apresentado como local/aleatório.
- Algumas atribuições IEEE ocultam intencionalmente o nome sob `Private`; a aplicação não tenta reidentificar o titular.
- A organização que recebeu o bloco pode não ser a marca comercial visível no dispositivo.
- Equipamentos virtuais, bridges, adaptadores USB e componentes OEM podem revelar o titular da interface, não o fabricante do produto completo.
- Uma snapshot incorporada fica naturalmente menos atual que a listagem online; a atualização opcional existe para obter atribuições publicadas depois da release.

## Atualização opcional na aplicação

O botão **Verificar atualização IEEE** transfere MA-L, MA-M, MA-S e IAB diretamente das URLs oficiais, valida formato, registo, tamanho e número mínimo de entradas e só depois substitui atomicamente a cópia local. Uma falha deixa intacta a base incorporada.

Os ficheiros atualizados ficam em:

```text
%LOCALAPPDATA%\LocalNetworkScanner\vendor-database.tsv.gz
```

Esta ação é opcional e iniciada pelo utilizador. Não existe atualização silenciosa, telemetria ou envio de MACs, IPs, inventário, SSID, topologia ou outros dados da rede. O pedido contém apenas os metadados HTTP normais necessários para obter os ficheiros públicos da IEEE.

## Atualizar a snapshot de desenvolvimento

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\update-bundled-vendors.ps1
```

O script descarrega as quatro listagens oficiais, valida o schema e os prefixos, preserva de forma determinística titulares históricos repetidos, remove endereços postais, normaliza apenas `registo + prefixo + organização`, comprime o resultado e grava hashes das fontes no cabeçalho interno. A atribuição e os termos aplicáveis são documentados em [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Direitos e redistribuição

**IEEE. All rights reserved.** A snapshot e os dados derivados da IEEE não são colocados sob a licença MIT do Local Network Scanner. A inclusão não implica certificação, patrocínio ou endorsement da IEEE.

Antes de redistribuir publicamente uma release que contenha estes dados, é necessário obter autorização escrita da [IEEE Registration Authority](https://standards.ieee.org/products-programs/regauth/contact/) ou através do [formulário de permissão IEEE SA](https://standards.ieee.org/ipr/copyright-permissions-form/), e cumprir o texto e as condições que forem fornecidos. Consulte [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) antes de publicar.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
