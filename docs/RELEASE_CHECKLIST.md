<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Checklist de release Windows

Uma release só deve ser marcada como concluída quando todos os itens obrigatórios estiverem verificados. Guardar evidência dos comandos, versões, hashes e máquinas usadas.

## 1. Identidade e âmbito

- [ ] A versão em `Directory.Build.props` coincide com o changelog, nome do ZIP e tag.
- [ ] `Product`, `Company`, copyright e publisher representam a entidade que vai distribuir a aplicação.
- [ ] `scripts/check-copyright.ps1` confirma cabeçalho e rodapé em todos os ficheiros comentáveis.
- [ ] O nome “Local Network Scanner” e o ícone são consistentes na UI, propriedades do EXE e instalador.
- [ ] A licença MIT continua a ser a licença pretendida para o código e distribuição.
- [ ] O `CHANGELOG.md` descreve apenas funcionalidades presentes nessa revisão.
- [ ] Não existem links placeholder, contactos inexistentes ou alegações de capacidades futuras.

## 2. Código e build reproduzível

- [ ] `dotnet --version` resolve para `10.0.301` ou para um patch permitido por `global.json`.
- [ ] A árvore de trabalho está limpa e a revisão/tag a publicar foi registada.
- [ ] `scripts/check.ps1` termina com exit code `0` sem `-SkipWpf`.
- [ ] O build `Release` tem zero warnings e zero errors.
- [ ] A formatação foi validada com `dotnet format --verify-no-changes --no-restore`.
- [ ] Dependências novas foram revistas quanto a licença, manutenção e vulnerabilidades.
- [ ] Não existem certificados, chaves, dumps, relatórios reais ou credenciais no repositório.

Comando base:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1
```

## 3. Testes

- [ ] Existe pelo menos um projeto de testes; o pipeline falha quando a contagem total é zero.
- [ ] Testes unitários cobrem intervalos CIDR, parsing de portas, MAC/OUI, VLAN e classificação.
- [ ] Testes de integração usam listeners de loopback e dados simulados, sem depender da rede do runner.
- [ ] Testes reais de rede são opt-in, limitados a um laboratório privado e nunca executados por defeito em CI.
- [ ] Cancelamento durante descoberta e scan de portas não bloqueia nem deixa tarefas pendentes.
- [ ] Exportação JSON/CSV e migração/leitura do histórico foram testadas com dados hostis e Unicode.
- [ ] A UI foi verificada com teclado, leitor de ecrã, escala 100/150/200%, tema claro/escuro e janela pequena.
- [ ] Português é apresentado corretamente; ausência de dados usa “indisponível/desconhecido” sem inventar valores.
- [ ] Perfis Rápido, Normal e Avançado aplicam limites distintos e mostram descrições coerentes na UI.
- [ ] A lista de dispositivos permanece a vista principal e **Abrir topologia** só fica disponível quando existe mapa.
- [ ] A janela de topologia abre/fecha sem repetir o scan e mantém zoom, pan, seleção e exportações.
- [ ] Códigos `LNS-USR-*`, `LNS-NET-*`, `LNS-DEV-*` e `LNS-APP-*` têm categoria, severidade, ação recomendada e contexto sanitizado.

## 4. Limites, privacidade e utilização segura

- [ ] A UI liga para `docs/TECHNICAL_LIMITS.md` ou apresenta um resumo equivalente.
- [ ] VLAN é descrita como informação da interface local ou inferência, nunca como scan por dispositivo.
- [ ] “Mesmo segmento L2” mostra a confiança; uma observação SNMP/FDB nunca é apresentada como prova de ligação ao mesmo switch físico.
- [ ] SNMP permanece opt-in; timeouts, switch sem resposta e tabela incompleta degradam para “desconhecido”, não para uma conclusão falsa.
- [ ] FDB-ID só é convertido em VLAN com mapeamento VLAN→FDB único; PVID é apenas referência, não a VLAN inferida do dispositivo.
- [ ] MACs repetidos preservam múltiplas observações e não são reduzidos arbitrariamente a uma porta.
- [ ] Dados de acesso SNMP não aparecem em logs, exports, screenshots, argumentos partilhados nem artefactos.
- [ ] O sinal Wi-Fi é identificado como sinal da ligação local, não RSSI de equipamentos remotos.
- [ ] Protocolos são identificados por descoberta/portas/respostas leves; não é alegada captura de pacotes.
- [ ] Relatórios e histórico são tratados como inventário sensível.
- [ ] O utilizador é lembrado de analisar apenas redes autorizadas.
- [ ] O fluxo normal foi testado sem privilégios de administrador.

## 5. Publish portátil

- [ ] Publish x64 concluído:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish-windows.ps1 -RuntimeIdentifier win-x64
```

- [ ] Publish ARM64 concluído ou a arquitetura foi explicitamente retirada da matriz de suporte:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish-windows.ps1 -RuntimeIdentifier win-arm64
```

- [ ] Cada pasta de publish contém os executáveis esperados e não contém PDBs, segredos ou ficheiros temporários.
- [ ] O smoke test `LocalNetworkScanner.Cli.exe --help` termina com exit code `0` numa máquina da arquitetura publicada; cross-publish ARM64 num host x64 não conta como smoke ARM64.
- [ ] A UI arranca, inicia e cancela um scan de laboratório e fecha sem processo residual.
- [ ] O ZIP inclui UI, CLI, README, licença, changelog e limites técnicos.
- [ ] Exports JSON schema v3 e GraphML abrem sem perda do tipo, origem, confiança e evidência das ligações ou dos diagnósticos documentados.
- [ ] As opções CLI `--html` e `--graphml` foram verificadas com dados sintéticos ou de laboratório.
- [ ] O SHA-256 publicado corresponde exatamente ao ZIP.

Verificação manual do checksum:

```powershell
$zip = '.\artifacts\release\LocalNetworkScanner-1.2.0-win-x64.zip'
$expected = (Get-Content "$zip.sha256").Split(' ')[0]
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SHA-256 invalido.' }
```

## 6. Assinatura e reputação

- [ ] Foi escolhido e documentado um dos dois estados: release não assinada ou release Authenticode assinada.
- [ ] Numa release não assinada, página da release, README e instruções de instalação indicam claramente `NotSigned` e o possível aviso do SmartScreen.
- [ ] Checksums não são apresentados como substitutos de Authenticode nem como prova da identidade do publisher.
- [ ] O artefacto foi testado com SmartScreen/Defender numa máquina sem histórico do produto.

Se a release for assinada:

- [ ] O certificado está válido, tem chave privada e identidade correta.
- [ ] A chave é obtida de um secret store ou serviço de assinatura; não é copiada para o repositório.
- [ ] UI, CLI e instaladores são assinados antes de calcular checksums e criar a release.
- [ ] A assinatura usa SHA-256 e timestamp de uma autoridade confiável.
- [ ] `Get-AuthenticodeSignature` devolve `Valid` para todos os executáveis finais.

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
- [ ] A desinstalação preserva os dados locais e essa decisão está documentada.
- [ ] Instalador e respetivo `.sha256` correspondem à arquitetura e versão da tag.
- [ ] O estado Authenticode é apresentado honestamente na release.

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
- [ ] Switch SNMP indisponível, credenciais rejeitadas e tabelas FDB incompletas produzem avisos sem interromper o scan base.
- [ ] Modo offline/sem interface ativa mostra uma mensagem acionável.
- [ ] Entrada inválida, interface ausente, MAC inválido, fabricante/tipo desconhecido e falha inesperada apresentam o código correto sem expor dados sensíveis.
- [ ] Nomes, SSIDs e hostnames com Unicode não quebram a UI nem CSV/JSON.

## 9. Publicação e pós-release

- [ ] ZIP, checksum, changelog e instruções de instalação estão anexados à release correta.
- [ ] Os hashes e assinaturas foram novamente verificados depois do upload.
- [ ] A release explica arquitetura, versão mínima de Windows suportada e known issues.
- [ ] Existe um canal privado para vulnerabilidades e um canal normal para suporte.
- [ ] Foi guardada uma cópia imutável dos artefactos e logs de build.
- [ ] Foi preparado um plano de rollback ou retirada da release.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
