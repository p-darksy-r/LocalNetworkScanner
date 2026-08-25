<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Windows App Control e erro 4551

O erro de instalação **“CreateProcess falhou; código 4551 — Uma política de Controlo de Aplicações bloqueou este ficheiro”** significa:

- decimal: `4551`;
- hexadecimal Win32: `0x11C7`;
- HRESULT frequente: `0x800711C7`;
- símbolo: `ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION`.

O Windows conseguiu instalar ou extrair o ficheiro, mas uma política de integridade de código recusou a sua execução. A origem pode ser Smart App Control, App Control for Business/WDAC ou uma política gerida pela organização. Não é seguro concluir que o instalador está corrompido apenas a partir deste código.

`CreateProcess` falha antes de o código do Local Network Scanner começar a executar. Por isso, a aplicação não consegue mostrar uma janela, alterar a decisão ou “corrigir-se” depois do bloqueio. A correção de distribuição tem de existir antecipadamente: assinatura Authenticode confiável, timestamp válido e, quando aplicável, autorização do publisher pela política da organização.

## Comportamento do instalador

O instalador já não tenta iniciar automaticamente a aplicação na página final. Assim, o bloqueio do primeiro arranque deixa de transformar uma cópia de ficheiros concluída num aparente “erro de instalação”. Depois de o instalador terminar, abra **Local Network Scanner** pelo menu Iniciar.

Esta alteração não contorna a política: se o executável não for permitido, o Windows continuará corretamente a bloqueá-lo quando o utilizador o iniciar.

O mesmo se aplica a `app\LocalNetworkScanner.exe` num checkout do código. A pasta `app` apenas evita procurar a build local entre diretórios de compilação; copiar ou reconstruir os mesmos bytes não cria confiança Authenticode, não remove a marca de origem e não altera Smart App Control/WDAC. O lançador apresenta `LNS-REL-007` quando consegue observar o erro `4551` e nunca desativa a política.

## Diagnóstico seguro

Não desative Smart App Control, App Control for Business, AppLocker, Microsoft Defender ou outra política de segurança para executar a aplicação. Num computador gerido, envie as evidências ao administrador de TI.

1. Confirme que descarregou a arquitetura correta e compare o SHA-256 com `SHA256SUMS.txt`.
2. Confirme o estado Authenticode:

```powershell
$exe = "$env:LOCALAPPDATA\Programs\LocalNetworkScanner\LocalNetworkScanner.exe"
Get-AuthenticodeSignature -LiteralPath $exe |
  Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

3. Crie um relatório de diagnóstico apenas de leitura:

```powershell
$tool = "$env:LOCALAPPDATA\Programs\LocalNetworkScanner\tools\diagnose-app-control.ps1"
& $tool -FilePath $exe -Minutes 60 -OutputPath "$env:USERPROFILE\Desktop\LNS-AppControl.json"
```

Ao trabalhar a partir do repositório, use `.\scripts\diagnose-app-control.ps1`. O schema v2 classifica separadamente ficheiro ausente, alvo sem assinatura, assinatura inválida/não confiável, publisher válido mas bloqueado e ausência de evento correlacionado. Apenas uma coincidência pelo caminho completo confirma o alvo automaticamente. Quando o Windows regista `\Device\...`, o `SHA256 Flat Hash` exato em conjunto com o mesmo caminho relativo à raiz produz evidência média/provável, mas não confirma o volume: duas cópias podem estar sujeitas a regras por caminho diferentes. Uma coincidência apenas pelo hash identifica conteúdo byte a byte igual e também permanece inconclusiva; uma coincidência só pelo nome tem confiança baixa. Reveja o JSON antes de o partilhar: eventos de Code Integrity podem conter caminhos locais, hashes e identificadores da política da organização.

4. Em Windows 11 22H2 ou mais recente, liste as políticas ativas sem as alterar:

```powershell
CiTool.exe -lp -json
```

5. Consulte **Visualizador de Eventos > Registos de Aplicações e Serviços > Microsoft > Windows > CodeIntegrity > Operational**. Os eventos mais relevantes são:

   - `3077`: um ficheiro foi bloqueado por uma política em modo de imposição;
   - `3076`: o ficheiro teria sido bloqueado por uma política em modo de auditoria;
   - `3089`: informação de assinatura correlacionada;
   - `3099`: ativação de política;
   - `3114`: bloqueio relacionado com segurança de código dinâmico .NET.

Também pode consultar diretamente os bloqueios recentes:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
  Id = 3076, 3077
  StartTime = (Get-Date).AddHours(-1)
} | Format-List TimeCreated, Id, Message
```

Se o PC for gerido, o administrador deve decidir se autoriza o publisher, o hash ou um catálogo, conforme a política da organização. Remover a marca de origem da Internet com `Unblock-File` não substitui essa decisão e não ignora uma política App Control.

## Assinatura das releases

Os artefactos oficiais históricos já publicados sem certificado, incluindo a release `v1.2.0`, são explicitamente **`NotSigned`**. As prereleases `v1.3.x`/`v1.4.0` com o título histórico `Private QA (NotSigned)` também continuam sem assinatura; como o repositório é agora público, os respetivos assets são publicamente acessíveis, mas não se tornam por isso builds de produção. O workflow bloqueia qualquer publicação de produção que não esteja `Signed`. Confirme sempre `SIGNING-STATE.txt` e valide localmente com `Get-AuthenticodeSignature`. Um checksum confirma que o ficheiro é igual ao publicado, mas não substitui Authenticode nem prova a identidade do publisher.

A `v1.2.0` não deve ser tratada como uma distribuição de produção compatível com Smart App Control. Criar um certificado autoassinado durante o build também não resolve a distribuição geral: o computador do utilizador não possui uma cadeia pública que confirme a identidade desse publisher.

O caminho de produção versionado no workflow foi implementado para Microsoft Artifact Signing por OIDC, mas esse serviço não está configurado neste repositório e não assinou nenhuma release atual. Se fosse ativado com uma identidade elegível, a chave RSA permaneceria no serviço/HSM e o runner receberia apenas um token temporário. Esse caminho foi desenhado para:

- assina `LocalNetworkScanner.exe`, `LocalNetworkScanner.Cli.exe` e `diagnose-app-control.ps1` antes de criar os ZIPs;
- manda o Inno Setup assinar o instalador e o desinstalador embebido;
- usa SHA-256 e timestamp RFC 3161;
- valida signer, timestamp, hashes e a mesma identidade em todos os ficheiros;
- instala, executa e remove os ZIPs/instaladores exatos em Windows x64 e ARM64 nativos;
- falha explicitamente se a assinatura for pedida mas a configuração estiver ausente ou inválida;
- manter o estado `NotSigned` no modo de QA sem assinatura; esse modo só pode publicar uma prerelease quando a API confirma que o repositório é privado, nunca como release pública de produção nem como `Latest`.

Configuração que o backend Microsoft exigiria no GitHub:

- Environment protegido `release-signing`, com reviewers e restrições de deployment;
- credencial federada OIDC limitada a esse environment e função mínima no perfil de assinatura;
- variáveis `ARTIFACT_SIGNING_ENDPOINT`, `ARTIFACT_SIGNING_ACCOUNT`, `ARTIFACT_SIGNING_PROFILE` e IDs Azure;
- variável `ARTIFACT_SIGNING_ENABLED=true` apenas depois da identidade estar pronta.

O workflow não lê PFX, palavra-passe ou chave privada. Os antigos secrets `AUTHENTICODE_PFX_*`, caso existam, devem ser removidos depois de confirmar que nenhuma outra automação depende deles.

A avaliação de elegibilidade para a SignPath Foundation está pendente. O projeto ainda não foi aceite e o workflow ainda não envia artefactos à SignPath. Uma eventual integração exigirá GitHub Actions artifacts, origin verification e aprovação manual, e substituirá ou generalizará o backend atual; não se deve configurar credenciais ou alegar assinatura antes de o serviço fornecer e aprovar a configuração. Consulte a [Code signing policy](../CODE_SIGNING_POLICY.md).

O preflight usa códigos `LNS-REL-*` e termina antes do build quando a tag não corresponde ao HEAD de `main`, falta Artifact Signing/OIDC ou não existe autorização IEEE. Consulte [Assinatura e prontidão de release](SIGNING.md) para a configuração completa.

Numa futura release pública assinada, o script de diagnóstico também deverá ter Authenticode. Numa build `NotSigned`, o PowerShell pode bloquear o script ou executá-lo em Constrained Language; nesse caso, use o Event Viewer/CiTool com o administrador. Um diagnóstico que não arrancou não prova que a aplicação esteja corrompida.

Uma assinatura válida melhora identidade, integridade e regras por publisher, mas não garante autorização: a política ativa pode exigir um publisher específico, reputação, managed installer, catálogo ou hash aprovado.

## Referências oficiais

- [Microsoft — eventos 3076 e 3077 de App Control](https://learn.microsoft.com/windows-server/security/osconfig/osconfig-how-to-configure-app-control-for-business#monitor-event-logs)
- [Microsoft — visão geral do Smart App Control](https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview)
- [Microsoft — testar assinaturas com Smart App Control](https://learn.microsoft.com/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control)
- [Microsoft — referência técnica do CiTool](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands)
- [Microsoft — assinatura de código com App Control](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/deployment/use-code-signing-for-better-control-and-protection)
- [Microsoft — comportamento do PowerShell sob App Control](https://learn.microsoft.com/powershell/scripting/security/app-control/how-app-control-works)
- [Microsoft — integrações do Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/how-to-signing-integrations)
- [SignPath Foundation — condições para projetos open source](https://signpath.org/terms.html)
- [SignPath — integração com GitHub](https://docs.signpath.io/trusted-build-systems/github)
- [Microsoft — SignTool](https://learn.microsoft.com/windows/win32/seccrypto/signtool)
- [Inno Setup — SignTool](https://jrsoftware.org/ishelp/topic_setup_signtool.htm)
- [Inno Setup — SignedUninstaller](https://jrsoftware.org/ishelp/topic_setup_signeduninstaller.htm)

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
