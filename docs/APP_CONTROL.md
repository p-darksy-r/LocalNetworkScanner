<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Windows App Control e erro 4551

O erro de instalação **“CreateProcess falhou; código 4551 — Uma política de Controlo de Aplicações bloqueou este ficheiro”** significa:

- decimal: `4551`;
- hexadecimal Win32: `0x11C7`;
- HRESULT frequente: `0x800711C7`;
- símbolo: `ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION`.

O Windows conseguiu instalar ou extrair o ficheiro, mas uma política de integridade de código recusou a sua execução. A origem pode ser Smart App Control, App Control for Business/WDAC ou uma política gerida pela organização. Não é seguro concluir que o instalador está corrompido apenas a partir deste código.

## Comportamento do instalador

O instalador já não tenta iniciar automaticamente a aplicação na página final. Assim, o bloqueio do primeiro arranque deixa de transformar uma cópia de ficheiros concluída num aparente “erro de instalação”. Depois de o instalador terminar, abra **Local Network Scanner** pelo menu Iniciar.

Esta alteração não contorna a política: se o executável não for permitido, o Windows continuará corretamente a bloqueá-lo quando o utilizador o iniciar.

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

Ao trabalhar a partir do repositório, use `.\scripts\diagnose-app-control.ps1`. Reveja o JSON antes de o partilhar: eventos de Code Integrity podem conter caminhos locais e identificadores da política da organização.

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

Os artefactos oficiais históricos já publicados sem certificado, incluindo a release `v1.2.0`, são explicitamente **`NotSigned`**. As novas GitHub Releases são bloqueadas se os binários não estiverem `Signed`; artefactos privados de QA podem continuar `NotSigned`. Confirme sempre `SIGNING-STATE.txt` e valide localmente com `Get-AuthenticodeSignature`. Um checksum confirma que o ficheiro é igual ao publicado, mas não substitui Authenticode nem prova a identidade do publisher.

O pipeline suporta assinatura opcional com um certificado RSA de Code Signing emitido por uma CA confiável:

- assina `LocalNetworkScanner.exe` e `LocalNetworkScanner.Cli.exe` antes de criar os ZIPs;
- manda o Inno Setup assinar o instalador e o desinstalador embebido;
- usa SHA-256 e timestamp RFC 3161;
- valida cadeia, revogação, EKU, signer e timestamp;
- falha explicitamente se a assinatura for pedida mas a configuração estiver ausente ou inválida;
- mantém o estado `NotSigned` nos artefactos privados de QA quando a assinatura não é pedida, sem os publicar nem simular sucesso.

Configuração no GitHub:

- variável de repositório `AUTHENTICODE_ENABLED=true` para assinar releases por tag;
- secret `AUTHENTICODE_PFX_BASE64` com o PFX codificado em Base64;
- secret `AUTHENTICODE_PFX_PASSWORD` com a palavra-passe do PFX;
- input manual `sign_release=true` para uma execução `workflow_dispatch`.

O certificado é importado apenas no store do utilizador do runner efémero e removido num passo `always()`. A palavra-passe não é passada na linha de comandos do SignTool.

Uma assinatura válida melhora identidade, integridade e regras por publisher, mas não garante autorização: a política ativa pode exigir um publisher específico, reputação, managed installer, catálogo ou hash aprovado.

## Referências oficiais

- [Microsoft — eventos 3076 e 3077 de App Control](https://learn.microsoft.com/windows-server/security/osconfig/osconfig-how-to-configure-app-control-for-business#monitor-event-logs)
- [Microsoft — referência técnica do CiTool](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands)
- [Microsoft — assinatura de código com App Control](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/deployment/use-code-signing-for-better-control-and-protection)
- [Microsoft — SignTool](https://learn.microsoft.com/windows/win32/seccrypto/signtool)
- [Inno Setup — SignTool](https://jrsoftware.org/ishelp/topic_setup_signtool.htm)
- [Inno Setup — SignedUninstaller](https://jrsoftware.org/ishelp/topic_setup_signeduninstaller.htm)

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
