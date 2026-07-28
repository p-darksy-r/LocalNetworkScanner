<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Instalação no Windows

As releases disponibilizam dois formatos para cada arquitetura suportada. A partir do candidato 1.3.0, ambos incluem o runtime .NET e a snapshot offline MA-L/MA-M/MA-S/IAB da versão, sem exigir a instalação separada do SDK, do runtime ou de uma base de fabricantes.

O primeiro arranque e a identificação de titulares de prefixos IEEE não exigem Internet. A aplicação só contacta as listagens públicas da IEEE quando o utilizador escolhe explicitamente a atualização opcional. Os pacotes incluem `THIRD_PARTY_NOTICES.md`; confirme os termos e a autorização aplicáveis antes de redistribuir publicamente uma build que contenha a snapshot.

## Escolher a arquitetura

- `win-x64`: Windows 10/11 em computadores Intel ou AMD de 64 bits;
- `win-arm64`: Windows 11 em computadores ARM64.

Confirme em **Definições > Sistema > Acerca de > Tipo de sistema** quando tiver dúvidas.

## Instalador por utilizador

O ficheiro `LocalNetworkScanner-<versão>-<arquitetura>-setup.exe` instala a UI e a CLI em `%LOCALAPPDATA%\Programs\LocalNetworkScanner`, cria uma entrada no menu Iniciar e oferece um atalho opcional no ambiente de trabalho.

O instalador:

- não pede privilégios administrativos no fluxo normal;
- não instala drivers, serviços nem extensões de rede;
- não altera o `PATH` do sistema;
- inclui um desinstalador normal do Windows;
- termina sem iniciar automaticamente a aplicação; abra-a depois pelo menu Iniciar;
- preserva snapshots e preferências em `%LOCALAPPDATA%\LocalNetworkScanner` quando é removido.

Para apagar também os dados locais depois da desinstalação, elimine manualmente `%LOCALAPPDATA%\LocalNetworkScanner`. Reveja primeiro os snapshots: podem constituir um inventário sensível da rede.

## Versão portátil

Extraia `LocalNetworkScanner-<versão>-<arquitetura>.zip` para uma pasta em que tenha permissões de escrita e execute `LocalNetworkScanner.exe`. Não execute diretamente de dentro do ZIP.

O pacote contém também `LocalNetworkScanner.Cli.exe` para automação. O histórico continua a ser guardado em `%LOCALAPPDATA%\LocalNetworkScanner`; “portátil” descreve apenas a distribuição sem instalador.

## Verificar a integridade

Compare o SHA-256 do ficheiro descarregado com `SHA256SUMS.txt` ou com o ficheiro `.sha256` adjacente na release:

```powershell
$file = '.\LocalNetworkScanner-1.3.0-win-x64.zip'
(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
```

Uma diferença significa que o ficheiro não deve ser executado.

## Erro 4551: política bloqueou o ficheiro

`CreateProcess falhou; código 4551` corresponde a `ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION` (`0x11C7`). O instalador pode ter copiado os ficheiros corretamente e o Windows ter bloqueado apenas a tentativa de executar a aplicação.

As versões novas do instalador não iniciam a aplicação automaticamente. Isto permite distinguir uma instalação concluída de um primeiro arranque bloqueado, sem desativar nem contornar a política.

Não desligue Smart App Control, App Control for Business/WDAC, AppLocker ou Microsoft Defender. Confirme o checksum e a assinatura, recolha os eventos `3077` (imposição) ou `3076` (auditoria) em **Microsoft-Windows-CodeIntegrity/Operational** e, num PC gerido, peça ao administrador para avaliar a autorização. Consulte [Windows App Control e erro 4551](APP_CONTROL.md) para o diagnóstico completo e para a ferramenta apenas de leitura incluída em `tools\diagnose-app-control.ps1`.

## Assinatura, App Control e SmartScreen

Os artefactos da release `v1.2.0` estão explicitamente marcados **`NotSigned`**. O Microsoft Defender SmartScreen ou uma política App Control podem recusá-los. Cada release indica `Signed` ou `NotSigned` em `SIGNING-STATE.txt`; considere-a não assinada salvo indicação explícita e confirmação local de `Get-AuthenticodeSignature`.

O checksum deteta alterações no ficheiro relativamente à release publicada, mas não substitui uma assinatura de código nem confirma, sozinho, a identidade do publisher.

O pipeline está preparado para assinar UI, CLI, instalador e desinstalador com um certificado RSA de Code Signing emitido por uma CA confiável. Se a assinatura for solicitada e as credenciais estiverem ausentes ou inválidas, o build falha em vez de publicar silenciosamente como assinado. Uma assinatura válida também não substitui uma regra de autorização da organização.

## Compilar o instalador localmente

O ZIP portátil não requer ferramentas adicionais. Para criar o instalador é necessário [Inno Setup 6](https://jrsoftware.org/isdl.php):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-installer.ps1 -RuntimeIdentifier win-x64
```

Se o compilador não estiver no caminho normal:

```powershell
.\scripts\build-installer.ps1 -RuntimeIdentifier win-x64 -IsccPath 'C:\Tools\Inno Setup 6\ISCC.exe'
```

O script publica primeiro o pacote portátil, valida os ficheiros de staging, compila o instalador e cria um checksum SHA-256. Não simula nem ignora a ausência do compilador e não afirma que o resultado está assinado.

Para uma build Authenticode, importe previamente o certificado no store `CurrentUser\My` e indique o thumbprint:

```powershell
.\scripts\build-installer.ps1 `
  -RuntimeIdentifier win-x64 `
  -SigningCertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
  -TimestampServer 'http://timestamp.digicert.com'
```

O script exige um certificado RSA com chave privada, EKU de Code Signing e cadeia confiável. Assina com SHA-256, exige timestamp RFC 3161 e verifica todos os executáveis finais. O thumbprint SHA-1 serve apenas para selecionar o certificado; não é o algoritmo usado na assinatura dos ficheiros.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
