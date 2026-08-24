<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Instalação no Windows

As releases disponibilizam dois formatos para cada arquitetura suportada. A partir da linha 1.3.x, ambos incluem o runtime .NET e a snapshot offline MA-L/MA-M/MA-S/IAB da versão, sem exigir a instalação separada do SDK, do runtime ou de uma base de fabricantes.

O primeiro arranque e a identificação de titulares de prefixos IEEE não exigem Internet. A aplicação só contacta as listagens públicas da IEEE quando o utilizador escolhe explicitamente a atualização opcional. Os pacotes incluem `THIRD_PARTY_NOTICES.md`. A snapshot não está sob MIT e o projeto ainda não arquivou uma clarificação/autorização escrita que resolva a sua redistribuição; a acessibilidade pública dos ficheiros não deve ser interpretada como licença.

## Escolher a arquitetura

- `win-x64`: Windows 11, ou uma edição Windows 10 ainda suportada pelo .NET 10, em computadores Intel ou AMD de 64 bits;
- `win-arm64`: Windows 11 em computadores ARM64.

Confirme em **Definições > Sistema > Acerca de > Tipo de sistema** quando tiver dúvidas.

## Instalador por utilizador

O ficheiro `LocalNetworkScanner-<versão>-<arquitetura>-setup.exe` instala a UI e a CLI em `%LOCALAPPDATA%\Programs\LocalNetworkScanner`, cria uma entrada no menu Iniciar e oferece um atalho opcional no ambiente de trabalho.

O instalador:

- não pede privilégios administrativos no fluxo normal;
- não instala drivers, serviços nem extensões de rede;
- não altera o `PATH` do sistema;
- inclui um desinstalador normal do Windows;
- permite reparar a mesma versão ou atualizar para uma mais recente, mas recusa um instalador mais antigo quando encontra uma versão superior na localização predefinida;
- termina sem iniciar automaticamente a aplicação; abra-a depois pelo menu Iniciar;
- preserva snapshots e preferências em `%LOCALAPPDATA%\LocalNetworkScanner` quando é removido.

O bloqueio de downgrade protege a compatibilidade das preferências e dados locais, incluindo quando a instalação existente usa um diretório personalizado registado pelo instalador. Para regressar deliberadamente a uma versão anterior, exporte primeiro o que necessita, desinstale a versão atual e avalie a compatibilidade dos dados; não apague nem substitua o executável instalado manualmente para contornar a validação.

Para apagar também os dados locais depois da desinstalação, elimine manualmente `%LOCALAPPDATA%\LocalNetworkScanner`. Reveja primeiro os snapshots: podem constituir um inventário sensível da rede.

Consulte [PRIVACY.md](../PRIVACY.md) para a lista completa de comunicações iniciadas pelo utilizador, dados locais, retenção e eliminação.

## Versão portátil

Extraia `LocalNetworkScanner-<versão>-<arquitetura>.zip` para uma pasta em que tenha permissões de escrita e execute `LocalNetworkScanner.exe`. Não execute diretamente de dentro do ZIP.

O pacote contém também `LocalNetworkScanner.Cli.exe` para automação. O histórico continua a ser guardado em `%LOCALAPPDATA%\LocalNetworkScanner`; “portátil” descreve apenas a distribuição sem instalador.

## Verificar a integridade

Compare o SHA-256 do ficheiro descarregado com `SHA256SUMS.txt` ou com o ficheiro `.sha256` adjacente na release:

```powershell
$file = '.\LocalNetworkScanner-<versão>-win-x64.zip'
(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
```

Uma diferença significa que o ficheiro não deve ser executado.

## Erro 4551: política bloqueou o ficheiro

`CreateProcess falhou; código 4551` corresponde a `ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION` (`0x11C7`). O instalador pode ter copiado os ficheiros corretamente e o Windows ter bloqueado apenas a tentativa de executar a aplicação.

O erro é produzido antes de a aplicação arrancar. Nenhuma alteração à UI consegue autorizar retroativamente um processo que o Windows se recusou a criar; a correção de distribuição é usar binários previamente assinados por uma identidade confiável ou obter uma decisão explícita do administrador da política.

As versões novas do instalador não iniciam a aplicação automaticamente. Isto permite distinguir uma instalação concluída de um primeiro arranque bloqueado, sem desativar nem contornar a política.

Não desligue Smart App Control, App Control for Business/WDAC, AppLocker ou Microsoft Defender. Confirme o checksum e a assinatura, recolha os eventos `3077` (imposição) ou `3076` (auditoria) em **Microsoft-Windows-CodeIntegrity/Operational** e, num PC gerido, peça ao administrador para avaliar a autorização. Consulte [Windows App Control e erro 4551](APP_CONTROL.md) para o diagnóstico completo e para a ferramenta apenas de leitura incluída em `tools\diagnose-app-control.ps1`.

## Assinatura, App Control e SmartScreen

Os artefactos históricos da release `v1.2.0` estão explicitamente marcados **`NotSigned`** e não são recomendados para instalação de produção. O Microsoft Defender SmartScreen ou uma política App Control podem recusá-los. As prereleases `v1.3.x`/`v1.4.0` que conservam o título histórico `Private QA (NotSigned)` também não têm Authenticode; os seus assets estão agora publicamente acessíveis porque o repositório é público, mas continuam a ser apenas QA. Confirme sempre `SIGNING-STATE.txt` e o resultado local de `Get-AuthenticodeSignature`.

O checksum deteta alterações no ficheiro relativamente à release publicada, mas não substitui uma assinatura de código nem confirma, sozinho, a identidade do publisher.

O workflow versionado contém um caminho de produção para assinar UI, CLI, diagnóstico PowerShell, instalador e desinstalador através de Microsoft Artifact Signing por OIDC, mas esse backend não está configurado e não assinou os downloads atuais. A avaliação de elegibilidade para a SignPath Foundation está pendente; o projeto ainda não foi aceite nem integrado. Qualquer backend futuro deve manter a chave privada fora do GitHub e falhar se a identidade, o timestamp ou uma assinatura estiverem ausentes ou inválidos. Uma assinatura válida também não substitui uma regra de autorização da organização. Consulte a [Code signing policy](../CODE_SIGNING_POLICY.md).

A validação de release deixou de depender apenas do build: os ZIPs e instaladores exatos são instalados, executados e removidos em runners Windows x64 e ARM64 nativos antes da publicação. No backend atual, os dez ficheiros candidatos atravessam uma draft release ainda não publicada; depois dos testes, o atestado e o SBOM são acrescentados ao contrato permanente de 12 assets. Uma integração SignPath futura terá de usar um GitHub Actions artifact verificável pelo conector antes da assinatura. O estado real, alternativas legítimas e códigos `LNS-REL-*` estão documentados em [Assinatura e prontidão de release](SIGNING.md).

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

Para um laboratório/PKI privada ou runner próprio ligado a token/HSM, os scripts continuam a aceitar um certificado instalado em `CurrentUser\My` pelo thumbprint:

```powershell
.\scripts\build-installer.ps1 `
  -RuntimeIdentifier win-x64 `
  -SigningCertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
  -TimestampServer 'http://timestamp.digicert.com'
```

Este modo local exige RSA, chave privada protegida, EKU de Code Signing, cadeia confiável e timestamp. O thumbprint SHA-1 serve apenas para selecionar o certificado; não é o algoritmo usado na assinatura dos ficheiros. Não exporte uma chave pública de produção para PFX só para usar este exemplo: o backend cloud atualmente versionado usa Artifact Signing/OIDC e uma futura integração SignPath também deverá manter a chave fora do runner.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
