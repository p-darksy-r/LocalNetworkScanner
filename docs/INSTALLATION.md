<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Instalação no Windows

As releases disponibilizam dois formatos para cada arquitetura suportada. Ambos incluem o runtime .NET e não exigem a instalação separada do SDK ou do runtime.

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
- preserva snapshots e preferências em `%LOCALAPPDATA%\LocalNetworkScanner` quando é removido.

Para apagar também os dados locais depois da desinstalação, elimine manualmente `%LOCALAPPDATA%\LocalNetworkScanner`. Reveja primeiro os snapshots: podem constituir um inventário sensível da rede.

## Versão portátil

Extraia `LocalNetworkScanner-<versão>-<arquitetura>.zip` para uma pasta em que tenha permissões de escrita e execute `LocalNetworkScanner.exe`. Não execute diretamente de dentro do ZIP.

O pacote contém também `LocalNetworkScanner.Cli.exe` para automação. O histórico continua a ser guardado em `%LOCALAPPDATA%\LocalNetworkScanner`; “portátil” descreve apenas a distribuição sem instalador.

## Verificar a integridade

Compare o SHA-256 do ficheiro descarregado com `SHA256SUMS.txt` ou com o ficheiro `.sha256` adjacente na release:

```powershell
$file = '.\LocalNetworkScanner-1.2.0-win-x64.zip'
(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
```

Uma diferença significa que o ficheiro não deve ser executado.

## Assinatura e SmartScreen

O pipeline público não possui nem utiliza um certificado de assinatura. Até uma release indicar explicitamente uma assinatura Authenticode válida, considere os executáveis **não assinados**. O Microsoft Defender SmartScreen pode apresentar um aviso de reputação.

O checksum deteta alterações no ficheiro relativamente à release publicada, mas não substitui uma assinatura de código nem confirma, sozinho, a identidade do publisher.

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

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
