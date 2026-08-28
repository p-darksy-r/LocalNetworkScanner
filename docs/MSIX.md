<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# MSIX: testes PrivateTest e Microsoft Store

## Estado e objetivo

O projeto inclui uma infraestrutura separada para empacotar a aplicação WPF como MSIX em x64 e ARM64. Este caminho destina-se a dois cenários distintos:

- **`PrivateTest`**: pacote assinado por um certificado autoassinado, apenas para computadores de teste onde esse certificado foi confiado deliberadamente;
- **`Store`**: candidato MSIX com a identidade exata reservada no Partner Center, sem assinatura local, destinado exclusivamente à certificação e publicação pela Microsoft Store.

Esta infraestrutura não altera as tags, releases ou a decisão de não prosseguir com a candidatura gratuita SignPath Foundation. Também não transforma os ZIPs, os instaladores Inno Setup ou os executáveis soltos publicados no GitHub em ficheiros assinados. Até existir uma publicação Store aprovada ou uma release Authenticode válida por outro backend, esses downloads mantêm o estado documentado em [Assinatura e prontidão de release](SIGNING.md).

## Porque a Microsoft Store é diferente

Um MSIX submetido pelo canal MSIX/AppX não precisa de um certificado comprado pelo developer. Depois de o pacote passar a certificação, a Microsoft Store substitui qualquer assinatura existente e reassina o pacote com uma identidade Microsoft globalmente confiável. A Store também aloja o pacote e distribui as atualizações.

Esta vantagem aplica-se apenas à instalação entregue pela Store. Se for submetido um instalador **EXE ou MSI**, a Microsoft não o reassina: o publisher continua responsável por uma assinatura Authenticode emitida por uma CA do Microsoft Trusted Root Program. Da mesma forma, extrair ou publicar separadamente o `LocalNetworkScanner.exe` de um MSIX não lhe transfere a confiança da assinatura do pacote.

Um candidato `Store` sem assinatura local também não é um pacote de sideload: não o tente instalar por duplo clique. A validação local do fluxo Store verifica estrutura, manifesto e conteúdo, mas o pacote só adquire a assinatura instalável e publicamente confiável depois da certificação. Para testar a instalação antes disso, produza o modo `PrivateTest`.

Referências oficiais:

- [Microsoft — Sign your MSIX package: end-to-end guide](https://learn.microsoft.com/windows/msix/package/sign-msix-package-guide)
- [Microsoft — Code signing options for Windows app developers](https://learn.microsoft.com/windows/apps/package-and-deploy/code-signing-options)
- [Microsoft — App package requirements for MSIX](https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/app-package-requirements)

## Certificado local PrivateTest

Execute a criação no utilizador Windows que vai compilar o pacote:

```powershell
.\scripts\new-private-test-certificate.ps1
```

O desenho de segurança é intencional:

- a chave privada é criada como **não exportável** em `CurrentUser\My` e nunca é escrita no repositório, num PFX ou num secret;
- apenas o certificado público X.509 é exportado para `crt\LocalNetworkScanner-PrivateTest.crt`;
- o certificado inclui utilização de chave `DigitalSignature` e EKU de Code Signing;
- `.crt` não contém a chave privada e, por si só, não consegue assinar novos pacotes;
- o nome `PrivateTest` deve permanecer visível: este certificado não representa uma identidade pública verificada.

Antes de instalar um pacote `PrivateTest`, confirme o thumbprint apresentado pelo script e, numa consola PowerShell elevada, confie explicitamente o certificado:

```powershell
.\scripts\install-private-test-certificate.ps1
```

O certificado público é colocado em `LocalMachine\TrustedPeople`, nunca em `Trusted Root Certification Authorities`. Confiar uma raiz autoassinada alargaria desnecessariamente a autoridade do certificado. Remova a confiança do computador quando os testes terminarem.

Esta confiança permite ao Windows validar a assinatura do pacote nesse computador; não cria reputação SmartScreen, não prova a identidade pública do autor e não obriga App Control for Business/WDAC, AppLocker ou outra política empresarial a autorizar a aplicação. Uma política pode continuar a bloquear o pacote, mesmo com assinatura criptograficamente válida.

## Assets MSIX

Gere e valide os logos/tiles exigidos pelo manifesto antes do primeiro build e sempre que o ícone-fonte mudar:

```powershell
.\scripts\generate-msix-assets.ps1
```

Os assets produzidos pertencem ao pacote e devem respeitar os nomes e dimensões declarados no manifesto. O script não cria uma identidade Store nem publica qualquer recurso remoto.

## Criar e testar um pacote PrivateTest

Depois de criar e confiar o certificado:

```powershell
.\scripts\build-msix.ps1 -RuntimeIdentifier win-x64 -Mode PrivateTest
```

Para ARM64:

```powershell
.\scripts\build-msix.ps1 -RuntimeIdentifier win-arm64 -Mode PrivateTest
```

Valide o ficheiro exato produzido antes da instalação:

```powershell
.\scripts\validate-msix-package.ps1 `
  -Path '<caminho-do-pacote.msix>' `
  -ExpectedMode PrivateTest `
  -RequireTrustedSignature
```

O modo `PrivateTest` fixa automaticamente o signer ao thumbprint do CRT público versionado; para um certificado efémero diferente, passe explicitamente `-ExpectedSignerThumbprint`. Deve confirmar, no mínimo, assinatura, cadeia confiada localmente, Subject/Publisher, arquitetura PE/MSIX, versão, manifesto, conjunto fechado de payloads e hashes. Teste x64 num Windows x64 real e ARM64 num Windows ARM64 real; criar um pacote ARM64 noutro processador não substitui esse teste.

## Preparar um candidato Microsoft Store

Segundo a documentação Microsoft atual, o novo onboarding iniciado em [storedeveloper.microsoft.com](https://storedeveloper.microsoft.com/) não cobra taxa de registo. Um developer individual usa uma conta Microsoft pessoal e conclui verificação de identidade com documento oficial e selfie; isto substitui a antiga taxa, mas não dispensa o acordo, a verificação nem a certificação da aplicação. Começar diretamente noutro fluxo antigo do Partner Center pode apresentar condições diferentes. Consulte [Free developer registration for individual developers](https://learn.microsoft.com/windows/apps/publish/whats-new-individual-developer) e [Steps to open a developer account](https://learn.microsoft.com/windows/apps/publish/partner-center/open-a-developer-account).

Depois do onboarding, reserve **Local Network Scanner** como produto MSIX/PWA no Partner Center. Em **Product management > Product identity**, copie exatamente, incluindo maiúsculas, espaços e pontuação:

- `Package/Identity/Name` → `IdentityName`;
- `Package/Identity/Publisher` → `Publisher`;
- `Package/Properties/PublisherDisplayName` → `PublisherDisplayName`.

Não invente estes valores e não reutilize o Subject `PrivateTest`. Um exemplo de build por arquitetura é:

```powershell
.\scripts\build-msix.ps1 `
  -RuntimeIdentifier win-x64 `
  -Mode Store `
  -IdentityName '<Package/Identity/Name>' `
  -Publisher '<Package/Identity/Publisher>' `
  -PublisherDisplayName '<Package/Properties/PublisherDisplayName>'
```

Repita para `win-arm64`, ou produza o bundle das duas arquiteturas com:

```powershell
.\scripts\build-msix-bundle.ps1 `
  -Mode Store `
  -IdentityName '<Package/Identity/Name>' `
  -Publisher '<Package/Identity/Publisher>' `
  -PublisherDisplayName '<Package/Properties/PublisherDisplayName>'
```

Valide o candidato sem tentar instalá-lo:

```powershell
.\scripts\validate-msix-package.ps1 `
  -Path '<caminho-do-pacote.msix-ou-msixbundle>' `
  -ExpectedMode Store `
  -ExpectedIdentityName '<Package/Identity/Name>' `
  -ExpectedPublisher '<Package/Identity/Publisher>' `
  -ExpectedPublisherDisplayName '<Package/Properties/PublisherDisplayName>'
```

No modo Store, o validador recusa-se a continuar sem os três valores esperados e compara-os de forma exata e sensível a maiúsculas/minúsculas em cada pacote do bundle.

O Partner Center aceita `.msix`, `.msixbundle` e `.msixupload`, entre outros formatos AppX. Para x64 e ARM64, um bundle evita downloads incompatíveis e permite à Store escolher a arquitetura correta. Quando estiver disponível um `.msixupload`, este é o formato recomendado para submissão porque pode transportar o bundle e símbolos de crash analytics.

Referências oficiais:

- [Microsoft — View product identity details](https://learn.microsoft.com/windows/apps/publish/view-app-identity-details)
- [Microsoft — Upload MSIX app packages](https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/upload-app-packages)
- [Microsoft — Package identity overview](https://learn.microsoft.com/windows/apps/desktop/modernize/package-identity-overview)

## Procedimento integral, linha a linha

Os blocos seguintes mostram a sequência completa para aprendizagem e QA. Execute-os a partir da raiz do repositório. Não copie os valores demonstrativos para a Store: os três valores de identidade têm de vir do seu próprio produto no Partner Center.

### 1. Confirmar ferramentas

```powershell
Set-Location 'D:\Projects\LocalNetworkScanner'
dotnet --version
Get-Command New-SelfSignedCertificate
Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' `
  -Recurse `
  -File `
  -Filter makeappx.exe | Select-Object -First 1 -ExpandProperty FullName
Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' `
  -Recurse `
  -File `
  -Filter signtool.exe | Select-Object -First 1 -ExpandProperty FullName
```

### 2. Criar/reutilizar a chave e exportar apenas o CRT público

```powershell
$certificateInfo = .\scripts\new-private-test-certificate.ps1
$certificateInfo | Format-List
$certificateInfo.Thumbprint
$certificateInfo.PublicCertificatePath
```

Confirmar que o ficheiro versionável não transporta a chave privada:

```powershell
$public = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
  (Resolve-Path '.\crt\LocalNetworkScanner-PrivateTest.crt').Path
)
$public | Format-List Subject, Issuer, Thumbprint, NotBefore, NotAfter, HasPrivateKey
$rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($public)
$rsa.KeySize
$rsa.Dispose()
$public.Dispose()
```

O resultado obrigatório é `HasPrivateKey: False`, RSA 3072 ou superior, Subject igual a `CN=p-darksy-r Local Network Scanner Private Test` e EKU Code Signing. A chave correspondente fica em:

```powershell
Get-Item "Cert:\CurrentUser\My\$($certificateInfo.Thumbprint)" |
  Format-List Subject, Thumbprint, HasPrivateKey, NotAfter
```

### 3. Construir, assinar e validar um MSIX interno

```powershell
.\scripts\generate-msix-assets.ps1
.\scripts\build-msix.ps1 `
  -Mode PrivateTest `
  -RuntimeIdentifier win-x64 `
  -SigningCertificateThumbprint $certificateInfo.Thumbprint

$state = Get-Content `
  '.\artifacts\msix\private-test\win-x64\MSIX-BUILD-STATE.json' `
  -Raw | ConvertFrom-Json
$packagePath = Join-Path `
  '.\artifacts\msix\private-test\win-x64' `
  $state.packageFile

.\scripts\validate-msix-package.ps1 `
  -Path $packagePath `
  -ExpectedMode PrivateTest `
  -ExpectedSignerThumbprint $certificateInfo.Thumbprint

Get-FileHash -LiteralPath $packagePath -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $packagePath |
  Format-List Status, StatusMessage, SignerCertificate
```

Antes de confiar o certificado, `Get-AuthenticodeSignature` pode indicar que a cadeia não é confiável, embora o signer e o hash estejam íntegros. O validador recusa sempre `NotSigned` e `HashMismatch`; use `-RequireTrustedSignature` depois do passo seguinte para exigir também `Status=Valid`.

### 4. Confiar apenas num PC de laboratório

Abra uma segunda consola **PowerShell como administrador** e execute:

```powershell
Set-Location 'D:\Projects\LocalNetworkScanner'
$public = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
  (Resolve-Path '.\crt\LocalNetworkScanner-PrivateTest.crt').Path
)
$thumbprint = $public.Thumbprint
$public.Dispose()
$state = Get-Content `
  '.\artifacts\msix\private-test\win-x64\MSIX-BUILD-STATE.json' `
  -Raw | ConvertFrom-Json
$packagePath = Join-Path `
  '.\artifacts\msix\private-test\win-x64' `
  $state.packageFile

.\scripts\install-private-test-certificate.ps1 `
  -Action Install `
  -ExpectedThumbprint $thumbprint `
  -Confirm:$false

.\scripts\validate-msix-package.ps1 `
  -Path $packagePath `
  -ExpectedMode PrivateTest `
  -ExpectedSignerThumbprint $thumbprint `
  -RequireTrustedSignature
```

### 5. Instalar, abrir e remover o pacote

Ainda na consola elevada:

```powershell
Add-AppxPackage -Path $packagePath

$installed = Get-AppxPackage 'p-darksy-r.LocalNetworkScanner.PrivateTest'
$installed | Format-List Name, Version, Architecture, PackageFullName, InstallLocation

Start-Process explorer.exe `
  -ArgumentList "shell:AppsFolder\$($installed.PackageFamilyName)!LocalNetworkScanner"
```

Depois de confirmar arranque, scan autorizado, histórico, exportação e topologia:

```powershell
Get-AppxPackage 'p-darksy-r.LocalNetworkScanner.PrivateTest' |
  Remove-AppxPackage

.\scripts\install-private-test-certificate.ps1 `
  -Action Remove `
  -ExpectedThumbprint $thumbprint `
  -Confirm:$false
```

A remoção do pacote não deve ser usada para apagar inventários sem os rever. Os dados locais podem permanecer em `%LOCALAPPDATA%` conforme a política de retenção da aplicação.

### 6. Criar e validar o bundle x64+ARM64

```powershell
.\scripts\build-msix-bundle.ps1 `
  -Mode PrivateTest `
  -SigningCertificateThumbprint $certificateInfo.Thumbprint

$bundleState = Get-Content `
  '.\artifacts\msix\private-test\bundle\MSIX-BUNDLE-STATE.json' `
  -Raw | ConvertFrom-Json
$bundlePath = Join-Path `
  '.\artifacts\msix\private-test\bundle' `
  $bundleState.bundleFile

.\scripts\validate-msix-package.ps1 `
  -Path $bundlePath `
  -ExpectedMode PrivateTest `
  -ExpectedSignerThumbprint $certificateInfo.Thumbprint
```

O bundle contém exatamente um pacote x64 e um ARM64 com a mesma identidade e versão. O ARM64 deve ainda ser instalado e exercitado num computador ARM64 real.

### 7. Gerar o candidato Store quando existir Product identity

```powershell
$identityName = '<Package/Identity/Name do Partner Center>'
$publisher = '<Package/Identity/Publisher do Partner Center>'
$publisherDisplayName = '<Package/Properties/PublisherDisplayName do Partner Center>'

.\scripts\build-msix-bundle.ps1 `
  -Mode Store `
  -IdentityName $identityName `
  -Publisher $publisher `
  -PublisherDisplayName $publisherDisplayName

$storeState = Get-Content `
  '.\artifacts\msix\store\bundle\MSIX-BUNDLE-STATE.json' `
  -Raw | ConvertFrom-Json
$storeBundle = Join-Path `
  '.\artifacts\msix\store\bundle' `
  $storeState.bundleFile

.\scripts\validate-msix-package.ps1 `
  -Path $storeBundle `
  -ExpectedMode Store `
  -ExpectedIdentityName $identityName `
  -ExpectedPublisher $publisher `
  -ExpectedPublisherDisplayName $publisherDisplayName

Get-AuthenticodeSignature -LiteralPath $storeBundle |
  Format-List Status, StatusMessage
```

Neste ponto, `Status=NotSigned` é intencional e obrigatório para este pipeline. Não execute `Add-AppxPackage` sobre o candidato Store; carregue o bundle validado no Partner Center, complete propriedades/listagem/privacidade, justifique `runFullTrust`, execute o Windows App Certification Kit no candidato aplicável e submeta-o para certificação. Só o artefacto aprovado e distribuído pela Store recebe a assinatura Microsoft.

### 8. Comandos de baixo nível executados pelos scripts

Para referência, o fluxo seguro automatiza estas ferramentas. Os caminhos de staging, o manifesto final e o thumbprint são validados antes de cada chamada:

```powershell
dotnet restore `
  .\LocalNetworkScanner.Wpf\LocalNetworkScanner.Wpf.csproj `
  --runtime win-x64 `
  -p:PublishReadyToRun=true

dotnet publish `
  .\LocalNetworkScanner.Wpf\LocalNetworkScanner.Wpf.csproj `
  --configuration Release `
  --runtime win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -p:PublishTrimmed=false `
  -p:PublishReadyToRun=true `
  -p:DebugType=None `
  -p:DebugSymbols=false

& '<Windows SDK>\makeappx.exe' pack `
  /v /o /h SHA256 `
  /d '<layout com AppxManifest.xml>' `
  /p '<pacote.msix>'

& '<Windows SDK>\signtool.exe' sign `
  /v /fd SHA256 /s My `
  /sha1 '<thumbprint PrivateTest>' `
  '<pacote.msix>'

& '<Windows SDK>\makeappx.exe' bundle `
  /v /o /bv 1.4.1.0 `
  /d '<pasta com os MSIX x64 e ARM64>' `
  /p '<bundle.msixbundle>'
```

O modo Store omite deliberadamente a chamada `signtool`. Use os scripts versionados, em vez de executar esta sequência manual, para preservar as verificações de identidade, capacidades, arquitetura, segredos, hashes e limpeza.

## Manifesto e `runFullTrust`

O Local Network Scanner é uma aplicação WPF desktop e deve permanecer um `packagedClassicApp` com `uap10:TrustLevel="mediumIL"`. O manifesto usa `TargetDeviceFamily Name="Windows.Desktop"` e declara:

```xml
<Capabilities>
  <rescap:Capability Name="runFullTrust" />
</Capabilities>
```

`runFullTrust` é uma capability restrita. Na submissão, o Partner Center exige uma justificação clara e a Microsoft revê-a durante a certificação. A justificação deve explicar apenas o comportamento real: a aplicação desktop usa APIs Win32/.NET para ICMP, sockets, ARP/NDP, interfaces de rede e descoberta local iniciada pelo utilizador. Também inicia ferramentas Windows no contexto do utilizador — `netsh.exe` para sinal Wi-Fi, `powershell.exe` para informação VLAN e, apenas por ações explícitas da UI, `cmd.exe` com `ping.exe`/`tracert.exe`, `explorer.exe` e `mstsc.exe`. O scan avançado pode iniciar uma instalação local de `nmap.exe` quando o utilizador ativa essa opção; o caminho é validado e Nmap não é incluído nem descarregado. A aplicação não instala drivers ou serviços e não pede elevação administrativa no fluxo normal.

Não declare `allowElevation`, `broadFileSystemAccess` ou outras capabilities apenas para facilitar a certificação. Um processo desktop `mediumIL` já executa com os direitos do utilizador; capabilities de rede destinadas a AppContainer não devem ser acrescentadas sem uma necessidade técnica demonstrada.

Referências oficiais:

- [Microsoft — Package a .NET WPF app with MSIX](https://learn.microsoft.com/windows/apps/desktop/modernize/dotnet/package-app)
- [Microsoft — Generate MSIX package components](https://learn.microsoft.com/windows/msix/desktop/desktop-to-uwp-manual-conversion)
- [Microsoft — App capability declarations](https://learn.microsoft.com/windows/apps/package-and-deploy/app-capability-declarations)

## Compatibilidade a validar antes da submissão

- a pasta instalada sob `WindowsApps` é somente de leitura; histórico, preferências, logs e bases atualizadas devem permanecer em `%LOCALAPPDATA%\LocalNetworkScanner`;
- a aplicação não deve depender do current working directory nem tentar substituir o executável instalado;
- no canal Store, as atualizações pertencem à Store, não ao atual publicador GitHub/launcher local;
- todos os payloads e dados de terceiros precisam de autorização de redistribuição aplicável;
- o Windows App Certification Kit deve passar sobre o pacote final;
- x64 e ARM64 devem ser testados nas respetivas arquiteturas nativas;
- a declaração de privacidade, as funcionalidades de scan e as notas para certificação devem descrever o comportamento real, sem esconder Nmap, enumeração de portas ou avisos heurísticos.

Consulte também [Instalação](INSTALLATION.md), [Assinatura e prontidão de release](SIGNING.md), [Code signing policy](../CODE_SIGNING_POLICY.md), [Privacidade](../PRIVACY.md) e [avisos de terceiros](../THIRD_PARTY_NOTICES.md).

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
