# Contribuir

Obrigado pelo interesse no Local Network Scanner. O projeto privilegia resultados tecnicamente honestos, utilização autorizada e uma experiência Windows acessível.

## Preparar o ambiente

É necessário Windows 10/11, o SDK indicado por `global.json` e PowerShell 5.1 ou 7.

```powershell
git clone https://github.com/p-darksy-r/LocalNetworkScanner.git
cd LocalNetworkScanner
dotnet restore .\LocalNetworkScanner.slnx
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -VerifyFormat
```

## Antes de abrir um pull request

- mantenha scans reais fora dos testes automáticos;
- use listeners de loopback, parsers e fixtures sintéticas nos testes;
- nunca adicione credenciais SNMP, inventários, SSIDs, MACs, certificados ou chaves reais;
- distinga dados observados, dados fornecidos pela infraestrutura e inferências;
- preserve cancelamento, limites de concorrência e resultados parciais;
- atualize documentação e changelog quando o comportamento visível mudar;
- confirme teclado, escala e alto contraste quando alterar a WPF.

O CI executa restore, `dotnet format --verify-no-changes`, build Release, o test harness determinístico e um smoke da CLI.

## Segurança

Não abra uma issue pública para uma vulnerabilidade explorável. Use um [GitHub Security Advisory privado](https://github.com/p-darksy-r/LocalNetworkScanner/security/advisories/new) e siga [SECURITY.md](SECURITY.md).

## Releases

Uma tag `vX.Y.Z` só é aceite pelo workflow de release quando corresponde à versão de `Directory.Build.props`. Apenas o responsável pelo repositório deve criar tags de release. Os builds públicos permanecem não assinados até existir um processo Authenticode documentado; nunca adicione certificados ou secrets ao repositório.
