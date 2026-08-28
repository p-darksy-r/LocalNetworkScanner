<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

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

O repositório exige um cabeçalho e um rodapé de copyright nos formatos que aceitam comentários. O aplicador é idempotente; execute-o depois de criar ou renomear ficheiros e reveja o diff:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\apply-copyright.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\check-copyright.ps1
```

`LICENSE`, binários e formatos estritamente sem comentários são excluídos. A política e a matriz de formatos estão em [docs/COPYRIGHT_POLICY.md](docs/COPYRIGHT_POLICY.md).

## Antes de abrir um pull request

- mantenha scans reais fora dos testes automáticos;
- use listeners de loopback, parsers e fixtures sintéticas nos testes;
- nunca adicione credenciais SNMP, inventários, SSIDs, MACs, certificados ou chaves reais;
- distinga dados observados, dados fornecidos pela infraestrutura e inferências;
- preserve cancelamento, limites de concorrência e resultados parciais;
- associe novos erros públicos a um código e ação recomendada sem incluir credenciais ou inventário no contexto;
- mantenha a lista como experiência principal e a topologia como visualização opcional;
- atualize documentação e changelog quando o comportamento visível mudar;
- atualize [PRIVACY.md](PRIVACY.md) antes de introduzir uma nova comunicação externa, dado local, retenção ou integração de terceiros;
- preserve a exatidão da [Code signing policy](CODE_SIGNING_POLICY.md): nunca apresente uma candidatura, assinatura ou aprovação externa como concluída sem evidência;
- confirme teclado, escala e alto contraste quando alterar a WPF.

O CI verifica copyright, executa restore, `dotnet format --verify-no-changes`, build Release, o test harness determinístico e um smoke da CLI.

## Segurança

Não abra uma issue pública para uma vulnerabilidade explorável. Use um [GitHub Security Advisory privado](https://github.com/p-darksy-r/LocalNetworkScanner/security/advisories/new) e siga [SECURITY.md](SECURITY.md).

## Releases

Uma tag `vX.Y.Z` só é aceite pelo workflow de release quando corresponde à versão de `Directory.Build.props`. Apenas o responsável pelo repositório deve criar tags de release. Como o repositório é público, o workflow atual recusa gerar ou publicar um novo candidato `PrivateQa/NotSigned`; as prereleases com esse título são históricas e continuam sem assinatura. Uma release de produção exige assinatura Authenticode Public Trust validada, testes nativos dos pacotes exatos e autorização/licença de redistribuição aplicável; nunca adicione certificados, chaves ou secrets ao repositório.

Uma resposta escrita da SignPath indicou que o projeto seria provavelmente problemático para o programa gratuito Foundation devido à sua categoria de scanner de rede, pelo que não existe candidatura ou integração ativa. Contribuições não devem alegar aprovação Foundation, adicionar credenciais ou antecipar identificadores do serviço. Alterações à lógica de enumeração de portas, Nmap, avaliação heurística de risco, dados IEEE ou pipeline de assinatura exigem revisão explícita contra [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md), [PRIVACY.md](PRIVACY.md) e [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Uma eventual subscrição regular SignPath requer decisão e configuração separadas.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
