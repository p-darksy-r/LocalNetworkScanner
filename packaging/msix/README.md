<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Empacotamento MSIX

Esta pasta contém o manifesto e os recursos visuais usados para criar o pacote MSIX da aplicação WPF. O manifesto descreve uma aplicação clássica Windows empacotada, com nível de confiança `mediumIL` e a capacidade restrita `runFullTrust` necessária para iniciar o executável de ambiente de trabalho.

## Valores do manifesto

O processo de empacotamento deve substituir todos os valores seguintes antes de executar o `MakeAppx.exe`:

- `__IDENTITY_NAME__`: identidade reservada no Partner Center ou identidade interna de testes;
- `__PUBLISHER__`: Publisher exato do Partner Center ou Subject exato do certificado de testes;
- `__PUBLISHER_DISPLAY_NAME__`: nome público do editor;
- `__DISPLAY_NAME__`: nome apresentado pelo Windows;
- `__VERSION__`: versão de quatro componentes exigida pelo MSIX, por exemplo `1.4.1.0`;
- `__ARCHITECTURE__`: arquitetura do pacote, atualmente `x64` ou `arm64`.

Para publicação na Microsoft Store, a identidade e o Publisher devem corresponder exatamente aos valores atribuídos ao produto no Partner Center. O certificado interno e os seus valores não devem ser usados como identidade de produção.

## Recursos visuais

Os PNG em `Assets` são derivados de `LocalNetworkScanner.Wpf/Assets/AppIcon.png`. Para os recriar sem modificar o ícone de origem, execute na raiz do repositório:

```powershell
pwsh -NoProfile -File .\scripts\generate-msix-assets.ps1
```

O gerador usa uma área segura uniforme, fundo transparente e o fundo de mosaico azul-escuro definido no manifesto. Os ficheiros produzidos têm dimensões exatas para Store, lista de aplicações e mosaicos do Windows.

## Superfície de permissões

O manifesto declara apenas `runFullTrust`. Não são declaradas capacidades de rede redundantes: a aplicação WPF clássica executa com as permissões normais do utilizador e continua limitada pelos controlos do Windows, pela firewall e pelas autorizações da rede.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
