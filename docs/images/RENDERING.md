<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Renderizar as imagens da aplicação

`main-window-current.png` e `topology-window-current.png` são produzidas pela UI WPF real com uma fixture inteiramente sintética. O processo não enumera interfaces nem executa qualquer scan:

```powershell
dotnet run --project .\LocalNetworkScanner.Tests\LocalNetworkScanner.Tests.csproj -c Release -- --render-doc-images
```

Os dois PNGs recebem descrição e copyright nos metadados. Nomes, IPs, MACs, VLANs, fabricantes, portas e ligações pertencem apenas à fixture de documentação.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
