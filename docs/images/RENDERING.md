<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Renderizar as imagens da aplicação

`main-window-current.png` e `topology-window-current.png` são produzidas pela UI WPF real com uma fixture inteiramente sintética. O processo não enumera interfaces nem executa qualquer scan:

```powershell
dotnet run --project .\LocalNetworkScanner.Tests\LocalNetworkScanner.Tests.csproj -c Release -- --render-doc-images
```

Os dois PNGs recebem descrição e copyright nos metadados. Nomes, IPs, MACs, VLANs, fabricantes, portas e ligações pertencem apenas à fixture de documentação.

Se o Windows App Control bloquear a assembly WPF local, não desative a política. O workflow manual **Render documentation images** executa o mesmo renderer num runner Windows alojado pelo GitHub e publica os dois PNGs sintéticos num artefacto com retenção de um dia:

```powershell
gh workflow run render-doc-images.yml --ref main
gh run list --workflow render-doc-images.yml --limit 1
gh run download <run-id> --name LocalNetworkScanner-documentation-images --dir .\docs\images
```

Reveja visualmente ambas as imagens antes do commit; o workflow valida apenas o formato PNG e um tamanho mínimo.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
