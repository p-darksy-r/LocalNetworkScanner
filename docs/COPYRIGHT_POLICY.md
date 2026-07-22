<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Política de copyright dos ficheiros

O código e a documentação do Local Network Scanner são distribuídos sob a licença MIT. Para tornar a proveniência visível em ficheiros isolados, todo o ficheiro textual cujo formato aceite comentários deve conter os marcadores oficiais no início e no fim.

## Marcadores oficiais

Conteúdo do cabeçalho:

```text
Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
```

Conteúdo do rodapé:

```text
Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
```

O mesmo texto é usado no cabeçalho e no rodapé. O delimitador respeita o formato: `//` em C# e `global.json`, `#` em PowerShell/YAML, `<!-- -->` em XML/XAML/Markdown e `;` em Inno Setup. Uma declaração XML ou shebang pode legalmente anteceder o cabeçalho; o rodapé é sempre a última linha não vazia.

## Aplicar e validar

O aplicador remove cópias exatas dos marcadores oficiais e os marcadores C# obsoletos conhecidos das primeiras versões, volta a colocar a forma atual na posição correta e preserva o tipo de newline e o BOM. Pode ser executado repetidamente sem produzir alterações adicionais:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\apply-copyright.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\check-copyright.ps1
```

Também é possível limitar a aplicação a caminhos concretos durante trabalho paralelo:

```powershell
powershell -ExecutionPolicy Bypass -Command "& '.\scripts\apply-copyright.ps1' -Path @('docs', 'README.md')"
```

Sem `-Path`, o checker percorre todo o repositório e falha se faltar qualquer marcador num ficheiro reconhecido como comentável. Também aceita a mesma lista opcional de caminhos para validação local durante trabalho paralelo. O CI e o workflow de release usam sempre a verificação repo-wide.

## Formatos e exclusões

São reconhecidos C#, projetos e propriedades MSBuild, XML, XAML, manifests, solução `.slnx`, Markdown, YAML, PowerShell, Python, shell, TOML, Inno Setup, `CODEOWNERS`, `.gitignore`, `.gitattributes` e `.editorconfig`. `global.json` também é abrangido porque o parser do .NET SDK suporta comentários nesse ficheiro.

As exclusões são deliberadas:

- `LICENSE`, para manter intacto o texto canónico da licença MIT;
- imagens, ícones, executáveis, ZIPs e outros formatos binários, que não têm comentários textuais seguros;
- JSON estrito diferente de `global.json` e outros formatos textuais sem sintaxe de comentário compatível;
- conteúdo gerado ou externo em `.git`, `.vs`, `artifacts`, `bin`, `obj`, `packages` e `TestResults`.

Um formato novo deve ser adicionado simultaneamente ao aplicador e ao checker. Não se deve inserir um comentário inválido apenas para satisfazer a política.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
