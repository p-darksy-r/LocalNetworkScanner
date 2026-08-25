<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Abrir a aplicação local

Esta pasta mantém um ponto de entrada simples para a build correspondente ao checkout atual do projeto. Não executa `git pull`, não procura versões remotas e não altera o código-fonte.

Faça duplo clique em **`Abrir Local Network Scanner.cmd`**. O lançador:

1. deteta automaticamente se este computador é Windows x64 ou Windows ARM64;
2. compara a versão, a arquitetura, o SHA-256 e uma impressão digital dos fontes com `APP-BUILD.json`;
3. reutiliza imediatamente `LocalNetworkScanner.exe` quando já está atualizado;
4. caso contrário, compila a publicação self-contained/single-file e valida versão, PE e SHA-256 antes de substituir a cópia anterior;
5. abre a aplicação apenas depois de a atualização terminar com sucesso.

O duplo clique usa o modo `-Quick`: omite a repetição do harness e dos smoke tests porque vai abrir imediatamente a própria UI, mas não omite a compilação nem as validações do payload. Para atualizar sem abrir e executar primeiro o gate local completo, use a partir da raiz do repositório:

```powershell
.\scripts\update-local-app.ps1
```

Para forçar uma reconstrução, use `-Force`; `-Quick -Force` mantém o caminho rápido. A primeira materialização ou uma atualização requer o .NET SDK indicado por `global.json`. Se uma atualização falhar, o executável anterior é preservado; se estiver aberto, feche-o e repita.

O payload publicado para esta conveniência fica em `artifacts\local-app\<runtime>`. Este fluxo não lê nem escreve `artifacts\release`, staging, instaladores ou candidatos assinados; o modo completo pode usar os restantes diretórios normais de build/teste.

## Ficheiros gerados

- `LocalNetworkScanner.exe`: UI Windows self-contained da arquitetura nativa do computador;
- `APP-BUILD.json`: versão, runtime, commit, estado do worktree, SHA-256 e estado Authenticode;
- `.update-*.tmp`: temporários transitórios removidos pelo script mesmo em caso de erro.
- `.update.lock`: exclusão mútua transitória que impede dois duplos cliques de publicarem sobre os mesmos ficheiros.

Estes ficheiros gerados são ignorados pelo Git. O executável ronda dezenas de MB e versioná-lo faria crescer permanentemente o histórico a cada build. Um `.lnk` também não é guardado porque contém caminhos dependentes do computador; o lançador `.cmd` usa apenas caminhos relativos e continua válido quando a pasta do projeto é movida.

O lançador prefere PowerShell 7 (`pwsh`) e, se este não estiver instalado, usa o Windows PowerShell. Em ambos os casos, `ExecutionPolicy Bypass` aplica-se apenas ao processo do lançador, porque alguns computadores recusam por predefinição scripts locais do checkout. Isto não altera a política do sistema e não desativa App Control, WDAC, AppLocker, Defender ou SmartScreen.

## Limite de distribuição

`app` é uma conveniência para quem trabalha num checkout do código. Não é uma release oficial, não altera a assinatura e não contorna SmartScreen, Smart App Control, WDAC ou o erro `4551`. Enquanto a assinatura pública estiver pendente, a build local continua normalmente `NotSigned`.

Atualmente não existe uma release estável/`Latest` assinada; os assets existentes são QA históricos `NotSigned`. Quando existir uma distribuição de produção, os utilizadores finais deverão obtê-la apenas pela página de Releases e confirmar o respetivo `SIGNING-STATE.txt`. O estado atual está sempre descrito no [README principal](../README.md#local-network-scanner).

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
