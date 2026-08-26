<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Certificado privado de teste

Esta pasta contém apenas o certificado público `LocalNetworkScanner-PrivateTest.crt`, em formato X.509 DER. O ficheiro `.crt` não contém a chave privada e não atribui confiança pública à aplicação.

A chave privada correspondente é criada como RSA 3072, SHA-256, não exportável, com finalidade `Code Signing`, e permanece exclusivamente no repositório de certificados `CurrentUser\My` do Windows da máquina onde o gerador for executado. O projeto nunca cria nem guarda ficheiros PFX, P12, PEM, KEY ou PVK.

## Criar ou reutilizar o certificado

Na raiz do repositório, execute:

```powershell
pwsh -NoProfile -File .\scripts\new-private-test-certificate.ps1
```

O gerador reutiliza um certificado compatível ainda válido ou cria um novo. Exporta somente a parte pública para esta pasta e **não** instala confiança automaticamente.

Se for executado noutra conta ou máquina sem a chave correspondente, será criado um certificado diferente e o `.crt` público mudará. Essa rotação deve ser revista e commitada de forma deliberada: pacotes assinados com o certificado anterior deixam de corresponder ao novo ficheiro, e cada computador de QA terá de remover a confiança antiga e confiar explicitamente o novo thumbprint.

## Autorizar testes MSIX nesta máquina

Para instalar um MSIX assinado com este certificado, abra manualmente o PowerShell como administrador e execute:

```powershell
.\scripts\install-private-test-certificate.ps1 -Action Install -Confirm:$false
```

O script valida rigorosamente o certificado e adiciona apenas a parte pública a `LocalMachine\TrustedPeople`. Nunca escreve em `Trusted Root Certification Authorities`.

Para remover exatamente o mesmo certificado de teste:

```powershell
.\scripts\install-private-test-certificate.ps1 -Action Remove -Confirm:$false
```

A remoção compara o conteúdo binário, o assunto e o thumbprint antes de apagar, e só atua em `LocalMachine\TrustedPeople`. A chave privada em `CurrentUser\My` não é alterada.

## Limites de segurança

- Este certificado destina-se apenas a QA interno e sideload controlado.
- Outros computadores só aceitarão o pacote depois de um administrador confiar explicitamente neste `.crt`.
- Um pacote assinado assim não deve ser apresentado como uma release pública ou como software assinado por uma autoridade confiável.
- Na Microsoft Store, os valores de identidade atribuídos pelo Partner Center devem ser usados no manifesto; após certificação, a Microsoft volta a assinar o pacote para distribuição.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
