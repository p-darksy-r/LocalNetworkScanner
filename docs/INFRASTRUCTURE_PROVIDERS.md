<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Provedores de infraestrutura

O scan base continua a funcionar sem qualquer controlador. Quando existe uma
fonte autorizada de telemetria, a aplicação pode associar dados do switch,
access point ou controlador aos dispositivos encontrados, mantendo sempre a
origem e a confiança da evidência.

## O que já está disponível

- a topologia SNMP v2c opcional consulta o switch indicado pelo utilizador;
- entradas FDB/Q-BRIDGE são materializadas como evidência `GenericSnmp`;
- por cada MAC associado podem ser mostrados switch, porta/interface, VLAN e
  PVID (quando o equipamento os publica);
- a presença na FDB nunca altera `Mesmo switch físico` para confirmado;
- JSON schema v8, CSV e HTML preservam a origem, a confiança e o resumo de
  infraestrutura.

## Contrato para integrações futuras

O núcleo expõe `IInfrastructureProvider` em
`LocalNetworkScanner.Core.Services`. Uma implementação deve:

1. operar apenas depois de o utilizador selecionar a infraestrutura e confirmar
   que tem autorização;
2. usar apenas endpoints de leitura e limitar tempo, tamanho de resposta e
   concorrência;
3. exigir TLS validado por defeito e nunca aceitar credenciais no URL;
4. guardar segredos apenas no armazenamento protegido do Windows, nunca em
   `ScanOptions`, logs, diagnósticos ou exports;
5. devolver `InfrastructureObservation` com IP ou MAC, fonte, confiança e
   evidência textual curta;
6. falhar de forma isolada: `LNS-NET-012` deixa o inventário base utilizável.

O contrato não é uma implementação UniFi. A API UniFi varia entre versões
locais e cloud; o conector só deve ser ativado depois de testar autenticação,
TLS, limites e mapeamento de clientes/APs/switches num ambiente autorizado.
Não se deve inferir modelo, porta física ou RSSI por cliente quando o
controlador não os fornece explicitamente.

## Privacidade

Dados de infraestrutura podem revelar topologia, portas, VLANs, SSIDs, BSSIDs e
nomes de equipamentos. São tratados como dados sensíveis e ficam apenas no
resultado local ou no destino de exportação escolhido pelo utilizador. Antes de
partilhar um inventário, use o relatório de suporte agregado e reveja qualquer
export detalhado.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
