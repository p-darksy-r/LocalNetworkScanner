<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->

# Limites técnicos e interpretação dos resultados

Este documento faz parte do produto. Um scanner de rede credível deve explicar o que mediu, o que inferiu e o que não consegue determinar a partir de um computador Windows comum.

## Modelo de observação

O Local Network Scanner faz descoberta ativa. Envia pedidos ICMP e multicast e tenta ligações TCP. Também consulta informação que o Windows mantém sobre a interface e a vizinhança local. Não permanece a observar todo o tráfego da rede.

Um dispositivo pode não ser encontrado mesmo estando ligado. Firewalls podem bloquear ICMP, todas as portas de descoberta podem estar fechadas, multicast pode estar filtrado e o equipamento pode estar numa rede isolada.

## Perfis de scan

Os perfis alteram timeouts, concorrência e profundidade, mas não eliminam as limitações dos protocolos:

- **Rápido** faz descoberta leve e testa apenas portas essenciais; é adequado à primeira passagem e reduz o impacto;
- **Normal** testa serviços comuns e recolhe identidade e sinais de segurança com duração equilibrada; é a predefinição recomendada;
- **Avançado** testa mais portas, recolhe respostas leves adicionais e tolera dispositivos mais lentos; produz mais atividade e pode demorar substancialmente mais.

Uma opção manual pode substituir um valor do perfil. Assim, dois scans com o mesmo nome de perfil não são necessariamente equivalentes se as opções avançadas forem diferentes. Cancelamento mantém os resultados parciais já confirmados, mas estes não devem ser confundidos com cobertura completa.

## Diagnósticos e responsabilidade provável

Os códigos `LNS-USR-*`, `LNS-NET-*`, `LNS-DEV-*` e `LNS-APP-*` classificam a origem provável e apresentam uma ação recomendada. A categoria ajuda a resolver o problema; não é prova absoluta de culpa. Por exemplo, um timeout pode resultar do dispositivo, firewall, Wi-Fi ou congestionamento, e um fabricante desconhecido pode ser normal num MAC privado/aleatório.

Diagnósticos não fatais preservam o inventário que foi possível obter. Um código relativo a um dispositivo afeta normalmente apenas esse alvo; um erro fatal de configuração ou aplicação pode impedir o scan. Consulte [Códigos de erro e diagnóstico](ERROR_CODES.md).

## IP e disponibilidade

- Uma resposta ICMP é evidência direta de que o endereço respondeu naquele momento.
- Uma ligação TCP bem-sucedida também confirma disponibilidade, mesmo quando ICMP está bloqueado.
- A ausência de resposta não prova que o endereço está livre ou que o dispositivo está desligado.
- NAT, routing, VPNs, firewalls e isolamento de clientes alteram aquilo que é visível.

O produto limita o scan explícito da CLI a endereços privados/locais. Isso reduz erros de utilização, mas não substitui autorização.

## Endereços MAC e fabricante

O MAC é normalmente obtido através da vizinhança ARP. ARP opera no domínio de camada 2; para um destino roteado, o computador vê normalmente o MAC do gateway e não o MAC do dispositivo final. Por isso, um MAC remoto pode estar indisponível.

O fabricante é uma correspondência heurística de prefixos OUI. A base local pode não conter todos os fabricantes e endereços privados/aleatórios não identificam de forma fiável a marca do equipamento.

## Portas, serviços e protocolos

O scan de portas atual usa ligações TCP. Uma porta aberta significa apenas que uma ligação foi aceite naquele instante.

- Não é um scan exaustivo de UDP.
- Não executa exploração nem confirma vulnerabilidades.
- O nome do serviço pode resultar do número da porta ou de uma resposta leve e pode estar errado quando a aplicação usa uma porta não convencional.
- O risco apresentado é uma priorização heurística, não uma auditoria de conformidade nem um parecer de segurança.

A coluna de protocolos resume evidências de descoberta, portas e respostas de serviço. Não representa tipos ou contagens de todos os pacotes existentes na rede. Não existe captura de pacotes nem inspeção profunda de tráfego.

## Intensidade do sinal Wi-Fi

No Windows, a aplicação consulta a interface Wi-Fi local e pode mostrar SSID, BSSID, canal, tipo de rádio e percentagem de sinal devolvida pelo sistema.

Essa percentagem:

- descreve a ligação entre este computador e o access point atual;
- não é uma medição por dispositivo descoberto;
- não é garantidamente um valor RSSI em dBm;
- pode estar ausente devido ao driver, estado da interface, idioma/formato da ferramenta do Windows ou política do sistema.

Para obter sinal por cliente seria necessária telemetria fornecida pelo access point ou controlador, que o projeto não consulta.

## VLAN

A deteção de VLAN limita-se à interface local. A aplicação procura:

- um ID explícito no nome ou descrição da interface; ou
- uma propriedade avançada de VLAN exposta pelo driver ao Windows.

Um ID encontrado desta forma descreve a configuração conhecida do adaptador local. A aplicação não lê tags 802.1Q em tráfego capturado.

Quando um dispositivo da mesma subnet tem uma entrada ARP direta, a aplicação pode associá-lo ao segmento local e apresentar a VLAN local como inferência. Isso não é uma descoberta independente da VLAN do dispositivo.

Se a topologia SNMP v2c opcional estiver ativada para um switch gerido, a aplicação consulta tabelas Bridge/Q-BRIDGE, a relação VLAN→FDB e PVID. O índice de uma entrada Q-BRIDGE é um FDB-ID, não uma VLAN. A aplicação só o converte em VLAN quando a tabela do switch fornece uma correspondência única. Se várias VLANs partilharem a mesma FDB, a VLAN fica desconhecida.

O PVID descreve o tratamento de frames sem tag recebidos nessa porta e é mostrado apenas como referência. Não é usado como prova da VLAN do MAC. Mesmo uma VLAN obtida por mapeamento inequívoco representa o estado publicado pelo switch naquele momento; trunks, tabelas expiradas e múltiplos switches continuam a exigir interpretação.

Interfaces trunk, adaptadores virtuais, bridges, teaming, VPNs, drivers que removem tags e VLANs configuradas apenas no switch podem tornar o resultado incompleto ou ambíguo.

## Mesmo segmento e mesmo switch

Uma entrada ARP direta, combinada com a mesma subnet IP, suporta com confiança moderada a hipótese de alcance direto em camada 2. Ainda assim, o segmento pode atravessar vários switches, bridges ou uma infraestrutura virtual.

Sem integração de infraestrutura, o programa não confirma que dois dispositivos estão ligados ao mesmo switch físico.

O motor inclui uma integração SNMP v2c opcional e desativada por defeito para um switch gerido explicitamente indicado. Quando ativada, consulta:

- identificação básica do equipamento;
- tabelas de encaminhamento Bridge e Q-BRIDGE, preservando observações repetidas do mesmo MAC;
- correspondência entre porta bridge, interface e nome da interface;
- mapeamento VLAN→FDB e PVID quando o switch disponibiliza esses objetos.

A presença de um MAC na FDB confirma apenas que a bridge gerida o aprendeu. Não prova que o dispositivo está fisicamente ligado a esse switch: a entrada pode apontar para uma porta de acesso, uplink, trunk, access point, stack ou bridge remota. Por isso, a aplicação mantém “mesmo switch físico” desconhecido mesmo quando o MAC local e o MAC remoto aparecem na FDB.

Uma porta/interface só é apresentada como única quando existe uma única observação compatível. Se o mesmo MAC surgir em várias FDB, VLANs ou portas, todas as observações são preservadas e o caminho fica ambíguo. A ausência de um MAC também nunca prova “switch diferente”: a entrada pode ter expirado ou não ser exposta pelo equipamento.

O switch autorizado pode fornecer vizinhos LLDP, incluindo chassis, porta e identidade do sistema anunciados. Nesta versão, o enriquecimento LLDP não recolhe a tabela separada de endereços de gestão remotos. Também não existe SNMPv3, descoberta automática de switches, seguimento de uma topologia com vários switches ou suporte garantido para MIBs específicas de fabricante. Sem dados adicionais da infraestrutura, o produto não confirma ligação física direta. Switches não geridos não fornecem esta evidência.

SNMP v2c não protege os dados de acesso ao nível do protocolo. A opção deve ser usada apenas numa rede de gestão confiável, com autorização, e os dados de acesso não devem aparecer em exports, logs ou documentação partilhada.

## Grafo de topologia e GraphML

O grafo combina entidades observadas pelo scan com relações fornecidas pela infraestrutura ou inferidas. Cada ligação preserva o seu tipo, a origem, a confiança e um resumo da evidência; a aparência visual não transforma uma inferência em facto.

A lista de dispositivos é a vista principal do resultado. O grafo só é criado visualmente quando o utilizador escolhe **Abrir topologia** e aparece numa janela separada. Abrir ou fechar essa janela não executa um novo scan, não promove inferências a factos e não altera o inventário subjacente.

A exportação GraphML transporta estes atributos para ferramentas externas. Uma ferramenta que ignore os atributos ou aplique o seu próprio layout pode fazer relações fracas parecerem tão fortes como relações confirmadas. Ao analisar ou partilhar o ficheiro, mantenha visíveis a origem e a confiança e consulte a evidência textual.

O JSON schema v3 inclui a topologia e os diagnósticos estruturados além do inventário. Consumidores automáticos devem verificar `schemaVersion` e não assumir compatibilidade estrutural com exports de versões anteriores. HTML e GraphML podem incluir diagnósticos relevantes, mas não substituem o contexto completo do JSON.

LLDP descreve aquilo que um equipamento participante anuncia e o switch autorizado expõe. Pode revelar vizinhos de infraestrutura e portas, mas não garante um caminho completo de extremo a extremo: dispositivos finais frequentemente não anunciam LLDP, tabelas podem estar incompletas e equipamentos intermédios não consultados continuam desconhecidos.

## Descoberta multicast

mDNS, SSDP/UPnP e WS-Discovery dependem de multicast ou broadcast local. Os resultados podem desaparecer quando existem:

- isolamento de clientes Wi-Fi;
- regras de firewall;
- VLANs distintas;
- snooping ou filtragem multicast;
- serviços desativados no dispositivo.

Uma resposta pode revelar apenas um nome ou endpoint e não garante que todos os serviços do equipamento foram identificados.

## Tipo de dispositivo e sistema operativo

O tipo de equipamento e o sistema operativo provável são calculados a partir de sinais como hostname, fabricante, TTL, portas e serviços. Estes valores devem ser apresentados como “provável” ou “inferido”. Proxies, containers, equipamentos configurados manualmente e sistemas atualizados podem produzir classificações incorretas.

## Histórico e tempo

O histórico compara snapshots. Um dispositivo pode parecer novo quando muda de MAC, usa endereços aleatórios ou deixa de ter um MAC observável. Portas podem abrir ou fechar entre scans sem representar uma alteração permanente.

Os resultados são um retrato temporal, não monitorização contínua.

## Escala e impacto

Redes e intervalos grandes multiplicam pings, tentativas TCP, resolução de nomes e probes. Os perfis limitam concorrência e timeouts, mas um scan Avançado pode demorar e gerar muitos eventos nos equipamentos de segurança.

Comece pelo perfil Rápido, confirme o intervalo e avance para Normal ou Avançado apenas quando necessário. Cancele o scan se a rede apresentar degradação.

## Permissões e portabilidade

O fluxo normal foi desenhado para uma conta sem elevação. Algumas propriedades do adaptador podem exigir permissões, suporte do driver ou ferramentas do Windows disponíveis. Um campo indisponível deve permanecer vazio ou desconhecido.

O executável self-contained inclui o runtime .NET, mas continua dependente de APIs e ferramentas do Windows. Não existe garantia de comportamento equivalente noutros sistemas operativos.

## Dados sensíveis

Snapshots e exportações podem conter IPs, MACs, SSIDs, BSSIDs, hostnames, serviços e portas. Estes dados permitem mapear uma rede. Guarde-os com controlo de acesso e remova identificadores antes de pedir suporte público.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
