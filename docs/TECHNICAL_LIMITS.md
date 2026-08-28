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

Antes de iniciar, a UI calcula uma estimativa conservadora a partir do número de endereços, portas de descoberta, portas completas e probes de serviço. A estimativa assume que todas as portas inventariadas podem exigir um probe adicional e, por isso, serve para classificar a carga como normal, alta ou extrema, não para prever a duração nem o número real de pacotes. Nmap executa tráfego adicional no seu próprio orçamento e é assinalado separadamente. Quando se aplicam vários avisos — carga alta/extrema, SNMP v2c sem cifragem ou Nmap — a UI reúne-os num único diálogo antes de transmitir.

## Diagnósticos e responsabilidade provável

Os códigos `LNS-USR-*`, `LNS-NET-*`, `LNS-DEV-*` e `LNS-APP-*` classificam a origem provável e apresentam uma ação recomendada. A categoria ajuda a resolver o problema; não é prova absoluta de culpa. Por exemplo, um timeout pode resultar do dispositivo, firewall, Wi-Fi ou congestionamento, e um fabricante desconhecido pode ser normal num MAC privado/aleatório.

Diagnósticos não fatais preservam o inventário que foi possível obter. Um código relativo a um dispositivo afeta normalmente apenas esse alvo; um erro fatal de configuração ou aplicação pode impedir o scan. Consulte [Códigos de erro e diagnóstico](ERROR_CODES.md).

Uma exceção não tratada na UI inicia um encerramento controlado: pede o cancelamento do trabalho pendente, evita voltar a guardar preferências num estado potencialmente corrompido e tenta escrever `%LOCALAPPDATA%\LocalNetworkScanner\logs\app.log`. Este registo não é telemetria nem um dump. É limitado a 512 KiB, roda apenas para `app.previous.log` e conserva versão/ambiente, origem controlada, tipo/HResult, severidade/código e stack sanitizada; omite mensagens e argumentos da exceção, alvo/contexto do diagnóstico, credenciais, IPs, MACs, hostnames e o caminho do perfil do utilizador.

## IP e disponibilidade

- Uma resposta ICMP é evidência direta de que o endereço respondeu naquele momento.
- Uma ligação TCP bem-sucedida também confirma disponibilidade, mesmo quando ICMP está bloqueado.
- Uma linha ARP que surgiu depois do baseline só confirma alcance quando está `Reachable` e não marcada `IsUnreachable`; uma resposta ARP direta sem entrada prévia também confirma. Uma entrada preexistente `Reachable` constitui alcance recente. Uma entrada transitória como `Stale` só confirma depois de `SendARP` e de uma segunda leitura nativa `Reachable`, sem `IsUnreachable` e com o mesmo MAC; `Permanent` permanece passiva.
- A ausência de resposta não prova que o endereço está livre ou que o dispositivo está desligado.
- NAT, routing, VPNs, firewalls e isolamento de clientes alteram aquilo que é visível.

No Windows e em IPv4, o pedido ICMP usa explicitamente o endereço da interface escolhida através da API assíncrona do sistema, sem reservar uma thread por host enquanto espera. Se essa origem não puder ser respeitada, o probe falha de forma fechada em vez de sair silenciosamente por outra interface ou VPN. O timeout/cancelamento devolvido à UI é imediato; uma operação nativa já iniciada pode terminar isoladamente em background até ao seu timeout para libertar os recursos com segurança.

O produto limita o scan explícito da CLI a endereços privados/locais. Isso reduz erros de utilização, mas não substitui autorização.

## Identidade, fabricante e modelo

A identidade resulta de uma fusão determinística por campo. A aplicação mantém separadamente o titular IEEE do prefixo MAC e o fabricante/modelo anunciado por UPnP, DNS-SD ou SNMP. Cada evidência conserva método, origem e confiança; empates têm uma prioridade estável e a confiança consolidada usa o campo selecionado menos confiável. Valores contraditórios não são tratados como autenticação. O Nmap contribui hostname, tipo/OS provável e produtos de serviços, mas estes últimos permanecem banners e não são convertidos em modelo físico.

Uma ausência de modelo é normal. Muitos dispositivos não publicam descrição UPnP, TXT DNS-SD ou ENTITY-MIB; firewalls podem bloquear os pedidos e MACs locais não têm um titular IEEE global. Mesmo quando existe uma resposta, o administrador ou firmware do equipamento pode ter configurado texto incorreto.

As descrições UPnP só são obtidas do URL `HTTP(S)` cujo host literal é exatamente o IP privado que enviou o SSDP. Redirects, proxy, credenciais no URL, destinos diferentes, documentos grandes e XML com DTD são recusados. O scan limita este enriquecimento a 32 descrições, quatro pedidos concorrentes e um orçamento global máximo de oito segundos. Isto reduz SSRF, XXE e abuso de recursos, mas não torna os metadados autenticados.

## Endereços MAC e titular IEEE

O MAC é normalmente obtido através da vizinhança ARP. ARP opera no domínio de camada 2; para um destino roteado, o computador vê normalmente o MAC do gateway e não o MAC do dispositivo final. Por isso, um MAC remoto pode estar indisponível. Antes da descoberta, a aplicação captura um baseline da vizinhança e inicia ICMP, TCP e ARP em paralelo. Uma entrada do baseline pode preencher o MAC de um host confirmado por outro meio, mas só acrescenta evidência ARP se estiver atualmente `Reachable` ou se uma revalidação dirigida tiver sucesso. Para estados transitórios até `Stale`, `SendARP` é seguido de `GetIpNetEntry2`: código de retorno, comprimento, MAC, estado `Reachable` e ausência de `IsUnreachable` têm todos de ser coerentes. `CurrentReachableNeighbor` distingue esta evidência de `ActiveArp`; `NeighborCache` continua passiva. A aplicação não chama `ResolveIpNetEntry2` nem limpa a tabela inteira, mas a própria API `SendARP` pode atualizar ou invalidar a entrada alvo no Windows. Em grupos de alvos silenciosos esta confirmação nativa pode acrescentar alguns segundos, limitada pela concorrência da sessão. Se o baseline não puder ser lido, a descoberta ARP degrada de forma fechada e emite `LNS-NET-011`, sem invalidar alvos confirmados por outros protocolos.

A aplicação inclui uma snapshot offline das listagens IEEE MA-L, MA-M, MA-S e IAB. A snapshot de 2026-08-12 contém 58 166 linhas de origem e 58 163 prefixos únicos depois da normalização. Não é necessário um download inicial. A resolução usa o prefixo mais longo disponível, na ordem `/36 → /28 → /24`, para que MA-S/IAB e MA-M não sejam escondidos por uma correspondência MA-L menos específica.

O resultado é o **titular registado do prefixo IEEE**. Não confirma o fabricante físico, a marca ou o modelo:

- `Private` significa que a IEEE não publica a identidade do titular;
- um MAC localmente administrado ou aleatório não permite inferir de forma fiável uma organização;
- um MAC multicast/grupo não identifica uma interface individual;
- virtualização, adaptadores USB, componentes OEM, contract manufacturing e blocos partilhados podem identificar apenas a interface ou o titular do bloco;
- o registo CID é excluído porque não deve ser tratado como origem de um MAC EUI global.

A base incorporada envelhece com a release. A atualização a partir das quatro URLs oficiais é opcional, explícita e substituída apenas depois de validação; uma falha mantém a snapshot funcional. Esta operação não envia telemetria, MACs, IPs, inventário, SSID ou topologia. Consulte [Base de entidades MAC incorporada](VENDOR_DATABASE.md).

## Portas, serviços e protocolos

O scan de portas atual usa ligações TCP. Uma porta aberta significa apenas que uma ligação foi aceite naquele instante.

- Não é um scan exaustivo de UDP.
- Não executa exploração nem confirma vulnerabilidades.
- O nome do serviço pode resultar do número da porta ou de uma resposta leve e pode estar errado quando a aplicação usa uma porta não convencional.
- Uma porta habitualmente associada a TLS não é marcada como cifrada sem um handshake concluído. “Falha” significa que a verificação foi tentada mas ficou indeterminada; não prova que o serviço esteja em texto simples.
- O risco apresentado é uma priorização heurística, não uma auditoria de conformidade nem um parecer de segurança.

A coluna de protocolos resume evidências de descoberta, portas e respostas de serviço. Não representa tipos ou contagens de todos os pacotes existentes na rede. Não existe captura de pacotes nem inspeção profunda de tráfego.

### Nmap opcional

No perfil Avançado, o utilizador pode pedir enriquecimento através de um `nmap.exe` já instalado. A autodeteção fica limitada às instalações locais em `Program Files`; o `PATH`, caminhos UNC e device paths não são executados. Um caminho explícito tem de ser absoluto, local, existente e terminar em `nmap.exe`; a UI mostra-o antes do consentimento e recomenda confirmar a assinatura/publisher. A aplicação valida `nmap --version`, usa argumentos estruturados sem shell e executa apenas TCP Connect/version-light sem privilégios (`--unprivileged -sT -sV --version-light -Pn -n`), com alvos RFC1918, portas, lotes, output XML, tempo e tamanho limitados. Não executa NSE, scan UDP, raw sockets, tentativa de credenciais ou deteção de SO privilegiada.

Nmap e Npcap não são incluídos, instalados ou licenciados pelo Local Network Scanner. O utilizador é responsável pela instalação e licença aplicáveis. A ausência ou falha do binário gera `LNS-NET-009`/`LNS-NET-010` sem invalidar o inventário nativo já recolhido.

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

Quando um dispositivo da mesma subnet produz uma linha ARP nova e `Reachable`, uma resposta ARP direta sem entrada prévia ou um vizinho atual/revalidado `Reachable`, a aplicação pode associá-lo ao segmento local e apresentar a VLAN local como inferência moderada. Uma entrada que permaneça passiva/`Stale` ou qualquer estado nativo não alcançável não basta. Isso não é uma descoberta independente da VLAN do dispositivo.

Se a topologia SNMP v2c opcional estiver ativada para um switch gerido, a aplicação consulta tabelas Bridge/Q-BRIDGE, a relação VLAN→FDB e PVID. O índice de uma entrada Q-BRIDGE é um FDB-ID, não uma VLAN. A aplicação só o converte em VLAN quando a tabela do switch fornece uma correspondência única. Se várias VLANs partilharem a mesma FDB, a VLAN fica desconhecida.

O PVID descreve o tratamento de frames sem tag recebidos nessa porta e é mostrado apenas como referência. Não é usado como prova da VLAN do MAC. Mesmo uma VLAN obtida por mapeamento inequívoco representa o estado publicado pelo switch naquele momento; trunks, tabelas expiradas e múltiplos switches continuam a exigir interpretação.

Interfaces trunk, adaptadores virtuais, bridges, teaming, VPNs, drivers que removem tags e VLANs configuradas apenas no switch podem tornar o resultado incompleto ou ambíguo.

## Mesmo segmento e mesmo switch

Uma linha ARP nova e `Reachable`, uma resposta ARP direta sem entrada prévia ou um vizinho atual/revalidado `Reachable`, combinados com a mesma subnet IP, suportam com confiança moderada a hipótese de alcance direto em camada 2. Uma entrada passiva que permaneça `Stale` ou um estado nativo não alcançável não produz essa inferência. Ainda assim, o segmento pode atravessar vários switches, bridges ou uma infraestrutura virtual.

Sem integração de infraestrutura, o programa não confirma que dois dispositivos estão ligados ao mesmo switch físico.

O motor inclui uma integração SNMP v2c opcional e desativada por defeito para um switch gerido explicitamente indicado. Quando ativada, consulta:

- identificação básica do equipamento;
- tabelas de encaminhamento Bridge e Q-BRIDGE, preservando observações repetidas do mesmo MAC;
- correspondência entre porta bridge, interface e nome da interface;
- mapeamento VLAN→FDB e PVID quando o switch disponibiliza esses objetos.

A presença de um MAC na FDB confirma apenas que a bridge gerida o aprendeu. Não prova que o dispositivo está fisicamente ligado a esse switch: a entrada pode apontar para uma porta de acesso, uplink, trunk, access point, stack ou bridge remota. Por isso, a aplicação mantém “mesmo switch físico” desconhecido mesmo quando o MAC local e o MAC remoto aparecem na FDB.

Uma porta/interface só é apresentada como única quando existe uma única observação compatível. Se o mesmo MAC surgir em várias FDB, VLANs ou portas, todas as observações são preservadas e o caminho fica ambíguo. A ausência de um MAC também nunca prova “switch diferente”: a entrada pode ter expirado ou não ser exposta pelo equipamento.

O switch autorizado pode fornecer vizinhos LLDP, incluindo chassis, porta e identidade do sistema anunciados. Nesta versão, o enriquecimento LLDP não recolhe a tabela separada de endereços de gestão remotos. Também não existe SNMPv3, descoberta automática de switches, seguimento de uma topologia com vários switches ou suporte garantido para MIBs específicas de fabricante. Sem dados adicionais da infraestrutura, o produto não confirma ligação física direta. Switches não geridos não fornecem esta evidência.

SNMP v2c não protege os dados de acesso ao nível do protocolo. A opção deve ser usada apenas numa rede de gestão confiável, com autorização e uma community dedicada apenas de leitura; a UI pede confirmação antes de a enviar a cada dispositivo online consultado. Os dados de acesso não devem aparecer em exports, logs ou documentação partilhada. A consulta de identidade usa somente a community indicada, MIB-II e ENTITY-MIB; não tenta valores comuns, não persiste a community e não usa texto de `sysDescr` como prova forte quando o chassis não publica campos próprios.

O núcleo também expõe `IInfrastructureProvider`, um contrato assíncrono e somente leitura para controladores externos. As observações são correlacionadas por IP ou MAC, recebem uma confiança explícita e são exportadas com a sua origem. O contrato não define autenticação nem guarda segredos; cada integração deve exigir autorização explícita, validar TLS, limitar tempo/tamanho e remover credenciais de mensagens, logs e exports. A implementação UniFi está apenas preparada para uma futura integração testada; não se deve inferir suporte a uma API concreta a partir do contrato.

## Grafo de topologia e GraphML

O grafo combina entidades observadas pelo scan com relações fornecidas pela infraestrutura ou inferidas. Cada ligação preserva o seu tipo, a origem, a confiança e um resumo da evidência; a aparência visual não transforma uma inferência em facto.

A lista de dispositivos é a vista principal do resultado. O grafo só é criado visualmente quando o utilizador escolhe **Abrir topologia** e aparece numa janela separada. Abrir ou fechar essa janela não executa um novo scan, não promove inferências a factos e não altera o inventário subjacente. Ao filtrar clientes ou alertas, a vista conserva os ancestrais de infraestrutura que ligam cada correspondência ao mapa; estes nós são contexto visual, não correspondências adicionais.

A exportação GraphML transporta estes atributos para ferramentas externas. Uma ferramenta que ignore os atributos ou aplique o seu próprio layout pode fazer relações fracas parecerem tão fortes como relações confirmadas. Ao analisar ou partilhar o ficheiro, mantenha visíveis a origem e a confiança e consulte a evidência textual.

O JSON schema v8 inclui a topologia, os diagnósticos estruturados, o estado TLS triestado, evidências de identidade, endpoints mDNS/DNS-SD, `devices[].macAddressSource` e a snapshot opcional `infrastructure`. CSV e HTML também mostram a proveniência MAC e um resumo de infraestrutura. Consumidores automáticos devem verificar `schemaVersion` e não assumir compatibilidade estrutural com exports de versões anteriores. HTML e GraphML podem incluir diagnósticos relevantes, mas não substituem o contexto completo do JSON.

LLDP descreve aquilo que um equipamento participante anuncia e o switch autorizado expõe. Pode revelar vizinhos de infraestrutura e portas, mas não garante um caminho completo de extremo a extremo: dispositivos finais frequentemente não anunciam LLDP, tabelas podem estar incompletas e equipamentos intermédios não consultados continuam desconhecidos.

## Descoberta multicast

mDNS, SSDP/UPnP e WS-Discovery dependem de multicast ou broadcast local. Os resultados podem desaparecer quando existem:

- isolamento de clientes Wi-Fi;
- regras de firewall;
- VLANs distintas;
- snooping ou filtragem multicast;
- serviços desativados no dispositivo.

O browse DNS-SD começa pela enumeração PTR e faz consultas dirigidas e limitadas aos tipos, instâncias, registos SRV/TXT e endereços A/AAAA anunciados. Um SRV válido pode acrescentar serviço, porta, transporte, endpoint e evidência ao dispositivo já confirmado; não transforma sozinho um endereço indireto anunciado em dispositivo online. Só acumula datagramas com cabeçalho e origem mDNS compatíveis; nomes comprimidos, referências inválidas, pacotes truncados e respostas excessivas são rejeitados ou limitados para que uma resposta multicast não possa criar trabalho ilimitado. Um registo “goodbye” com TTL zero retira a evidência correspondente já observada durante o scan.

As transmissões iniciais de SSDP, WS-Discovery e mDNS/DNS-SD podem ser repetidas até três vezes, com jitter, cancelamento imediato e um orçamento global comum. Em mDNS, as repetições também contam para o limite total de datagramas. Isto reduz perdas transitórias; não atravessa VLANs, isolamento Wi-Fi ou firewalls e não autoriza uma tempestade de retries.

Uma resposta pode revelar apenas um nome, metadados declarados pelo dispositivo ou endpoint e não garante que todos os serviços do equipamento foram identificados. TXT é informação anunciada e não é tratada como identidade autenticada. O parser só promove uma allowlist curta de chaves de fabricante/modelo e limita tamanho/quantidade; restantes valores continuam fora da identidade.

WS-Discovery associa sempre a descoberta ao endereço IP que enviou o datagrama. `XAddrs` é preservado como metadado, mas não pode fazer outro IP parecer online. As respostas XML têm DTD e resolução externa desativadas, além de limites de tamanho e quantidade.

## Tipo de dispositivo e sistema operativo

O tipo de equipamento e o sistema operativo provável são calculados a partir de sinais como hostname, fabricante, TTL, portas e serviços. Estes valores devem ser apresentados como “provável” ou “inferido”. Proxies, containers, equipamentos configurados manualmente e sistemas atualizados podem produzir classificações incorretas.

## Histórico e tempo

O histórico compara snapshots. Um dispositivo pode parecer novo quando muda de MAC, usa endereços aleatórios ou deixa de ter um MAC observável. Portas podem abrir ou fechar entre scans sem representar uma alteração permanente. Alias, notas e favoritos editados enquanto chegam resultados incrementais são preservados; iniciar outro scan ou limpar a lista exige confirmação quando existem alterações locais ainda não guardadas.

Os resultados são um retrato temporal, não monitorização contínua.

## Escala e impacto

Redes e intervalos grandes multiplicam pings, tentativas TCP, resolução de nomes e probes. Os perfis limitam concorrência e timeouts, mas um scan Avançado pode demorar e gerar muitos eventos nos equipamentos de segurança. A estimativa apresentada antes do início é um limite operacional aproximado; não inclui uma previsão temporal e identifica o Nmap como atividade adicional, porque essa ferramenta gere a sua própria execução.

Comece pelo perfil Rápido, confirme o intervalo e avance para Normal ou Avançado apenas quando necessário. Cancele o scan se a rede apresentar degradação.

## Permissões e portabilidade

O fluxo normal foi desenhado para uma conta sem elevação. Algumas propriedades do adaptador podem exigir permissões, suporte do driver ou ferramentas do Windows disponíveis. Um campo indisponível deve permanecer vazio ou desconhecido.

O executável self-contained inclui o runtime .NET, mas continua dependente de APIs e ferramentas do Windows. Não existe garantia de comportamento equivalente noutros sistemas operativos.

## Dados sensíveis

Snapshots e exportações podem conter IPs, MACs, SSIDs, BSSIDs, hostnames, fabricante/modelo, firmware, serial, serviços e portas. Estes dados permitem mapear e inventariar uma rede. Guarde-os com controlo de acesso e remova identificadores antes de pedir suporte público.

Não existe telemetria do produto. Os únicos pedidos externos fora do scan são ações explícitas, como abrir um link ou atualizar opcionalmente as listagens IEEE; a atualização obtém ficheiros públicos sem anexar o inventário da rede.

A [política de privacidade](../PRIVACY.md) documenta os ficheiros locais, comunicações, terceiros, retenção e eliminação. A SignPath informou que o projeto seria provavelmente problemático para o programa gratuito Foundation; nenhuma release atual foi assinada pela Foundation e não existe integração ativa. Consulte a [Code signing policy](../CODE_SIGNING_POLICY.md) antes de interpretar o estado de distribuição.

<!-- Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License. -->
