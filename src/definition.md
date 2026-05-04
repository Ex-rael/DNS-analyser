Pontifícia Universidade Católica do Rio Grande do Sul
Escola Politécnica
Laboratório de Redes de Computadores
Trabalho 1 - Análise de DNS: Censura, Desempenho e Privacidade
O sistema de resolução de nomes da Internet, o Domain Name System (DNS),
tradicionalmente opera sobre UDP na porta 53, sem criptografia. As consultas DNS
percorrem a rede em texto claro, o que permite a intermediários, como provedores de
acesso (ISPs), administradores de rede e serviços de DNS público, observar, interceptar e
até manipular as respostas.
Diversos provedores de DNS público oferecem servidores com diferentes políticas de
filtragem: alguns bloqueiam domínios associados a malware e phishing, outros bloqueiam
conteúdo adulto, e alguns não aplicam nenhum filtro. Já os ISPs brasileiros operam
servidores DNS recursivos que podem aplicar bloqueios por determinação judicial.
O aumento das preocupações com privacidade e segurança levou ao desenvolvimento de
versões criptografadas do DNS:
•
•
DNS over TLS (DoT) - DNS criptografado sobre TLS, porta 853 (RFC 7858)
DNS over HTTPS (DoH) - DNS encapsulado em HTTPS, porta 443 (RFC 8484)
Isso significa que a resposta para uma mesma consulta DNS pode variar conforme o
servidor utilizado, e que a visibilidade do tráfego depende do protocolo utilizado, o
que levanta questões importantes sobre censura, transparência e privacidade na Internet.
1. Objetivo do Trabalho
Desenvolver uma ferramenta para análise de resolução DNS, organizada em três partes
progressivas:
1.
2.
3.
Scanner DNS multi-servidor (UDP) — consultar múltiplos servidores DNS para um
mesmo domínio, detectar bloqueios e avaliar desempenho.
Análise de tráfego — capturar e analisar o tráfego gerado com Wireshark,
avaliando a visibilidade das consultas.
Privacidade com DNS over TLS (extra) — estender a ferramenta para suportar
consultas criptografadas via DoT e comparar com o DNS tradicional.
Parte 1 — Scanner DNS sobre UDP
2.1 Comunicação DNS
•
Usar exclusivamente UDP na porta 53 para comunicação com os servidores DNS.
•
Construir as mensagens de consulta DNS em formato binário conforme a RFC
1035.•
•
Interpretar as respostas binárias recebidas, extraindo: código de resposta (RCODE),
endereços IP retornados (registros tipo A) e demais informações relevantes.
Não utilizar biblioteca, módulo ou framework (seja nativo da linguagem ou de
terceiros) que realize a abstração da montagem ou do parsing do protocolo DNS,
como por exemplo, dnspython (Python), net.Resolver (Go), dns (Node.js),
gethostbyname, JNDI/DNS (Java), ou qualquer função que receba uma string (ex:
"www.pucrs.br") e devolva o IP automaticamente. A construção e interpretação das
mensagens deve ser feita pelo aluno.
2.2 Consulta Multi-Servidor
•
A ferramenta deve aceitar um nome de domínio como entrada e consultá-lo em
todos os servidores DNS configurados.
•
Para cada servidor, registrar: resposta obtida (IPs, RCODE), tempo de resposta e
eventuais falhas (timeout, recusa).
•
Exibir os resultados de forma organizada, permitindo a comparação visual entre
servidores.
2.3 Detecção de Bloqueio
A ferramenta deve ser capaz de identificar respostas que indicam bloqueio ou manipulação,
como:
•
•
•
•
NXDOMAIN (domínio não existe) — quando a maioria dos servidores resolve
normalmente.
REFUSED — o servidor recusa a consulta.
IP divergente — o servidor retorna um IP diferente do consenso (possível
redirecionamento para página de aviso).
Endereços nulos — respostas como 0.0.0.0 ou 127.0.0.1.
2.4 Avaliação de Desempenho
•
Executar pelo menos 10 consultas por servidor para um domínio de controle (ex:
www.example.com).
•
Para cada servidor, calcular: tempo médio, tempo mínimo, tempo máximo e taxa
de perda.
•
Gerar um ranking dos servidores ordenado por desempenho.
Parte 2 — Análise de Tráfego com Wireshark
Utilizando a ferramenta desenvolvida na Parte 1, capturar o tráfego de rede com o
Wireshark (ou tcpdump) durante a execução de consultas DNS.
3.1 Captura
•
Capturar o tráfego durante a consulta de pelo menos 2 domínios (um de controle e
um bloqueado por algum servidor).
•
Filtrar o tráfego pela porta 53 (UDP).3.2 Análise
A partir da captura, observe e análise:
•
•
•
•
Os endereços IP de origem e destino das consultas.
As portas utilizadas.
O conteúdo das consultas e respostas DNS — é possível visualizar o domínio
consultado?
O número e tamanho dos pacotes enviados e recebidos por consulta.
3.3 Capturas de Tela
Incluir no relatório capturas de tela do Wireshark deixando destacado:
•
•
Uma consulta DNS e sua respectiva resposta.
O conteúdo decodificado (domínio consultado, IP retornado).
Parte 3 — DNS over TLS
Estender a ferramenta para suportar DNS over TLS (DoT), adicionando uma camada de
criptografia às consultas DNS.
4.1 Implementação do Cliente DoT
•
Utilizar TLS sobre TCP.
•
Conectar-se aos servidores públicos na porta 853.
•
Enviar as consultas DNS no formato binário, precedidas por um prefixo de 2 bytes
com o tamanho da mensagem (conforme RFC 7858).
•
Receber e interpretar a resposta.
Servidores que suportam DoT:
Servidor
Google
Cloudflare
Quad9
Hostname DoT
dns.google
one.one.one.one
dns.quad9.net
4.2 Comparação de Desempenho
•
Executar pelo menos 10 consultas para o mesmo domínio usando UDP (Parte 1) e
DoT (Parte 3).
•
Comparar os tempos de resposta entre os dois protocolos.
4.3 Análise de Tráfego (DoT vs. UDP)
•
Capturar o tráfego DoT com Wireshark e comparar com a captura da Parte 2.
•
O conteúdo da consulta DNS é visível no tráfego DoT?
•
Quantos pacotes e bytes são necessários para uma consulta DoT vs. UDP?
4.4 Restrições Técnicas (Parte 3)
•
Pode utilizar o módulo ssl de bibliotecas padrão da linguagem escolhida.
•
Não é necessário implementar DoH (DNS over HTTPS).5. Servidores DNS
A lista inicial de servidores a serem testados inclui os seguintes. O aluno deve incluir pelo
menos 5 servidores adicionais de sua escolha (outros provedores públicos, ISPs
brasileiros, servidores regionais, etc.):
Sem filtragem
Servidor
Google Public DNS
Google Public DNS (secundário)
Cloudflare
Cloudflare (secundário)
Quad9 (sem filtro)
Verisign
IP
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.10
64.6.64.6
Com filtragem de segurança (malware/phishing)
Servidor
IP
Quad9
9.9.9.9
OpenDNS
208.67.222.222
CleanBrowsing Security 185.228.168.9
AdGuard DNS
94.140.14.14
Com filtragem familiar (adulto + segurança)
Servidor
IP
Cloudflare Family
1.1.1.3
OpenDNS FamilyShield 208.67.222.123
CleanBrowsing Family
185.228.168.168
AdGuard Family
94.140.14.15
Sugestões de servidores adicionais: DNS de ISPs brasileiros (Vivo, Claro, TIM, Oi),
Control D (76.76.2.0), Comodo Secure (8.26.56.26), DNS do próprio sistema operacional
do aluno.
6. Domínios de Teste
Os seguintes domínios devem ser incluídos na análise. O aluno deve acrescentar pelo
menos 3 domínios adicionais de sua escolha para enriquecer o estudo:
Domínio
Propósito
www.example.com
Controle — nenhum servidor deveria bloquear
www.pucrs.br
Controle regional
internetbadguys.com Domínio de teste do OpenDNS — bloqueado por filtros de
segurança
reddit.com
Rede social — potencialmente bloqueado por filtros familiaresDomínio
tinder.com
polymarket.com
Propósito
Aplicativo de encontros — potencialmente bloqueado por filtros
familiares
Mercado de previsões — bloqueado no Brasil por ordem judicial
(Anatel)
O aluno pode pesquisar e incluir outros domínios que estejam sujeitos a bloqueio judicial
no Brasil ou que sejam filtrados por políticas de diferentes provedores DNS.
7. Relatório e Questões
O relatório técnico deve apresentar os resultados e uma análise crítica abordando:
7.1 Análise de Bloqueio (Parte 1)
•
Para cada domínio testado, apresentar uma tabela comparativa com as respostas
de todos os servidores.
•
Quais servidores bloquearam quais domínios? Com qual técnica (NXDOMAIN,
redirecionamento, recusa)?
•
Existe consenso entre filtros da mesma categoria?
•
É possível contornar um bloqueio DNS trocando o servidor?
7.2 Análise de Desempenho (Parte 1)
•
Apresentar o ranking de desempenho dos servidores em tabela.
•
Quais servidores apresentam menor latência? O que pode explicar as diferenças?
•
A filtragem afeta o tempo de resposta?
7.3 Análise de Tráfego (Parte 2)
•
Incluir capturas de tela do Wireshark com os destaques.
•
O conteúdo das consultas DNS é visível no tráfego capturado?
•
Quais informações um intermediário (ISP, atacante) poderia extrair observando o
tráfego?
7.4 Questões para Reflexão
1. O DNS tradicional (UDP, porta 53) oferece privacidade ao usuário? Justifique.
2. O bloqueio por DNS é eficaz como mecanismo de censura? O usuário pode
contorná-lo? Como?
3. Qual a diferença entre um DNS público (ex: Google, Cloudflare) e um DNS de ISP?
Qual o aluno usa atualmente?
4. Se dois servidores retornam IPs diferentes para o mesmo domínio, como determinar
qual resposta é legítima?
7.5 Questões Adicionais — Parte 3
Para os alunos que implementarem o cliente DoT:
5.
Qual abordagem apresenta menor latência: DNS/UDP ou DNS/TLS? Qual
apresenta maior overhead?6.
7.
8.
O conteúdo das consultas DNS é visível no tráfego DoT capturado pelo Wireshark
(mostrar imagens com os destaques)?
O DoT é mais fácil ou mais difícil de bloquear do que o DNS tradicional? Por quê?
Qual protocolo oferece maior privacidade ao usuário?
8. Entrega e Apresentação
Grupos: Até 3 componentes.
Data Entrega e apresentação: 18/05 (Todos os participantes devem estar presentes)
Entrega no Moodle: Arquivo .zip, com o nome de todos os integrantes do grupo, contendo:
1.
2.
3.
4.
Código-fonte da ferramenta desenvolvida.
Relatório técnico em formato PDF contendo:
–
Descrição da ferramenta e como utilizá-la
–
Tabelas comparativas de resolução por domínio
–
Ranking de desempenho
–
Capturas de tela do Wireshark com os destaques (Parte 2 e Parte 3)
–
Comparação UDP vs. DoT (Parte 3)
–
Análise crítica respondendo às questões propostas
Arquivo(s) de dados (CSV ou similar) com os resultados brutos das consultas.
README com instruções de execução.
IMPORTANTE: Não serão aceitos trabalhos entregues fora do prazo. Não serão aceitos
trabalhos de pessoas que não estiverem em um grupo. Apenas um integrante de cada
grupo deverá realizar a entrega. Trabalhos que não compilam ou que não executam não
serão avaliados. Todos os trabalhos serão analisados e comparados. Caso seja identificada
cópia de trabalhos, todos os trabalhos envolvidos receberão nota ZERO.
Referências
•
•
•
•
•
•
•
•
•
RFC 1035 — Domain Names: Implementation and Specification
RFC 7858 — DNS over Transport Layer Security (DoT)
RFC 8484 — DNS Queries over HTTPS (DoH)
Google Public DNS: https://developers.google.com/speed/public-dns
Cloudflare DNS: https://developers.cloudflare.com/1.1.1.1/
Quad9: https://quad9.net/
OpenDNS: https://www.opendns.com/
CleanBrowsing: https://cleanbrowsing.org/
AdGuard DNS: https://adguard-dns.io/