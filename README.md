# DNS Analyser — Análise de Censura, Desempenho e Privacidade

**PUCRS — Escola Politécnica — Laboratório de Redes de Computadores**  
Trabalho 1 — DNS: Censura, Desempenho e Privacidade

---

## Descrição

Ferramenta em Java para análise de resolução DNS, implementada do zero sobre UDP/53 e TLS/853, sem uso de bibliotecas de abstração DNS. Cobre as três partes do trabalho:

- **Parte 1** — Scanner DNS multi-servidor com detecção de bloqueio e ranking de desempenho
- **Parte 2** — Geração de tráfego para captura e análise no Wireshark
- **Parte 3** — Cliente DNS over TLS (DoT) com comparação de desempenho vs UDP

---

## Requisitos

| Componente | Versão mínima |
|---|---|
| Java (JDK) | 11 |
| Sistema operacional | Linux, macOS ou Windows |

Sem dependências externas. Apenas a biblioteca padrão do Java é utilizada.

---

## Compilação

Compile todos os arquivos `.java` de uma vez no diretório do projeto:

```bash
javac *.java
```

---

## Execução

### Modo completo (todos os domínios de teste)

```bash
java Main
```

Executa o scanner para todos os 9 domínios da Seção 6, avaliação de desempenho (10 consultas × 20 servidores) e comparação DoT vs UDP.

### Modo domínio único

```bash
java Main www.exemplo.com
```

Executa o scanner apenas para o domínio informado (útil para testes rápidos ou durante a captura com Wireshark).

---

## Saída

### Console

A execução imprime três seções:

1. **Scanner multi-servidor** — tabela por domínio com RCODE, tempo de resposta, IPs retornados e status de bloqueio detectado (`NXDOMAIN`, `REFUSED`, `IP_NULO`, `IP_DIVERGENTE` ou `OK`).
2. **Ranking de desempenho** — servidores ordenados por tempo médio (média, mín, máx, taxa de perda).
3. **Comparação DoT vs UDP** — latência de cada servidor via DNS over TLS e via UDP.

### Arquivos CSV (gerados automaticamente)

| Arquivo | Conteúdo |
|---|---|
| `dns_scanner_results.csv` | Resultados brutos do scanner: um registro por servidor por domínio |
| `dns_performance_results.csv` | Estatísticas de desempenho UDP e DoT |

Os arquivos são criados no diretório de execução ao final de cada rodada.

#### Colunas — `dns_scanner_results.csv`

```
timestamp, dominio, proposito, servidor_ip, servidor_nome, categoria,
rcode, tempo_ms, ips, status_bloqueio
```

#### Colunas — `dns_performance_results.csv`

```
tipo, timestamp, dominio, servidor_ip, servidor_nome, categoria,
media_ms, min_ms, max_ms, perda_pct
```

---

## Estrutura do projeto

```
.
├── Main.java               # Ponto de entrada; orquestra as 3 partes
├── DNSClient.java          # Cliente UDP/53 (Parte 1 — §2.1)
├── DNSDoTClient.java       # Cliente DoT TLS/853 (Parte 3 — §4.1)
├── DNSMessageBuilder.java  # Monta mensagens DNS binárias (RFC 1035)
├── DNSResponseParser.java  # Parseia respostas DNS binárias (RFC 1035)
├── DNSResult.java          # Modelo de resultado de uma consulta
└── README.md               # Este arquivo
```

---

## Servidores DNS testados (Seção 5)

| IP | Nome | Categoria |
|---|---|---|
| 8.8.8.8 | Google DNS | Sem filtro |
| 8.8.4.4 | Google DNS (sec.) | Sem filtro |
| 1.1.1.1 | Cloudflare | Sem filtro |
| 1.0.0.1 | Cloudflare (sec.) | Sem filtro |
| 9.9.9.10 | Quad9 (sem filtro) | Sem filtro |
| 64.6.64.6 | Verisign | Sem filtro |
| 9.9.9.9 | Quad9 | Segurança |
| 208.67.222.222 | OpenDNS | Segurança |
| 185.228.168.9 | CleanBrowsing Security | Segurança |
| 94.140.14.14 | AdGuard DNS | Segurança |
| 1.1.1.3 | Cloudflare Family | Familiar |
| 208.67.222.123 | OpenDNS FamilyShield | Familiar |
| 185.228.168.168 | CleanBrowsing Family | Familiar |
| 94.140.14.15 | AdGuard Family | Familiar |
| 76.76.2.0 | Control D | Adicional |
| 8.26.56.26 | Comodo Secure DNS | Adicional |
| 156.154.70.1 | Neustar/Vercara | Adicional |
| 84.200.69.80 | DNS.Watch | Adicional |
| 198.101.242.72 | Alternate DNS | Adicional |
| 45.90.28.0 | NextDNS | Adicional |

---

## Domínios de teste (Seção 6)

| Domínio | Propósito |
|---|---|
| www.example.com | Controle — nenhum bloqueio esperado |
| www.pucrs.br | Controle regional |
| internetbadguys.com | Bloqueado por filtros de segurança (OpenDNS) |
| reddit.com | Possível bloqueio por filtros familiares |
| tinder.com | Possível bloqueio por filtros familiares |
| polymarket.com | Bloqueado no Brasil por ordem judicial (Anatel) |
| www.google.com | Controle adicional |
| thepiratebay.org | Frequentemente bloqueado por ISPs |
| www.youtube.com | Controle popular |

---

## Captura com Wireshark (Parte 2)

Para capturar o tráfego DNS durante a execução:

1. Abra o Wireshark e selecione a interface de rede ativa (ex: `eth0`, `wlan0`).
2. Aplique o filtro: `udp.port == 53`
3. Inicie a captura e execute a ferramenta em outro terminal:
   ```bash
   java Main www.example.com
   java Main internetbadguys.com
   ```
4. Para capturar tráfego DoT (Parte 3), use o filtro: `tcp.port == 853`

---

## Referências

- RFC 1035 — Domain Names: Implementation and Specification
- RFC 7858 — DNS over Transport Layer Security (DoT)
- RFC 8484 — DNS Queries over HTTPS (DoH)