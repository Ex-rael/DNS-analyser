import java.util.*;
import java.util.stream.*;

/**
 * Ponto de entrada da ferramenta DNS Analyser — PUCRS, Lab. de Redes de Computadores.
 *
 * Executa as três partes do trabalho em sequência:
 *   Parte 1 §2.2 — Scanner DNS multi-servidor (todos os dominos de teste)
 *   Parte 1 §2.4 — Avaliação de desempenho (10 consultas × todos os servidores)
 *   Parte 3 §4   — DNS over TLS com comparação vs UDP
 *
 * Uso: java Main [dominio]
 *   Sem argumento → executa todos os domínios de teste (§6)
 *   Com argumento → executa apenas o domínio fornecido
 */
public class Main {

    // =========================================================
    //  Servidores DNS — Seção 5 do trabalho
    //  Formato de cada entrada: { IP, nome, categoria }
    // =========================================================
    static final String[][] DNS_SERVERS = {
        // Sem filtragem
        {"8.8.8.8",          "Google DNS",              "Sem filtro"},
        {"8.8.4.4",          "Google DNS (sec.)",       "Sem filtro"},
        {"1.1.1.1",          "Cloudflare",              "Sem filtro"},
        {"1.0.0.1",          "Cloudflare (sec.)",       "Sem filtro"},
        {"9.9.9.10",         "Quad9 (sem filtro)",      "Sem filtro"},
        {"64.6.64.6",        "Verisign",                "Sem filtro"},
        // Com filtragem de segurança (malware/phishing)
        {"9.9.9.9",          "Quad9",                   "Segurança"},
        {"208.67.222.222",   "OpenDNS",                 "Segurança"},
        {"185.228.168.9",    "CleanBrowsing Security",  "Segurança"},
        {"94.140.14.14",     "AdGuard DNS",             "Segurança"},
        // Com filtragem familiar (adulto + segurança)
        {"1.1.1.3",          "Cloudflare Family",       "Familiar"},
        {"208.67.222.123",   "OpenDNS FamilyShield",    "Familiar"},
        {"185.228.168.168",  "CleanBrowsing Family",    "Familiar"},
        {"94.140.14.15",     "AdGuard Family",          "Familiar"},
        // Adicionais — mínimo 5 extras exigidos pela Seção 5
        {"76.76.2.0",        "Control D",               "Adicional"},
        {"8.26.56.26",       "Comodo Secure DNS",       "Adicional"},
        {"156.154.70.1",     "Neustar/Vercara",         "Adicional"},
        {"84.200.69.80",     "DNS.Watch",               "Adicional"},
        {"198.101.242.72",   "Alternate DNS",           "Adicional"},
        {"45.90.28.0",       "NextDNS",                 "Adicional"},
    };

    // =========================================================
    //  Domínios de teste — Seção 6 do trabalho
    //  Formato: { domínio, propósito }
    // =========================================================
    static final String[][] TEST_DOMAINS = {
        {"www.example.com",     "Controle — nenhum bloqueio esperado"},
        {"www.pucrs.br",        "Controle regional"},
        {"internetbadguys.com", "Bloqueado por filtros de segurança (OpenDNS)"},
        {"reddit.com",          "Possível bloqueio por filtros familiares"},
        // Adicionais — mínimo 3 extras exigidos pela Seção 6
        {"www.google.com",      "Controle adicional"},
        {"thepiratebay.org",    "Frequentemente bloqueado por ISPs"},
        {"www.youtube.com",     "Controle popular"},
    };

    /** Domínio de controle para avaliação de desempenho (§2.4) */
    static final String PERF_DOMAIN  = "www.example.com";

    /** Número mínimo de consultas por servidor exigido pela §2.4 */
    static final int    PERF_QUERIES = 10;

    // =========================================================
    //  Servidores DoT — Seção 4.1 do trabalho
    //  Formato: { hostname DoT, nome, IP UDP equivalente }
    // =========================================================
    static final String[][] DOT_SERVERS = {
        {"dns.google",      "Google DoT",     "8.8.8.8"},
        {"one.one.one.one", "Cloudflare DoT", "1.1.1.1"},
        {"dns.quad9.net",   "Quad9 DoT",      "9.9.9.9"},
    };

    // =========================================================
    //  main
    // =========================================================
    public static void main(String[] args) throws Exception {

        String singleDomain = args.length > 0 ? args[0] : null;
        DNSClient client = new DNSClient();

        printBanner();

        // ── Parte 1 §2.2 e §2.3: Scanner + detecção de bloqueio ──────────
        printSection("PARTE 1 — SCANNER DNS MULTI-SERVIDOR  (§2.2 / §2.3)");

        String[][] domainsToScan = singleDomain != null
                ? new String[][]{{singleDomain, "Entrada do usuário"}}
                : TEST_DOMAINS;

        for (String[] entry : domainsToScan) {
            runScanner(client, entry[0], entry[1]);
        }

        // ── Parte 1 §2.4: Avaliação de desempenho ────────────────────────
        printSection("PARTE 1 — AVALIAÇÃO DE DESEMPENHO  (§2.4) — "
                + PERF_QUERIES + " consultas por servidor");
        runPerformance(client, PERF_DOMAIN, PERF_QUERIES);

        // ── Parte 3 §4: DNS over TLS ──────────────────────────────────────
        printSection("PARTE 3 — DNS OVER TLS  (§4) — comparação DoT vs UDP");
        runDoT(PERF_DOMAIN, PERF_QUERIES);
    }

    // =========================================================
    //  Parte 1 §2.2 / §2.3 — Scanner multi-servidor
    // =========================================================

    /**
     * Consulta todos os servidores DNS para um domínio e exibe os resultados,
     * detectando bloqueios conforme §2.3.
     */
    static void runScanner(DNSClient client, String domain, String purpose) {
        System.out.printf("%n>>> Domínio: %-35s [%s]%n", domain, purpose);
        printLine(125);
        System.out.printf("%-20s %-26s %-14s %-11s %9s  %-28s%n",
                "Servidor IP", "Nome", "Categoria", "RCODE", "Tempo(ms)", "IPs / Detalhe");
        printLine(125);

        // Coleta resultados de todos os servidores
        List<DNSResult> results = new ArrayList<>(DNS_SERVERS.length);
        for (String[] srv : DNS_SERVERS) {
            DNSResult r = client.query(srv[0], domain);
            r.server     = srv[0];
            r.serverName = srv[1];
            results.add(r);
        }

        // Determina IP de consenso para detecção de IP divergente (§2.3)
        String consensusIp = detectConsensusIp(results);

        // Pré-calcula status para evitar recálculo (usado na contagem final)
        String[] statuses = new String[results.size()];
        for (int i = 0; i < results.size(); i++) {
            statuses[i] = blockStatus(results.get(i), consensusIp);
        }

        for (int i = 0; i < results.size(); i++) {
            DNSResult r  = results.get(i);
            String cat   = DNS_SERVERS[i][2];
            String status = statuses[i];

            String ipsStr  = r.hasError()             ? "(" + r.error + ")"
                           : r.ipAddresses.isEmpty()  ? "(sem registros A)"
                           : String.join(", ", r.ipAddresses);

            String timeStr = r.timeMs >= 0 ? r.timeMs + " ms" : "-";
            String tag     = status.equals("OK") ? "" : "  [" + status + "]";

            System.out.printf("%-20s %-26s %-14s %-11s %9s  %s%s%n",
                    r.server, r.serverName, cat,
                    r.rcodeLabel(), timeStr, ipsStr, tag);
        }

        printLine(125);

        // Resumo por domínio: consenso e contagem de bloqueios
        long blocked = Arrays.stream(statuses)
                .filter(s -> !s.equals("OK") && !s.equals("TIMEOUT/ERRO"))
                .count();
        long errors  = Arrays.stream(statuses).filter(s -> s.equals("TIMEOUT/ERRO")).count();

        System.out.printf("  Consenso IP: %-18s  Bloqueios detectados: %d  Timeouts/erros: %d  (total %d servidores)%n",
                consensusIp != null ? consensusIp : "indefinido",
                blocked, errors, results.size());
    }

    // =========================================================
    //  Parte 1 §2.4 — Avaliação de desempenho
    // =========================================================

    /**
     * Executa N consultas para cada servidor e exibe ranking por desempenho (§2.4).
     * Calcula: tempo médio, mínimo, máximo e taxa de perda.
     */
    static void runPerformance(DNSClient client, String domain, int n) {
        System.out.printf("%nDomínio de controle: %s  (%d consultas/servidor)%n%n", domain, n);

        List<double[]>  stats  = new ArrayList<>(DNS_SERVERS.length);
        List<String[]>  labels = new ArrayList<>(DNS_SERVERS.length);

        for (String[] srv : DNS_SERVERS) {
            List<DNSResult> results = client.queryMultiple(srv[0], domain, n);

            // Filtra apenas respostas bem-sucedidas para os cálculos
            List<Long> times = results.stream()
                    .filter(r -> !r.hasError() && r.timeMs >= 0)
                    .map(r -> r.timeMs)
                    .collect(Collectors.toList());

            double loss = (n - times.size()) * 100.0 / n;
            double avg  = times.isEmpty() ? Double.MAX_VALUE
                        : times.stream().mapToLong(Long::longValue).average().orElse(0);
            long   min  = times.isEmpty() ? -1 : times.stream().mapToLong(Long::longValue).min().orElse(-1);
            long   max  = times.isEmpty() ? -1 : times.stream().mapToLong(Long::longValue).max().orElse(-1);

            stats.add(new double[]{avg, min, max, loss});
            labels.add(new String[]{srv[0], srv[1]});
        }

        // Ordena por tempo médio — ranking §2.4
        List<Integer> ranking = IntStream.range(0, stats.size()).boxed()
                .sorted(Comparator.comparingDouble(i -> stats.get(i)[0]))
                .collect(Collectors.toList());

        System.out.printf("%-5s %-20s %-26s %10s %10s %10s %9s%n",
                "Rank", "Servidor IP", "Nome", "Media(ms)", "Min(ms)", "Max(ms)", "Perda(%)");
        printLine(100);

        int rank = 1;
        for (int i : ranking) {
            double[] s = stats.get(i);
            String[] l = labels.get(i);
            String avg = s[0] >= Double.MAX_VALUE ? "N/A" : String.format("%.1f", s[0]);
            String min = s[1] < 0 ? "N/A" : String.format("%.0f", s[1]);
            String max = s[2] < 0 ? "N/A" : String.format("%.0f", s[2]);
            System.out.printf("%-5d %-20s %-26s %10s %10s %10s %8.1f%%%n",
                    rank++, l[0], l[1], avg, min, max, s[3]);
        }
    }

    // =========================================================
    //  Parte 3 §4 — DNS over TLS
    // =========================================================

    /**
     * Executa consultas DoT e UDP para os mesmos servidores e compara desempenho (§4.2).
     * Evidencia também a diferença de privacidade: conteúdo cifrado vs. texto claro (§4.3).
     */
    static void runDoT(String domain, int n) {
        DNSDoTClient dotClient = new DNSDoTClient();
        DNSClient    udpClient = new DNSClient();

        System.out.printf("%nDomínio: %s  (%d consultas por protocolo/servidor)%n%n", domain, n);
        System.out.printf("%-20s %-18s %12s %12s %12s %9s%n",
                "Servidor", "Protocolo", "Media(ms)", "Min(ms)", "Max(ms)", "Perda(%)");
        printLine(92);

        for (String[] srv : DOT_SERVERS) {
            String hostname = srv[0];
            String name     = srv[1];
            String udpIp    = srv[2];

            // DoT (TCP/TLS porta 853) — §4.1
            printProtocolRow(name, "DoT (TCP/853)",
                    dotClient.queryMultiple(hostname, domain, n), n);

            // UDP equivalente para comparação direta — §4.2
            printProtocolRow(name, "UDP (porta 53)",
                    udpClient.queryMultiple(udpIp, domain, n), n);

            System.out.println();
        }

        // Observações para §4.3 — análise de tráfego DoT vs UDP
        System.out.println("Observacoes para analise de trafego (§4.3):");
        System.out.println("  - DNS UDP (porta 53): consulta visivel em texto claro no Wireshark.");
        System.out.println("  - DNS DoT (porta 853): payload cifrado por TLS — dominio NAO visivel.");
        System.out.println("  - DoT requer handshake TLS (~3 RTTs extras) => maior latencia inicial.");
        System.out.println("  - DoT gera mais pacotes por consulta (TCP SYN + TLS handshake + dados).");
    }

    // =========================================================
    //  Helpers — detecção de bloqueio (§2.3)
    // =========================================================

    /**
     * Determina o IP de consenso: primeiro IP mais frequente entre respostas NOERROR.
     * Servidores divergentes são candidatos a bloqueio por redirecionamento (§2.3).
     */
    static String detectConsensusIp(List<DNSResult> results) {
        Map<String, Integer> freq = new HashMap<>();
        for (DNSResult r : results) {
            if (!r.hasError() && r.rcode == 0 && !r.ipAddresses.isEmpty()) {
                freq.merge(r.ipAddresses.get(0), 1, Integer::sum);
            }
        }
        return freq.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(null);
    }

    /**
     * Classifica o status da resposta conforme critérios de bloqueio do §2.3:
     *   NXDOMAIN      — domínio declarado inexistente (quando maioria resolve normalmente)
     *   REFUSED       — servidor recusa a consulta
     *   IP_NULO       — retorno de 0.0.0.0 ou 127.0.0.1
     *   IP_DIVERGENTE — IP diferente do consenso (possível redirecionamento)
     *   TIMEOUT/ERRO  — sem resposta ou erro de rede
     *   OK            — resposta normal
     */
    static String blockStatus(DNSResult r, String consensusIp) {
        if (r.hasError())            return "TIMEOUT/ERRO";
        if (r.rcode == 3)            return "NXDOMAIN";
        if (r.rcode == 5)            return "REFUSED";
        if (!r.ipAddresses.isEmpty()) {
            for (String ip : r.ipAddresses) {
                if (ip.equals("0.0.0.0") || ip.equals("127.0.0.1")) return "IP_NULO";
            }
            if (consensusIp != null && !r.ipAddresses.contains(consensusIp)) {
                return "IP_DIVERGENTE";
            }
        }
        return "OK";
    }

    // =========================================================
    //  Helpers — formatação
    // =========================================================

    static void printProtocolRow(String name, String proto, List<DNSResult> results, int n) {
        List<Long> times = results.stream()
                .filter(r -> !r.hasError() && r.timeMs >= 0)
                .map(r -> r.timeMs)
                .collect(Collectors.toList());

        double loss  = (n - times.size()) * 100.0 / n;
        String avg   = times.isEmpty() ? "N/A"
                     : String.format("%.1f", times.stream().mapToLong(Long::longValue).average().orElse(0));
        String min   = times.isEmpty() ? "N/A"
                     : String.valueOf(times.stream().mapToLong(Long::longValue).min().orElse(-1));
        String max   = times.isEmpty() ? "N/A"
                     : String.valueOf(times.stream().mapToLong(Long::longValue).max().orElse(-1));

        System.out.printf("%-20s %-18s %12s %12s %12s %8.1f%%%n",
                name, proto, avg, min, max, loss);
    }

    static void printBanner() {
        System.out.println("=".repeat(68));
        System.out.println("  DNS Analyser — Analise de Censura, Desempenho e Privacidade");
        System.out.println("  PUCRS — Escola Politecnica — Laboratorio de Redes");
        System.out.println("=".repeat(68));
        System.out.println("  Uso: java Main [dominio]");
        System.out.println("       Sem argumento: executa todos os dominios de teste (§6)");
        System.out.println("=".repeat(68));
    }

    static void printSection(String title) {
        System.out.printf("%n%s%n  %s%n%s%n", "=".repeat(70), title, "=".repeat(70));
    }

    static void printLine(int len) {
        System.out.println("-".repeat(len));
    }
}

