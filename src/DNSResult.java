import java.util.ArrayList;
import java.util.List;

/**
 * Resultado de uma consulta DNS.
 * Correlação com requisitos:
 *  - §2.2: server, serverName, timeMs, rcode, ipAddresses
 *  - §2.3: rcodeLabel() e hasError() suportam detecção de bloqueio
 *  - §2.4: timeMs alimenta o cálculo de desempenho
 */
public class DNSResult {

    /** IP ou hostname do servidor consultado (§2.2) */
    public String server = "";

    /** Nome amigável do servidor (ex: "Google DNS") */
    public String serverName = "";

    /** Tempo de resposta em milissegundos (§2.4) */
    public long timeMs = -1;

    /** Código de resposta DNS — RCODE (§2.3) */
    public int rcode = -1;

    /** Endereços IP retornados — registros tipo A (§2.1) */
    public List<String> ipAddresses = new ArrayList<>();

    /** Mensagem de erro (timeout, recusa de conexão etc.) */
    public String error;

    /**
     * Rótulo textual do RCODE conforme RFC 1035 (§2.3).
     * NXDOMAIN (3) e REFUSED (5) são indicadores primários de bloqueio.
     */
    public String rcodeLabel() {
        switch (rcode) {
            case 0:  return "NOERROR";
            case 1:  return "FORMERR";
            case 2:  return "SERVFAIL";
            case 3:  return "NXDOMAIN";
            case 5:  return "REFUSED";
            default: return rcode >= 0 ? "RCODE(" + rcode + ")" : "-";
        }
    }

    /** Indica se a consulta falhou por erro de rede (§2.2 — eventuais falhas). */
    public boolean hasError() {
        return error != null && !error.isEmpty();
    }
}