import javax.net.ssl.*;
import java.io.*;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Cliente DNS over TLS (DoT) — Parte 3 do trabalho (§4).
 *
 * Diferenças em relação ao DNSClient (UDP):
 *  - §4.1: usa TLS sobre TCP (SSLSocket) em vez de DatagramSocket/UDP
 *  - §4.1: porta 853 (RFC 7858) em vez de porta 53
 *  - §4.1: cada mensagem DNS é precedida por 2 bytes com o seu tamanho (RFC 7858 §3.3)
 *  - §4.1: a resposta também começa com 2 bytes de comprimento antes do payload DNS
 *
 * Módulo ssl/TLS da biblioteca padrão Java (SSLSocket) — permitido por §4.4.
 * A construção e interpretação do payload DNS binário continua sendo feita
 * manualmente (DNSMessageBuilder e DNSResponseParser), conforme §2.1.
 */
public class DNSDoTClient {

    private static final int DOT_PORT   = 853;    // RFC 7858 (§4.1)
    private static final int TIMEOUT_MS = 5000;   // TLS tem handshake adicional

    /**
     * Realiza uma única consulta DoT (§4.1).
     * Conecta ao hostname via TLS, envia a consulta DNS binária com prefixo de 2 bytes
     * e interpreta a resposta.
     *
     * @param hostname  Hostname do servidor DoT (ex: "dns.google") — necessário para SNI
     * @param domain    Domínio a consultar
     */
    public DNSResult query(String hostname, String domain) {

        DNSResult result = new DNSResult();
        result.server = hostname;

        // SSLSocketFactory usa o truststore padrão da JVM (CA raízes confiáveis)
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, DOT_PORT)) {
            socket.setSoTimeout(TIMEOUT_MS);
            // Handshake TLS explícito; também configura SNI automaticamente pelo hostname
            socket.startHandshake();

            OutputStream out = socket.getOutputStream();
            InputStream  in  = socket.getInputStream();

            byte[] dnsQuery = DNSMessageBuilder.buildQuery(domain);

            // Prefixo de 2 bytes com o comprimento da mensagem DNS (RFC 7858 §3.3)
            out.write((dnsQuery.length >> 8) & 0xFF);
            out.write(dnsQuery.length & 0xFF);

            long start = System.currentTimeMillis();
            out.write(dnsQuery);
            out.flush();

            // Ler os 2 bytes de comprimento da resposta
            int hi = in.read();
            int lo = in.read();
            if (hi < 0 || lo < 0) {
                result.error = "conexão encerrada pelo servidor";
                return result;
            }
            int responseLen = (hi << 8) | lo;

            // Ler o payload DNS completo (pode exigir múltiplas leituras sobre TCP)
            byte[] responseData = new byte[responseLen];
            int bytesRead = 0;
            while (bytesRead < responseLen) {
                int n = in.read(responseData, bytesRead, responseLen - bytesRead);
                if (n < 0) break;
                bytesRead += n;
            }

            result.timeMs = System.currentTimeMillis() - start;

            // Mesmo parser binário RFC 1035 do DNS tradicional (§2.1)
            DNSResponseParser.parse(Arrays.copyOf(responseData, bytesRead), result);

        } catch (SocketTimeoutException e) {
            result.error = "timeout";
        } catch (Exception e) {
            result.error = e.getMessage();
        }

        return result;
    }

    /**
     * Executa N consultas DoT para avaliação de desempenho comparativa (§4.2).
     */
    public List<DNSResult> queryMultiple(String hostname, String domain, int count) {
        List<DNSResult> results = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            results.add(query(hostname, domain));
        }
        return results;
    }
}
