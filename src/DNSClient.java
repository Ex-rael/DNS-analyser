import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Cliente DNS sobre UDP (porta 53) — Parte 1 do trabalho.
 *
 * Correlação com requisitos:
 *  - §2.1: usa exclusivamente UDP/53; sem bibliotecas de abstração DNS
 *  - §2.2: query() realiza a consulta a um servidor individual; registra tempo e erros
 *  - §2.4: queryMultiple() repete N consultas para avaliação de desempenho
 */
public class DNSClient {

    private static final int DNS_PORT   = 53;
    private static final int TIMEOUT_MS = 2000;   // §2.2: falhas de timeout
    private static final int BUFFER_SIZE = 1024;  // suficiente para respostas UDP tipicas

    /**
     * Realiza uma única consulta DNS via UDP (§2.1 e §2.2).
     * Registra o tempo de resposta e qualquer falha (timeout, recusa).
     */
    public DNSResult query(String dnsServer, String domain) {

        DNSResult result = new DNSResult();
        result.server = dnsServer;

        // try-with-resources garante fechamento do socket mesmo em caso de exceção
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(TIMEOUT_MS);

            byte[] query = DNSMessageBuilder.buildQuery(domain);

            InetAddress address = InetAddress.getByName(dnsServer);
            DatagramPacket packet = new DatagramPacket(query, query.length, address, DNS_PORT);

            long start = System.currentTimeMillis();
            socket.send(packet);

            byte[] buffer = new byte[BUFFER_SIZE];
            DatagramPacket response = new DatagramPacket(buffer, buffer.length);
            socket.receive(response);

            result.timeMs = System.currentTimeMillis() - start;

            byte[] responseData = Arrays.copyOf(response.getData(), response.getLength());
            DNSResponseParser.parse(responseData, result);

        } catch (SocketTimeoutException e) {
            result.error = "timeout";          // §2.2: registrar timeout
        } catch (Exception e) {
            result.error = e.getMessage();     // §2.2: registrar outras falhas
        }

        return result;
    }

    /**
     * Executa N consultas ao mesmo servidor/domínio para avaliação de desempenho (§2.4).
     * Calcula média, mínimo, máximo e taxa de perda a partir da lista retornada.
     */
    public List<DNSResult> queryMultiple(String dnsServer, String domain, int count) {
        List<DNSResult> results = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            results.add(query(dnsServer, domain));
        }
        return results;
    }
}
