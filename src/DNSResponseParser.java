import java.util.ArrayList;
import java.util.List;

/**
 * Parseia respostas DNS binárias conforme RFC 1035 — §2.1 do trabalho.
 *
 * Extrai:
 *  - RCODE (§2.1 e §2.3): código de resposta para detecção de bloqueio
 *  - Registros tipo A (§2.1): endereços IPv4 retornados pelo servidor
 *
 * Restrição §2.1: interpretação manual do binário, sem bibliotecas DNS.
 */
public class DNSResponseParser {

    public static void parse(byte[] data, DNSResult result) {

        if (data.length < 12) {
            result.error = "resposta muito curta";
            return;
        }

        // RCODE: últimos 4 bits do byte 3 do cabeçalho (RFC 1035 §4.1.1)
        // Valores relevantes para §2.3: 0=NOERROR, 3=NXDOMAIN, 5=REFUSED
        result.rcode = data[3] & 0x0F;

        // ANCOUNT: número de registros na seção de respostas (bytes 6-7)
        int answerCount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);

        // Pular cabeçalho (12 bytes fixos) e seção de questão
        int index = 12;
        index = skipName(data, index);
        index += 4; // QTYPE (2 bytes) + QCLASS (2 bytes)

        List<String> ips = new ArrayList<>();

        for (int i = 0; i < answerCount && index < data.length; i++) {

            // Pular nome do registro de resposta (pode usar compressão — RFC 1035 §4.1.4)
            index = skipName(data, index);

            if (index + 10 > data.length) break;

            int type = ((data[index] & 0xFF) << 8) | (data[index + 1] & 0xFF);
            index += 2; // TYPE
            index += 2; // CLASS
            index += 4; // TTL

            int dataLength = ((data[index] & 0xFF) << 8) | (data[index + 1] & 0xFF);
            index += 2;

            if (index + dataLength > data.length) break;

            if (type == 1 && dataLength == 4) {
                // Registro A: 4 bytes IPv4 (§2.1 — extrair endereços IP retornados)
                String ip = (data[index]     & 0xFF) + "." +
                            (data[index + 1] & 0xFF) + "." +
                            (data[index + 2] & 0xFF) + "." +
                            (data[index + 3] & 0xFF);
                ips.add(ip);
            }
            // Outros tipos (CNAME, MX, etc.) são ignorados; index avança normalmente

            index += dataLength;
        }

        result.ipAddresses = ips;
    }

    /**
     * Avança o índice além de um nome DNS, tratando ponteiros de compressão (RFC 1035 §4.1.4).
     * Suporta nomes com labels simples, ponteiros, e a combinação de ambos.
     */
    private static int skipName(byte[] data, int index) {
        while (index < data.length) {
            int len = data[index] & 0xFF;
            if (len == 0) {
                return index + 1;          // fim do nome (byte nulo)
            }
            if ((len & 0xC0) == 0xC0) {
                return index + 2;          // ponteiro de compressão: 2 bytes, fim da sequência
            }
            index += len + 1;              // label: comprimento + bytes do label
        }
        return index;
    }
}
