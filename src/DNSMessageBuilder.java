import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Random;

public class DNSMessageBuilder {

    public static byte[] buildQuery(String domain) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        Random rand = new Random();

        // Header
        dos.writeShort(rand.nextInt(0xFFFF)); // ID
        dos.writeShort(0x0100); // Flags (standard query)
        dos.writeShort(1); // QDCOUNT
        dos.writeShort(0); // ANCOUNT
        dos.writeShort(0); // NSCOUNT
        dos.writeShort(0); // ARCOUNT

        // Question
        for (String label : domain.split("\\.")) {
            dos.writeByte(label.length());
            dos.writeBytes(label);
        }

        dos.writeByte(0x00); // end of name

        dos.writeShort(1); // QTYPE = A
        dos.writeShort(1); // QCLASS = IN

        return baos.toByteArray();
    }
}