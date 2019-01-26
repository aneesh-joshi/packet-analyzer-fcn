import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class TempTest {
    public static void main(String[] args) {
        String fileName = "data/new_udp_packet1.bin";

        try (InputStream inputStream = new FileInputStream(fileName)) {
            byte[] fullPacket = new byte[(int) new File(fileName).length()];
            inputStream.read(fullPacket);
            unwrapEthernet(fullPacket);
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    static void unwrapEthernet(byte[] packet) {
        System.out.println("--------Ethernet-----------");
        int i = 0;
        int offset = 6;
        System.out.print("Destination Mac Address ");
        for (; i < offset; i++) {
            System.out.print(": " + String.format("%02x", Byte.toUnsignedInt(packet[i])));
        }
        System.out.println();
        offset += 6;
        System.out.print("Source Mac Address ");
        for (; i < offset; i++) {
            System.out.print(": " + String.format("%02x", Byte.toUnsignedInt(packet[i])));
        }

        System.out.println("\nLength " + packet.length);

        int packetLength = 1500;
        offset += 2;
        System.out.print("Length "); // TODO
        for (; i < offset; i++) {
            System.out.print(": " + String.format("%02x", Byte.toUnsignedInt(packet[i])));
        }
        System.out.println();
        unwrapIP(packet, offset, packetLength);
    }

    static void unwrapIP(byte[] packet, int offset, int packetLength) {
        System.out.println("---------IP--------------");

        int i = offset;

        System.out.println("Version : " + ((packet[i] & 0xF0) >> 4));
        System.out.println("Header Length : " + (packet[i] & 0x0F) * 4);
        int interHeaderLength = packet[i] & 0x0F;
        i += 1;
        offset += 1;

        offset += 1;
        System.out.print("DSCP + ECN"); // TODO
        for (; i < offset; i++) {
            System.out.print(": " + String.format("%02x", Byte.toUnsignedInt(packet[i])));
        }
        System.out.println();

        offset += 2;
        System.out.print("Total Length ");
        System.out.print((Byte.toUnsignedInt(packet[i]) << 8) + Byte.toUnsignedInt(packet[i + 1]));
        i += 2;
        System.out.println();

        offset += 2;
        System.out.print("Identification ");
        System.out.print((Byte.toUnsignedInt(packet[i]) << 8) + Byte.toUnsignedInt(packet[i + 1]));
        i += 2;
        System.out.println();

        System.out.println("Flags = " + String.format("0x%02X", (packet[i] & 0b11100000) >> 5));
        byte doFrag = (byte) ((packet[i] & 0b01000000) >> 6);
        byte moreFrag = (byte) ((packet[i] & 0b00100000) >> 5); // TODO
        System.out.printf(".%d.. .... = %s\n", doFrag, (doFrag == 1 ? "fragment " : "do not fragment"));
        System.out.printf("..%d. .... = %s\n", moreFrag, (moreFrag == 1 ? "more fragments " : "last fragment"));

        System.out.println("Fragment Offset = " +
                (((Byte.toUnsignedInt(packet[i]) & 0b00011111) << (3 + 8)) + Byte.toUnsignedInt(packet[i + 1]) + " bytes"));

        i += 2;

        System.out.println("Time to live: " + Byte.toUnsignedInt(packet[i]) + " seconds/hop");
        i += 1;

        // Assuming only ICMP, TCP and UDP packets exist
        String packetProtocol = (packet[i] == 17 ? "UDP" : packet[i] == 1 ? "ICMP" : "TCP");
        System.out.println("Protocol = " + packet[i] + " (" + packetProtocol + ")");
        i += 1;

        System.out.print("Header Checksum ");
        System.out.print((Byte.toUnsignedInt(packet[i]) << 8) + Byte.toUnsignedInt(packet[i + 1]));
        i += 2;
        System.out.println();

        offset = i + 4;
        System.out.print("Source Address: ");
        for (; i < offset; i++) {
            System.out.print(Byte.toUnsignedInt(packet[i]) + (i + 1 == offset ? "" : "."));
        }
        System.out.println();


        offset = i + 4;
        System.out.print("Destination Address: ");
        for (; i < offset; i++) {
            System.out.print(Byte.toUnsignedInt(packet[i]) + (i + 1 == offset ? "" : "."));
        }
        System.out.println();

        if (interHeaderLength > 5) {
            System.exit(42);//TODO
        }

        switch (packetProtocol) {
            case "UDP":
                processUDP(packet, offset);
                break;
            case "TCP":
                processTCP(packet, offset);
                break;
            case "ICMP":
                processUDP(packet, offset);
                break;
            default:
                System.out.println("Unknown protocol");
                System.exit(42);
        }
    }

    static String getNextNBytes(byte[] packet, int offset, int N) {
        int res = Byte.toUnsignedInt(packet[offset]);
        for (int i = 1; i < N; i++) {
            res = (res << 8) + Byte.toUnsignedInt(packet[offset + i]);
        }
        return "" + res;
    }

    static String getNextNBytesHex(byte[] packet, int offset, int N) {
        if(offset > packet.length)
            return "";
        String res = String.format("%02X", Byte.toUnsignedInt(packet[offset]));
        for (int i = 1; i < N && offset + i < packet.length; i++) {
            res += (i % 2 == 0 ? " " : "") + String.format("%02X", Byte.toUnsignedInt(packet[offset + i]));
        }
        return res;
    }

    static void processUDP(byte[] packet, int i) {
        System.out.println("------------UDP-----------");
        System.out.print("Source Port ");
        System.out.println(getNextNBytes(packet, i, 2));
        i += 2;

        System.out.print("Destination Port ");
        System.out.println(getNextNBytes(packet, i, 2));
        i += 2;

        System.out.print("Length ");
        System.out.println(getNextNBytes(packet, i, 2));
        i += 2;

        System.out.print("Checksum ");
        System.out.println("0x" + Integer.toHexString(
                (Byte.toUnsignedInt(packet[i]) << 8) + Byte.toUnsignedInt(packet[i + 1]))
        );
        i += 2;
        while (i < packet.length) {
            System.out.println(getNextNBytesHex(packet, i, 16) + " ");
            i += 16;
        }

    }

    static void processTCP(byte[] packet, int offset) {

    }

    static void processICMP(byte[] packet, int offset) {

    }

}