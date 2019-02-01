/**
 * Project submitted by Aneesh Joshi (aj4524@rit.edu) as part of Foundations of Computer Networks
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class pktanalyzer {
    /**
     * Main driver method for calling the packet analyzer
     * @param args only one argument needed which is the data file
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java pktanalyzer datafile.\nPlease use correctly.");
            System.exit(0);
        }
        String fileName = args[0];

        try (InputStream inputStream = new FileInputStream(fileName)) {
            byte[] fullPacket = new byte[(int) new File(fileName).length()];
            inputStream.read(fullPacket);
            unwrapEthernet(fullPacket);
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    /**
     * Returns a string representation of the number made on N bytes.
     * @param packet the packet array
     * @param offset the position to start reading from
     * @param N the number of bytes to consider
     * @return string representation of the number made on N bytes
     */
    static String getNextNBytesLong(byte[] packet, int offset, int N) {
        long res = (long) Byte.toUnsignedInt(packet[offset]);
        for (int i = 1; i < N; i++) {
            res = (res << 8) + (long) Byte.toUnsignedInt(packet[offset + i]);
        }
        return "" + res;
    }

    /**
     * Returns a string representation of the number made on N bytes in the 0x fromat
     * @param packet the packet array
     * @param offset the position to start reading from
     * @param N the number of bytes to consider
     * @return string representation of the number made on N bytes in the 0x format
     */
    static String getNextNBytesHex(byte[] packet, int offset, int N) {
        if (offset > packet.length)
            return "";
        String res = String.format("%02x", Byte.toUnsignedInt(packet[offset]));
        for (int i = 1; i < N && offset + i < packet.length; i++) {
            res += (i % 2 == 0 ? " " : "") + String.format("%02x", Byte.toUnsignedInt(packet[offset + i]));
        }
        return res;
    }

    /**
     * Returns a string representation of the address stored in N bytes
     * @param packet the packet array
     * @param offset the position to start reading from
     * @param N the number of bytes to consider
     * @return a string representation of the address stored in N bytes
     */
    static String getNByteAddress(byte[] packet, int offset, int N) {
        String res = "";
        for (int i = offset; i < offset + N; i++) {
            res += String.format("%02x", Byte.toUnsignedInt(packet[i])) + (offset == offset + N - 1 ? "" : ":");
        }
        return res;
    }

    /**
     * Returns the ascii format of N bytes
     * @param packet the packet array
     * @param offset the position to start reading from
     * @param N the number of bytes to consider
     * @return the ascii format of N bytes
     */
    static String getAsciiRepresentation(byte[] packet, int offset, int N) {
        String res = "";
        int temp;
        for (int i = offset; i < packet.length && i < offset + N; i++) {
            temp = Byte.toUnsignedInt(packet[i]);
            res += (char) (temp != '\n' && temp != '\b' ? temp : '.');
        }
        return res;
    }

    /**
     * Unwraps the ethernet header, displays it and then calls unwrapIP
     * @param packet the byte array of the packet
     */
    static void unwrapEthernet(byte[] packet) {
        System.out.println("--------Ethernet Header-----------");
        int i = 0;

        System.out.println("Destination Mac Address = " + getNByteAddress(packet, i, 6));
        i += 6;

        System.out.println("Source Mac Address = " + getNByteAddress(packet, i, 6));
        i += 6;

        System.out.println("Length : " + packet.length + " bytes");

        System.out.println("Ethertype: " + getNextNBytesHex(packet, i, 2)); // TODO check other values
        i += 2;

        unwrapIP(packet, i);
    }

    /**
     * Unwraps the IP header, displays it and then calls the unwrapper function of the appropriate protocol
     * @param packet the byte array of the packet
     */
    static void unwrapIP(byte[] packet, int offset) {
        System.out.println("---------IP--------------");

        int i = offset;

        System.out.println("Version : " + ((packet[i] & 0xF0) >> 4));
        System.out.println("Header Length : " + (packet[i] & 0x0F) * 4 + " bytes");
        int interHeaderLength = packet[i] & 0x0F;
        i += 1;

        String[] precedenceValues = {"Routine", "Priority", "Immediate", "Flash", "Flash Override", "Critical",
                "Internetwork Control", "Network Control"};
        System.out.println("Type of Service : " + String.format("0x%02x", Byte.toUnsignedInt(packet[i])));
        int precedenceNumber = ((packet[i] & 0b11100000) >> 5);
        int delay = ((packet[i] & 0b00010000) >> 4);
        int throughput = ((packet[i] & 0b00001000) >> 3);
        int reliability = ((packet[i] & 0b00000100) >> 2);
        int cost = ((packet[i] & 0b00000010) >> 1);
        int mbz = ((packet[i] & 0b00000001) >> 4);
        System.out.println("\t xxx. .... = " + precedenceNumber + "(" + precedenceValues[precedenceNumber] + ") (Precedence) ");
        System.out.printf("\t ...%d .... = %s\n", delay, (delay == 0 ? "Normal Delay" : "Low Delay"));
        System.out.printf("\t .... %d... = %s\n", throughput, (throughput == 0 ? "Normal Throughput" : "High Throughput"));
        System.out.printf("\t .... .%d.. = %s\n", reliability, (reliability == 0 ? "Normal Reliability" : "High Relia"));
        System.out.printf("\t .... ..%d. = %s\n", cost, (cost == 0 ? "Normal Cost" : "Low Cost"));
        System.out.printf("\t .... ...%d = %s\n", mbz, "Checking bit");
        i += 1;

        System.out.println("Total Length : " + getNextNBytesLong(packet, i, 2) + " bytes");
        i += 2;
        System.out.println("Identification : " + getNextNBytesLong(packet, i, 2));
        i += 2;

        System.out.println("Flags : " + String.format("0x%02X", (packet[i] & 0b11100000) >> 5));
        int doFrag = ((packet[i] & 0b01000000) >> 6);
        int moreFrag = ((packet[i] & 0b00100000) >> 5);
        System.out.printf(".%d.. .... = %s\n", doFrag, (doFrag == 0 ? "ok to fragment " : "do not fragment"));
        System.out.printf("..%d. .... = %s\n", moreFrag, (moreFrag == 1 ? "more fragments " : "last fragment"));

        System.out.println("Fragment Offset = " +
                (((Byte.toUnsignedInt(packet[i]) & 0b00011111) << (3 + 8)) +
                        Byte.toUnsignedInt(packet[i + 1]) + " bytes")
        );
        i += 2;

        System.out.println("Time to live: " + Byte.toUnsignedInt(packet[i]) + " seconds/hop");
        i += 1;

        // Assuming only ICMP, TCP and UDP packets exist
        String packetProtocol = (packet[i] == 17 ? "UDP" : packet[i] == 1 ? "ICMP" : "TCP");
        System.out.println("Protocol : " + packet[i] + " (" + packetProtocol + ")");
        i += 1;

        System.out.println("Header Checksum : 0x" + getNextNBytesHex(packet, i, 2));
        i += 2;

        offset = i + 4;
        System.out.print("Source Address: ");
        for (; i < offset; i++) {
            System.out.print(Byte.toUnsignedInt(packet[i]) + (i + 1 == offset ? "\n" : "."));
        }

        offset = i + 4;
        System.out.print("Destination Address: ");
        for (; i < offset; i++) {
            System.out.print(Byte.toUnsignedInt(packet[i]) + (i + 1 == offset ? "\n" : "."));
        }

        if (interHeaderLength > 5) {
            System.exit(42);//TODO add options
        } else {
            System.out.println("No Options");
        }

        switch (packetProtocol) {
            case "UDP":
                unwrapUDP(packet, offset);
                break;
            case "TCP":
                unwrapTCP(packet, offset);
                break;
            case "ICMP":
                unwrapICMP(packet, offset);
                break;
            default:
                System.out.println("Unknown protocol");
                System.exit(42);
        }
    }

    /**
     * Unwraps the UDP header and data and displays it
     * @param packet the byte array of the packet
     */
    static void unwrapUDP(byte[] packet, int i) {
        System.out.println("------------UDP-----------");
        System.out.println("Source Port : " + getNextNBytesLong(packet, i, 2));
        i += 2;

        System.out.println("Destination Port : " + getNextNBytesLong(packet, i, 2));
        i += 2;

        System.out.println("Length : " + getNextNBytesLong(packet, i, 2));
        i += 2;

        System.out.println("Checksum : 0x" + getNextNBytesHex(packet, i, 2));
        i += 2;

        while (i < packet.length) {
            System.out.println(getNextNBytesHex(packet, i, 16) + "\t\t\t" + getAsciiRepresentation(packet, i, 16));
            i += 16;
        }


    }

    /**
     * Unwraps the TCP header and data and displays it
     * @param packet the byte array of the packet
     */
    static void unwrapTCP(byte[] packet, int i) {
        System.out.println("\n----------TCP-----------");
        System.out.println("Source Port : " + getNextNBytesLong(packet, i, 2));
        i += 2;

        System.out.println("Destination Port : " + getNextNBytesLong(packet, i, 2));
        i += 2;

        System.out.println("Sequence Number : " + getNextNBytesLong(packet, i, 4));
        i += 4;

        System.out.println("Acknowledgement Number : " + getNextNBytesLong(packet, i, 4));
        i += 4;

        System.out.println("Data Offset : " +
                (((Byte.toUnsignedInt(packet[i]) & 0b11110000) >> 4)) + " bytes");
        i += 1;


        int isUrgent = ((packet[i] & 0b00100000) >> 5);
        int isAck = ((packet[i] & 0b00010000) >> 4);
        int isPush = ((packet[i] & 0b00001000) >> 3);
        int isReset = ((packet[i] & 0b00000100) >> 2);
        int isSyn = ((packet[i] & 0b00000010) >> 1);
        int isFin = ((packet[i] & 0b00000001));

        System.out.println("Flags : " + Integer.toHexString(packet[i] & 0b00111111));
        System.out.printf("\t..%d. .... = %s\n", isUrgent, (isUrgent == 1 ? "URGENT " : "No urgent pointer"));
        System.out.printf("\t...%d .... = %s\n", isAck, (isAck == 1 ? "Acknowledgement " : "No acknowledgment"));
        System.out.printf("\t.... %d... = %s\n", isPush, (isPush == 1 ? "Push " : "No push"));
        System.out.printf("\t.... .%d.. = %s\n", isReset, (isReset == 1 ? "Reset " : "no reset"));
        System.out.printf("\t.... ..%d. = %s\n", isSyn, (isSyn == 1 ? "SYN " : "no syn"));
        System.out.printf("\t.... ...%d = %s\n", isFin, (isFin == 1 ? "FIN " : "no fin"));
        i += 1;

        System.out.println("Window = " + getNextNBytesLong(packet, i, 2));
        i += 2;

        System.out.println("Checksum = 0x" + getNextNBytesHex(packet, i, 2));
        i += 2;

        System.out.println("Urgent pointer = " + getNextNBytesLong(packet, i, 2));
        i += 2;

        // TODO offset

        i += 2;
        while (i < packet.length) {
            System.out.println(getNextNBytesHex(packet, i, 16) + "\t\t\t" + getAsciiRepresentation(packet, i, 16));
            i += 16;
        }
    }

    /**
     * Unwraps the ICMP header and data and displays it
     * @param packet the byte array of the packet
     */
    static void unwrapICMP(byte[] packet, int i) {
        System.out.println("----------ICMP-------------");
        System.out.println("Type : " + getNextNBytesLong(packet, i++, 1));
        System.out.println("Code : " + getNextNBytesLong(packet, i++, 1));
        System.out.println("Checksum : 0x" + getNextNBytesHex(packet, i, 2));
        i += 2;

        System.out.println("Rest of Header:");
        while (i < packet.length) {
            System.out.println(getNextNBytesHex(packet, i, 16) + "\t\t\t" + getAsciiRepresentation(packet, i, 16));
            i += 16;
        }
    }

}