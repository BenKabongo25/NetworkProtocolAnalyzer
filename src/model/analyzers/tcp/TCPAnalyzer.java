package model.analyzers.tcp;

import model.analyzers.AnalyzerException;
import model.analyzers.dhcp.DHCPAnalyzer;
import model.analyzers.dns.DNSAnalyzer;
import model.analyzers.ip.IPProtocol;
import model.analyzers.ip.IPProtocolType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TCPAnalyzer extends IPProtocol {

    private int portSource;
    private int portDestination;
    private long sequence;
    private long acknowledgment;
    private int THL;
    private int reserved;
    private int ECN;
    private int CWR;
    private int ECE;
    private int URG;
    private int ACK;
    private int PSH;
    private int RST;
    private int SYN;
    private int FIN;
    private int window;
    private int checksum;
    private int urgentPointer;
    private String data;
    private List<TCPOption> options;
    private DHCPAnalyzer dhcpAnalyzer;
    private DNSAnalyzer dnsAnalyzer;

    public TCPAnalyzer(String[] t) {
        super("Transmission Control Protocol", "TCP", IPProtocolType.TCP, t);
    }

    public TCPAnalyzer(String t) {
        super("Transmission Control Protocol", "TCP", IPProtocolType.TCP, t);
    }

    @Override
    public void analyze() throws AnalyzerException {
        portSource = Integer.parseInt(t[0] + t[1], 16);
        informations.put("Port Source", new String[]{String.valueOf(portSource), ""});

        portDestination = Integer.parseInt(t[2] + t[3], 16);
        informations.put("Port Destination", new String[]{String.valueOf(portDestination), ""});

        sequence = Long.parseLong(t[4] + t[5] + t[6] + t[7], 16);
        informations.put("Sequence Number", new String[]{String.valueOf(sequence), "0x" + t[4] + t[5] + t[6] + t[7]});

        acknowledgment = Long.parseLong(t[8] + t[9] + t[10] + t[11], 16);
        informations.put("Acknowledgment", new String[]{String.valueOf(acknowledgment), "0x" + t[8] + t[9] + t[10] + t[11]});

        THL = Integer.parseInt(t[12].substring(0,1), 16);
        informations.put("THL", new String[]{String.valueOf(THL), "0x" + t[12].substring(0,1)});

        String ABCD = Integer.toBinaryString(Integer.parseInt(t[12].substring(1) + t[13], 16));
        if (ABCD.length() < 12) ABCD = "0000000000000000".substring(0, 12-ABCD.length()) + ABCD;
        reserved = Integer.parseInt(ABCD.substring(0, 3), 2);
        ECN = Integer.parseInt(ABCD.substring(3, 4), 2);
        CWR = Integer.parseInt(ABCD.substring(4, 5), 2);
        ECE = Integer.parseInt(ABCD.substring(5, 6), 2);
        URG = Integer.parseInt(ABCD.substring(6, 7), 2);
        ACK = Integer.parseInt(ABCD.substring(7, 8), 2);
        PSH = Integer.parseInt(ABCD.substring(8, 9), 2);
        RST = Integer.parseInt(ABCD.substring(9, 10), 2);
        SYN = Integer.parseInt(ABCD.substring(10, 11), 2);
        FIN = Integer.parseInt(ABCD.substring(11, 12), 2);

        informations.put("Reserved", new String[]{String.valueOf(reserved), "0x" + ABCD.substring(0, 3)});
        informations.put("ECN", new String[]{String.valueOf(ECN), (ECN == 0) ? "Not set": "Set"});
        informations.put("CWR", new String[]{String.valueOf(CWR), (CWR == 0) ? "Not set": "Set"});
        informations.put("ECE", new String[]{String.valueOf(ECE), (ECE == 0) ? "Not set": "Set"});
        informations.put("URG", new String[]{String.valueOf(URG), (URG == 0) ? "Not set": "Set"});
        informations.put("ACK", new String[]{String.valueOf(ACK), (ACK == 0) ? "Not set": "Set"});
        informations.put("PSH", new String[]{String.valueOf(PSH), (PSH == 0) ? "Not set": "Set"});
        informations.put("RST", new String[]{String.valueOf(RST), (RST == 0) ? "Not set": "Set"});
        informations.put("SYN", new String[]{String.valueOf(SYN), (SYN == 0) ? "Not set": "Set"});
        informations.put("FIN", new String[]{String.valueOf(FIN), (FIN == 0) ? "Not set": "Set"});

        window = Integer.parseInt(t[14] + t[15], 16);
        informations.put("Window", new String[]{String.valueOf(window), "0x" + t[14] + t[15]});

        checksum = Integer.parseInt(t[16] + t[17], 16);
        informations.put("Checksum", new String[]{String.valueOf(checksum), "0x" + t[16] + t[17]});

        urgentPointer = Integer.parseInt(t[18] + t[19], 16);
        informations.put("Urgent Pointer", new String[]{String.valueOf(urgentPointer), "0x" + t[18] + t[19]});

        options = new ArrayList<>();
        int size_options = 4 * THL - 20;
        if (size_options > 0) {
            int i = 20;
            while (i < 20 + size_options) {
                int kind = Integer.parseInt(t[i], 16);
                TCPOption option;
                if (kind == 0) {
                    option = new TCPOption(OptionType.EndOfOptionList, kind, 0, "");
                    i++;
                }
                else if (kind == 1) {
                    option = new TCPOption(OptionType.NoOperation, kind, 0, "");
                    i++;
                }
                else {
                    OptionType type = OptionType.getOptionType(kind);
                    if (type == null)
                        type = OptionType.UNRECOGNIZED_OPTION;
                    int length = Integer.parseInt(t[i+1], 16);
                    //if (length != type.getLength())
                    //    throw new AnalyzerException("TCP. " + type.getMeaning() + "Option. Length.  Must be equal to " +
                    //            type.getLength() + "but it is equal to " + length, i + 1);
                    String value = "";
                    if (length > 2) {
                        value = String.join("", Arrays.copyOfRange(t, i + 2, i + length));
                    }
                    option = new TCPOption(type, kind, length, value);
                    i += length;
                }
                options.add(option);
            }
        }

        data = "";
        String[] t1 = Arrays.copyOfRange(t, 8, t.length);
        // DHCP
        if (portDestination == 67 || portDestination == 68 || portSource == 67 || portSource == 68) {
            dhcpAnalyzer = new DHCPAnalyzer(t1);
            protocolName = dhcpAnalyzer.getProtocolName();
            try {
                dhcpAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 8);
            }
        }
        // DNS
        else if (portSource == 53 || portDestination == 53) {
            dnsAnalyzer = new DNSAnalyzer(t1);
            protocolName = dnsAnalyzer.getProtocolName();
            try {
                dnsAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 8);
            }
        }
        // Datas
        else {
            data = String.join("", t1);
        }
    }

    public int getPortSource() {
        return portSource;
    }

    public int getPortDestination() {
        return portDestination;
    }

    public long getSequence() {
        return sequence;
    }

    public long getAcknowledgment() {
        return acknowledgment;
    }

    public int getTHL() {
        return THL;
    }

    public int getReserved() {
        return reserved;
    }

    public int getECN() {
        return ECN;
    }

    public int getCWR() {
        return CWR;
    }

    public int getECE() {
        return ECE;
    }

    public int getURG() {
        return URG;
    }

    public int getACK() {
        return ACK;
    }

    public int getPSH() {
        return PSH;
    }

    public int getRST() {
        return RST;
    }

    public int getSYN() {
        return SYN;
    }

    public int getFIN() {
        return FIN;
    }

    public int getWindow() {
        return window;
    }

    public int getChecksum() {
        return checksum;
    }

    public int getUrgentPointer() {
        return urgentPointer;
    }

    public List<TCPOption> getOptions() {
        return options;
    }

    public String getData() {
        return data;
    }

    public DHCPAnalyzer getDhcpAnalyzer() {
        return dhcpAnalyzer;
    }

    public DNSAnalyzer getDnsAnalyzer() {
        return dnsAnalyzer;
    }

    @Override
    public String getRecap() {
        return super.getRecap() + ", Src port : " + portSource + ", Dest port : " + portDestination + ", " + t.length + " bytes";
    }

    @Override
    public String toString() {
        String s = super.toString();
        if (!options.isEmpty()) {
            s += "\nOptions TCP\n -------------------";
            for (TCPOption option : options) {
                if (option.getOptionType() != OptionType.UNRECOGNIZED_OPTION)
                    s += "\n\t" + option.getOptionType() + (option.getValue().isEmpty() ? "" : " value =" + option.getValue());
                else
                    s += "Unrecognized option, kind = " + option.getKind() + ", length = " + option.getLength() +
                            (option.getValue().isEmpty() ? "" : " value =" + option.getValue());
            }
        }
        if (dhcpAnalyzer != null)
            s += dhcpAnalyzer.toString();
        else if (dnsAnalyzer != null)
            s += dnsAnalyzer.toString();
        else
            s += "\nData\t: " + data;
        return s;
    }
}
