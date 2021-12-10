package model.analyzers.ip;

import model.analyzers.icmp.ICMPAnalyzer;
import model.analyzers.tcp.TCPAnalyzer;
import model.analyzers.udp.UDPAnalyzer;
import model.address.AddressIPv4;
import model.analyzers.AnalyzerException;
import model.analyzers.ethernet.EtherType;
import model.analyzers.ethernet.Type;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class IPv4Analyzer extends EtherType {

    private int version;
    private int IHL;
    private int TOS;
    private Precedence precedence;
    private int delay;
    private int throughput;
    private int relibility;
    private int reserved;
    private int totalLength;
    private int identifier;
    private int R;
    private int DF;
    private int MF;
    private int fragmentOffset;
    private int TTL;
    private IPProtocolType protocolType; // icmp 1 tcp 6 udp 17
    private ICMPAnalyzer icmpAnalyzer;
    private TCPAnalyzer tcpAnalyzer;
    private UDPAnalyzer udpAnalyzer;
    private int headerChecksum;
    private AddressIPv4 source;
    private AddressIPv4 destination;
    private List<IPOption> options;
    private Map<String, String[]> tosInformation;

    public IPv4Analyzer(String[] t) {
        super("Internet Protocol Version 4", "IPv4", Type.IPv4, t);
    }

    public IPv4Analyzer(String t) {
        super("Internet Protocol Version 4", "IPv4", Type.IPv4, t);
    }

    public void analyze() throws AnalyzerException {
        version = Integer.parseInt(t[0].substring(0, 1), 16);
        if (version != 4)
            throw new AnalyzerException("IPv4. Version. Value must be equal t0 4", 0);
        informations.put("Version", new String[]{String.valueOf(version), "0x4"});

        IHL = Integer.parseInt(t[0].substring(1), 16);
        if (IHL < 5)
            throw new AnalyzerException("IPv4. IHL. Value must be greater then 5", 0);
        informations.put("Header length", new String[]{String.valueOf(IHL), "0x" + t[0].substring(1)});

        TOS = Integer.parseInt(t[1], 16);
        informations.put("TOS", new String[]{String.valueOf(TOS), "0x" + t[1]});

        tosInformation = new LinkedHashMap<>();
        String services = Integer.toBinaryString(TOS);
        if (services.length() < 8)
            services = "00000000".substring(0, 8-services.length()) + services;
        int prec = Integer.parseInt(services.substring(0, 3), 2);
        precedence = Precedence.getPrecedence(prec);
        if (precedence == null) precedence = Precedence.Routine;
        tosInformation.put("Precedence", new String[]{precedence.toString(), "0b" + services.substring(0, 3)});
        delay = Integer.parseInt(services.substring(3, 4), 2);
        tosInformation.put("Delay", new String[]{String.valueOf(delay), (delay == 0) ? "Normal":"Low"});
        throughput = Integer.parseInt(services.substring(4, 5), 2);
        tosInformation.put("Throughput", new String[]{String.valueOf(throughput), (throughput == 0) ? "Normal":"High"});
        relibility = Integer.parseInt(services.substring(5, 6), 2);
        tosInformation.put("Relibility", new String[]{String.valueOf(relibility), (relibility == 0) ? "Normal":"High"});
        reserved = Integer.parseInt(services.substring(6, 8), 2);
        tosInformation.put("Reserved", new String[]{String.valueOf(reserved), "0b" + services.substring(6, 8)});

        totalLength = Integer.parseInt(t[2] + t[3], 16);
        informations.put("Total Length", new String[]{String.valueOf(totalLength), "0x" + t[2] + t[3]});

        identifier = Integer.parseInt(t[4] + t[5], 16);
        informations.put("Identifier", new String[]{String.valueOf(identifier), "0x" + t[4] + t[5]});

        String R_DF_MF_FO = Integer.toBinaryString(Integer.parseInt(t[6] + t[7], 16));
        if (R_DF_MF_FO.length() < 16)
            R_DF_MF_FO = "0000000000000000".substring(0, 16-R_DF_MF_FO.length()) + R_DF_MF_FO;
        R = Integer.parseInt(R_DF_MF_FO.substring(0, 1), 2);
        DF = Integer.parseInt(R_DF_MF_FO.substring(1, 2), 2);
        MF = Integer.parseInt(R_DF_MF_FO.substring(2, 3), 2);
        fragmentOffset = Integer.parseInt(R_DF_MF_FO.substring(3), 2);

        informations.put("Reserved bit (R)", new String[]{String.valueOf(R), ""});
        informations.put("DF", new String[]{String.valueOf(DF), (DF == 1)?"Don't Fragment":"May Fragment"});
        informations.put("MF", new String[]{String.valueOf(MF), (MF == 1)?"More Fragments":"Last Fragment"});
        informations.put("Fragment Offset", new String[]{String.valueOf(fragmentOffset), "0b" + R_DF_MF_FO.substring(3)});

        TTL = Integer.parseInt(t[8], 16);
        informations.put("TTL", new String[]{String.valueOf(TTL), "0x"+t[8]});

        String p = t[9];
        if (p.equals(IPProtocolType.ICMP.getValue()))
            protocolType = IPProtocolType.ICMP;
        else if (p.equals(IPProtocolType.TCP.getValue()))
            protocolType = IPProtocolType.TCP;
        else if (p.equals(IPProtocolType.UDP.getValue()))
            protocolType = IPProtocolType.UDP;

        if (protocolType != null)
            informations.put("Protocol", new String[]{protocolType.toString(), ""});
        else
            informations.put("Protocol", new String[]{"0x" + p, "Unrecognized value"});

        headerChecksum = Integer.parseInt(t[10] + t[11], 16);
        informations.put("Checksum", new String[]{String.valueOf(headerChecksum), "0x" + t[10] + t[11]});

        source = new AddressIPv4(Integer.parseInt(t[12], 16),
                Integer.parseInt(t[13], 16),
                Integer.parseInt(t[14], 16),
                Integer.parseInt(t[15], 16));
        informations.put("IP Source", new String[]{source.toString(), ""});

        destination = new AddressIPv4(Integer.parseInt(t[16], 16),
                Integer.parseInt(t[17], 16),
                Integer.parseInt(t[18], 16),
                Integer.parseInt(t[19], 16));
        informations.put("IP Destination", new String[]{destination.toString(), ""});

        options = new ArrayList<>();
        int size_options = 4 * IHL - 20;
        if (size_options > 0) {
            int i = 20;
            while (i < 20 + size_options) {
                int type = Integer.parseInt(t[i], 16);
                if (type == 0) { // EOL
                    options.add(new IPOption(OptionType.EOL, 1)); i++;
                }
                else if (type == 1) { // NO
                    options.add(new IPOption(OptionType.NO, 1)); i++;
                }
                else if (type == 7) { // RR
                    int size = Integer.parseInt(t[i+1], 16);
                    int start = i - 34;
                    int pointer = Integer.parseInt(t[i+2], 16);
                    List<AddressIPv4> iPv4Address = new ArrayList<>();
                    if (pointer - start > 4) {
                        int numberOfAddress = (size - 3) / 4;
                        for (int j = 0; j < numberOfAddress; j++) {
                            int k = i + 3 + j * 4;
                            AddressIPv4 address = new AddressIPv4(Integer.parseInt(t[k], 16),
                                    Integer.parseInt(t[k+1], 16),
                                    Integer.parseInt(t[k+2], 16),
                                    Integer.parseInt(t[k+3], 16));
                            iPv4Address.add(address);
                        }
                    }
                    options.add(new IPOption(OptionType.RR, size, iPv4Address));
                    i += size;
                }
                else
                    throw new AnalyzerException("IP. Options. UnrecognType " + type, i);
            }
        }

        int s = IHL * 4;
        if (protocolType == IPProtocolType.ICMP) {
            icmpAnalyzer = new ICMPAnalyzer(Arrays.copyOfRange(t, s, t.length));
            try {
                icmpAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + s);
            }
            protocolName = icmpAnalyzer.getProtocolName();
        }
        else if (protocolType == IPProtocolType.TCP) {
            tcpAnalyzer = new TCPAnalyzer(Arrays.copyOfRange(t, s, t.length));
            try {
                tcpAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + s);
            }
            protocolName = tcpAnalyzer.getProtocolName();
        }
        else if (protocolType == IPProtocolType.UDP) {
            udpAnalyzer = new UDPAnalyzer(Arrays.copyOfRange(t, s, t.length));
            try {
                udpAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + s);
            }
            protocolName = udpAnalyzer.getProtocolName();
        }
    }

    public int getVersion() {
        return version;
    }

    public int getIHL() {
        return IHL;
    }

    public int getTOS() {
        return TOS;
    }

    public Precedence getPrecedence() {
        return precedence;
    }

    public int getDelay() {
        return delay;
    }

    public int getThroughput() {
        return throughput;
    }

    public int getRelibility() {
        return relibility;
    }

    public int getReserved() {
        return reserved;
    }

    public int getTotalLength() {
        return totalLength;
    }

    public int getIdentifier() {
        return identifier;
    }

    public int getR() {
        return R;
    }

    public int getDF() {
        return DF;
    }

    public int getMF() {
        return MF;
    }

    public int getFragmentOffset() {
        return fragmentOffset;
    }

    public int getTTL() {
        return TTL;
    }

    public IPProtocolType getProtocolType() {
        return protocolType;
    }

    public ICMPAnalyzer getIcmpAnalyzer() {
        return icmpAnalyzer;
    }

    public TCPAnalyzer getTcpAnalyzer() {
        return tcpAnalyzer;
    }

    public UDPAnalyzer getUdpAnalyzer() {
        return udpAnalyzer;
    }

    public int getHeaderChecksum() {
        return headerChecksum;
    }

    public AddressIPv4 getSource() {
        return source;
    }

    public AddressIPv4 getDestination() {
        return destination;
    }

    public List<IPOption> getOptions() {
        return options;
    }

    public Map<String, String[]> getTosInformation() {
        return tosInformation;
    }

    @Override
    public String getRecap() {
        return super.getRecap() + ", Src : " + source + ", Dest : " + destination + ", " + t.length + " bytes";
    }

    @Override
    public String toString() {
        String s = super.toString();
        if (tosInformation != null && !tosInformation.isEmpty()) {
            s += "\nServices Field\n-------------------";
            for (String key: tosInformation.keySet()) {
                String[] value = tosInformation.get(key);
                s += "\n\t" + key + " : " + value[0] + ((value[1].isEmpty()) ? "": " (" + value[1] + ")");
            }
        }
        if (options != null && !options.isEmpty()) {
            s += "\nOptions IP \n-------------------";
            for (IPOption option : options) {
                s += "\n\t" + option.getOptionType();
                if (!option.getiPv4Adress().isEmpty())
                    for (AddressIPv4 ip: option.getiPv4Adress())
                        s += "\n\t\t" + ip;
            }
        }
        if (icmpAnalyzer != null)
            s += icmpAnalyzer;
        else if (tcpAnalyzer != null)
            s += tcpAnalyzer;
        else if (udpAnalyzer != null)
            s += udpAnalyzer;
        return s;
    }
}
