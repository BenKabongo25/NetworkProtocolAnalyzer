package model.analyzers.ip;

import model.address.AddressIPv6;
import model.analyzers.AnalyzerException;
import model.analyzers.ethernet.EtherType;
import model.analyzers.ethernet.Type;
import model.analyzers.icmp.ICMPAnalyzer;
import model.analyzers.tcp.TCPAnalyzer;
import model.analyzers.udp.UDPAnalyzer;

import java.util.Arrays;

public class IPv6Analyzer extends EtherType {

    private int version;
    private int trafficClass;
    private long flowLabel;
    private int payloadLength;
    private IPProtocolType nextHeader;
    private UDPAnalyzer udpAnalyzer;
    private TCPAnalyzer tcpAnalyzer;
    private ICMPAnalyzer icmpAnalyzer;
    private int hopLimit;
    private AddressIPv6 source;
    private AddressIPv6 destination;

    public IPv6Analyzer(String[] t) {
        super("Internet Protocol Version 6", "IPv6", Type.IPv6, t);
    }

    public IPv6Analyzer(String t) {
        super("Internet Protocol Version 6", "IPv6", Type.IPv6, t);
    }

    @Override
    public void analyze() throws AnalyzerException {
        version = Integer.parseInt(t[0].substring(0, 1), 16);
        if (version != 6)
            throw new AnalyzerException("IPv6. Version. Value must be equal t0 6", 0);
        informations.put("Version", new String[]{String.valueOf(version), "0x6"});

        trafficClass = Integer.parseInt(t[0].substring(1) + t[1].substring(0, 1), 16);
        informations.put("Traffic Class", new String[]{String.valueOf(trafficClass), "0x" + t[0].substring(1) + t[1].substring(0, 1)});

        flowLabel = Long.parseLong(t[1].substring(1) + t[2] + t[3], 16);
        informations.put("Flow Label", new String[]{String.valueOf(flowLabel), "0x" + t[1].substring(1) + t[2] + t[3]});

        payloadLength = Integer.parseInt(t[4] + t[5], 16);
        informations.put("Payload Length", new String[]{String.valueOf(payloadLength), "0x" + t[4] + t[5]});

        String nh = t[6];
        if (nh.equals(IPProtocolType.ICMP.getValue()))
            nextHeader = IPProtocolType.ICMP;
        else if (nh.equals(IPProtocolType.TCP.getValue()))
            nextHeader = IPProtocolType.TCP;
        else if (nh.equals(IPProtocolType.UDP.getValue()))
            nextHeader = IPProtocolType.UDP;

        if (nextHeader != null)
            informations.put("Next Header", new String[]{nextHeader.toString(), ""});
        else
            informations.put("Next Header", new String[]{"0x" + nh, "Unrecognized value"});

        hopLimit = Integer.parseInt(t[7], 16);
        informations.put("Hop Limit", new String[]{String.valueOf(hopLimit), "0x" + t[7]});

        source = new AddressIPv6(
                String.join("", Arrays.copyOfRange(t, 8, 10)),
                String.join("", Arrays.copyOfRange(t, 10, 12)),
                String.join("", Arrays.copyOfRange(t, 12, 14)),
                String.join("", Arrays.copyOfRange(t, 14, 16)),
                String.join("", Arrays.copyOfRange(t, 16, 18)),
                String.join("", Arrays.copyOfRange(t, 18, 20)),
                String.join("", Arrays.copyOfRange(t, 20, 22)),
                String.join("", Arrays.copyOfRange(t, 22, 24))
        );
        destination = new AddressIPv6(
                String.join("", Arrays.copyOfRange(t, 24, 26)),
                String.join("", Arrays.copyOfRange(t, 26, 28)),
                String.join("", Arrays.copyOfRange(t, 28, 30)),
                String.join("", Arrays.copyOfRange(t, 30, 32)),
                String.join("", Arrays.copyOfRange(t, 32, 34)),
                String.join("", Arrays.copyOfRange(t, 34, 36)),
                String.join("", Arrays.copyOfRange(t, 36, 38)),
                String.join("", Arrays.copyOfRange(t, 38, 40))
        );
        informations.put("Source", new String[]{source.toString(), ""});
        informations.put("Destination", new String[]{destination.toString(), ""});

        if (nextHeader == IPProtocolType.ICMP) {
            icmpAnalyzer = new ICMPAnalyzer(Arrays.copyOfRange(t, 40, t.length));
            protocolName = icmpAnalyzer.getProtocolName();
            try {
                icmpAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 40);
            }
        }
        else if (nextHeader == IPProtocolType.TCP) {
            tcpAnalyzer = new TCPAnalyzer(Arrays.copyOfRange(t, 40, t.length));
            protocolName = tcpAnalyzer.getProtocolName();
            try {
                tcpAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 40);
            }
        }
        else if (nextHeader == IPProtocolType.UDP) {
            udpAnalyzer = new UDPAnalyzer(Arrays.copyOfRange(t, 40, t.length));
            protocolName = udpAnalyzer.getProtocolName();
            try {
                udpAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 40);
            }
        }
    }

    public int getVersion() {
        return version;
    }

    public int getTrafficClass() {
        return trafficClass;
    }

    public long getFlowLabel() {
        return flowLabel;
    }

    public int getPayloadLength() {
        return payloadLength;
    }

    public IPProtocolType getNextHeader() {
        return nextHeader;
    }

    public UDPAnalyzer getUdpAnalyzer() {
        return udpAnalyzer;
    }

    public TCPAnalyzer getTcpAnalyzer() {
        return tcpAnalyzer;
    }

    public ICMPAnalyzer getIcmpAnalyzer() {
        return icmpAnalyzer;
    }

    public int getHopLimit() {
        return hopLimit;
    }

    public AddressIPv6 getSource() {
        return source;
    }

    public AddressIPv6 getDestination() {
        return destination;
    }

    @Override
    public String getRecap() {
        return super.getRecap() + ", Src : " + source + ", Dest : " + destination + ", " + t.length + " bytes";
    }

    @Override
    public String toString() {
        String s = super.toString();
        if (icmpAnalyzer != null)
            s += icmpAnalyzer;
        else if (tcpAnalyzer != null)
            s += tcpAnalyzer;
        else if (udpAnalyzer != null)
            s += udpAnalyzer;
        return s;
    }
}
