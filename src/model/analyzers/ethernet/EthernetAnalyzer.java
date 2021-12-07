package model.analyzers.ethernet;

import model.address.AddressMAC;
import model.analyzers.AnalyzerException;
import model.analyzers.SimpleAnalyzer;
import model.analyzers.arp.ARPAnalyzer;
import model.analyzers.ip.IPv4Analyzer;
import model.analyzers.ip.IPv6Analyzer;

import java.util.Arrays;

public class EthernetAnalyzer extends SimpleAnalyzer {

    private AddressMAC macDestination;
    private AddressMAC macSource;
    private Type etherType;
    private ARPAnalyzer arpAnalyzer;
    private IPv4Analyzer iPv4Analyzer;
    private IPv6Analyzer iPv6Analyzer;

    public EthernetAnalyzer(String t) {
        super("Ethernet Protocol II", "Ethernet II", t);
    }

    public EthernetAnalyzer(String[] t) {
        super("Ethernet Protocol II", "Ethernet II", t);
    }

    @Override
    public void analyze() throws AnalyzerException {
        macDestination = new AddressMAC(t[0], t[1], t[2], t[3], t[4], t[5]);
        String cast = (macDestination.isBroadcast()) ? "broadcast" : "unicast";
        informations.put("MAC Destination", new String[]{macDestination.toString(), cast});
        macSource = new AddressMAC(t[6], t[7], t[8], t[9], t[10], t[11]);
        informations.put("MAC Source", new String[]{macSource.toString(), ""});

        String etv = t[12] + t[13];
        etv = etv.toLowerCase();
        if (etv.equals(Type.IPv4.getValue())) {
            etherType = Type.IPv4;
            informations.put("EtherType", new String[]{etherType.toString(), ""});
            iPv4Analyzer = new IPv4Analyzer(Arrays.copyOfRange(t, 14, t.length));
            protocolName = iPv4Analyzer.getProtocolName();
            try {
                iPv4Analyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 14);
            }
        }
        else if (etv.equals(Type.ARP.getValue())) {
            etherType = Type.ARP;
            informations.put("EtherType", new String[]{etherType.toString(), ""});
            arpAnalyzer = new ARPAnalyzer(Arrays.copyOfRange(t, 14, t.length));
            protocolName = arpAnalyzer.getProtocolName();
            try {
                arpAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 14);
            }
        }
        else if (etv.equals(Type.IPv6.getValue())) {
            etherType = Type.IPv6;
            informations.put("EtherType", new String[]{etherType.toString(), ""});
            iPv6Analyzer = new IPv6Analyzer(Arrays.copyOfRange(t, 14, t.length));
            protocolName = iPv6Analyzer.getProtocolName();
            try {
                iPv6Analyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 14);
            }
        }
        else
            informations.put("EtherType", new String[]{"0x"+etv, "Unrecognized value"});
    }

    public AddressMAC getMacDestination() {
        return macDestination;
    }

    public AddressMAC getMacSource() {
        return macSource;
    }

    public Type getEtherType() {
        return etherType;
    }

    public ARPAnalyzer getArpAnalyzer() {
        return arpAnalyzer;
    }

    public IPv4Analyzer getIPv4Analyzer() {
        return iPv4Analyzer;
    }

    public IPv6Analyzer getIPv6Analyzer() {
        return iPv6Analyzer;
    }

    @Override
    public String getRecap() {
        return super.getRecap() + ", Src : " + macSource + ", Dest : " + macDestination + ", " + t.length + " bytes";
    }

    @Override
    public String toString() {
        String s = super.toString();
        if (etherType.equals(Type.IPv4))
            s += iPv4Analyzer;
        else if (etherType.equals(Type.ARP))
            s += arpAnalyzer;
        else
            s += iPv6Analyzer;
        return s;
    }
}
