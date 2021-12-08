package model.analyzers.udp;

import model.analyzers.AnalyzerException;
import model.analyzers.dhcp.DHCPAnalyzer;
import model.analyzers.dns.DNSAnalyzer;
import model.analyzers.ip.IPProtocol;
import model.analyzers.ip.IPProtocolType;

import java.util.Arrays;

public class UDPAnalyzer extends IPProtocol {

    private int portSource;
    private int portDestination;
    private int length;
    private int checksum;
    private String data;
    private DHCPAnalyzer dhcpAnalyzer;
    private DNSAnalyzer dnsAnalyzer;

    public UDPAnalyzer(String[] t) {
        super("User Datagram Protocol", "UDP", IPProtocolType.UDP, t);
    }

    public UDPAnalyzer(String t) {
        super("User Datagram Protocol", "UDP", IPProtocolType.UDP, t);
    }

    @Override
    public void analyze() throws AnalyzerException {
        portSource = Integer.parseInt(t[0] + t[1], 16);
        portDestination = Integer.parseInt(t[2] + t[3], 16);
        length = Integer.parseInt(t[4] + t[5], 16);
        checksum = Integer.parseInt(t[6] + t[7], 16);

        informations.put("Port Source", new String[]{String.valueOf(portSource), "0x" + t[0] + t[1]});
        informations.put("Port Destination", new String[]{String.valueOf(portDestination), "0x" + t[2] + t[3]});
        informations.put("Length", new String[]{String.valueOf(length), "0x" + t[4] + t[5]});
        informations.put("Checksum", new String[]{String.valueOf(checksum), "0x" + t[4] + t[5]});

        data = "";

        String[] t1 = Arrays.copyOfRange(t, 8, t.length);
        // DHCP
        if (portDestination == 67 || portDestination == 68 || portSource == 67 || portSource == 68) {
            dhcpAnalyzer = new DHCPAnalyzer(t1);
            try {
                dhcpAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 8);
            }
            protocolName = dhcpAnalyzer.getProtocolName();
        }
        // DNS
        else if (portSource == 53 || portDestination == 53) {
            dnsAnalyzer = new DNSAnalyzer(t1);
            try {
                dnsAnalyzer.analyze();
            } catch (AnalyzerException ae) {
                throw new AnalyzerException(ae.getMessage(), ae.getByteNumber() + 8);
            }
            protocolName = dnsAnalyzer.getProtocolName();
        }
        // Data
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

    public int getLength() {
        return length;
    }

    public int getChecksum() {
        return checksum;
    }

    public DHCPAnalyzer getDhcpAnalyzer() {
        return dhcpAnalyzer;
    }

    public DNSAnalyzer getDnsAnalyzer() {
        return dnsAnalyzer;
    }

    public String getData() {
        return data;
    }

    @Override
    public String getRecap() {
        return super.getRecap() + ", Src port : " + portSource + ", Dest port : " + portDestination + ", " + t.length + " bytes";
    }

    @Override
    public String toString() {
        String s = super.toString();
        if (dhcpAnalyzer != null)
            s += dhcpAnalyzer.toString();
        else if (dnsAnalyzer != null)
            s += dnsAnalyzer.toString();
        else
            s += "\nData: " + data;
        return s;
    }
}
