package model.analyzers.arp;

import model.address.AddressIPv4;
import model.address.AddressIPv6;
import model.address.AddressMAC;
import model.analyzers.AnalyzerException;
import model.analyzers.ethernet.EtherType;
import model.analyzers.ethernet.Type;
import model.enums.HardwareAddressLength;
import model.enums.HardwareType;

public class ARPAnalyzer extends EtherType {

    private HardwareType hardwareType;
    private ProtocolType protocolType;
    private HardwareAddressLength hardwareAddressLength;
    private ProtocolAddressLength protocolAddressLength;
    private Operation operation;
    private int senderHardwareAddress1; // hardware address length = 1
    private AddressMAC senderHardwareAddress6; // h.a.l = 6
    private AddressIPv4 senderProtocolAddress4; // protocol address length = 4 (ipv4)
    private AddressIPv6 senderProtocolAddress6; // p.a.l = 16 (ipv6)
    private int targetHardwareAddress1; // h.a.l = 1
    private AddressMAC targetHardwareAdress6; // h.a.l = 6
    private AddressIPv4 targetProtocolAdress4; // p.a.l = 4
    private AddressIPv6 targetProtocolAdress6; // p.a.l = 16

    public ARPAnalyzer(String[] t) {
        super("Address Resolution Protocol", "ARP", Type.ARP, t);
    }

    public ARPAnalyzer(String t) {
        super("Address Resolution Protocol", "ARP", Type.ARP, t);
    }

    @Override
    public void analyze() throws AnalyzerException {
        int ht = Integer.parseInt(t[0] + t[1], 16);
        if (ht == 1)
            hardwareType = HardwareType.Ethernet;
        else if (ht == 2)
            hardwareType = HardwareType.ExperimentalEthernet;
        else
            hardwareType = HardwareType.UNRECOGNIZED;
        informations.put("Hardware Type", new String[]{hardwareType.toString(), ""});

        String pt = t[2] + t[3];
        if (pt.equals("0800")) {
            protocolType = ProtocolType.IP;
            informations.put("Protocol Type", new String[]{protocolType.toString(), ""});
        } else {
            informations.put("Protocol Type", new String[]{"Unrecognized value", "0x"+pt});
        }

        int o = Integer.parseInt(t[6] + t[7], 16);
        if (o == 1)
            operation = Operation.Request;
        else if (o == 2)
            operation = Operation.Reply;
        else
            operation = Operation.Unrecognized;
        informations.put("Operation", new String[]{operation.toString(), ""});

        int hal = Integer.parseInt(t[4], 16);
        int pal = Integer.parseInt(t[5], 16);

        if (hal == 1) {
            hardwareAddressLength = HardwareAddressLength.TokenRing;
            senderHardwareAddress1 = Integer.parseInt(t[8], 16);
            targetHardwareAddress1 = Integer.parseInt(t[8+hal+pal], 16);

            informations.put("Hardware Address Length", new String[]{hardwareAddressLength.toString(), ""});
            informations.put("Sender Hardware Address", new String[]{String.valueOf(senderHardwareAddress1), "0x" + t[8]});
            informations.put("Target Hardware Address", new String[]{String.valueOf(targetHardwareAddress1), "0x" + t[8+hal+pal]});
        }
        else if (hal == 6) {
            hardwareAddressLength = HardwareAddressLength.Ethernet;
            senderHardwareAddress6 = new AddressMAC(t[8], t[9], t[10], t[11], t[12], t[13]);
            int i = 8 + hal + pal;
            targetHardwareAdress6 = new AddressMAC(t[i], t[i+1], t[i+2], t[i+3], t[i+4], t[i+5]);

            informations.put("Hardware Address Length", new String[]{hardwareAddressLength.toString(), ""});
            informations.put("Sender Hardware Address", new String[]{String.valueOf(senderHardwareAddress6), ""});
            informations.put("Target Hardware Address", new String[]{String.valueOf(targetHardwareAdress6), ""});
        }

        if (pal == 4) {
            protocolAddressLength = ProtocolAddressLength.IPv4;
            int i = 8 + hal;
            senderProtocolAddress4 = new AddressIPv4(
                    Integer.parseInt(t[i], 16),
                    Integer.parseInt(t[i+1], 16),
                    Integer.parseInt(t[i+2], 16),
                    Integer.parseInt(t[i+3], 16)
            );
            i = 8 + 2 * hal + pal;
            targetProtocolAdress4 = new AddressIPv4(
                    Integer.parseInt(t[i], 16),
                    Integer.parseInt(t[i+1], 16),
                    Integer.parseInt(t[i+2], 16),
                    Integer.parseInt(t[i+3], 16)
            );

            informations.put("Protocol Address Length", new String[]{protocolAddressLength.toString(), ""});
            informations.put("Sender Protocol Address", new String[]{senderProtocolAddress4.toString(), ""});
            informations.put("Target Protocol Address", new String[]{targetProtocolAdress4.toString(), ""});
        }
        else if (pal == 16) {
            protocolAddressLength = ProtocolAddressLength.IPv6;
            int i = 8 + hal;
            senderProtocolAddress6 = new AddressIPv6(t[i]+t[i+1], t[i+2]+t[i+3], t[i+4]+t[i+5], t[i+6]+t[i+7],
                    t[i+8]+t[i+9], t[i+10]+t[i+11], t[i+12]+t[i+13], t[i+14]+t[i+15]);
            i = 8 + 2 * hal + pal;
            targetProtocolAdress6 = new AddressIPv6(t[i]+t[i+1], t[i+2]+t[i+3], t[i+4]+t[i+5], t[i+6]+t[i+7],
                    t[i+8]+t[i+9], t[i+10]+t[i+11], t[i+12]+t[i+13], t[i+14]+t[i+15]);

            informations.put("Protocol Address Length", new String[]{protocolAddressLength.toString(), ""});
            informations.put("Sender Protocol Address", new String[]{senderProtocolAddress6.toString(), ""});
            informations.put("Target Protocol Address", new String[]{targetProtocolAdress6.toString(), ""});
        }
    }

    public HardwareType getHardwareType() {
        return hardwareType;
    }

    public ProtocolType getProtocolType() {
        return protocolType;
    }

    public HardwareAddressLength getHardwareAddressLength() {
        return hardwareAddressLength;
    }

    public ProtocolAddressLength getProtocolAddressLength() {
        return protocolAddressLength;
    }

    public Operation getOperation() {
        return operation;
    }

    public int getSenderHardwareAddress1() {
        return senderHardwareAddress1;
    }

    public AddressMAC getSenderHardwareAddress6() {
        return senderHardwareAddress6;
    }

    public AddressIPv4 getSenderProtocolAddress4() {
        return senderProtocolAddress4;
    }

    public AddressIPv6 getSenderProtocolAddress6() {
        return senderProtocolAddress6;
    }

    public int getTargetHardwareAddress1() {
        return targetHardwareAddress1;
    }

    public AddressMAC getTargetHardwareAdress6() {
        return targetHardwareAdress6;
    }

    public AddressIPv4 getTargetProtocolAdress4() {
        return targetProtocolAdress4;
    }

    public AddressIPv6 getTargetProtocolAdress6() {
        return targetProtocolAdress6;
    }

    @Override
    public String getRecap() {
        return name + " (" + operation.getName() + "), " + t.length + " bytes";
    }
}
