package model.analyzers.icmp;

import model.address.AddressIPv4;
import model.analyzers.AnalyzerException;
import model.analyzers.ip.IPProtocol;
import model.analyzers.ip.IPProtocolType;

public class ICMPAnalyzer extends IPProtocol {

    private ICMPType icmpType; // all
    private int checksum; // all

    private int identifier; // echo reply, echo request, timestamp, timestamp reply
    private int sequence; // echo reply, echo request, timestamp, timestamp reply
    private int nextHopMTU; // destination unreachable
    private AddressIPv4 ipAddress; // redirect message
    private AddressIPv4 ipHeader; // source quench, redirect message, time exceded
    private int originateTimestamp; // timestamp, timestamp reply
    private int receiveTimestamp; // timestamp, timestamp reply
    private int transmitTimestamp; // timestamp, timestamp reply
    private AddressIPv4 addressMask; // adress mask, adress mak reply

    public ICMPAnalyzer(String[] t) {
        super("Internet Control Message Protocol", "ICMP", IPProtocolType.ICMP, t);
    }

    public ICMPAnalyzer(String t) {
        super("Internet Control Message Protocol", "ICMP", IPProtocolType.ICMP, t);
    }

    @Override
    public void analyze() throws AnalyzerException {
        int type = Integer.parseInt(t[0], 16);
        int code = Integer.parseInt(t[1], 16);

        icmpType = ICMPType.getICMPType(type, code);
        if (icmpType == null)
            throw new AnalyzerException("ICMP. Type & Code. Unrecognized values " + t[0] + " & " + t[1], 0);

        informations.put("Type", new String[]{String.valueOf(type), "0x"+t[0]});
        informations.put("Code", new String[]{String.valueOf(code), "0x"+t[1]});
        informations.put("Type-Code", new String[]{icmpType.getName() + " (" + icmpType.getDescription() + ")", ""});

        checksum = Integer.parseInt(t[2] + t[3], 16);
        informations.put("Checksum", new String[]{String.valueOf(checksum), "0x" + t[2] + t[3]});

        if (type == 0 || type == 8 || type == 13 || type == 14) {
            identifier = Integer.parseInt(t[4] + t[5], 16);
            sequence = Integer.parseInt(t[6] + t[7], 16);
            informations.put("Identifier", new String[]{String.valueOf(identifier), "0x" + t[4] + t[5]});
            informations.put("Sequence", new String[]{String.valueOf(sequence), "0x" + t[6] + t[7]});
        }

        if (type == 3) {
            nextHopMTU = Integer.parseInt(t[6] + t[7], 16);
            informations.put("Next Hop MTU", new String[]{String.valueOf(nextHopMTU), "0x" + t[6] + t[7]});
        }

        if (type == 5) {
            ipAddress = new AddressIPv4(Integer.parseInt(t[4], 16),
                    Integer.parseInt(t[5], 16),
                    Integer.parseInt(t[6], 16),
                    Integer.parseInt(t[7], 16));
            informations.put("IP Address", new String[]{ipAddress.toString(), ""});
        }

        if (type == 4 || type == 5 || type == 11) {
            ipHeader = new AddressIPv4(Integer.parseInt(t[8], 16),
                    Integer.parseInt(t[9], 16),
                    Integer.parseInt(t[10], 16),
                    Integer.parseInt(t[11], 16));
            informations.put("IP Header", new String[]{ipHeader.toString(), ""});
        }

        if (type == 13 || type == 14) {
            originateTimestamp = Integer.parseInt(t[8] + t[9] + t[10] + t[11], 16);
            receiveTimestamp = Integer.parseInt(t[12] + t[13] + t[14] + t[15], 16);
            transmitTimestamp  = Integer.parseInt(t[16] + t[17] + t[18] + t[19], 16);

            informations.put("Originate Timestamp", new String[]{String.valueOf(originateTimestamp), "0x" + t[8] + t[9] + t[10] + t[11]});
            informations.put("Receive Timestamp", new String[]{String.valueOf(receiveTimestamp), "0x" + t[12] + t[13] + t[14] + t[15]});
            informations.put("Transmit Timestamp", new String[]{String.valueOf(transmitTimestamp), "0x" + t[16] + t[17] + t[18] + t[19]});
        }

        if (type == 17 || type == 18) {
            addressMask = new AddressIPv4(Integer.parseInt(t[8], 16),
                    Integer.parseInt(t[9], 16),
                    Integer.parseInt(t[10], 16),
                    Integer.parseInt(t[11], 16));
            informations.put("Address Mask", new String[]{addressMask.toString(), ""});
        }
    }

    public ICMPType getIcmpType() {
        return icmpType;
    }

    public int getChecksum() {
        return checksum;
    }

    public int getIdentifier() {
        return identifier;
    }

    public int getSequence() {
        return sequence;
    }

    public int getNextHopMTU() {
        return nextHopMTU;
    }

    public AddressIPv4 getIpAddress() {
        return ipAddress;
    }

    public AddressIPv4 getIpHeader() {
        return ipHeader;
    }

    public int getOriginateTimestamp() {
        return originateTimestamp;
    }

    public int getReceiveTimestamp() {
        return receiveTimestamp;
    }

    public int getTransmitTimestamp() {
        return transmitTimestamp;
    }

    public AddressIPv4 getAddressMask() {
        return addressMask;
    }

    @Override
    public String getRecap() {
        return name + ", " + icmpType.getName() + ", Type : " + icmpType.getType() + ", Code : " + icmpType.getCode() + ", " + t.length + " bytes";
    }
}
