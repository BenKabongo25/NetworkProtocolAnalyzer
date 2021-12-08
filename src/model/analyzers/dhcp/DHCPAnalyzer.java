package model.analyzers.dhcp;

import model.address.AddressIPv4;
import model.address.AddressMAC;
import model.analyzers.AnalyzerException;
import model.analyzers.SimpleAnalyzer;
import model.enums.HardwareAddressLength;
import model.enums.HardwareType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DHCPAnalyzer extends SimpleAnalyzer {

    private OpCode operationCode;
    private DHCPMessageType messageType;
    private HardwareType hardwareType;
    private HardwareAddressLength hardwareAddressLength;
    private int hops;
    private long transactionIdentifier;
    private int seconds;
    private int broadcast;
    private int reserved;
    private AddressIPv4 clientIPAddress;
    private AddressIPv4 yourIPAddress;
    private AddressIPv4 serverIPAddress;
    private AddressIPv4 gatewayIPAddress;
    private AddressMAC clientHardwareAddress;
    private String serverName;
    private String bootFileName;
    private String magicCookie;

    private int optionId; // options counter
    private Map<Integer, DHCPOption<Long>> numberOptions;
    private Map<Integer, DHCPOption<String>> stringOptions;
    private Map<Integer, DHCPOption<List<Integer>>> listNumberOptions;
    private Map<Integer, DHCPOption<List<AddressIPv4>>> ipOptions;
    private Map<Integer, DHCPOption<List<AddressMAC>>> macOptions;

    private String padding;

    public DHCPAnalyzer(String[] t) {
        super("Dynamic Host Configuration Protocol", "DHCP", t);
    }

    public DHCPAnalyzer(String t) {
        super("Dynamic Host Configuration Protocol", "DHCP", t);
    }

    @Override
    public void analyze() throws AnalyzerException {
        int opcode = Integer.parseInt(t[0], 16);
        if (opcode == 1)
            operationCode = OpCode.BOOT_REQUEST;
        else if (opcode == 2)
            operationCode = OpCode.BOOT_REPLY;
        else
            operationCode = OpCode.UNRECOGNIZED;
        informations.put("Operation code", new String[]{operationCode.toString(), operationCode.getDescription()});

        int htype = Integer.parseInt(t[1], 16);
        if (htype == 1)
            hardwareType = HardwareType.Ethernet;
        else
            hardwareType = HardwareType.UNRECOGNIZED;
        informations.put("Hardware Type", new String[]{hardwareType.toString(), hardwareType.getDescription()});

        int hlen = Integer.parseInt(t[2], 16);
        if (hlen == 6)
            hardwareAddressLength = HardwareAddressLength.Ethernet;
        else
            hardwareAddressLength = HardwareAddressLength.UNRECOGNIZED;
        informations.put("Hardware Address Length", new String[]{hardwareAddressLength.toString(), hardwareAddressLength.getDescription()});

        hops = Integer.parseInt(t[3], 16);
        informations.put("Hops", new String[]{String.valueOf(hops), "0x" + t[3]});

        transactionIdentifier = Long.parseLong(t[4] + t[5] + t[6] + t[7], 16);
        informations.put("Transaction identifier", new String[]{String.valueOf(transactionIdentifier), "0x" +t[4] + t[5] + t[6] + t[7]});

        seconds = Integer.parseInt(t[8] + t[9], 16);
        informations.put("Seconds", new String[]{String.valueOf(seconds), "0x" + t[8] + t[9]});

        String ABCD = Integer.toBinaryString(Integer.parseInt(t[10] + t[11], 16));
        if (ABCD.length() < 16) ABCD = "0000000000000000".substring(0, 16-ABCD.length()) + ABCD;
        broadcast = Integer.parseInt(ABCD.substring(0, 1), 2);
        reserved = Integer.parseInt(ABCD.substring(1, 16), 2);

        informations.put("Broadcast Flag", new String[]{String.valueOf(broadcast), (broadcast == 0) ? "No":"Yes"});
        informations.put("Reserved", new String[]{String.valueOf(reserved), "0x" + ABCD.substring(1, 16)});

        clientIPAddress = new AddressIPv4(
                Integer.parseInt(t[12], 16),
                Integer.parseInt(t[13], 16),
                Integer.parseInt(t[14], 16),
                Integer.parseInt(t[15], 16));
        informations.put("Client IP address", new String[]{clientIPAddress.toString(), ""});

        yourIPAddress = new AddressIPv4(
                Integer.parseInt(t[16], 16),
                Integer.parseInt(t[17], 16),
                Integer.parseInt(t[18], 16),
                Integer.parseInt(t[19], 16));
        informations.put("Your IP address", new String[]{yourIPAddress.toString(), ""});

        serverIPAddress = new AddressIPv4(
                Integer.parseInt(t[20], 16),
                Integer.parseInt(t[21], 16),
                Integer.parseInt(t[22], 16),
                Integer.parseInt(t[23], 16));
        informations.put("Server IP address", new String[]{serverIPAddress.toString(), ""});

        gatewayIPAddress = new AddressIPv4(
                Integer.parseInt(t[24], 16),
                Integer.parseInt(t[25], 16),
                Integer.parseInt(t[26], 16),
                Integer.parseInt(t[27], 16));
        informations.put("Relay agent IP address", new String[]{gatewayIPAddress.toString(), ""});

        clientHardwareAddress = new AddressMAC(t[28], t[29], t[30], t[31], t[32], t[33]);
        informations.put("Client Hardware Address", new String[]{clientHardwareAddress.toString(), ""});

        serverName = "";
        for (String s: Arrays.copyOfRange(t,44, 108)) {
            int ascii = Integer.parseInt(s, 16);
            serverName += (ascii == 0) ? "" : Character.toString((char) ascii);
        }
        informations.put("Server Name", new String[]{serverName, ""});

        bootFileName = "";
        for (String s: Arrays.copyOfRange(t,108, 236)) {
            int ascii = Integer.parseInt(s, 16);
            bootFileName += (ascii == 0) ? "" : Character.toString((char) ascii);
        }
        informations.put("Boot File Name", new String[]{bootFileName, ""});

        magicCookie = String.join("" , Arrays.copyOfRange(t, 236, 240));
        informations.put("Magic Cookie", new String[]{(magicCookie.equals("63825363")) ? "OK":"Not OK", "0x" + magicCookie});

        int i = 240;
        optionId = 0;
        numberOptions = new HashMap<>();
        stringOptions = new HashMap<>();
        listNumberOptions = new HashMap<>();
        ipOptions = new HashMap<>();
        macOptions = new HashMap<>();

        while(true) {
            int code = Integer.parseInt(t[i], 16);
            OptionType type = OptionType.getOptionType(code);
            if (type == null)
                type = OptionType.UNRECOGNIZED_OPTION;
            if (code == 0) {
                numberOptions.put(optionId, new DHCPOption<>(type));
                i++;
            }
            else if (code == 255) {
                numberOptions.put(optionId, new DHCPOption<>(type));
                i++;
            }
            else if (code == 80) {
                //int length = Integer.parseInt(t[i+1], 16);
                //if (length != 0)
                //    throw new AnalyzerException("DHCP. The size of the <" + type.getName() + "> option must be equal to 0", i+1);
                numberOptions.put(optionId, new DHCPOption<>(type, code, 0));
                i += 2;
            }
            else {
                // if (length == 0)
                // throw new AnalyzerException("DHCP. The size of the <" + type.getName() + "> option must not be equal to 0", i+1);
                // unvariables length
                // if (type.getLength() > 0 && length != type.getLength())
                //    throw new AnalyzerException("DHCP. The size of the <" + type.getName() + "> option must be equal to " + type.getLength(), i+1);
                // variables length
                // else if (type.getLength() < 0 && length % (-1 * type.getLength()) != 0)
                //    throw new AnalyzerException("DHCP. The size of the <" + type.getName() + "> option must be a multiple of " + (-1 * type.getLength()), i+1);
                int length = Integer.parseInt(t[i+1], 16);
                String[] st = Arrays.copyOfRange(t, i + 2, i + 2 + length);
                if (type.getValueType() == OptionType.NUMBER_VALUE)
                    numberOptions.put(optionId, new DHCPOption<>(type, code, length, Long.parseLong(String.join("", st), 16)));
                else if (type.getValueType() == OptionType.ENUM_VALUE) {
                    int value = Integer.parseInt(String.join("", st), 16);
                    if (type.equals(OptionType.DHCPMessageTypeOption)) {
                        DHCPMessageType messageType = DHCPMessageType.getDHCPMessageType(value);
                        if (messageType == null)
                            messageType = DHCPMessageType.UNRECOGNIZED;
                        numberOptions.put(optionId, new DHCPOption<>(type, code, length, (long) messageType.getValue()));
                        nameCode = messageType.getName();
                        this.messageType = messageType;
                    }
                    else if (type.equals(OptionType.NetBIOSOverTCPIPNodeTypeOption)) {
                        NetBIOS netBIOS = NetBIOS.getNetBIOS(value);
                        if (netBIOS == null)
                            netBIOS = NetBIOS.UNRECOGNIZED;
                        numberOptions.put(optionId, new DHCPOption<>(type, code, length, (long) netBIOS.getValue()));
                    }
                    else if (type.equals(OptionType.OverloadOption)) {
                        Overload overload = Overload.getOptionOverload(value);
                        if (overload == null)
                            overload = Overload.UNRECOGNIZED;
                        numberOptions.put(optionId, new DHCPOption<>(type, code, length, (long) overload.getValue()));
                    }
                }
                else if (type.getValueType() == OptionType.STRING_VALUE) {
                    String value = "";
                    for (String s : st) {
                        int ascii = Integer.parseInt(s, 16);
                        value += (ascii == 0) ? "" : Character.toString((char) ascii);
                    }
                    stringOptions.put(optionId, new DHCPOption<>(type, code, length, value));
                }
                else if (type.getValueType() == OptionType.HEXA_VALUE) {
                    String value = "0x"  + String.join("", st);
                    stringOptions.put(optionId, new DHCPOption<>(type, code, length, value));
                }
                else if (type.getValueType() == OptionType.LIST_VALUE) {
                    List<Integer> values = new ArrayList<>();
                    for (int j = 0; j < length; j++) {
                        values.add(Integer.parseInt(st[j], 16));
                    }
                    listNumberOptions.put(optionId, new DHCPOption<>(type, code, length, values));
                }
                else if (type.getValueType() == OptionType.IP_VALUE) {
                    List<AddressIPv4> ips = new ArrayList<>();
                    for (int j = 0; j < length; j += 4) {
                        ips.add(new AddressIPv4(
                                Integer.parseInt(st[j], 16),
                                Integer.parseInt(st[j + 1], 16),
                                Integer.parseInt(st[j + 2], 16),
                                Integer.parseInt(st[j + 3], 16)));
                    }
                    ipOptions.put(optionId, new DHCPOption<>(type, code, length, ips));
                }
                else if (type.getValueType() == OptionType.MAC_VALUE) {
                    List<AddressMAC> macs = new ArrayList<>();
                    int j = 0;
                    macs.add(new AddressMAC(st[j], st[j+1], st[j+2], st[j+3], st[j+4], st[j+5]));
                    macOptions.put(optionId, new DHCPOption<>(type, code, length, macs));
                }
                i += 2 + length;
            }
            optionId++;
            if (code == 255 || i == t.length -1)
                break;
        }
        padding = (i >= t.length) ? "" : String.join("", Arrays.copyOfRange(t,i, t.length));
    }

    public OpCode getOperationCode() {
        return operationCode;
    }

    public DHCPMessageType getMessageType() {
        return messageType;
    }

    public HardwareType getHardwareType() {
        return hardwareType;
    }

    public HardwareAddressLength getHardwareAddressLength() {
        return hardwareAddressLength;
    }

    public int getHops() {
        return hops;
    }

    public long getTransactionIdentifier() {
        return transactionIdentifier;
    }

    public int getSeconds() {
        return seconds;
    }

    public int getBroadcast() {
        return broadcast;
    }

    public int getReserved() {
        return reserved;
    }

    public AddressIPv4 getClientIPAddress() {
        return clientIPAddress;
    }

    public AddressIPv4 getYourIPAddress() {
        return yourIPAddress;
    }

    public AddressIPv4 getServerIPAddress() {
        return serverIPAddress;
    }

    public AddressIPv4 getGatewayIPAddress() {
        return gatewayIPAddress;
    }

    public AddressMAC getClientHardwareAddress() {
        return clientHardwareAddress;
    }

    public String getServerName() {
        return serverName;
    }

    public String getBootFileName() {
        return bootFileName;
    }

    public String getMagicCookie() {
        return magicCookie;
    }

    public int getOptionsCount() {
        return optionId;
    }

    public Map<Integer, DHCPOption<Long>> getNumberOptions() {
        return numberOptions;
    }

    public Map<Integer, DHCPOption<String>> getStringOptions() {
        return stringOptions;
    }

    public Map<Integer, DHCPOption<List<Integer>>> getListNumberOptions() {
        return listNumberOptions;
    }

    public Map<Integer, DHCPOption<List<AddressIPv4>>> getIpOptions() {
        return ipOptions;
    }

    public Map<Integer, DHCPOption<List<AddressMAC>>> getMacOptions() {
        return macOptions;
    }

    public String getPadding() {
        return padding;
    }

    @Override
    public String toString() {
        String s =  super.toString();
        if (optionId > 0) {
            s += "\nOptions DHCP \n -------------------";
            for (int i = 0; i < optionId; i++) {
                if (numberOptions != null && numberOptions.containsKey(i)) {
                    DHCPOption<Long> option = numberOptions.get(i);
                    s += "\n\t" + option.getOptionType().getName() +
                            "\n\t\tLength = " + option.getLength();
                    int code = option.getOptionType().getCode();
                    if (code != 0 && code != 255 && code != 80) {
                        if (option.getOptionType().getValueType() == OptionType.ENUM_VALUE) {
                            long value = option.getValue();
                            if (option.getOptionType().equals(OptionType.DHCPMessageTypeOption))
                                s += "\n\t\tValue = " + DHCPMessageType.getDHCPMessageType((int)value).getName();
                            else if (option.getOptionType().equals(OptionType.OverloadOption))
                                s += "\n\t\tValue = " + Overload.getOptionOverload((int)value).getMeaning();
                            else if (option.getOptionType().equals(OptionType.NetBIOSOverTCPIPNodeTypeOption)) {
                                s += "\n\t\tValue = " + NetBIOS.getNetBIOS((int)value).getName();
                            }
                        }
                        else s += "\n\t\tValue = " + option.getValue();
                    }
                }
                else if (stringOptions != null && stringOptions.containsKey(i)) {
                    DHCPOption<String> option = stringOptions.get(i);
                    s += "\n\t" + option.getOptionType().getName() +
                            "\n\t\tLength = " + option.getLength() +
                            "\n\t\tValue = " + option.getValue();
                }
                else if (ipOptions != null && ipOptions.containsKey(i)) {
                    DHCPOption<List<AddressIPv4>> option = ipOptions.get(i);
                    s += "\n\t" + option.getOptionType().getName() +
                            "\n\t\tLength = " + option.getLength();
                    for (AddressIPv4 ip: option.getValue()) {
                        s += "\n\t\t" + ip;
                    }
                }
                else if (listNumberOptions != null && listNumberOptions.containsKey(i)) {
                    DHCPOption<List<Integer>> option = listNumberOptions.get(i);
                    if (option.getOptionType().equals(OptionType.ParameterRequestListOption)) {
                        s += "\n\t" + option.getOptionType().getName() +
                                "\n\t\tLength = " + option.getLength();
                        for (int value: option.getValue()) {
                            OptionType optionValue = OptionType.getOptionType(value);
                            s += "\n\t\t" + value + " = (" + value + ") " + ((optionValue == null) ? "Unrecognized": optionValue.getName());
                        }
                    }
                }
            }
        }
        if (padding != null && !padding.isEmpty())
            s += "\nPadding\t: " + padding;
        return s;
    }

    @Override
    public String getRecap() {
        return super.getRecap() + ", " + t.length + " bytes";
    }
}
